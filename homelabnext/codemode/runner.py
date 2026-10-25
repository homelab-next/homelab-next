# SPDX-License-Identifier: Apache-2.0
"""The Code Mode runner: ``codemode.execute``'s handler (ADR-0031 decisions 2, 6 and 7; CM-5b).

The broker hands the runner one ``codemode.execute`` request, ``{request_id, actor, params}``
with ``params`` a ``schemas/codemode/execution_request``, while that request is in flight
(``docs/broker.md``, "Code Mode capability tokens").  :meth:`Runner.handle`:

1. checks the request and, for a resume, its journal (only a **paused** execution of the same
   actor and code digest resumes) and the paused request's state, read with ``token_status``
   (``paused_by_state``), never by polling ``token_run``, which spends the execution's cap: while
   it reads ``pending`` or ``expired`` the run ends ``paused`` again at once, issued no token and
   having sent nothing;
2. asks the broker for the run's token (``issue_token``, as the runner the run is bound to),
   listing the actions the actor is granted (never ``codemode.*``; the broker narrows them to what
   ``decide()`` admits, and the call cap and lifetime come from the request's budget);
3. serves the run's broker endpoint (:class:`_Relay`, the CM-4 wire at the executor's
   ``broker_bind``) and hands the program, the endpoint and the token to the
   :class:`~conformance.protocols.codemode_executor.CodeExecutor`;
4. turns every call the program makes into a broker request made **with the token**: ``call`` is
   ``token_call``, ``submit`` is ``token_submit``, and on a resume the step that paused is
   ``token_run`` of the paused request; each call is journalled (:mod:`.journal`) and answered;
5. returns a ``schemas/codemode/execution_result`` and spends the token (``paused`` when the run
   ended on a pause, else ``finished``).

**Answers to the program.**  A broker answer becomes a CM-4 reply:

* ``{result}``: ``ok`` with the value.  An exec handler's envelope (``{exit_code, output,
  truncated, stderr_bytes}``, recognised by exactly those keys) is unwrapped to ``output``: the
  handler's stdout decoded as JSON when it is JSON, else its text (the broker decides, CM-3).
  The cases that are not that success are defined here: **text** output is the value as a
  string; **truncated** output (the handler printed more than its ``max_output_bytes``) is never
  returned, the program gets ``broker.Error`` with reason ``output-truncated``; a **non-zero
  exit** never reaches the runner as a result (the broker refuses it, ``handler-failed``, an
  error reply); an output that does not match the action's ``result_schema`` (from the search
  index, when the runner has one) is ``broker.Error`` with reason ``result-schema-mismatch``,
  data, never a runner failure; a result over the journal's ``max_result_bytes`` is
  ``result-too-large``.  In each of these the call record and the journal keep the broker's own
  outcome (``ok``) and result: the record is what the broker decided, the reply what the program
  may use;
* ``{state: pending}``: a pending reply, which pauses the run (the broker has paused the token);
* a refusal (``Denied``, ``InvalidArguments``): a **denied call**, recorded with the broker's
  reason (``invalid-params`` for invalid arguments without one), and the program gets
  ``broker.Denied`` with that reason: a value it can catch and act on (the CM-4 contract), never
  an exception it cannot see.  A refusal the broker raised once it had built the request carries
  its ``request_id`` and ``request_digest`` and is journalled; a token refusal (``TOKEN_REFUSALS``)
  has neither and is not, so a resume calls again with its new token;
* any other ``BrokerError``: an **error call** (``broker.Error``) with its reason; a transport
  failure is ``broker-unreachable``.

**Resume without replay.**  A resume runs the program again from the start in a fresh sandbox,
but no step the journal holds is sent again: a settled step whose action and call fingerprint
match is answered from the journal and marked ``replayed`` (its outcome, reason and ids the
recorded ones); the pending step is ``token_run`` of its request; only the steps after it are new
broker calls.  A call that differs from the journal's at its step (a program that is not
deterministic) is refused with ``broker.Error`` reason ``replay-mismatch``, every later call too,
and the run ends ``error``: the journal is never replayed into a different program.  The cap is
the execution's (the broker's): a resume's token carries what is left of it.

**Status.**  A run with a pending call is ``paused`` (``pending`` names it), whatever the
program did after; otherwise a cap the executor reports is ``limit``; a replay mismatch is
``error``; a call the broker refused ``call-cap-reached`` ends the run ``limit`` (``calls``),
since the broker's count is the enforcement; otherwise the executor's status stands (``ok`` with
the value, ``denied`` when the program let a denial escape, ``error``).  ``calls``, ``pending``
and the journal are the runner's own record of what the broker answered; ``value``, ``logs``
and ``error.message`` are program output, untrusted.

**Transport.**  In process the broker is a :class:`~conformance.protocols.broker.CodemodeTokens`
(the reference service or the fake) for both roles.  Over the socket the runner speaks as its
``codemode.runners`` peer (:class:`SocketRunnerBroker`) and the relay as a ``codemode.sandboxes``
peer (:class:`SocketSandboxBroker`: ``token-call``, ``token-submit``, ``token-run`` with the
token on its bearer line, ``BrokerClient``'s sandbox path), so in a deployment the relay's
connection is made from the sandbox's user, the one the token is bound to.  The real executor and
its sandbox host are CM-7 and CM-8.
"""

from __future__ import annotations

import contextlib
import hmac
import json
import logging
import os
import re
import socket
import threading
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from conformance.protocols.broker import (
    TOKEN_REFUSALS,
    BrokerError,
    Denied,
    InvalidArguments,
    IssuedToken,
    code_digest,
)
from conformance.protocols.codemode_executor import (
    MESSAGE_MAX,
    MESSAGE_UNSAFE,
    BrokerEndpoint,
    ExecutorError,
    Limits,
)
from homelabnext.broker import validation

from .journal import (
    DEFAULT_MAX_RESULT_BYTES,
    DEFAULT_PAUSED_RETENTION_DAYS,
    DEFAULT_RETENTION_DAYS,
    JOURNAL_RECORD,
    Journal,
    JournalError,
    digest_of,
)

__all__ = [
    "DEFAULT_RUNNER_ID",
    "ENVELOPE_KEYS",
    "ID_LESS_REASONS",
    "RESULT_SCHEMA",
    "Runner",
    "RunnerError",
    "SocketRunnerBroker",
    "SocketSandboxBroker",
    "load_index",
    "unwrap",
]

log = logging.getLogger("homelabnext.codemode.runner")

DEFAULT_RUNNER_ID = "svc:codemode-runner"
#: the result's schema (``schemas/codemode/execution_result``)
RESULT_SCHEMA = "codemode/execution_result"
#: an exec handler's answer as the broker wraps it (``docs/broker.md``, "Exec handlers")
ENVELOPE_KEYS = frozenset({"exit_code", "output", "truncated", "stderr_bytes"})
#: reasons of a call the broker refused before it built a request: no ids, never journalled
ID_LESS_REASONS = frozenset({*TOKEN_REFUSALS, "broker-unreachable", "rate-limited"})
#: the broker's success reasons, never a denied call's (``schemas/codemode``)
_SUCCESS = frozenset({"allowed", "approved", "approval-required"})
_REASON_RE = re.compile(r"^[a-z][a-z0-9-]{0,63}$")
_UNSAFE = re.compile(MESSAGE_UNSAFE)
#: the longest wire line the relay reads from the program (a call's JSON)
MAX_LINE_BYTES = 1 << 20
#: the run's defaults when its budget names none (the broker's ``codemode.default_wall_s`` is 60)
DEFAULT_WALL_S = 60
DEFAULT_CPU_S = 10.0
DEFAULT_MEMORY_MB = 256
DEFAULT_OUTPUT_BYTES = 64 * 1024
#: the sandbox id a pool's tokens are bound to (a pool peer accepts only tokens bound to no
#: dedicated sandbox, ``docs/broker.md``)
DEFAULT_SANDBOX_ID = "sandbox-pool"
MAX_LOG_LINES, MAX_LOG_CHARS = 100, 1000
#: how often the journal is swept at most (s of the injected clock)
SWEEP_INTERVAL_S = 60.0


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _stamp(t: datetime) -> str:
    return t.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _line(text: str, limit: int = MESSAGE_MAX) -> str:
    return _UNSAFE.sub(" ", str(text))[:limit]


class RunnerError(RuntimeError):
    """A runner bug (a result it built does not validate): the broker reports the execute as
    ``handler-failed``.  Never raised for anything a program or the broker did."""


def unwrap(result: Any) -> tuple[str, Any]:
    """``("ok", value)`` for a broker result as the program gets it, or ``("error", reason)``:
    an exec envelope is unwrapped to its ``output`` (see the module doc for the cases)."""
    if isinstance(result, Mapping) and set(result) == ENVELOPE_KEYS:
        if result.get("truncated") is True:
            return "error", "output-truncated"
        if result.get("exit_code") != 0:
            return "error", "handler-failed"
        return "ok", result.get("output")
    return "ok", result


def load_index(directory: str | os.PathLike[str]) -> dict[str, dict[str, dict[str, Any]]]:
    """The generator's search indexes under ``directory`` (``<profile>/search.json``, ``hnx
    codemode gen``): ``{profile id: {action name: entry}}``.  An unreadable or malformed file is
    skipped (logged): the runner then knows less, never more."""
    out: dict[str, dict[str, dict[str, Any]]] = {}
    root = Path(directory)
    for path in sorted(root.glob("*/search.json")):
        if path.is_symlink() or path.parent.is_symlink():
            continue
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
            profile = doc["profile"]
            entries = {a["name"]: dict(a) for a in doc["actions"]}
        except (OSError, ValueError, KeyError, TypeError):
            log.warning("codemode: %s is not a search index; skipped", path)
            continue
        if isinstance(profile, str):
            out[profile] = entries
    return out


# ---------------------------------------------------------------- the socket adapters
class SocketRunnerBroker:
    """The runner's three operations over the broker socket, as its ``codemode.runners`` peer
    (the broker takes the identity from the peer; ``runner`` is ignored)."""

    def __init__(self, client: Any) -> None:
        self.client = client

    def issue_token(self, runner, request_id, *, sandbox_id, actions, max_calls=None, ttl_s=None):
        got = self.client.token_issue(
            request_id,
            sandbox_id=sandbox_id,
            actions=list(actions),
            max_calls=max_calls,
            ttl_s=ttl_s,
        )
        return IssuedToken(got["secret"], got["claims"])

    def spend_token(self, runner, token_id, outcome="finished"):
        self.client.token_spend(token_id, outcome)

    def token_status(self, runner, token_id):
        return self.client.token_status(token_id)


class SocketSandboxBroker:
    """The relay's three operations as a ``codemode.sandboxes`` peer: ``BrokerClient``'s sandbox
    path, the token on its bearer line (``docs/broker.md``, "Sandbox socket framing")."""

    def __init__(self, client: Any) -> None:
        self.client = client

    def token_call(self, token, command, args, *, target=None, sandbox_id=None):
        return self.client.token_call(token, command, args, target=target)

    def token_submit(self, token, command, args, *, target=None, sandbox_id=None):
        return self.client.token_submit(token, command, args, target=target)

    def token_run(self, token, request_id, *, sandbox_id=None):
        return self.client.token_run(token, request_id)


# ---------------------------------------------------------------- one run
@dataclass
class _Run:
    """What one run of an execution knows and has recorded."""

    request_id: str
    actor: str
    execution_id: str
    code_digest: str
    secret: str = field(default="", repr=False)
    token_id: str = ""
    max_calls: int = 1  # the calls the run's token may make
    journal: dict[int, dict[str, Any]] = field(default_factory=dict)  # step -> {record, call}
    calls: list[dict[str, Any]] = field(default_factory=list)
    pending: list[dict[str, Any]] = field(default_factory=list)
    next_step: int = 0
    mismatch: int | None = None  # the step whose call differed from the journal's
    capped: bool = False  # the broker refused a call call-cap-reached
    lock: threading.Lock = field(default_factory=threading.Lock)


class Runner:
    """``codemode.execute``'s handler (see the module doc).

    ``broker`` holds the runner's operations (``issue_token``, ``spend_token``,
    ``token_status``); ``sandbox_broker`` the sandbox's (``token_call``, ``token_submit``,
    ``token_run``), the same object in process.  ``actions_for(actor)`` names the actions a token
    may list for that actor (default: the actor's actions in ``index``, the generator's search
    index, :func:`load_index`), which the broker narrows again.  ``index`` also gives each
    action's ``result`` schema, which the runner checks an output against.  Register it with
    ``broker.register_runner(runner.runner_id, runner.handle)`` in process; over the socket the
    manifest's ``codemode.execute`` handler is the runner's client (CM-8)."""

    def __init__(
        self,
        broker: Any,
        executor: Any,
        state_dir: str | os.PathLike[str],
        *,
        runner_id: str = DEFAULT_RUNNER_ID,
        sandbox_broker: Any = None,
        actions_for: Callable[[str], Iterable[str]] | None = None,
        index: Mapping[str, Mapping[str, Mapping[str, Any]]] | None = None,
        sandbox_id: str = DEFAULT_SANDBOX_ID,
        clock: Callable[[], datetime] = _utcnow,
        default_wall_s: int = DEFAULT_WALL_S,
        cpu_s: float = DEFAULT_CPU_S,
        default_memory_mb: int = DEFAULT_MEMORY_MB,
        default_output_bytes: int = DEFAULT_OUTPUT_BYTES,
        max_result_bytes: int = DEFAULT_MAX_RESULT_BYTES,
        retention_days: float = DEFAULT_RETENTION_DAYS,
        paused_retention_days: float = DEFAULT_PAUSED_RETENTION_DAYS,
    ) -> None:
        self.broker = broker
        self.sandbox_broker = sandbox_broker if sandbox_broker is not None else broker
        self.executor = executor
        self.runner_id = runner_id
        self.index = {p: dict(v) for p, v in (index or {}).items()}
        if actions_for is None:
            actions_for = self._indexed_actions
        self.actions_for = actions_for
        self.sandbox_id = sandbox_id
        self.clock = clock
        self.default_wall_s = int(default_wall_s)
        self.cpu_s = float(cpu_s)
        self.default_memory_mb = int(default_memory_mb)
        self.default_output_bytes = int(default_output_bytes)
        self.store = Journal(
            state_dir,
            max_result_bytes=max_result_bytes,
            retention_days=retention_days,
            paused_retention_days=paused_retention_days,
        )
        self._swept: datetime | None = None

    @property
    def languages(self) -> frozenset[str]:
        return frozenset(getattr(self.executor, "languages", ()))

    def _indexed_actions(self, actor: str) -> list[str]:
        return sorted(self.index.get(actor, {}))

    def journal(self, actor: str, execution_id: str) -> list[dict[str, Any]]:
        """Every journal record of ``actor``'s execution, in append order."""
        return self.store.records(actor, execution_id)

    def sweep(self, *, force: bool = False) -> int:
        """Drop journals past their retention, at most once a minute unless ``force``."""
        now = self.clock()
        recent = self._swept is not None and (now - self._swept).total_seconds() < SWEEP_INTERVAL_S
        if not force and recent:
            return 0
        self._swept = now
        return self.store.sweep(now)

    # ---------------------------------------------------------------- the handler
    def handle(self, request: Mapping[str, Any]) -> dict[str, Any]:
        """Run one ``codemode.execute`` request; returns its execution result."""
        params = request.get("params")
        problems = validation.named_errors("codemode/execution_request", params)
        if problems:  # the broker checks this before the handler runs; never trust the caller
            raise RunnerError(f"not an execution request: {problems[0]}")
        try:
            self.sweep()
        except OSError:
            log.exception("codemode: the journal could not be swept")
        run = _Run(
            request_id=str(request["request_id"]),
            actor=str(request["actor"]),
            execution_id=params["execution_id"],
            code_digest=code_digest(params["language"], params["code"]),
        )
        if params["language"] not in self.languages:
            langs = ", ".join(sorted(self.languages)) or "nothing"
            return self._finish(run, None, error=("sandbox", f"this runner runs {langs}"))
        if params.get("resume"):
            early = self._resume_check(run)
            if early is not None:
                return early
        refused = self._issue(run, params)
        if refused is not None:
            return refused
        return self._execute(run, params)

    def _error(self, run: _Run, kind: str, message: str) -> dict[str, Any]:
        return self._finish(run, None, error=(kind, message))

    def _resume_check(self, run: _Run) -> dict[str, Any] | None:
        """For a resume: None when it may run (the paused request is approved, or denied, which
        the program then sees as a denial), else the result to return now without a token."""
        meta = self.store.execution(run.actor, run.execution_id)
        if meta is None or meta.get("state") != "paused":
            return self._error(run, "token", "execution-not-resumable")
        if meta.get("code_digest") != run.code_digest:
            return self._error(run, "token", "resume-code-mismatch")
        run.journal = self.store.steps(run.actor, run.execution_id)
        waiting = [s for s, e in run.journal.items() if e["record"]["outcome"] == "pending"]
        if len(waiting) != 1 or waiting[0] != max(run.journal):
            return self._error(run, "token", "journal-has-no-paused-step")
        pending = run.journal[waiting[0]]["record"]
        try:
            status = self.broker.token_status(self.runner_id, meta["tokens"][-1])
        except BrokerError as exc:
            return self._error(run, "token", _reason_of(exc, "broker-error"))
        if status.get("paused_by") != pending.get("request_id"):
            return self._error(run, "token", "paused-request-mismatch")
        state = status.get("paused_by_state")
        if state in ("approved", "denied"):
            return None
        if state in ("pending", "expired"):  # still waiting: paused again, nothing sent
            for step, entry in run.journal.items():
                rec = entry["record"]
                if rec["outcome"] == "pending":
                    self._pending(run, step, rec)
                else:
                    run.calls.append(_call_of(rec, replayed=True))
            return self._finish(run, None, waited=True)
        return self._error(run, "token", f"paused-request-{_reason(state, 'unknown')}"[:64])

    def _issue(self, run: _Run, params: Mapping[str, Any]) -> dict[str, Any] | None:
        granted = {a for a in self.actions_for(run.actor) if isinstance(a, str)}
        actions = sorted(a for a in granted if not a.startswith("codemode."))[:200]
        if not actions:
            return self._error(run, "token", "no-granted-actions")
        try:
            issued = self.broker.issue_token(
                self.runner_id, run.request_id, sandbox_id=self.sandbox_id, actions=actions
            )
        except BrokerError as exc:
            return self._error(run, "token", _reason_of(exc, "broker-error"))
        run.secret, run.token_id = issued.secret, str(issued.claims["token_id"])
        run.max_calls = int(issued.claims.get("max_calls", 1))
        now = self.clock()
        if params.get("resume"):
            self.store.update(run.actor, run.execution_id, now, state="running", token=run.token_id)
        elif not self.store.begin(run.actor, run.execution_id, run.code_digest, run.token_id, now):
            self._spend(run, "finished")
            return self._error(run, "token", "execution-exists")
        return None

    def _limits(self, run: _Run, params: Mapping[str, Any]) -> Limits:
        budget = params.get("budget") or {}
        wall = int(budget.get("wall_s", self.default_wall_s))
        out = int(budget.get("max_output_bytes", self.default_output_bytes))
        cap = run.max_calls
        return Limits(
            cpu_s=min(float(wall), self.cpu_s),
            memory_bytes=int(budget.get("memory_mb", self.default_memory_mb)) << 20,
            wall_s=float(wall),
            # the broker's cap is the enforcement: the client may send one past it, so the
            # broker's call-cap-reached is what the runner sees and reports
            max_calls=len(run.journal) + cap + 1,
            output_bytes=out,
            result_bytes=out,
        )

    def _execute(self, run: _Run, params: Mapping[str, Any]) -> dict[str, Any]:
        res = None
        failure: tuple[str, str] | None = None
        try:
            limits = self._limits(run, params)
            with _Relay(self, run, tuple(self.executor.broker_bind)) as relay:
                endpoint = BrokerEndpoint(relay.host, relay.port, token=run.secret)
                res = self.executor.run(
                    params["code"], language=params["language"], broker=endpoint, limits=limits
                )
        except ExecutorError as exc:
            failure = ("sandbox", _line(f"{type(exc).__name__}: {exc}"))
        except Exception as exc:  # the executor failed: still a result, never a runner crash
            log.error("codemode: the executor failed (%s)", type(exc).__name__)
            failure = ("sandbox", "the executor failed")
        return self._finish(run, res, error=failure)

    # ---------------------------------------------------------------- the end of a run
    def _spend(self, run: _Run, outcome: str) -> None:
        try:
            self.broker.spend_token(self.runner_id, run.token_id, outcome)
        except BrokerError as exc:  # the end of the execute spends a live token anyway
            log.warning("codemode: token not spent %s (%s)", outcome, _reason_of(exc, "error"))

    def _finish(
        self, run: _Run, res: Any, *, error: tuple[str, str] | None = None, waited: bool = False
    ) -> dict[str, Any]:
        out: dict[str, Any] = {
            "execution_id": run.execution_id,
            "actor": run.actor,
            "code_digest": run.code_digest,
            "calls": sorted(run.calls, key=lambda c: c["step"]),
        }
        out.update(self._status(run, res, error))
        if res is not None:
            logs = self._log_lines(getattr(res, "output", "") or "")
            if logs:
                out["logs"] = logs
        out["finished_at"] = _stamp(self.clock())
        if run.token_id and not waited:
            paused = out["status"] == "paused"
            self._spend(run, "paused" if paused else "finished")
            with contextlib.suppress(JournalError, OSError):
                state = "paused" if paused else "finished"
                self.store.update(run.actor, run.execution_id, self.clock(), state=state)
        self._check_result(out)
        return out

    def _log_lines(self, output: str) -> list[str]:
        """The printed output as the result's ``logs``: single lines, unsafe characters as
        spaces, at most 100 lines of 1000 characters."""
        return _logs(output)

    def _check_result(self, out: Mapping[str, Any]) -> None:
        problems = validation.named_errors(RESULT_SCHEMA, out)
        if problems:
            raise RunnerError(f"the runner built an invalid result: {problems[0]}")

    def _status(self, run: _Run, res: Any, error: tuple[str, str] | None) -> dict[str, Any]:
        if run.pending:
            return {"status": "paused", "pending": list(run.pending)}
        if error is not None:
            return {"status": "error", "error": {"kind": error[0], "message": error[1]}}
        status = getattr(res, "status", "error")
        if status == "limit":
            return {"status": "limit", "limit": res.limit if res.limit else "wall"}
        if run.mismatch is not None:
            msg = f"step {run.mismatch}: the call differs from the journal's; nothing was replayed"
            return {"status": "error", "error": {"kind": "runtime", "message": msg}}
        if run.capped:
            return {"status": "limit", "limit": "calls"}
        if status == "ok":
            out = {"status": "ok", "value": res.value}
            if res.truncated:
                out["truncated"] = True
            return out
        if status == "denied" and any(c["outcome"] == "denied" for c in run.calls):
            return {"status": "denied"}
        if status == "error" and res.error is not None:
            kind = res.error.kind
            kind = (
                kind if kind in ("syntax", "runtime", "sandbox", "token", "broker") else "sandbox"
            )
            return {"status": "error", "error": {"kind": kind, "message": _line(res.error.message)}}
        why = {"paused": "a pause the broker did not answer", "denied": "a denial not relayed"}
        msg = f"the sandbox reported {why.get(status, 'an unknown status')}"
        return {"status": "error", "error": {"kind": "sandbox", "message": msg}}

    # ---------------------------------------------------------------- one call
    def _pending(self, run: _Run, step: int, rec: Mapping[str, Any]) -> None:
        call = _call_of(rec)
        run.calls.append(call)
        run.pending.append(
            {
                "step": step,
                "request_id": rec["request_id"],
                "request_digest": rec["request_digest"],
                "action": rec["action"],
            }
        )

    def serve_call(self, run: _Run, msg: Any) -> dict[str, Any]:
        """One wire request from the program: the reply (see the module doc)."""
        if not isinstance(msg, Mapping):
            return _err("request-malformed")
        token, action, args = msg.get("token"), msg.get("action"), msg.get("args", {})
        op, target = msg.get("op", "call"), msg.get("target")
        if args is None:
            args = {}
        if (
            not isinstance(action, str)
            or not isinstance(args, Mapping)
            or op not in ("call", "submit")
            or not (target is None or isinstance(target, str))
        ):
            return _err("request-malformed")
        with run.lock:
            step = run.next_step
            run.next_step += 1
            if not (isinstance(token, str) and hmac.compare_digest(token, run.secret)):
                return self._refused(run, step, action, target, "denied", "token-invalid")
            if run.mismatch is not None:
                return _err("replay-mismatch")
            fp = self.store.fingerprint(f"{op}:{action}", target, dict(args))
            entry = run.journal.get(step)
            if entry is not None:
                return self._replay(run, step, entry, action, fp)
            return self._send(run, step, op, action, target, dict(args), fp)

    def _replay(self, run, step, entry, action, fp) -> dict[str, Any]:
        rec = entry["record"]
        if rec["action"] != action or not hmac.compare_digest(str(entry.get("call")), fp):
            run.mismatch = step
            return _err("replay-mismatch")
        if rec["outcome"] == "pending":  # approved (or denied): run the paused request by its id
            try:
                answer = self.sandbox_broker.token_run(run.secret, rec["request_id"])
            except BrokerError as exc:
                return self._refusal(run, step, action, rec.get("target"), exc, fp)
            except Exception:
                return self._refused(run, step, action, rec.get("target"), "error", "")
            return self._answered(run, step, action, rec.get("target"), answer, fp)
        run.calls.append(_call_of(rec, replayed=True))
        if rec["outcome"] == "ok":
            return self._reply_ok(run, action, rec.get("result"), rec.get("result_digest"))
        if rec["outcome"] == "denied":
            return {"ok": False, "denied": True, "reason": rec["reason"]}
        return _err(rec["reason"])

    def _send(self, run, step, op, action, target, args, fp) -> dict[str, Any]:
        kw = {"target": target} if target is not None else {}
        try:
            if op == "submit":
                answer = self.sandbox_broker.token_submit(run.secret, action, args, **kw)
            else:
                answer = self.sandbox_broker.token_call(run.secret, action, args, **kw)
        except BrokerError as exc:
            return self._refusal(run, step, action, target, exc, fp)
        except Exception:  # an adapter fault: the call may not have reached the broker
            log.error("codemode: a broker call failed outside the contract")
            return self._refused(run, step, action, target, "error", "")
        return self._answered(run, step, action, target, answer, fp)

    def _record(self, run, step, action, target, outcome, **kw) -> dict[str, Any]:
        rec: dict[str, Any] = {
            "execution_id": run.execution_id,
            "actor": run.actor,
            "code_digest": run.code_digest,
            "step": step,
            "action": action,
        }
        if target is not None:
            rec["target"] = target
        rec["outcome"] = outcome
        rec.update({k: v for k, v in kw.items() if v is not None})
        rec["recorded_at"] = _stamp(self.clock())
        return rec

    def _journal(self, run, rec: dict[str, Any], fp: str) -> None:
        problems = validation.named_errors(JOURNAL_RECORD, rec)
        if problems:
            raise RunnerError(f"the runner built an invalid journal record: {problems[0]}")
        self.store.append(rec, fp)
        run.journal[rec["step"]] = {"record": rec, "call": fp}

    def _answered(self, run, step, action, target, answer, fp) -> dict[str, Any]:
        ids = _ids(answer)
        if not isinstance(answer, Mapping) or ids is None:
            return self._refused(run, step, action, target, "error", "")
        if answer.get("state") == "pending":
            rec = self._record(run, step, action, target, "pending", **ids)
            self._journal(run, rec, fp)
            self._pending(run, step, rec)
            return {"ok": False, "pending": True, **ids}
        result = answer.get("result")
        kept, digest, _whole = self.store.kept_result(result)
        rec = self._record(run, step, action, target, "ok", **ids)
        rec.update(result=kept, result_digest=digest)
        self._journal(run, rec, fp)
        run.calls.append(_call_of(rec))
        return self._reply_ok(run, action, kept, digest)

    def _reply_ok(self, run, action, result, digest) -> dict[str, Any]:
        if digest is not None and digest_of(result) != digest:
            return _err("result-too-large")
        kind, value = unwrap(result)
        if kind == "error":
            return _err(value)
        schema = ((self.index.get(run.actor, {}).get(action) or {}).get("result") or {}).get(
            "schema"
        )
        if isinstance(schema, Mapping):
            try:
                bad = validation.inline_errors(schema, value)
            except Exception:  # a schema the validator cannot use checks nothing
                bad = []
            if bad:
                return _err("result-schema-mismatch")
        return {"ok": True, "value": value}

    def _refusal(self, run, step, action, target, exc: BrokerError, fp) -> dict[str, Any]:
        """A broker refusal as a call record (journalled when it names its request) and a
        reply the program sees: a denial (``Denied``, ``InvalidArguments``) or an error."""
        if isinstance(exc, Denied):
            outcome, fallback = "denied", "broker-denied"
        elif isinstance(exc, InvalidArguments):
            outcome, fallback = "denied", "invalid-params"
        else:
            outcome, fallback = "error", "broker-error"
        reason = _reason_of(exc, fallback)
        if reason == "transport-error":
            reason = "broker-unreachable"
        ids = _ids(exc)
        if ids is None or reason in ID_LESS_REASONS:
            return self._refused(run, step, action, target, outcome, reason)
        rec = self._record(run, step, action, target, outcome, reason=reason, **ids)
        self._journal(run, rec, fp)
        run.calls.append(_call_of(rec))
        if outcome == "denied":
            return {"ok": False, "denied": True, "reason": reason}
        return _err(reason)

    def _refused(self, run, step, action, target, outcome, reason) -> dict[str, Any]:
        """A call the broker refused before it built a request: recorded without ids, never
        journalled.  A reason that is not one of those is a transport failure as far as the
        record can tell (``broker-unreachable``)."""
        if reason not in ID_LESS_REASONS:
            outcome, reason = "error", "broker-unreachable"
        if reason == "call-cap-reached":
            run.capped = True
        call = {"step": step, "action": _action(action), "outcome": outcome, "reason": reason}
        if target is not None and _svc(target):
            call["target"] = target
        run.calls.append(call)
        if outcome == "denied":
            return {"ok": False, "denied": True, "reason": reason}
        return _err(reason)


# ---------------------------------------------------------------- the relay
class _Relay:
    """The run's broker endpoint: the CM-4 wire (one JSON line per connection, one reply line)
    at the executor's ``broker_bind``.  Calls are served one at a time, in arrival order: a
    program's calls are synchronous, and the step is the order the runner received them in."""

    def __init__(self, runner: Runner, run: _Run, bind: tuple[str, int]) -> None:
        self.runner, self.run = runner, run
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((bind[0], int(bind[1])))
        self.sock.listen(16)
        self.host, self.port = self.sock.getsockname()[:2]
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._loop, name="codemode-relay", daemon=True)

    def __enter__(self) -> _Relay:
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self._stop.set()
        with contextlib.suppress(OSError):
            self.sock.shutdown(socket.SHUT_RDWR)
        self.sock.close()
        self._thread.join(timeout=5.0)

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            with conn:
                try:
                    self._serve(conn)
                except Exception:  # one bad connection never ends the relay
                    log.exception("codemode: a relayed call failed")

    def _serve(self, conn: socket.socket) -> None:
        conn.settimeout(max(1.0, float(self.runner.default_wall_s)))
        buf = b""
        while b"\n" not in buf and len(buf) <= MAX_LINE_BYTES:
            chunk = conn.recv(65536)
            if not chunk:
                break
            buf += chunk
        line = buf.split(b"\n", 1)[0]
        if len(line) > MAX_LINE_BYTES:
            reply = _err("request-too-large")
        else:
            try:
                msg = json.loads(line.decode("utf-8"))
            except (UnicodeDecodeError, ValueError):
                reply = _err("request-malformed")
            else:
                reply = self.runner.serve_call(self.run, msg)
        data = json.dumps(reply, ensure_ascii=False, default=repr).encode("utf-8") + b"\n"
        with contextlib.suppress(OSError):
            conn.sendall(data)


# ---------------------------------------------------------------- helpers
def _err(reason: str) -> dict[str, Any]:
    return {"ok": False, "error": True, "reason": reason}


def _reason(value: Any, fallback: str) -> str:
    text = str(value or "")
    return text if _REASON_RE.match(text) and text not in _SUCCESS else fallback


def _reason_of(exc: BaseException, fallback: str) -> str:
    return _reason(getattr(exc, "reason", ""), fallback)


_SLUG_RE = re.compile(r"^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$")
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_ACTION_RE = re.compile(r"^[a-z][a-z0-9-]*(\.[a-z][a-z0-9-]*)+$")
_SVC_RE = re.compile(r"^svc:[a-z][a-z0-9]*(?:-[a-z0-9]+)*$")


def _svc(target: Any) -> bool:
    return isinstance(target, str) and bool(_SVC_RE.match(target))


def _action(action: str) -> str:
    """An action name as a record may hold it (a program can send anything)."""
    return action if _ACTION_RE.match(action) and len(action) <= 128 else "invalid.action"


def _ids(source: Any) -> dict[str, str] | None:
    """``{request_id, request_digest}`` of a broker answer or refusal, when it names both."""
    if isinstance(source, Mapping):
        rid, digest = source.get("request_id"), source.get("request_digest")
    else:
        rid, digest = getattr(source, "request_id", None), getattr(source, "request_digest", None)
    ok = isinstance(rid, str) and len(rid) <= 64 and _SLUG_RE.match(rid)
    if ok and isinstance(digest, str) and _DIGEST_RE.match(digest):
        return {"request_id": rid, "request_digest": digest}
    return None


def _call_of(rec: Mapping[str, Any], *, replayed: bool = False) -> dict[str, Any]:
    call: dict[str, Any] = {}
    for k in ("step", "action", "target", "request_id", "request_digest", "outcome", "reason"):
        if k in rec:
            call[k] = rec[k]
    if replayed:
        call["replayed"] = True
    return call


def _logs(output: str) -> list[str]:
    lines = [_line(t.rstrip("\r"), MAX_LOG_CHARS) for t in output.split("\n")]
    while lines and not lines[-1]:
        lines.pop()
    return lines[:MAX_LOG_LINES]
