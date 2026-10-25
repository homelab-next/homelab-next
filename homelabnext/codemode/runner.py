# SPDX-License-Identifier: Apache-2.0
"""The Code Mode runner: ``codemode.execute``'s handler (ADR-0031 decisions 2, 6 and 7; CM-5b).

The broker hands the runner one ``codemode.execute`` request, ``{request_id, actor, params}``
with ``params`` a ``schemas/codemode/execution_request``, while that request is in flight
(``docs/broker.md``, "Code Mode capability tokens").  :meth:`Runner.handle`:

1. checks the request and, for a resume, its journal (only a **paused** execution of the same
   actor and code digest resumes, claimed atomically so two resumes never both run) and the
   paused request's state, read with ``token_status`` (``paused_by_state``), never by polling
   ``token_run``, which spends the execution's cap: while it reads ``pending`` or ``expired`` the
   run ends ``paused`` again at once, issued no token and having sent nothing;
2. asks the broker for the run's token (``issue_token``, as the runner the run is bound to),
   listing the actions the actor is granted (never ``codemode.*``; the broker narrows them to what
   ``decide()`` admits, and the call cap and lifetime come from the request's budget);
3. serves the run's broker endpoint (:class:`_Relay`, the CM-4 wire, a fresh listener per run on
   an ephemeral port of the executor's ``broker_bind``) and hands the program, the endpoint and
   the token to the :class:`~conformance.protocols.codemode_executor.CodeExecutor`;
4. turns every call the program makes into a broker request made **with the token**: ``call`` is
   ``token_call``, ``submit`` is ``token_submit``, and on a resume the step that paused is
   ``token_run`` of the paused request; each is journalled (:mod:`.journal`): its intent before
   it is sent, its answer after;
5. returns a ``schemas/codemode/execution_result`` and spends the token (``paused`` when the run
   ended on a pause, else ``finished``).

**The relay.**  A request reaches the broker, and takes a **step**, only once the relay has
accepted it: it presents the run's token (compared in constant time), names a well-formed action
(``^[a-z][a-z0-9-]*(\\.[a-z][a-z0-9-]*)+$``) and, if any, a ``svc:`` target, and arrives while the
run has steps left (at most :data:`~.journal.MAX_STEPS`).  Anything else is refused at the relay
(``token-invalid``, ``request-malformed``, ``call-cap-reached``): it takes no step, is not a
call of the result and never reaches the broker, so nobody else's line can shift a program's
steps; a program that sends more than :data:`MAX_LOCAL_REFUSALS` of them ends ``error``.  The
relay serves connections concurrently, at most :data:`MAX_CONNECTIONS` at once, each with a short
read timeout (:data:`READ_TIMEOUT_S`, or the run's own wall budget when shorter), and calls are
decided one at a time.  With ``relay_uids`` it also accepts only connections from those local
users (the peer's uid read from ``/proc/net/tcp``): the run's token is the boundary, the uid
check a second one.  The relay stops accepting before the result is built, and waits for the
calls in flight, so nothing changes the run after its result.

**Answers to the program.**  A broker answer becomes a CM-4 reply:

* ``{result}``: ``ok`` with the value.  For an action the search index says is ``exec``, the
  handler's envelope (``{exit_code, output, truncated, stderr_bytes}``) is unwrapped to
  ``output``: the handler's stdout decoded as JSON when it is JSON, else its text (the broker
  decides, CM-3).  The cases that are not that success are defined here: **text** output is the
  value as a string; **truncated** output (the handler printed more than its
  ``max_output_bytes``) is never returned, the program gets ``broker.Error`` with reason
  ``output-truncated``; a **non-zero exit** never reaches the runner as a result (the broker
  refuses it, ``handler-failed``, an error reply); an output that does not match the action's
  result schema in the index is ``broker.Error`` with reason ``result-schema-mismatch``, data,
  never a runner failure; a result over the journal's bounds is ``result-too-large``.  In each of
  these the call record and the journal keep the broker's own outcome (``ok``) and result, and the
  call record says what the program got instead (``delivered_as``);
* ``{state: pending}``: a pending reply, which pauses the run (the broker has paused the token);
* a refusal (``Denied``, ``InvalidArguments``): a **denied call**, recorded with the broker's
  reason (``invalid-params`` for invalid arguments without one), and the program gets
  ``broker.Denied`` with that reason: a value it can catch and act on (the CM-4 contract), never
  an exception it cannot see.  A refusal the broker raised once it had built the request carries
  its ``request_id`` and ``request_digest``; a token refusal (``TOKEN_REFUSALS``) has neither;
* any other ``BrokerError``: an **error call** (``broker.Error``) with its reason; a transport
  failure, or an adapter fault, is ``broker-unreachable``.

Every one of these is journalled, a refusal without request ids too (as the runner's own entry,
not a ``journal_step`` record), so a resume answers it from the journal like any other step.

**Resume without replay.**  A resume runs the program again from the start in a fresh sandbox,
and no step the journal holds is sent again: a settled step whose action and call fingerprint
match is answered from the journal and marked ``replayed`` (its outcome, reason and ids the
recorded ones); the pending step is ``token_run`` of its request; only the steps after it are new
broker calls.  A call that differs from the journal's at its step (a program that is not
deterministic) is refused with ``broker.Error`` reason ``replay-mismatch``, every later call too,
and the run ends ``error``: the journal is never replayed into a different program.  A step whose
intent is journalled but not its answer is **unknown** (``step-outcome-unknown``): it is never
sent again, and the run ends ``error``; for the pending step, whose request has ids, the runner
asks the broker instead: a request that still waits (or was approved, or denied) never ran, and
the resume goes on.  The cap is the execution's (the broker's): a resume's token carries what is
left of it.

**Failures of the journal.**  The journal is written before a call is sent and after it is
answered.  When the intent cannot be written the call is not sent; when the answer cannot be,
the call has happened: the run stops relaying at once (every later call is refused
``journal-unavailable``), the call is still reported in ``calls``, and the run ends ``error`` with
its token spent ``finished``, so the execution never resumes and nothing is re-sent.  A pending
call of such a run is reported as an ``error`` call (``journal-unavailable``): its request stays
pending at the broker, for its owner to cancel.  A crash leaves the journal ``running`` with an
owner that is gone; the runner marks it ``interrupted`` (at its sweep, or when a resume finds
it), and an interrupted execution never resumes, as the broker's own sweep spends the crashed
run's token.

**Status.**  A run whose journal failed, or that met an unknown step, is ``error`` (kind
``broker``); then a run with a pending call is ``paused`` (``pending`` names it), whatever the
program did after; otherwise a cap the executor reports is ``limit``; a replay mismatch is
``error`` (``runtime``); a call refused ``call-cap-reached`` (by the broker, or at the relay past
the step bound) ends the run ``limit`` (``calls``); otherwise the executor's status stands (``ok``
with the value, ``denied`` when the program let a denial escape, ``error``).  ``calls``,
``pending`` and the journal are the runner's own record of what the broker answered; ``value``,
``logs`` and ``error.message`` are program output, untrusted.

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
from homelabnext.broker.state import _alive, process_identity

from .journal import (
    DEFAULT_MAX_EXECUTION_BYTES,
    DEFAULT_MAX_RESULT_BYTES,
    DEFAULT_PAUSED_RETENTION_DAYS,
    DEFAULT_RETENTION_DAYS,
    JOURNAL_RECORD,
    MAX_STEPS,
    Journal,
    JournalError,
    digest_of,
)

__all__ = [
    "DEFAULT_RUNNER_ID",
    "ENVELOPE_KEYS",
    "ID_LESS_REASONS",
    "MAX_CONNECTIONS",
    "MAX_LOCAL_REFUSALS",
    "READ_TIMEOUT_S",
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
#: the keys of an exec handler's answer as the broker wraps it (``docs/broker.md``, "Exec
#: handlers"; ``BrokerService._run_exec``): what :func:`unwrap` takes apart for an exec action
ENVELOPE_KEYS = frozenset({"exit_code", "output", "truncated", "stderr_bytes"})
#: reasons of a call the broker refused before it built a request: no request ids
ID_LESS_REASONS = frozenset({*TOKEN_REFUSALS, "broker-unreachable", "rate-limited"})
#: the broker's success reasons, never a denied call's (``schemas/codemode``)
_SUCCESS = frozenset({"allowed", "approved", "approval-required"})
_REASON_RE = re.compile(r"^[a-z][a-z0-9-]{0,63}$")
_UNSAFE = re.compile(MESSAGE_UNSAFE)
#: the longest wire line the relay reads from the program (a call's JSON)
MAX_LINE_BYTES = 1 << 20
#: connections the relay serves at once; more are answered ``busy`` and closed
MAX_CONNECTIONS = 8
#: how long the relay waits for one request line (the run's wall budget when shorter)
READ_TIMEOUT_S = 5.0
#: requests a run's relay refuses itself (wrong token, malformed, past the step bound) before
#: it ends the run
MAX_LOCAL_REFUSALS = 32
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
#: paused_by_state values that say the paused request has not run (so a resume may run it)
_NOT_RUN = frozenset({"approved", "denied", "pending", "expired"})


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _stamp(t: datetime) -> str:
    return t.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _line(text: str, limit: int = MESSAGE_MAX) -> str:
    return _UNSAFE.sub(" ", str(text))[:limit]


class RunnerError(RuntimeError):
    """A runner bug (a result it built does not validate): the broker reports the execute as
    ``handler-failed``.  Never raised for anything a program or the broker did."""


def unwrap(result: Any, kind: str | None = "exec") -> tuple[str, Any]:
    """``("ok", value)`` for a broker result as the program gets it, or ``("error", reason)``.
    Only an ``exec`` action's envelope is unwrapped to its ``output`` (``kind`` from the search
    index); any other result is the value as the broker gave it.  A non-zero exit is not handled
    here: the broker refuses it (``handler-failed``) and never answers it as a result."""
    if kind == "exec" and isinstance(result, Mapping) and set(result) == ENVELOPE_KEYS:
        if result.get("truncated") is True:
            return "error", "output-truncated"
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
            log.warning("codemode: a search index under %s is malformed; skipped", root)
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
    wall_s: float = float(DEFAULT_WALL_S)
    owns_journal: bool = False  # this run created or claimed the journal: it settles its state
    journal: dict[int, dict[str, Any]] = field(default_factory=dict)  # step -> its entries
    calls: list[dict[str, Any]] = field(default_factory=list)
    pending: list[dict[str, Any]] = field(default_factory=list)
    next_step: int = 0
    mismatch: int | None = None  # the step whose call differed from the journal's
    unknown: int | None = None  # a step whose outcome the journal does not hold
    failed: int | None = None  # the step whose answer the journal could not record
    capped: bool = False  # a call was refused call-cap-reached
    local_refusals: int = 0  # requests the relay refused itself
    closed: bool = False  # the relay has stopped: nothing changes the run any more
    lock: threading.Lock = field(default_factory=threading.Lock)


class Runner:
    """``codemode.execute``'s handler (see the module doc).

    ``broker`` holds the runner's operations (``issue_token``, ``spend_token``,
    ``token_status``); ``sandbox_broker`` the sandbox's (``token_call``, ``token_submit``,
    ``token_run``), the same object in process.  ``actions_for(actor)`` names the actions a token
    may list for that actor (default: the actor's actions in ``index``, the generator's search
    index, :func:`load_index`), which the broker narrows again.  ``index`` also gives each
    action's ``kind`` (an exec envelope is unwrapped) and ``result`` schema (an output is checked
    against it).  ``relay_uids``, when given, are the only local users whose connections the
    relay accepts.  Register it with ``broker.register_runner(runner.runner_id, runner.handle)``
    in process; over the socket the manifest's ``codemode.execute`` handler is the runner's
    client (CM-8)."""

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
        relay_uids: Iterable[int] | None = None,
        clock: Callable[[], datetime] = _utcnow,
        default_wall_s: int = DEFAULT_WALL_S,
        cpu_s: float = DEFAULT_CPU_S,
        default_memory_mb: int = DEFAULT_MEMORY_MB,
        default_output_bytes: int = DEFAULT_OUTPUT_BYTES,
        max_result_bytes: int = DEFAULT_MAX_RESULT_BYTES,
        max_execution_bytes: int = DEFAULT_MAX_EXECUTION_BYTES,
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
        self.relay_uids = None if relay_uids is None else frozenset(int(u) for u in relay_uids)
        self.clock = clock
        self.default_wall_s = int(default_wall_s)
        self.cpu_s = float(cpu_s)
        self.default_memory_mb = int(default_memory_mb)
        self.default_output_bytes = int(default_output_bytes)
        self.store = Journal(
            state_dir,
            max_result_bytes=max_result_bytes,
            max_execution_bytes=max_execution_bytes,
            retention_days=retention_days,
            paused_retention_days=paused_retention_days,
        )
        self._swept: datetime | None = None
        self._active: set[str] = set()  # request ids of the runs this process is running
        self._active_lock = threading.Lock()
        self._identity = process_identity()

    @property
    def languages(self) -> frozenset[str]:
        return frozenset(getattr(self.executor, "languages", ()))

    def _indexed_actions(self, actor: str) -> list[str]:
        return sorted(self.index.get(actor, {}))

    def journal(self, actor: str, execution_id: str) -> list[dict[str, Any]]:
        """Every journal record of ``actor``'s execution, in append order."""
        return self.store.records(actor, execution_id)

    def _owner(self, run: _Run) -> dict[str, Any]:
        return {**self._identity, "request_id": run.request_id}

    def _owner_alive(self, owner: Mapping[str, Any]) -> bool:
        """Whether the run that wrote ``owner`` may still be running: one of this process's
        own runs only while it is active here, another process's by its identity."""
        same = all(owner.get(k) == v for k, v in self._identity.items())
        if same:
            with self._active_lock:
                return owner.get("request_id") in self._active
        return _alive(dict(owner))

    def sweep(self, *, force: bool = False) -> dict[str, int]:
        """Mark crashed runs ``interrupted`` and drop journals past their retention, at most once
        a minute unless ``force``."""
        now = self.clock()
        recent = self._swept is not None and (now - self._swept).total_seconds() < SWEEP_INTERVAL_S
        if not force and recent:
            return {}
        self._swept = now
        return self.store.sweep(now, alive=self._owner_alive)

    # ---------------------------------------------------------------- the handler
    def handle(self, request: Mapping[str, Any]) -> dict[str, Any]:
        """Run one ``codemode.execute`` request; returns its execution result."""
        params = request.get("params")
        problems = validation.named_errors("codemode/execution_request", params)
        if problems:  # the broker checks this before the handler runs; never trust the caller
            raise RunnerError(f"not an execution request: {problems[0]}")
        run = _Run(
            request_id=str(request["request_id"]),
            actor=str(request["actor"]),
            execution_id=params["execution_id"],
            code_digest=code_digest(params["language"], params["code"]),
            wall_s=float((params.get("budget") or {}).get("wall_s", self.default_wall_s)),
        )
        with self._active_lock:
            self._active.add(run.request_id)
        try:
            return self._handle(run, params)
        except (JournalError, OSError) as exc:  # the journal went away mid-run: still a result
            log.error("codemode: the step journal failed (%s)", type(exc).__name__)
            return self._finish(run, None, error=("broker", "the step journal failed"))
        finally:
            with self._active_lock:
                self._active.discard(run.request_id)

    def _handle(self, run: _Run, params: Mapping[str, Any]) -> dict[str, Any]:
        try:
            self.sweep()
        except (JournalError, OSError):
            log.exception("codemode: the journal could not be swept")
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
        the program then sees as a denial), the execution claimed; else the result to return
        now, without a token."""
        meta = self.store.execution(run.actor, run.execution_id)
        if meta is not None and meta.get("state") == "running":
            if not self._owner_alive(meta.get("owner") or {}):
                self.store.update(
                    run.actor, run.execution_id, self.clock(), expect="running", state="interrupted"
                )
                return self._error(run, "token", "execution-interrupted")
            return self._error(run, "token", "execution-not-resumable")
        if meta is not None and meta.get("state") == "interrupted":
            return self._error(run, "token", "execution-interrupted")
        if meta is None or meta.get("state") != "paused":
            return self._error(run, "token", "execution-not-resumable")
        if meta.get("code_digest") != run.code_digest:
            return self._error(run, "token", "resume-code-mismatch")
        try:
            run.journal = self.store.steps(run.actor, run.execution_id)
        except JournalError:
            return self._error(run, "broker", "the step journal is unreadable")
        steps = sorted(run.journal)
        if steps != list(range(len(steps))) or any("answer" not in run.journal[s] for s in steps):
            return self._error(run, "broker", "step-outcome-unknown")
        open_steps = [s for s in steps if self._is_open(run.journal[s])]
        if len(open_steps) != 1 or open_steps[0] != steps[-1]:
            return self._error(run, "token", "journal-has-no-paused-step")
        pending = run.journal[open_steps[0]]["answer"]["record"]
        try:
            status = self.broker.token_status(self.runner_id, meta["tokens"][-1])
        except BrokerError as exc:
            return self._error(run, "token", _reason_of(exc, "broker-error"))
        if status.get("paused_by") != pending.get("request_id"):
            return self._error(run, "token", "paused-request-mismatch")
        state = self._paused_state(status)
        if "run" in run.journal[open_steps[0]] and state not in _NOT_RUN:
            # a run of the pending request was sent and its answer is lost: the broker says it
            # is no longer waiting, so it may have run; it is never sent again
            return self._error(run, "broker", "step-outcome-unknown")
        if state in ("pending", "expired"):  # still waiting: paused again, nothing sent
            for step in steps:
                entry = run.journal[step]
                if self._is_open(entry):
                    self._pending(run, step, entry["answer"]["record"])
                else:
                    run.calls.append(self._replayed_call(run, step, entry))
            return self._finish(run, None, waited=True)
        if state not in ("approved", "denied"):
            return self._error(run, "token", f"paused-request-{_reason(state, 'unknown')}"[:64])
        claimed = self.store.update(
            run.actor,
            run.execution_id,
            self.clock(),
            expect="paused",
            state="running",
            owner=self._owner(run),
        )
        if not claimed:  # another resume took it first
            run.journal = {}
            return self._error(run, "token", "execution-not-resumable")
        run.owns_journal = True
        return None

    def _paused_state(self, status: Mapping[str, Any]) -> Any:
        """What the paused request's state says for a resume (``token_status``)."""
        return status.get("paused_by_state")

    @staticmethod
    def _is_open(entry: Mapping[str, Any]) -> bool:
        rec = (entry.get("answer") or {}).get("record")
        return rec is not None and rec.get("outcome") == "pending" and "settled" not in entry

    def _issue(self, run: _Run, params: Mapping[str, Any]) -> dict[str, Any] | None:
        granted = {a for a in self.actions_for(run.actor) if isinstance(a, str)}
        actions = sorted(a for a in granted if not a.startswith("codemode."))[:200]
        resume = bool(params.get("resume"))
        if not actions:
            self._unclaim(run, resume)
            return self._error(run, "token", "no-granted-actions")
        try:
            issued = self.broker.issue_token(
                self.runner_id, run.request_id, sandbox_id=self.sandbox_id, actions=actions
            )
        except BrokerError as exc:
            self._unclaim(run, resume)
            return self._error(run, "token", _reason_of(exc, "broker-error"))
        run.secret, run.token_id = issued.secret, str(issued.claims["token_id"])
        run.max_calls = int(issued.claims.get("max_calls", 1))
        now = self.clock()
        if resume:
            self.store.update(run.actor, run.execution_id, now, token=run.token_id)
        elif self.store.begin(
            run.actor,
            run.execution_id,
            run.code_digest,
            run.token_id,
            now,
            owner=self._owner(run),
        ):
            run.owns_journal = True
        else:  # a journal of that id exists (the broker forgot it): never touch it
            return self._error(run, "token", "execution-exists")
        return None

    def _unclaim(self, run: _Run, resume: bool) -> None:
        """A claimed resume that got no token goes back to paused, for a later resume."""
        if resume and run.owns_journal:
            self.store.update(
                run.actor, run.execution_id, self.clock(), expect="running", state="paused"
            )
            run.owns_journal = False

    def _limits(self, run: _Run, params: Mapping[str, Any]) -> Limits:
        budget = params.get("budget") or {}
        wall = int(budget.get("wall_s", self.default_wall_s))
        out = int(budget.get("max_output_bytes", self.default_output_bytes))
        return Limits(
            cpu_s=min(float(wall), self.cpu_s),
            memory_bytes=int(budget.get("memory_mb", self.default_memory_mb)) << 20,
            wall_s=float(wall),
            # the broker's cap and the relay's step bound are the enforcement: the client may
            # send one past the step bound, so the refusal the runner sees is the one it reports
            # (a token refusal is not counted by the broker, only by the step bound)
            max_calls=MAX_STEPS + 1,
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
        with run.lock:
            run.closed = True
        status = self._status(run, res, error)
        calls = sorted(run.calls, key=lambda c: c["step"])[:MAX_STEPS]
        if status["status"] != "paused":  # a run that is not paused reports no pending call
            for c in calls:
                if c["outcome"] == "pending":
                    c.update(outcome="error", reason="journal-unavailable")
        out: dict[str, Any] = {
            "execution_id": run.execution_id,
            "actor": run.actor,
            "code_digest": run.code_digest,
            "calls": calls,
        }
        out.update(status)
        if res is not None:
            logs = self._log_lines(getattr(res, "output", "") or "")
            if logs:
                out["logs"] = logs
        out["finished_at"] = _stamp(self.clock())
        if run.token_id and not waited:
            paused = out["status"] == "paused"
            self._spend(run, "paused" if paused else "finished")
            if run.owns_journal:
                try:
                    state = "paused" if paused else "finished"
                    self.store.update(run.actor, run.execution_id, self.clock(), state=state)
                except (JournalError, OSError):
                    log.error("codemode: the execution's journal state could not be written")
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
        if run.failed is not None:
            msg = (
                f"step {run.failed}: the step journal could not record it; the run was stopped "
                "and the execution does not resume"
            )
            return {"status": "error", "error": {"kind": "broker", "message": msg}}
        if run.unknown is not None:
            msg = (
                f"step {run.unknown}: its outcome is unknown (step-outcome-unknown); not sent again"
            )
            return {"status": "error", "error": {"kind": "broker", "message": msg}}
        if run.local_refusals > MAX_LOCAL_REFUSALS:
            msg = f"the relay refused {run.local_refusals} requests (too-many-refusals)"
            return {"status": "error", "error": {"kind": "token", "message": msg}}
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
        run.calls.append(_call_of(rec))
        run.pending.append(
            {
                "step": step,
                "request_id": rec["request_id"],
                "request_digest": rec["request_digest"],
                "action": rec["action"],
            }
        )

    def _local(self, run: _Run, outcome: str, reason: str) -> dict[str, Any]:
        """A request the relay refuses itself: no step, no call, never sent (see the module
        doc); the run ends ``error`` past :data:`MAX_LOCAL_REFUSALS` of them."""
        run.local_refusals += 1
        if run.local_refusals > MAX_LOCAL_REFUSALS:
            return _err("too-many-refusals")
        if outcome == "denied":
            return {"ok": False, "denied": True, "reason": reason}
        return _err(reason)

    def serve_call(self, run: _Run, msg: Any) -> dict[str, Any]:
        """One wire request from the program: the reply (see the module doc)."""
        with run.lock:
            if run.closed:
                return _err("run-ended")
            if run.local_refusals > MAX_LOCAL_REFUSALS:  # the run is ending: nothing more is sent
                return _err("too-many-refusals")
            if not isinstance(msg, Mapping):
                return self._local(run, "error", "request-malformed")
            token = msg.get("token")
            if not (isinstance(token, str) and hmac.compare_digest(token, run.secret)):
                return self._local(run, "denied", "token-invalid")
            action, args = msg.get("action"), msg.get("args", {})
            op, target = msg.get("op", "call"), msg.get("target")
            if args is None:
                args = {}
            if (
                not (
                    isinstance(action, str) and len(action) <= 128 and _ACTION_RE.fullmatch(action)
                )
                or not isinstance(args, Mapping)
                or op not in ("call", "submit")
                or not (target is None or _svc(target))
            ):
                return self._local(run, "error", "request-malformed")
            if run.failed is not None:
                return _err("journal-unavailable")
            if run.unknown is not None:
                return _err("step-outcome-unknown")
            if run.mismatch is not None:
                return _err("replay-mismatch")
            if run.next_step >= MAX_STEPS:
                run.capped = True
                return self._local(run, "denied", "call-cap-reached")
            step = run.next_step
            run.next_step += 1
            try:
                fp = self.store.fingerprint(f"{op}:{action}", target, dict(args))
            except (TypeError, ValueError):  # args that are not JSON: never sent
                run.next_step -= 1
                return self._local(run, "error", "request-malformed")
            entry = run.journal.get(step)
            if entry is not None:
                return self._replay(run, step, entry, op, action, target, fp)
            return self._send(run, step, op, action, target, dict(args), fp)

    # -- replay
    def _replayed_call(self, run, step, entry) -> dict[str, Any]:
        answer = entry["answer"]
        rec = (entry.get("settled") or {}).get("record") or answer.get("record")
        if rec is None:
            intent = entry["intent"]["intent"]
            refusal = answer["refusal"]
            call = {"step": step, "action": intent["action"]}
            if intent.get("target") is not None:
                call["target"] = intent["target"]
            call.update(outcome=refusal["outcome"], reason=refusal["reason"], replayed=True)
            return call
        call = _call_of(rec, replayed=True)
        if rec["outcome"] == "ok":
            _reply, delivered = self._reply_ok(run, rec["action"], rec.get("result"), rec)
            if delivered:
                call["delivered_as"] = delivered
        return call

    def _replay(self, run, step, entry, op, action, target, fp) -> dict[str, Any]:
        intent = entry.get("intent") or {}
        want = intent.get("intent") or {}
        same = (want.get("op"), want.get("action"), want.get("target")) == (op, action, target)
        if not same or not hmac.compare_digest(str(intent.get("call")), fp):
            run.mismatch = step
            return _err("replay-mismatch")
        answer = entry.get("answer")
        if answer is None:  # sent, its outcome never recorded: never sent again
            run.unknown = step
            return _err("step-outcome-unknown")
        if self._is_open(entry):  # approved (or denied): run the paused request by its id
            rec = answer["record"]
            if "run" not in entry and not self._commit(
                run, step, lambda: self.store.intend_run(run.actor, run.execution_id, step, call=fp)
            ):
                return _err("journal-unavailable")
            try:
                got = self.sandbox_broker.token_run(run.secret, rec["request_id"])
            except BrokerError as exc:
                return self._refusal(run, step, action, target, exc, fp, settle=True)
            except Exception:
                return self._refused(run, step, action, target, "error", "", fp, settle=True)
            return self._answered(run, step, action, target, got, fp, settle=True)
        call = self._replayed_call(run, step, entry)
        run.calls.append(call)
        if call.get("reason") == "call-cap-reached":
            run.capped = True
        rec = (entry.get("settled") or {}).get("record") or answer.get("record")
        if rec is not None and rec["outcome"] == "ok":
            return self._reply_ok(run, action, rec.get("result"), rec)[0]
        if call["outcome"] == "denied":
            return {"ok": False, "denied": True, "reason": call["reason"]}
        return _err(call["reason"])

    # -- a fresh call
    def _commit(self, run: _Run, step: int, write: Callable[[], None]) -> bool:
        """Write one journal entry; on failure the run stops (``run.failed``) and False."""
        try:
            write()
        except (JournalError, OSError, RunnerError) as exc:
            log.error("codemode: step %d could not be journalled (%s)", step, type(exc).__name__)
            run.failed = step
            return False
        return True

    def _send(self, run, step, op, action, target, args, fp) -> dict[str, Any]:
        if not self._commit(
            run,
            step,
            lambda: self.store.intend(
                run.actor, run.execution_id, step, op=op, action=action, target=target, call=fp
            ),
        ):
            return _err("journal-unavailable")  # nothing was sent
        kw = {"target": target} if target is not None else {}
        try:
            if op == "submit":
                answer = self.sandbox_broker.token_submit(run.secret, action, args, **kw)
            else:
                answer = self.sandbox_broker.token_call(run.secret, action, args, **kw)
        except BrokerError as exc:
            return self._refusal(run, step, action, target, exc, fp)
        except Exception:  # an adapter fault: the call may have reached the broker
            log.error("codemode: a broker call failed outside the contract")
            return self._refused(run, step, action, target, "error", "", fp)
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

    def _journal(self, run, rec: dict[str, Any], fp: str, *, settle: bool = False) -> bool:
        """Journal a broker-decided record (the answer, or a pending step's settled record),
        and keep it for this run; False (the run stopped) when it cannot be written."""

        def write() -> None:
            problems = validation.named_errors(JOURNAL_RECORD, rec)
            if problems:
                raise RunnerError(f"the runner built an invalid journal record: {problems[0]}")
            step = rec["step"]
            if settle:
                self.store.settle(run.actor, run.execution_id, step, call=fp, record=rec)
            else:
                self.store.answer(run.actor, run.execution_id, step, call=fp, record=rec)

        ok = self._commit(run, rec["step"], write)
        if ok:
            entry = run.journal.setdefault(rec["step"], {})
            entry["settled" if settle else "answer"] = {"record": rec, "call": fp}
        return ok

    def _answered(self, run, step, action, target, answer, fp, *, settle=False) -> dict[str, Any]:
        ids = _ids(answer)
        if not isinstance(answer, Mapping) or ids is None:
            return self._refused(run, step, action, target, "error", "", fp, settle=settle)
        if answer.get("state") == "pending" and not settle:
            rec = self._record(run, step, action, target, "pending", **ids)
            if not self._journal(run, rec, fp):
                run.calls.append(_call_of(rec))  # reported as an error call by _finish
                return _err("journal-unavailable")
            self._pending(run, step, rec)
            return {"ok": False, "pending": True, **ids}
        result = answer.get("result")
        used = self.store.used_bytes(run.actor, run.execution_id)
        kept, digest, _whole = self.store.kept_result(result, used=used)
        rec = self._record(run, step, action, target, "ok", **ids)
        rec.update(result=kept, result_digest=digest)
        journalled = self._journal(run, rec, fp, settle=settle)
        reply, delivered = self._reply_ok(run, action, kept, rec)
        call = _call_of(rec)
        if delivered:
            call["delivered_as"] = delivered
        run.calls.append(call)
        return reply if journalled else _err("journal-unavailable")

    def _reply_ok(self, run, action, result, rec) -> tuple[dict[str, Any], str | None]:
        """(the reply, the reason the program got instead of the value, or None)."""
        if digest_of(result) != rec.get("result_digest"):
            return _err("result-too-large"), "result-too-large"
        entry = self.index.get(run.actor, {}).get(action) or {}
        kind, value = unwrap(result, entry.get("kind"))
        if kind == "error":
            return _err(value), value
        schema = (entry.get("result") or {}).get("schema")
        if isinstance(schema, Mapping):
            try:
                bad = validation.inline_errors(schema, value)
            except Exception:  # a schema the validator cannot use checks nothing
                bad = []
            if bad:
                return _err("result-schema-mismatch"), "result-schema-mismatch"
        return {"ok": True, "value": value}, None

    def _refusal(self, run, step, action, target, exc, fp, *, settle=False) -> dict[str, Any]:
        """A broker refusal as a call record (journalled, a ``journal_step`` record when it names
        its request) and a reply the program sees: a denial (``Denied``, ``InvalidArguments``) or
        an error."""
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
            return self._refused(run, step, action, target, outcome, reason, fp, settle=settle)
        rec = self._record(run, step, action, target, outcome, reason=reason, **ids)
        journalled = self._journal(run, rec, fp, settle=settle)
        run.calls.append(_call_of(rec))
        if not journalled:
            return _err("journal-unavailable")
        if outcome == "denied":
            return {"ok": False, "denied": True, "reason": reason}
        return _err(reason)

    def _refused(
        self, run, step, action, target, outcome, reason, fp, *, settle=False
    ) -> dict[str, Any]:
        """A call the broker refused before it built a request: recorded without ids and
        journalled as the runner's own entry, so a resume answers it the same way.  A reason
        that is not one of those is a transport failure as far as the record can tell
        (``broker-unreachable``)."""
        if reason not in ID_LESS_REASONS:
            outcome, reason = "error", "broker-unreachable"
        if reason == "call-cap-reached":
            run.capped = True
        call = {"step": step, "action": action, "outcome": outcome, "reason": reason}
        if target is not None:
            call["target"] = target
        run.calls.append(call)
        if not settle:  # a pending step's run refused this way stays pending in the journal
            refusal = {"outcome": outcome, "reason": reason}
            if not self._commit(
                run,
                step,
                lambda: self.store.answer(
                    run.actor, run.execution_id, step, call=fp, refusal=refusal
                ),
            ):
                return _err("journal-unavailable")
            run.journal.setdefault(step, {})["answer"] = {"refusal": refusal, "call": fp}
        if outcome == "denied":
            return {"ok": False, "denied": True, "reason": reason}
        return _err(reason)


# ---------------------------------------------------------------- the relay
def _tcp_peer_uid(peer: tuple[str, int], local: tuple[str, int]) -> int | None:
    """The uid owning the IPv4 socket at ``peer`` connected to ``local``, from
    ``/proc/net/tcp`` (None when it cannot be told)."""

    def hexaddr(addr: tuple[str, int]) -> str:
        packed = socket.inet_aton(addr[0])
        return f"{int.from_bytes(packed, 'little'):08X}:{addr[1]:04X}"

    want_local, want_remote = hexaddr(peer), hexaddr(local)
    try:
        lines = Path("/proc/net/tcp").read_text().splitlines()[1:]
    except OSError:
        return None
    for row in lines:
        cols = row.split()
        if len(cols) > 7 and cols[1] == want_local and cols[2] == want_remote:
            with contextlib.suppress(ValueError):
                return int(cols[7])
    return None


class _Relay:
    """The run's broker endpoint: the CM-4 wire (one JSON line per connection, one reply line),
    a fresh listener per run on the executor's ``broker_bind`` (port 0: an ephemeral port).
    Connections are served concurrently, at most :data:`MAX_CONNECTIONS`, each with a short read
    timeout; the calls themselves are decided one at a time (``run.lock``), and the step is the
    order the runner received them in."""

    def __init__(self, runner: Runner, run: _Run, bind: tuple[str, int]) -> None:
        self.runner, self.run = runner, run
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((bind[0], int(bind[1])))
        self.sock.listen(16)
        self.host, self.port = self.sock.getsockname()[:2]
        self.timeout = max(0.5, min(READ_TIMEOUT_S, run.wall_s))
        self._slots = threading.BoundedSemaphore(MAX_CONNECTIONS)
        self._stop = threading.Event()
        self._workers: list[threading.Thread] = []
        self._thread = threading.Thread(target=self._loop, name="codemode-relay", daemon=True)

    def __enter__(self) -> _Relay:
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        """Stop accepting, then wait for every connection in flight: nothing changes the run
        once the result is being built."""
        self._stop.set()
        with contextlib.suppress(OSError):
            self.sock.shutdown(socket.SHUT_RDWR)
        self.sock.close()
        self._thread.join()
        for t in list(self._workers):
            t.join()
        with self.run.lock:
            self.run.closed = True

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                conn, addr = self.sock.accept()
            except OSError:
                return
            if self._stop.is_set():
                conn.close()
                return
            if not self._slots.acquire(blocking=False):
                with contextlib.suppress(OSError):
                    conn.sendall(json.dumps(_err("busy")).encode() + b"\n")
                conn.close()
                continue
            t = threading.Thread(target=self._worker, args=(conn, addr), daemon=True)
            self._workers = [w for w in self._workers if w.is_alive()] + [t]
            t.start()

    def _worker(self, conn: socket.socket, addr: tuple[str, int]) -> None:
        try:
            with conn:
                if self.runner.relay_uids is not None:
                    uid = _tcp_peer_uid(addr, (self.host, self.port))
                    if uid not in self.runner.relay_uids:
                        return  # not a peer the relay serves: closed unanswered, no step
                try:
                    self._serve(conn)
                except Exception:  # one bad connection never ends the relay
                    log.error("codemode: a relayed call failed")
        finally:
            self._slots.release()

    def _serve(self, conn: socket.socket) -> None:
        conn.settimeout(self.timeout)
        buf = b""
        try:
            while b"\n" not in buf and len(buf) <= MAX_LINE_BYTES:
                chunk = conn.recv(65536)
                if not chunk:
                    break
                buf += chunk
        except OSError:  # a peer that sends nothing in time holds no slot past the timeout
            return
        line = buf.split(b"\n", 1)[0]
        if len(line) > MAX_LINE_BYTES:
            reply = _err("request-too-large")
        else:
            try:
                msg = json.loads(line.decode("utf-8"))
            except (UnicodeDecodeError, ValueError):
                msg = None
            reply = self.runner.serve_call(self.run, msg)
        data = json.dumps(reply, ensure_ascii=False, default=repr).encode("utf-8") + b"\n"
        with contextlib.suppress(OSError):
            conn.sendall(data)


# ---------------------------------------------------------------- helpers
def _err(reason: str) -> dict[str, Any]:
    return {"ok": False, "error": True, "reason": reason}


def _reason(value: Any, fallback: str) -> str:
    text = str(value or "")
    return text if _REASON_RE.fullmatch(text) and text not in _SUCCESS else fallback


def _reason_of(exc: BaseException, fallback: str) -> str:
    return _reason(getattr(exc, "reason", ""), fallback)


_SLUG_RE = re.compile(r"^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$")
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_ACTION_RE = re.compile(r"^[a-z][a-z0-9-]*(\.[a-z][a-z0-9-]*)+$")
_SVC_RE = re.compile(r"^svc:[a-z][a-z0-9]*(?:-[a-z0-9]+)*$")


def _svc(target: Any) -> bool:
    return isinstance(target, str) and len(target) <= 128 and bool(_SVC_RE.fullmatch(target))


def _ids(source: Any) -> dict[str, str] | None:
    """``{request_id, request_digest}`` of a broker answer or refusal, when it names both."""
    if isinstance(source, Mapping):
        rid, digest = source.get("request_id"), source.get("request_digest")
    else:
        rid, digest = getattr(source, "request_id", None), getattr(source, "request_digest", None)
    ok = isinstance(rid, str) and len(rid) <= 64 and _SLUG_RE.fullmatch(rid)
    if ok and isinstance(digest, str) and _DIGEST_RE.fullmatch(digest):
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
