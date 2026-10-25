# SPDX-License-Identifier: Apache-2.0
"""In-memory allowlisted command broker with an audit trail, and the ``codemode-tokens``
feature: capability tokens held (as a digest of their secret) and enforced in memory."""

from __future__ import annotations

import hashlib
import itertools
import re
import secrets
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime, timedelta
from typing import Any

from conformance.protocols.broker import (
    CODEMODE_EXECUTE,
    ArgSpec,
    AuditRecord,
    BrokerError,
    Denied,
    InvalidArguments,
    IssuedToken,
    RequestStatus,
    arg_problems,
    code_digest,
)

NOT_OWNER = "not-request-owner"
#: the fake's Code Mode limits (a manifest's ``codemode`` block in the reference service)
MAX_CALLS = 50
TTL_MARGIN_S = 10
DEFAULT_WALL_S = 60
MAX_LIVE_PER_ACTOR = 4
_EPOCH = datetime(2026, 1, 1, tzinfo=UTC)
_SLUG = re.compile(r"^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$")


def _stamp(t: datetime) -> str:
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def _execution_problems(params: Any) -> list[str]:
    """The shape ``schemas/codemode/execution_request`` asks of ``codemode.execute``'s params
    (the fields the broker relies on; the reference service validates the whole schema)."""
    if not isinstance(params, Mapping):
        return ["params must be an object"]
    out = []
    eid = params.get("execution_id")
    if not (isinstance(eid, str) and _SLUG.match(eid) and len(eid) <= 64):
        out.append("execution_id")
    if params.get("language") not in ("python", "typescript"):
        out.append("language")
    if not (isinstance(params.get("code"), str) and params["code"]):
        out.append("code")
    budget = params.get("budget", {})
    if not isinstance(budget, Mapping) or any(
        not isinstance(v, int) or isinstance(v, bool) or v < 1 for v in budget.values()
    ):
        out.append("budget")
    if "resume" in params and not isinstance(params["resume"], bool):
        out.append("resume")
    extra = set(params) - {"execution_id", "language", "code", "budget", "resume"}
    return out + [f"unexpected {k}" for k in sorted(extra)]


class FakeBroker:
    features = frozenset({"codemode-tokens", "clock-control"})

    def __init__(self) -> None:
        self._cmds: dict[str, tuple[Callable[..., Any], Mapping[str, ArgSpec]]] = {}
        self._allow: dict[str, set[str]] = {}
        self._audit: list[AuditRecord] = []
        self._reqs: dict[str, dict[str, Any]] = {}
        self._seq = itertools.count(1)
        # codemode-tokens
        self._now = 0.0
        self._runners: dict[str, Callable[[Mapping[str, Any]], Any]] = {}
        self._inflight: dict[str, dict[str, Any]] = {}  # request id -> the running execute
        self._tokens: dict[str, dict[str, Any]] = {}  # token id -> claims, digest, state, calls
        self._by_digest: dict[str, str] = {}  # sha256 of a secret -> token id
        self._executions: dict[str, dict[str, Any]] = {}  # execution id -> actor, code, tokens
        self._token: dict[str, Any] | None = None  # the token the current call is made with

    def register(self, command, handler, args):
        self._cmds[command] = (handler, dict(args))

    def allow(self, caller, commands):
        self._allow.setdefault(caller, set()).update(commands)

    def _redact(self, spec: Mapping[str, ArgSpec], args: Mapping[str, Any]) -> dict[str, Any]:
        # redact by default: only a value the schema names, and does not mark secret, is shown
        # (a misspelt argument, or any argument of an unknown command, may well be a secret)
        return {
            k: (v if k in spec and not spec[k].secret else "<redacted>") for k, v in args.items()
        }

    def _log(self, caller, command, outcome, spec, args, **extra) -> None:
        self._audit.append(
            AuditRecord(caller, command, outcome, self._redact(spec, args), **self._ids(extra))
        )

    def _ids(self, extra: Mapping[str, Any]) -> dict[str, Any]:
        """``extra`` plus the token and execution ids of the call being made with a token."""
        if self._token is None or "token_id" in extra:
            return dict(extra)
        claims = self._token["claims"]
        return {**extra, "token_id": claims["token_id"], "execution_id": claims["execution_id"]}

    def _admit(self, caller, command, args, **extra):
        """The allowlist and argument checks shared by ``call`` and ``submit``."""
        entry = self._cmds.get(command)
        spec = entry[1] if entry else {}
        if entry is None or command not in self._allow.get(caller, set()):
            self._log(caller, command, "denied", spec, args, **extra)
            raise Denied(f"{caller!r} may not run {command!r}", reason="not-allowed")
        if command == CODEMODE_EXECUTE:  # the runner's params: an execution request
            problems = _execution_problems(args)
            if problems:
                self._log(caller, command, "invalid", spec, args, **extra)
                raise InvalidArguments("codemode.execute params: " + ", ".join(problems))
            return entry
        problems = arg_problems(spec, args)
        if problems:
            self._log(caller, command, "invalid", spec, args, **extra)
            raise InvalidArguments("; ".join(problems))
        return entry

    def _execute(self, caller, command, handler, spec, args, **extra):
        try:
            result = self._run_handler(command, handler, args)
        except BrokerError:
            self._log(caller, command, "error", spec, args, **extra)
            raise
        self._log(caller, command, "ok", spec, args, **extra)
        return result

    def call(self, caller, command, args):
        args = dict(args)  # checked and run as one snapshot
        handler, spec = self._admit(caller, command, args)
        if command == CODEMODE_EXECUTE:
            rid = f"req-{next(self._seq)}"
            return self._execute_run(caller, rid, handler, spec, args, operation="call")
        return self._execute(caller, command, handler, spec, args)

    # ---- deferred requests: bound to the caller that submitted them
    def submit(self, caller, command, args):
        args = dict(args)  # the copy that is checked is the copy that runs
        _, spec = self._admit(caller, command, args, operation="submit")
        rid = f"req-{next(self._seq)}"
        self._reqs[rid] = {"caller": caller, "command": command, "args": args}
        self._reqs[rid]["state"] = "pending"
        self._log(caller, command, "ok", spec, args, operation="submit", request_id=rid)
        return rid

    def _owns(self, caller, req) -> bool:
        return req["caller"] == caller

    def _deny_foreign(self, caller, request_id, operation, req) -> None:
        cmd = req["command"] if req else ""
        self._audit.append(AuditRecord(caller, cmd, "denied", {}, operation, request_id, NOT_OWNER))

    def _owned(self, caller, request_id, operation):
        """The request, if ``caller`` owns it; otherwise audit and refuse (unknown ids alike)."""
        req = self._reqs.get(request_id)
        if req is None or not self._owns(caller, req):
            self._deny_foreign(caller, request_id, operation, req)
            raise Denied(f"no request {request_id!r} for {caller!r}", reason=NOT_OWNER)
        return req

    def _spec(self, command):
        entry = self._cmds.get(command)
        return entry[1] if entry else {}

    def status(self, caller, request_id):
        req = self._owned(caller, request_id, "status")
        extra = {"operation": "status", "request_id": request_id}
        self._log(caller, req["command"], "ok", self._spec(req["command"]), {}, **extra)
        return RequestStatus(request_id, req["caller"], req["command"], req["state"])

    def run(self, caller, request_id):
        req = self._owned(caller, request_id, "run")
        cmd, args, extra = (
            req["command"],
            req["args"],
            {"operation": "run", "request_id": request_id},
        )
        if req["state"] != "pending":
            self._log(caller, cmd, "invalid", self._spec(cmd), args, **extra)
            raise BrokerError(f"request {request_id!r} is {req['state']}, not pending")
        handler, spec = self._cmds[cmd]
        req["state"] = "error"  # stays so if the handler fails: a request runs at most once
        if cmd == CODEMODE_EXECUTE:
            result = self._execute_run(caller, request_id, handler, spec, args, **extra)
        else:
            result = self._execute(caller, cmd, handler, spec, args, **extra)
        req["state"] = "done"
        return result

    def cancel(self, caller, request_id):
        req = self._owned(caller, request_id, "cancel")
        cmd, extra = req["command"], {"operation": "cancel", "request_id": request_id}
        if req["state"] != "pending":
            self._log(caller, cmd, "invalid", self._spec(cmd), {}, **extra)
            raise BrokerError(f"request {request_id!r} is {req['state']}, not pending")
        req["state"] = "cancelled"
        self._log(caller, cmd, "ok", self._spec(cmd), {}, **extra)

    # ---- codemode-tokens: the runner is codemode.execute's handler
    def tick(self, seconds: float) -> None:
        self._now += seconds

    def _clock(self) -> datetime:
        return _EPOCH + timedelta(seconds=self._now)

    def register_runner(self, runner, handler):
        self._runners[runner] = handler
        self._cmds[CODEMODE_EXECUTE] = (handler, {})

    def _execute_run(self, caller, rid, handler, spec, args, **extra):
        """Run ``codemode.execute``: the request is in flight while its handler runs, and a token
        of it still live when the handler returns is spent (it never outlives its run)."""
        self._inflight[rid] = {"request_id": rid, "actor": caller, "params": dict(args)}
        request = {"request_id": rid, "actor": caller, "params": dict(args)}
        try:
            return self._execute(
                caller, CODEMODE_EXECUTE, lambda **_: handler(request), spec, args, **extra
            )
        finally:
            del self._inflight[rid]
            for tok in self._tokens.values():
                if tok["claims"]["request_id"] == rid and tok["state"] == "live":
                    tok["state"] = "spent"

    def _refuse_issue(self, runner, rid, reason, message, **ids):
        self._audit.append(
            AuditRecord(runner, CODEMODE_EXECUTE, "denied", {}, "token-issue", rid, reason, **ids)
        )
        raise Denied(message, reason=reason)

    def _admitted(self, actor: str, action: str) -> bool:
        """Whether a call of ``action`` by ``actor`` would get past the allowlist."""
        return action in self._cmds and action in self._allow.get(actor, set())

    def _live(self, tok: Mapping[str, Any]) -> bool:
        return tok["state"] == "live" and self._clock() < tok["expires"]

    def issue_token(self, runner, request_id, *, sandbox_id, actions, max_calls=None, ttl_s=None):
        if runner not in self._runners:
            self._refuse_issue(runner, request_id, "not-a-codemode-runner", "not a runner")
        if not (isinstance(sandbox_id, str) and _SLUG.match(sandbox_id)) or not (
            isinstance(actions, (list, tuple))
            and actions
            and all(isinstance(a, str) for a in actions)
        ):
            raise InvalidArguments("sandbox_id is a slug; actions a non-empty list of names")
        for n in (max_calls, ttl_s):
            if n is not None and (not isinstance(n, int) or isinstance(n, bool) or n < 1):
                raise InvalidArguments("max_calls and ttl_s are positive integers")
        run = self._inflight.get(request_id)
        if run is None:
            self._refuse_issue(runner, request_id, "execution-not-in-flight", "not running")
        actor, params = run["actor"], run["params"]
        eid, budget = params["execution_id"], params.get("budget", {})
        ids = {"execution_id": eid}
        if any(t["claims"]["request_id"] == request_id for t in self._tokens.values()):
            self._refuse_issue(runner, request_id, "request-has-token", "issued once", **ids)
        if any(a.startswith("codemode.") for a in actions):
            self._refuse_issue(runner, request_id, "token-action-codemode", "no codemode", **ids)
        if len(set(actions)) != len(actions) or not all(self._admitted(actor, a) for a in actions):
            self._refuse_issue(runner, request_id, "token-action-not-admitted", "narrows", **ids)
        want = (
            max_calls
            if max_calls is not None
            else min(MAX_CALLS, budget.get("max_calls", MAX_CALLS))
        )
        if want > MAX_CALLS or want > budget.get("max_calls", MAX_CALLS):
            self._refuse_issue(runner, request_id, "token-max-calls-exceeded", "cap", **ids)
        limit = budget.get("wall_s", DEFAULT_WALL_S) + TTL_MARGIN_S
        ttl = ttl_s if ttl_s is not None else limit
        if ttl > limit:
            self._refuse_issue(runner, request_id, "token-ttl-exceeded", "too long", **ids)
        digest = code_digest(params["language"], params["code"])
        known = self._executions.get(eid)
        if not params.get("resume"):
            if known is not None:
                self._refuse_issue(runner, request_id, "execution-exists", "exists", **ids)
        else:
            last = self._tokens[known["tokens"][-1]] if known else None
            if known is None or known["actor"] != actor or last["state"] not in ("paused", "spent"):
                self._refuse_issue(runner, request_id, "execution-not-resumable", "no", **ids)
            if known["code_digest"] != digest:
                self._refuse_issue(runner, request_id, "resume-code-mismatch", "code", **ids)
        mine = [t for t in self._tokens.values() if t["claims"]["actor"] == actor and self._live(t)]
        if len(mine) >= MAX_LIVE_PER_ACTOR:
            self._refuse_issue(runner, request_id, "too-many-live-tokens", "live tokens", **ids)
        return self._mint(runner, run, digest, sandbox_id, list(actions), want, ttl)

    def _mint(self, runner, run, digest, sandbox_id, actions, max_calls, ttl):
        now = self._clock().replace(microsecond=0)
        tid, secret = f"tok-{next(self._seq)}", "hnxcmt_" + secrets.token_urlsafe(32)
        eid = run["params"]["execution_id"]
        claims = {
            "token_id": tid,
            "execution_id": eid,
            "request_id": run["request_id"],
            "code_digest": digest,
            "sandbox_id": sandbox_id,
            "actor": run["actor"],
            "issuer": "svc:broker",
            "audience": "svc:broker",
            "actions": actions,
            "max_calls": max_calls,
            "issued_at": _stamp(now),
            "expires_at": _stamp(now + timedelta(seconds=ttl)),
        }
        expires = now + timedelta(seconds=ttl)
        self._tokens[tid] = {"claims": claims, "state": "live", "calls": 0, "expires": expires}
        self._by_digest[self._digest(secret)] = tid  # the secret itself is never kept
        known = self._executions.setdefault(
            eid, {"actor": run["actor"], "code_digest": digest, "tokens": []}
        )
        known["tokens"].append(tid)
        self._audit.append(
            AuditRecord(
                runner,
                CODEMODE_EXECUTE,
                "ok",
                {"sandbox_id": sandbox_id},
                "token-issue",
                run["request_id"],
                "",
                tid,
                eid,
            )
        )
        return IssuedToken(secret, dict(claims))

    @staticmethod
    def _digest(secret: Any) -> str:
        raw = (
            secret.encode("utf-8", "replace") if isinstance(secret, str) else repr(secret).encode()
        )
        return hashlib.sha256(raw).hexdigest()

    def _token_for(self, token, command, operation, sandbox_id):
        """The token record a call presents, after every token check (in the contract's
        order); refusals are audited and never name the secret."""
        tid = self._by_digest.get(self._digest(token))
        tok = self._tokens.get(tid) if tid else None
        actor = tok["claims"]["actor"] if tok else "token:unknown"
        ids = {"token_id": tid, "execution_id": tok["claims"]["execution_id"]} if tok else {}
        reason = self._token_problem(tok, command, sandbox_id)
        if reason:
            self._audit.append(
                AuditRecord(actor, str(command), "denied", {}, operation, None, reason, **ids)
            )
            raise Denied("the token does not allow this call", reason=reason)
        tok["calls"] += 1
        return tok

    def _token_problem(self, tok, command, sandbox_id) -> str:
        if tok is None:
            return "token-invalid"
        claims = tok["claims"]
        if sandbox_id is not None and sandbox_id != claims["sandbox_id"]:
            return "token-sandbox-mismatch"
        if self._clock() >= tok["expires"]:
            return "token-expired"
        if tok["state"] == "spent":
            return "token-spent"
        if tok["state"] == "paused":
            return "token-paused"
        if command not in claims["actions"]:
            return "token-action-not-allowed"
        if tok["calls"] >= claims["max_calls"]:
            return "call-cap-reached"
        return ""

    def _as_token(self, tok, fn):
        outer, self._token = self._token, tok
        try:
            return fn()
        finally:
            self._token = outer

    def token_call(self, token, command, args, *, sandbox_id=None):
        tok = self._token_for(token, command, "call", sandbox_id)
        return self._as_token(tok, lambda: self.call(tok["claims"]["actor"], command, args))

    def token_submit(self, token, command, args, *, sandbox_id=None):
        tok = self._token_for(token, command, "submit", sandbox_id)
        rid = self._as_token(tok, lambda: self.submit(tok["claims"]["actor"], command, args))
        self._pause(tok, rid)
        return rid

    def _pause(self, tok, rid) -> None:
        """A submitted request waits for its owner: the program cannot go on."""
        if tok["state"] == "live":
            tok["state"] = "paused"
            tok["paused_by"] = rid

    def spend_token(self, runner, token_id):
        tok = self._tokens.get(token_id) if runner in self._runners else None
        if tok is None:
            reason = "not-a-codemode-runner" if runner not in self._runners else "unknown-token"
            self._audit.append(
                AuditRecord(runner, CODEMODE_EXECUTE, "denied", {}, "token-spend", None, reason)
            )
            raise Denied("no such token for this runner", reason=reason)
        tok["state"] = "spent"
        eid = tok["claims"]["execution_id"]
        self._audit.append(
            AuditRecord(runner, CODEMODE_EXECUTE, "ok", {}, "token-spend", None, "", token_id, eid)
        )

    @staticmethod
    def _run_handler(command, handler, args):
        failed = False
        try:
            result = handler(**dict(args))
        except Exception:
            failed = True
        if failed:  # raised outside the handler's except block: no __context__ to leak through
            raise BrokerError(f"{command} failed")
        return result

    def audit(self) -> Sequence[AuditRecord]:
        return list(self._audit)


class LoggingBroker(FakeBroker):
    """Defect: the audit trail records secret arguments in the clear."""

    def _redact(self, spec, args):
        return dict(args)


class CallerOnlyBroker(FakeBroker):
    """Defect: the allowlist is checked per caller, not per command."""

    def call(self, caller, command, args):
        if command in self._cmds and caller in self._allow:
            self._allow[caller].add(command)
        return super().call(caller, command, args)


class KeyNameRedactingBroker(FakeBroker):
    """Defect: redaction guesses from the argument's name instead of the schema's flag."""

    def _redact(self, spec, args):
        hints = ("secret", "token", "password", "key")
        return {k: ("<redacted>" if any(h in k for h in hints) else v) for k, v in args.items()}


class OkOnlyRedactingBroker(FakeBroker):
    """Defect: secrets are redacted on successful calls only; denied/invalid/error log them."""

    def _log(self, caller, command, outcome, spec, args, **extra):
        rec = self._redact(spec, args) if outcome == "ok" else dict(args)
        self._audit.append(AuditRecord(caller, command, outcome, rec, **extra))


class ChattyErrorBroker(FakeBroker):
    """Defect: a handler failure is passed through with the handler's own message and cause."""

    @staticmethod
    def _run_handler(command, handler, args):
        try:
            return handler(**dict(args))
        except Exception as exc:
            raise BrokerError(f"{command} failed: {exc}") from exc


class SharedRequestsBroker(FakeBroker):
    """Defect: deferred requests are not bound to their caller; anyone may read, run or cancel."""

    def _owns(self, caller, req):
        return True


class SilentForeignAccessBroker(FakeBroker):
    """Defect: a refused read/run/cancel of someone else's request leaves no audit record."""

    def _deny_foreign(self, caller, request_id, operation, req):
        return None


class SubmitSkipsAllowlistBroker(FakeBroker):
    """Defect: ``submit`` checks the arguments but not the allowlist, so a caller allowed
    nothing can submit any registered command and then run it as the request's owner."""

    def _admit(self, caller, command, args, **extra):
        entry = self._cmds.get(command)
        if extra.get("operation") == "submit" and entry is not None:
            problems = arg_problems(entry[1], args)
            if problems:
                self._log(caller, command, "invalid", entry[1], args, **extra)
                raise InvalidArguments("; ".join(problems))
            return entry
        return super()._admit(caller, command, args, **extra)


class SubmitSkipsArgsBroker(FakeBroker):
    """Defect: ``submit`` checks the allowlist but not the arguments, so the handler later runs
    with missing, unexpected or mistyped arguments."""

    def _admit(self, caller, command, args, **extra):
        entry = self._cmds.get(command)
        if (
            extra.get("operation") == "submit"
            and entry is not None
            and command in self._allow.get(caller, set())
        ):
            return entry
        return super()._admit(caller, command, args, **extra)


class DeferredClearAuditBroker(FakeBroker):
    """Defect: ``call`` is redacted, but the audit records of ``submit`` and ``run`` carry the
    secret arguments in the clear."""

    def _log(self, caller, command, outcome, spec, args, **extra):
        if extra.get("operation") in ("submit", "run"):
            self._audit.append(AuditRecord(caller, command, outcome, dict(args), **extra))
            return
        super()._log(caller, command, outcome, spec, args, **extra)


class RunAuditedTwiceBroker(FakeBroker):
    """Defect: running a request leaves a ``started`` record and then its outcome, two records
    for one operation."""

    def _execute(self, caller, command, handler, spec, args, **extra):
        if extra.get("operation") == "run":
            self._log(caller, command, "started", spec, args, **extra)
        return super()._execute(caller, command, handler, spec, args, **extra)


class SubmitKeepsCallerArgsBroker(FakeBroker):
    """Defect: ``submit`` checks the arguments and then keeps the caller's own mapping, so what
    ``run`` hands the handler is whatever that mapping holds by then - never validated."""

    def submit(self, caller, command, args):
        rid = super().submit(caller, command, args)
        self._reqs[rid]["args"] = args
        return rid


class RefusedSubmitUnauditedBroker(FakeBroker):
    """Defect: a denied or invalid ``submit`` leaves no audit record (``call`` still does), so a
    stranger can probe the allowlist through ``submit`` unseen."""

    def _log(self, caller, command, outcome, spec, args, **extra):
        if extra.get("operation") == "submit" and outcome in ("denied", "invalid"):
            return
        super()._log(caller, command, outcome, spec, args, **extra)


class UnauditedSubmitBroker(FakeBroker):
    """Defect: no ``submit`` is audited at all; only the later ``run`` leaves a record."""

    def _log(self, caller, command, outcome, spec, args, **extra):
        if extra.get("operation") == "submit":
            return
        super()._log(caller, command, outcome, spec, args, **extra)


class KnownSecretsOnlyBroker(FakeBroker):
    """Defect: redaction is by known key only, so the value of a misspelt secret argument, or of
    any argument of an unregistered command, is audited in the clear."""

    def _redact(self, spec, args):
        return {
            k: ("<redacted>" if spec.get(k, ArgSpec("str")).secret else v) for k, v in args.items()
        }


class RunChattyErrorBroker(FakeBroker):
    """Defect: ``call`` contains a handler failure, but ``run`` passes the handler's own message
    and cause through to the caller."""

    def _execute(self, caller, command, handler, spec, args, **extra):
        if extra.get("operation") != "run":
            return super()._execute(caller, command, handler, spec, args, **extra)
        try:
            result = handler(**dict(args))
        except Exception as exc:
            self._log(caller, command, "error", spec, args, **extra)
            raise BrokerError(f"{command} failed: {exc}") from exc
        self._log(caller, command, "ok", spec, args, **extra)
        return result


class GuessingRedactionBroker(FakeBroker):
    """Defect: an argument the schema does not name is redacted only when its name looks secret
    (``pass``, ``token``, ``key`` ...), the common logging-filter idiom: redaction by guess."""

    _LOOKS = re.compile(r"(?i)pass|word|secret|token|key|cred|pwd")

    def _redact(self, spec, args):
        return {
            k: (
                ("<redacted>" if spec[k].secret else v)
                if k in spec
                else ("<redacted>" if self._LOOKS.search(k) else v)
            )
            for k, v in args.items()
        }


class EchoingRefusalBroker(FakeBroker):
    """Defect: the audit trail is redacted, but ``InvalidArguments`` names each unexpected
    argument with its value (``unexpected lable='...'``), as validation libraries' messages do."""

    def _admit(self, caller, command, args, **extra):
        entry = self._cmds.get(command)
        if (
            entry is not None
            and command != CODEMODE_EXECUTE
            and command in self._allow.get(caller, set())
        ):
            spec = entry[1]
            problems = arg_problems(spec, args)
            if problems:
                self._log(caller, command, "invalid", spec, args, **extra)
                shown = [p for p in problems if not p.startswith("unexpected")]
                shown += [f"unexpected {k}={args[k]!r}" for k in args if k not in spec]
                raise InvalidArguments("; ".join(shown))
        return super()._admit(caller, command, args, **extra)


# ---- codemode-tokens defects
class WideningTokenBroker(FakeBroker):
    """Defect: a token may list any registered action, granted to the actor or not (the issuer
    checks that the action exists, not that the actor holds it), so the token widens a grant."""

    def _admitted(self, actor, action):
        return action in self._cmds

    def token_call(self, token, command, args, *, sandbox_id=None):
        tok = self._token_for(token, command, "call", sandbox_id)
        actor = tok["claims"]["actor"]
        self.allow(actor, [command])  # "the token is the grant"
        return self._as_token(tok, lambda: self.call(actor, command, args))


class AmbientActorBroker(FakeBroker):
    """Defect: a token-authenticated call runs as the actor of the latest token issued, an
    ambient "current execution", not as the actor the presented token names."""

    _latest = None

    def _mint(self, runner, run, *a, **kw):
        self._latest = run["actor"]
        return super()._mint(runner, run, *a, **kw)

    def token_call(self, token, command, args, *, sandbox_id=None):
        tok = self._token_for(token, command, "call", sandbox_id)
        return self._as_token(tok, lambda: self.call(self._latest, command, args))

    def token_submit(self, token, command, args, *, sandbox_id=None):
        tok = self._token_for(token, command, "submit", sandbox_id)
        rid = self._as_token(tok, lambda: self.submit(self._latest, command, args))
        self._pause(tok, rid)
        return rid


class ClientCapBroker(FakeBroker):
    """Defect: the call cap is left to the sandbox's client: the broker counts nothing, so a
    program that resets (or bypasses) its client calls without limit."""

    def _token_problem(self, tok, command, sandbox_id):
        if tok is not None and tok["calls"] >= tok["claims"]["max_calls"]:
            tok["calls"] = 0  # what a broker that never enforces the cap amounts to
        return super()._token_problem(tok, command, sandbox_id)


class NoPauseBroker(FakeBroker):
    """Defect: a submit through a token leaves the token live, so the program goes on past the
    call that is waiting for approval."""

    def _pause(self, tok, rid):
        return None


class SpentStillValidBroker(FakeBroker):
    """Defect: a spent token is still honoured (spending only flips a field nothing reads)."""

    def _token_problem(self, tok, command, sandbox_id):
        if tok is not None and tok["state"] == "spent":
            tok = {**tok, "state": "live"}
        return super()._token_problem(tok, command, sandbox_id)


class NoExpiryBroker(FakeBroker):
    """Defect: ``expires_at`` is written into the claims and never checked."""

    def _token_problem(self, tok, command, sandbox_id):
        if tok is not None:
            tok = {**tok, "expires": datetime.max.replace(tzinfo=UTC)}
        return super()._token_problem(tok, command, sandbox_id)


class ResumeAnyCodeBroker(FakeBroker):
    """Defect: a resume checks the execution's actor and state but not its code digest, so a
    paused execution resumes running another program under the journal of the first."""

    def issue_token(self, runner, request_id, **kw):
        run = self._inflight.get(request_id)
        known = self._executions.get(run["params"]["execution_id"]) if run else None
        if run and known and run["params"].get("resume"):
            p = run["params"]
            known["code_digest"] = code_digest(p["language"], p["code"])
        return super().issue_token(runner, request_id, **kw)


class EchoingTokenBroker(FakeBroker):
    """Defect: a refused token call names the token it was given, so the secret lands in the
    caller's error text (and in any log that records it)."""

    def _token_for(self, token, command, operation, sandbox_id):
        try:
            return super()._token_for(token, command, operation, sandbox_id)
        except Denied as exc:
            raise Denied(f"token {token!r} refused: {exc}", reason=exc.reason) from None
