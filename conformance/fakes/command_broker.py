# SPDX-License-Identifier: Apache-2.0
"""In-memory allowlisted command broker with an audit trail, and the ``codemode-tokens``
feature: capability tokens held (as a digest of their secret) and enforced in memory."""

from __future__ import annotations

import hashlib
import itertools
import json
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
    features = frozenset({"codemode-tokens", "clock-control", "approval-control"})

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
        #: (actor, execution id) -> code digest, the cap, tokens, state: ids are the actor's own
        self._executions: dict[tuple[str, str], dict[str, Any]] = {}
        self._token: dict[str, Any] | None = None  # the token the current call is made with
        self._execute_runner: str | None = None  # the runner codemode.execute's handler is

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
        return self._submit(caller, command, dict(args), f"req-{next(self._seq)}")

    def _submit(self, caller, command, args, rid):
        args = dict(args)  # the copy that is checked is the copy that runs
        _, spec = self._admit(caller, command, args, operation="submit")
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
        """The latest runner registered runs codemode.execute; every one stays a runner."""
        self._runners[runner] = handler
        self._execute_runner = runner
        self._cmds[CODEMODE_EXECUTE] = (handler, {})

    def _execute_run(self, caller, rid, handler, spec, args, **extra):
        """Run ``codemode.execute``: the request is in flight, for its runner, while its handler
        runs, and a token of it still live when the handler returns is spent (finished)."""
        run = {"request_id": rid, "actor": caller, "params": dict(args)}
        self._inflight[rid] = {**run, "runner": self._execute_runner}
        try:
            return self._execute(
                caller, CODEMODE_EXECUTE, lambda **_: handler(dict(run)), spec, args, **extra
            )
        finally:
            del self._inflight[rid]
            for tok in self._tokens.values():
                if tok["claims"]["request_id"] == rid:
                    if tok["state"] == "live":
                        tok.update(state="spent", outcome="finished")
                    self._settle(tok)

    def _settle(self, tok) -> None:
        """An execution's state follows its latest token."""
        ex = self._executions[tok["key"]]
        if ex["tokens"][-1] != tok["claims"]["token_id"]:
            return
        if tok["state"] == "live":
            ex["state"] = "running"
        elif tok["state"] == "paused" or tok.get("outcome") == "paused":
            ex["state"] = "paused"
        else:
            ex["state"] = "finished"

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

    def _run_for(self, runner, request_id):
        """The in-flight run ``runner`` may issue for; another runner's reads as none."""
        run = self._inflight.get(request_id)
        return run if run is not None and run["runner"] == runner else None

    def _remaining(self, known) -> int:
        """What is left of an execution's cap: it is per execution, across all its runs."""
        return known["max_calls"] - sum(self._tokens[t]["calls"] for t in known["tokens"])

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
        run = self._run_for(runner, request_id)
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
        digest = code_digest(params["language"], params["code"])
        known = self._executions.get((actor, eid))  # execution ids are the actor's own
        if not params.get("resume"):
            if known is not None:
                self._refuse_issue(runner, request_id, "execution-exists", "exists", **ids)
            cap = min(MAX_CALLS, budget.get("max_calls", MAX_CALLS))
        else:
            if not self._resumable(known):
                self._refuse_issue(runner, request_id, "execution-not-resumable", "no", **ids)
            if known["code_digest"] != digest:
                self._refuse_issue(runner, request_id, "resume-code-mismatch", "code", **ids)
            cap = min(self._resume_cap(known), budget.get("max_calls", MAX_CALLS))
            if cap < 1:
                self._refuse_issue(runner, request_id, "call-cap-reached", "cap spent", **ids)
        want = cap if max_calls is None else max_calls
        if want > cap:
            self._refuse_issue(runner, request_id, "token-max-calls-exceeded", "cap", **ids)
        limit = budget.get("wall_s", DEFAULT_WALL_S) + TTL_MARGIN_S
        ttl = ttl_s if ttl_s is not None else limit
        if ttl > limit:
            self._refuse_issue(runner, request_id, "token-ttl-exceeded", "too long", **ids)
        mine = [t for t in self._tokens.values() if t["claims"]["actor"] == actor and self._live(t)]
        if len(mine) >= MAX_LIVE_PER_ACTOR:
            self._refuse_issue(runner, request_id, "too-many-live-tokens", "live tokens", **ids)
        return self._mint(runner, run, digest, sandbox_id, list(actions), want, ttl)

    def _resumable(self, known) -> bool:
        return known is not None and known["state"] == "paused"

    def _resume_cap(self, known) -> int:
        return self._remaining(known)

    def _mint(self, runner, run, digest, sandbox_id, actions, max_calls, ttl):
        now = self._clock().replace(microsecond=0)
        tid, secret = f"tok-{next(self._seq)}", "hnxcmt_" + secrets.token_urlsafe(32)
        eid, actor = run["params"]["execution_id"], run["actor"]
        claims = {
            "token_id": tid,
            "execution_id": eid,
            "request_id": run["request_id"],
            "code_digest": digest,
            "sandbox_id": sandbox_id,
            "actor": actor,
            "issuer": "svc:broker",
            "audience": "svc:broker",
            "actions": actions,
            "max_calls": max_calls,
            "issued_at": _stamp(now),
            "expires_at": _stamp(now + timedelta(seconds=ttl)),
        }
        expires = now + timedelta(seconds=ttl)
        self._tokens[tid] = {
            "claims": claims,
            "state": "live",
            "calls": 0,
            "expires": expires,
            "runner": runner,
            "key": (actor, eid),
        }
        self._by_digest[self._digest(secret)] = tid  # the secret itself is never kept
        known = self._executions.setdefault(
            (actor, eid), {"code_digest": digest, "max_calls": max_calls, "tokens": []}
        )
        known["tokens"].append(tid)
        known["state"] = "running"
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

    @staticmethod
    def _request_digest(action, actor, args) -> str:
        body = json.dumps(
            {"action": action, "actor": actor, "params": args},
            sort_keys=True,
            separators=(",", ":"),
            default=repr,
        )
        return "sha256:" + hashlib.sha256(body.encode()).hexdigest()

    def _token_for(self, token, command, operation, sandbox_id, *, rid=None):
        """The token record a call presents, after every token check (in the contract's
        order), counted; refusals are audited and never name the secret."""
        tid = self._by_digest.get(self._digest(token))
        tok = self._tokens.get(tid) if tid else None
        reason = self._token_problem(tok, command, sandbox_id)
        if not reason and rid is not None:
            reason = self._run_problem(tok, rid)
        if reason:
            self._token_refused(tok, command, operation, reason)
        tok["calls"] += 1  # past the binding a token_run counts, refused or not
        if rid is not None:
            reason = self._approval_problem(rid)
            if reason == "request-denied":  # decided: the refusal names its request
                req = self._reqs[rid]
                request = {"request_id": rid, "request_digest": req.get("digest", "")}
                self._token_refused(tok, req["command"], operation, reason, request=request)
            elif reason:
                self._token_refused(tok, self._reqs[rid]["command"], operation, reason)
        return tok

    def _token_refused(self, tok, command, operation, reason, *, request=None):
        actor, ids = "token:unknown", {}
        if tok is not None:
            claims = tok["claims"]
            actor = claims["actor"]
            ids = {"token_id": claims["token_id"], "execution_id": claims["execution_id"]}
        rid = request["request_id"] if request else None
        self._audit.append(
            AuditRecord(actor, str(command or ""), "denied", {}, operation, rid, reason, **ids)
        )
        exc = Denied("the token does not allow this call", reason=reason)
        if request is not None:  # a decided request (request-denied) is named
            exc.request_id, exc.request_digest = request["request_id"], request["request_digest"]
        raise exc

    def _token_problem(self, tok, command, sandbox_id) -> str:
        if tok is None:
            return "token-invalid"
        claims = tok["claims"]
        if sandbox_id and sandbox_id != claims["sandbox_id"]:  # "" is a pool: no dedicated ids
            return "token-sandbox-mismatch"
        if self._clock() >= tok["expires"]:
            return "token-expired"
        if tok["state"] == "spent":
            return "token-spent"
        if tok["state"] == "paused":
            return "token-paused"
        if command is not None and command not in claims["actions"]:
            return "token-action-not-allowed"
        if tok["calls"] >= claims["max_calls"]:
            return "call-cap-reached"
        return ""

    def _run_problem(self, tok, rid) -> str:
        """Why ``token_run`` may not run ``rid``: only a request an earlier token of the same
        execution paused on, of the same actor, listed in the token, and runnable now."""
        known = self._executions[tok["key"]]
        paused = {  # an earlier token's: a paused token never runs its own request
            self._tokens[t].get("paused_by")
            for t in known["tokens"]
            if t != tok["claims"]["token_id"]
        }
        req = self._reqs.get(rid)
        if rid not in paused or req is None or req["caller"] != tok["claims"]["actor"]:
            return "token-request-not-paused"
        if req["command"] not in tok["claims"]["actions"]:
            return "token-action-not-allowed"
        return ""

    def _approval_problem(self, rid) -> str:
        """After the binding (and the count): whether the paused request may run now.  The
        fake's requests need no approval, so a pending one may; a denied one is decided."""
        state = self._reqs[rid]["state"]
        if state == "denied":
            return "request-denied"
        return "" if state == "pending" else "request-not-approved"

    def decide_request(self, request_id, verdict):
        """Test hook ``approval-control``: an approver's verdict on a pending request."""
        req = self._reqs[request_id]
        if verdict == "denied" and req["state"] == "pending":
            req["state"] = "denied"

    def _as_token(self, tok, fn, request=None):
        outer, self._token = self._token, tok
        try:
            return fn()
        except BrokerError as exc:
            if request is not None:
                self._carry(exc, request)
            raise
        finally:
            self._token = outer

    @staticmethod
    def _carry(exc, request) -> None:
        """A refusal after the request was built names it, as an answer does."""
        exc.request_id = request["request_id"]
        exc.request_digest = request["request_digest"]

    def _answer(self, request, target, **out):
        if target is not None:
            out["target"] = target
        return {**out, **request}

    def token_call(self, token, command, args, *, target=None, sandbox_id=None):
        tok = self._token_for(token, command, "call", sandbox_id)
        actor, args = tok["claims"]["actor"], dict(args)
        request = {
            "request_id": f"req-{next(self._seq)}",
            "request_digest": self._request_digest(command, actor, args),
        }
        result = self._as_token(tok, lambda: self.call(actor, command, args), request)
        return self._answer(request, target, result=result)

    def token_submit(self, token, command, args, *, target=None, sandbox_id=None):
        tok = self._token_for(token, command, "submit", sandbox_id)
        actor, args = tok["claims"]["actor"], dict(args)
        rid = f"req-{next(self._seq)}"
        request = {"request_id": rid, "request_digest": self._request_digest(command, actor, args)}
        self._as_token(tok, lambda: self._submit(actor, command, args, rid), request)
        self._reqs[rid]["digest"] = request["request_digest"]
        self._pause(tok, rid)
        return self._answer(request, target, state="pending")

    def token_run(self, token, request_id, *, sandbox_id=None):
        tok = self._token_for(token, None, "run", sandbox_id, rid=request_id)
        req = self._reqs[request_id]
        request = {"request_id": request_id, "request_digest": req.get("digest", "")}
        result = self._as_token(tok, lambda: self.run(req["caller"], request_id), request)
        return {"result": result, **request}

    def _pause(self, tok, rid) -> None:
        """A submitted request waits for its owner: the program cannot go on."""
        if tok["state"] == "live":
            tok["state"] = "paused"
            tok["paused_by"] = rid
            self._settle(tok)

    def _runner_token(self, runner, token_id):
        tok = self._tokens.get(token_id)
        return tok if tok is not None and tok["runner"] == runner else None

    def spend_token(self, runner, token_id, outcome="finished"):
        if outcome not in ("finished", "paused"):
            raise InvalidArguments("outcome is finished or paused")
        tok = self._runner_token(runner, token_id) if runner in self._runners else None
        reason = ""
        if tok is None:
            reason = "not-a-codemode-runner" if runner not in self._runners else "unknown-token"
        elif outcome == "paused" and tok["state"] != "paused" and tok.get("outcome") != "paused":
            reason = "token-not-paused"
        if reason:
            self._audit.append(
                AuditRecord(runner, CODEMODE_EXECUTE, "denied", {}, "token-spend", None, reason)
            )
            raise Denied("no such token for this runner", reason=reason)
        if tok["state"] != "spent":
            tok.update(state="spent", outcome=outcome)
            self._settle(tok)
        eid = tok["claims"]["execution_id"]
        self._audit.append(
            AuditRecord(
                runner,
                CODEMODE_EXECUTE,
                "ok",
                {"outcome": outcome},
                "token-spend",
                None,
                "",
                token_id,
                eid,
            )
        )

    def token_status(self, runner, token_id):
        tok = self._runner_token(runner, token_id) if runner in self._runners else None
        if tok is None:
            reason = "not-a-codemode-runner" if runner not in self._runners else "unknown-token"
            raise Denied("no such token for this runner", reason=reason)
        state = tok["state"]
        if state == "live" and self._clock() >= tok["expires"]:
            state = "expired"
        out = {"claims": dict(tok["claims"]), "state": state, "calls": tok["calls"]}
        if tok.get("outcome"):
            out["outcome"] = tok["outcome"]
        if tok.get("paused_by"):
            req = self._reqs.get(tok["paused_by"], {})
            out["paused_by"] = tok["paused_by"]
            out["paused_by_state"] = {"pending": "approved"}.get(req.get("state"), req.get("state"))
        return out

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

    def token_call(self, token, command, args, *, target=None, sandbox_id=None):
        tok = self._tokens.get(self._by_digest.get(self._digest(token), ""))
        if tok is not None:
            self.allow(tok["claims"]["actor"], [command])  # "the token is the grant"
        return super().token_call(token, command, args, target=target, sandbox_id=sandbox_id)


class AmbientActorBroker(FakeBroker):
    """Defect: a token-authenticated call runs as the actor of the latest token issued, an
    ambient "current execution", not as the actor the presented token names."""

    _latest = None

    def _mint(self, runner, run, *a, **kw):
        self._latest = run["actor"]
        return super()._mint(runner, run, *a, **kw)

    def _ambient(self, token, fn):
        tok = self._tokens.get(self._by_digest.get(self._digest(token), ""))
        if tok is None:
            return fn()
        real, tok["claims"]["actor"] = tok["claims"]["actor"], self._latest
        try:
            return fn()
        finally:
            tok["claims"]["actor"] = real

    def token_call(self, token, *a, **kw):
        return self._ambient(
            token, lambda: super(AmbientActorBroker, self).token_call(token, *a, **kw)
        )

    def token_submit(self, token, *a, **kw):
        return self._ambient(
            token, lambda: super(AmbientActorBroker, self).token_submit(token, *a, **kw)
        )


class ClientCapBroker(FakeBroker):
    """Defect: the call cap is left to the sandbox's client: the broker counts nothing, so a
    program that resets (or bypasses) its client calls without limit."""

    def _token_problem(self, tok, command, sandbox_id):
        if tok is not None and tok["calls"] >= tok["claims"]["max_calls"]:
            tok["calls"] = 0  # what a broker that never enforces the cap amounts to
        return super()._token_problem(tok, command, sandbox_id)


class PausedStillValidBroker(FakeBroker):
    """Defect: a paused token is still honoured: the pause is recorded (the execution waits) but
    nothing refuses the token, so the program goes on past the call that awaits approval."""

    def _token_problem(self, tok, command, sandbox_id):
        if tok is not None and tok["state"] == "paused":
            tok = {**tok, "state": "live"}
        return super()._token_problem(tok, command, sandbox_id)


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
        if run and run["params"].get("resume"):
            p = run["params"]
            known = self._executions.get((run["actor"], p["execution_id"]))
            if known:
                known["code_digest"] = code_digest(p["language"], p["code"])
        return super().issue_token(runner, request_id, **kw)


class FinishedResumesBroker(FakeBroker):
    """Defect: a finished execution resumes like a paused one (any ended token will do)."""

    def _resumable(self, known):
        return known is not None and known["state"] in ("paused", "finished")


class ResumeFreshCapBroker(FakeBroker):
    """Defect: the cap is per token, not per execution: every resume starts with a fresh
    ``max_calls``, so a program that pauses and resumes calls without bound."""

    def _resume_cap(self, known):
        return MAX_CALLS


class DeniedLooksPendingBroker(FakeBroker):
    """Defect: a paused request its approver denied is answered request-not-approved, a token
    refusal with no request named, so the runner waits on a request that will never run."""

    def _approval_problem(self, rid):
        reason = super()._approval_problem(rid)
        return "request-not-approved" if reason == "request-denied" else reason


class TokenRunAnyRequestBroker(FakeBroker):
    """Defect: ``token_run`` runs any pending request of the actor's, not only the one its
    execution paused on."""

    def _run_problem(self, tok, rid):
        req = self._reqs.get(rid)
        if req is None or req["caller"] != tok["claims"]["actor"]:
            return "token-request-not-paused"
        return ""


class RequestlessRefusalBroker(FakeBroker):
    """Defect: a token call refused after its request was built does not say which request,
    so the runner cannot journal the broker's answer."""

    @staticmethod
    def _carry(exc, request):
        return None


class AnyRunnerBroker(FakeBroker):
    """Defect: any runner may issue for, spend and read any run's token, not only the runner
    the run belongs to."""

    def _run_for(self, runner, request_id):
        return self._inflight.get(request_id)

    def _runner_token(self, runner, token_id):
        return self._tokens.get(token_id)


class EchoingTokenBroker(FakeBroker):
    """Defect: a refused token call names the token it was given, so the secret lands in the
    caller's error text (and in any log that records it)."""

    def _token_for(self, token, *a, **kw):
        try:
            return super()._token_for(token, *a, **kw)
        except Denied as exc:
            exc.args = (f"token {token!r} refused: {exc}",)  # the same refusal, now naming it
            raise
