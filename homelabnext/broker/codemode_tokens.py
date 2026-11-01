# SPDX-License-Identifier: Apache-2.0
"""Code Mode capability tokens (ADR-0031; frozen, ``tools/experimental.yml``): running
``codemode.execute``, issuing a token for an in-flight run, the token-authenticated calls, and
spending, pausing and sweeping tokens.  The host-wide token ``flock`` is the token store's
(:mod:`homelabnext.broker.tokens`), unchanged.

A part of :class:`homelabnext.broker.service.BrokerService` (its module doc says how the parts
fit); the methods read and write the service's own attributes, set in its ``__init__``."""

from __future__ import annotations

import contextlib
import copy
import json
import secrets
import threading
from collections.abc import Iterator, Mapping
from datetime import UTC, datetime, timedelta
from typing import Any

from conformance.protocols.broker import (
    CODEMODE_EXECUTE,
    BrokerError,
    Denied,
    InvalidArguments,
    IssuedToken,
    code_digest,
)

from . import (
    decide,
    validation,
)
from . import lanes as _lanes
from .common import (
    _AUDIT_FAILURES,
    _TOKEN,
    COALESCE_WINDOW_S,
    NOT_A_RUNNER,
    REQUEST_DENIED,
    SPEND_OUTCOMES,
    TOKEN_SWEEP_INTERVAL_S,
    TRANSPORT_PEER,
    UNKNOWN_TOKEN_CALLER,
    _Action,
    _carry,
    _reasoned_invalid,
    _stamp,
    log,
)
from .relay import BROKER_SOURCE
from .state import (
    is_id,
    new_id,
)
from .tokens import BEARER_PREFIX, execution_key, secret_digest


class _CodemodeTokensMixin:
    """Mixed into :class:`~homelabnext.broker.service.BrokerService`; not used on its own."""

    # ---------------------------------------------------------------- codemode tokens
    def _execute_run(self, act: _Action, request: Mapping[str, Any], args: Mapping[str, Any]):
        """Run ``codemode.execute``: in flight while its handler runs (only then can its runner be
        issued a token), bound to the runner it belongs to; a token of it still live when the
        handler returns is spent (outcome ``finished``)."""
        rid = request["request_id"]
        self.tokens.begin(
            rid,
            {
                "request_id": rid,
                "actor": request["actor"],
                "params": json.loads(json.dumps(dict(args))),
                "instance": self.state.instance_id(),
                "runner": self._runner_of_execute(),
                "started": _stamp(self._now()),
            },
        )
        try:
            return self._execute(act, request, args)
        finally:
            for tok in self.tokens.end(rid, _stamp(self._now())):
                with contextlib.suppress(*_AUDIT_FAILURES):
                    self._audit_token(
                        BROKER_SOURCE,
                        "token-spend",
                        "ok",
                        tok["claims"],
                        rid,
                        args={"outcome": "finished"},
                    )

    def _runner_of_execute(self) -> str | None:
        """The runner ``codemode.execute``'s handler belongs to, and so the only one its runs
        issue tokens to: the latest registered in process; else the one the manifest's action
        names (``runner``); else the manifest's only runner.  None (several, none named, which
        ``hnx broker validate`` refuses) issues to nobody."""
        registered = [r for r, h in self._runners.items() if h is not None]
        if registered:
            return registered[-1]
        entry = next((a for a in self.manifest["actions"] if a["action"] == CODEMODE_EXECUTE), {})
        if entry.get("runner"):
            return entry["runner"]
        manifest = list(self._runners)
        return manifest[0] if len(manifest) == 1 else None

    def sweep_tokens(self, *, force: bool = False) -> dict[str, int]:
        """Settle what a crash left (an in-flight run whose broker instance is gone is ended
        ``crashed``), drop expired entries from the live index, and remove ended executions older
        than ``codemode.retention_days``.  Runs at start and at most once a minute after."""
        now = self._now()
        if not force and (now - self._tokens_swept).total_seconds() < TOKEN_SWEEP_INTERVAL_S:
            return {}
        self._tokens_swept = now
        self.flush_coalesced()  # a window that ended with refusals held back leaves its count
        before = now - timedelta(days=self.token_retention_days)
        counts = self.tokens.sweep(
            _stamp(now), alive=self.state.instance_alive, retention_before=_stamp(before)
        )
        if counts.get("crashed"):
            log.warning("codemode: %d run(s) whose broker is gone ended crashed", counts["crashed"])
        return counts

    def _audit_token(self, who, operation, outcome, claims, rid=None, *, reason="", args=None):
        ids = {}
        if claims is not None:
            ids = {"token_id": claims["token_id"], "execution_id": claims["execution_id"]}
        self._audit(
            who,
            CODEMODE_EXECUTE,
            operation,
            outcome,
            reason=reason,
            args=args,
            request_id=rid,
            **ids,
        )

    def _issue_refused(self, runner, rid, reason, message, *, eid=None, outcome="denied", args):
        ids = {"execution_id": eid} if eid else {}
        self._audit(
            runner,
            CODEMODE_EXECUTE,
            "token-issue",
            outcome,
            reason=reason,
            args=args,
            request_id=str(rid)[:128],
            **ids,
        )
        if outcome == "invalid":
            err = InvalidArguments(message)
            err.reason = reason  # type: ignore[attr-defined]
            raise err
        raise Denied(message, reason=reason)

    def _probe(self, view: Mapping[str, Any], actor: str, action: str) -> str:
        """:func:`decide`'s verdict on ``actor`` asking for ``action`` with no approval (shadow
        mode: nothing is consumed): the one probe :meth:`actions_for` and :meth:`_admits` share."""
        probe = {"request_id": "req-probe", "action": action, "actor": actor, "params": {}}
        return decide(dict(view, mode="shadow"), probe, None, store=self.approvals)["verdict"]

    def _admits(self, view: Mapping[str, Any], actor: str, action: str) -> bool:
        """Whether :func:`decide` admits ``action`` for ``actor`` (allow or needs-approval)."""
        return self._probe(view, actor, action) in ("allow", "needs-approval")

    def issue_token(self, runner, request_id, *, sandbox_id, actions, max_calls=None, ttl_s=None):
        """A capability token for the in-flight ``codemode.execute`` request ``request_id``, for
        the runner that run belongs to only (see the module doc for every refusal).  Returns the
        secret, once, and the claims; the broker keeps the claims and the secret's digest."""
        who = runner if isinstance(runner, str) and runner else "<none>"
        shown = {
            "sandbox_id": sandbox_id if isinstance(sandbox_id, str) else repr(sandbox_id)[:64],
            "actions": list(actions)[:200] if isinstance(actions, (list, tuple)) else [],
            "max_calls": max_calls,
            "ttl_s": ttl_s,
        }
        if who not in self._runners:
            self._issue_refused(who, request_id, NOT_A_RUNNER, "not a runner", args=shown)
        bad = not (isinstance(sandbox_id, str) and is_id(sandbox_id))
        bad |= not (
            isinstance(actions, (list, tuple))
            and 0 < len(actions) <= 200
            and all(isinstance(a, str) for a in actions)
        )
        for n in (max_calls, ttl_s):
            bad |= n is not None and (not isinstance(n, int) or isinstance(n, bool) or n < 1)
        if bad:
            self._issue_refused(
                who,
                request_id,
                "invalid-params",
                "sandbox_id is a slug, actions a list of 1-200 "
                "names, max_calls and ttl_s positive integers",
                outcome="invalid",
                args=shown,
            )
        self.sweep_tokens()
        with self.tokens.locked():
            run = self.tokens.inflight(request_id)
            if (
                run is None
                or run.get("runner") != who  # another runner's run reads as no run at all
                or not self.state.instance_alive(run.get("instance"))
            ):
                self._issue_refused(
                    who,
                    request_id,
                    "execution-not-in-flight",
                    "no codemode.execute of that id is running for this runner",
                    args=shown,
                )
            return self._issue(who, run, sandbox_id, list(actions), max_calls, ttl_s, shown)

    def _issue(self, runner, run, sandbox_id, actions, max_calls, ttl_s, shown) -> IssuedToken:
        rid, actor, params = run["request_id"], run["actor"], run["params"]
        eid, budget = params["execution_id"], params.get("budget", {})

        def refuse(reason: str, message: str) -> None:
            self._issue_refused(runner, rid, reason, message, eid=eid, args=shown)

        if not _lanes.PROFILE_RE.match(actor):  # a token is an agent's: claims name a profile
            refuse("token-actor-invalid", "only an agent profile's run is issued a token")
        if self.tokens.token_of_request(rid) is not None:
            refuse("request-has-token", "this run already has its token")
        if any(a.startswith("codemode.") for a in actions):
            refuse("token-action-codemode", "a program cannot start another program")
        view = self._view()
        if len(set(actions)) != len(actions) or not all(
            self._admits(view, actor, a) for a in actions
        ):
            refuse("token-action-not-admitted", "a token lists only actions the actor may ask for")
        key = execution_key(actor, eid)
        known = self.tokens.execution(key)  # the actor's own: another's id is no answer at all
        digest = code_digest(params["language"], params["code"])
        if not params.get("resume"):
            if known is not None:
                refuse("execution-exists", "that execution id is taken: resume it or pick another")
            cap = min(self.codemode_max_calls, budget.get("max_calls", self.codemode_max_calls))
        else:
            if known is None or known.get("state") != "paused":
                refuse("execution-not-resumable", "no paused execution of that id")
            if known["code_digest"] != digest:
                refuse("resume-code-mismatch", "a resume runs the program that was paused")
            # the cap is the execution's, in total: a resume inherits what is left of it
            cap = min(
                known["max_calls"] - self.tokens.calls_of(known), budget.get("max_calls", 1 << 30)
            )
            if cap < 1:
                refuse("call-cap-reached", "the execution has made every call its cap allows")
        want = cap if max_calls is None else max_calls
        if want > cap:
            refuse("token-max-calls-exceeded", f"at most {cap} calls")
        limit = budget.get("wall_s", self.codemode_wall_s) + self.token_ttl_margin_s
        ttl = limit if ttl_s is None else ttl_s
        if ttl > limit:
            refuse("token-ttl-exceeded", f"a token for this run lives at most {limit}s")
        now = self._now().astimezone(UTC).replace(microsecond=0)
        if len(self.tokens.live_of(actor, _stamp(now))) >= self.live_tokens_per_actor:
            refuse("too-many-live-tokens", f"at most {self.live_tokens_per_actor} live tokens")
        secret = BEARER_PREFIX + secrets.token_urlsafe(32)  # 256 bits; returned once, never kept
        claims = {
            "token_id": new_id("tok"),
            "execution_id": eid,
            "request_id": rid,
            "code_digest": digest,
            "sandbox_id": sandbox_id,
            "actor": actor,
            "issuer": BROKER_SOURCE,
            "audience": BROKER_SOURCE,
            "actions": actions,
            "max_calls": want,
            "issued_at": _stamp(now),
            "expires_at": _stamp(now + timedelta(seconds=ttl)),
        }
        problems = validation.named_errors("codemode/token", claims)
        if problems:  # a bug in the broker, never the runner's input: nothing is issued
            raise BrokerError(f"token claims invalid: {problems[0]}")
        tok = {
            "claims": claims,
            "secret_sha256": secret_digest(secret),
            "runner": runner,
            "exec_key": key,
            "state": "live",
            "calls": 0,
        }
        self.tokens.put(tok)
        doc = known or {
            "key": key,
            "execution_id": eid,
            "actor": actor,
            "code_digest": digest,
            "max_calls": want,
            "tokens": [],
        }
        doc.update(
            tokens=[*doc["tokens"], claims["token_id"]], state="running", updated=_stamp(now)
        )
        self.tokens.put_execution(doc)
        self._audit_token(runner, "token-issue", "ok", claims, rid, args=shown)
        return IssuedToken(secret, copy.deepcopy(claims))

    def _token_problem(self, tok, action, sandbox_id) -> str:
        """Why a call with ``tok`` is refused, in the contract's order, or ``""``.  ``sandbox_id``
        is the calling sandbox's: None in process (not judged), ``""`` a pool peer (accepted only
        for a token no dedicated sandbox is named for), else one dedicated sandbox."""
        if tok is None:
            return "token-invalid"
        claims = tok["claims"]
        if sandbox_id is not None:
            dedicated = claims["sandbox_id"] in self._dedicated_sandboxes
            if (sandbox_id == "" and dedicated) or (
                sandbox_id != "" and sandbox_id != claims["sandbox_id"]
            ):
                return "token-sandbox-mismatch"
        expires = datetime.fromisoformat(claims["expires_at"].replace("Z", "+00:00"))
        if self._now() >= expires:
            return "token-expired"
        if tok["state"] in ("spent", "paused"):
            return f"token-{tok['state']}"
        if action is not None and action not in claims["actions"]:
            return "token-action-not-allowed"
        if tok["calls"] >= claims["max_calls"]:
            return "call-cap-reached"
        return ""

    def _token_refused(self, tok, command, operation, reason, rid=None, *, request=None):
        claims = tok["claims"] if tok else None
        ids = {}
        if claims:
            ids = {"token_id": claims["token_id"], "execution_id": claims["execution_id"]}
        if request is not None:
            ids["request_digest"] = request["digest"]
        args = None
        if claims is None:  # a secret that names no token: one record per peer and window
            coalesced = self._coalesce("token-invalid")
            if coalesced is None:
                raise Denied("the token does not allow this call", reason=reason)
            args = {"coalesced": coalesced} if coalesced else None
        self._audit(
            claims["actor"] if claims else UNKNOWN_TOKEN_CALLER,
            command,
            operation,
            "denied",
            reason=reason,
            request_id=rid,
            args=args,
            **ids,
        )
        err = Denied("the token does not allow this call", reason=reason)
        raise _carry(err, request) if request is not None else err

    def _coalesce(self, kind: str) -> int | None:
        """Coalesce one kind of refusal record per transport peer (``token-invalid``: a secret
        that names no token; ``sandbox-refused``: a sandbox's request refused by the transport
        before any token was read): the first of a :data:`COALESCE_WINDOW_S` window is written
        and returns how many the previous window held back (0 for none); every other one returns
        None and is counted.  A window is judged on the monotonic clock, and an elapsed time
        that is negative (a clock stepped back) ends it rather than extending it.  What a window
        held back is written once it ends, by :meth:`flush_coalesced` (a timer, the token
        sweep, or the next refusal), so a flood that stops still leaves its count."""
        peer = TRANSPORT_PEER.get() or "in-process"
        now = self._mono()
        with self._coalesce_lock:
            st = self._coalescing.get((kind, peer))
            if st is not None and 0 <= now - st[0] < COALESCE_WINDOW_S:
                st[1] += 1
                if st[1] == 1:
                    self._arm_flush(COALESCE_WINDOW_S - (now - st[0]))
                return None
            held = st[1] if st is not None else 0
            self._coalescing[(kind, peer)] = [now, 0]
            return held

    def flush_coalesced(self) -> int:
        """Write one record for every coalescing window that has ended with refusals held back
        (``args.coalesced``: how many), and forget it.  Returns how many it wrote."""
        now = self._mono()
        due = []
        with self._coalesce_lock:
            for key, (start, held) in list(self._coalescing.items()):
                if not 0 <= now - start < COALESCE_WINDOW_S:
                    del self._coalescing[key]
                    if held:
                        due.append((key, held))
        written = 0
        for (kind, peer), held in due:
            ctx = TRANSPORT_PEER.set(peer if peer.startswith("uid:") else None)
            try:
                caller = UNKNOWN_TOKEN_CALLER if kind == "token-invalid" else peer
                self._audit(caller, "", "connect", "denied", reason=kind, args={"coalesced": held})
                written += 1
            except _AUDIT_FAILURES as exc:
                # the trail cannot take it now: keep the count for the next flush, never lose it
                log.warning("%d coalesced %s refusal(s) not yet recorded (%s)", held, kind, exc)
                with self._coalesce_lock:
                    st = self._coalescing.get((kind, peer))
                    if st is None:  # still an ended window, so the next flush tries again
                        self._coalescing[(kind, peer)] = [now - COALESCE_WINDOW_S, held]
                    else:
                        st[1] += held
            finally:
                TRANSPORT_PEER.reset(ctx)
        return written

    def _arm_flush(self, delay: float) -> None:
        if not self.page_timers:
            return
        timer = threading.Timer(max(0.0, delay) + 0.05, self._flush_quietly)
        timer.daemon = True
        timer.start()

    def _flush_quietly(self) -> None:
        try:
            self.flush_coalesced()
        except Exception:  # a timer thread: the next sweep or refusal flushes again
            log.exception("coalesced refusal counts could not be written")

    def _count(self, tok: dict[str, Any]) -> None:
        tok["calls"] += 1
        self.tokens.save(tok)

    @contextlib.contextmanager
    def _as_token(self, tok: Mapping[str, Any]) -> Iterator[None]:
        """Records written meanwhile name the token; a refusal raised after admission says so
        (``admitted``: the cap bounds it, so the transport does not rate-limit it)."""
        ctx = _TOKEN.set(tok["claims"])
        try:
            yield
        except BrokerError as exc:
            exc.admitted = True  # type: ignore[attr-defined]
            raise
        finally:
            _TOKEN.reset(ctx)

    def _token_op(self, token, command, args, operation, target, sandbox_id) -> dict[str, Any]:
        """A call or submit made with a token, after the token checks and the count.  Both
        decide under the store's lock: a request that needs approval (and every submit) is
        stored and the token paused in that same step, so no call is admitted once the pause is
        decided, and a crash cannot leave a submitted request beside a live token."""
        args = dict(args) if isinstance(args, Mapping) else args
        with self.tokens.locked():
            tok = self.tokens.by_secret(token)
            reason = self._token_problem(tok, command, sandbox_id)
            if not reason:
                self._count(tok)
                actor = tok["claims"]["actor"]
                with self._as_token(tok):
                    act, request, decision = self._admit(actor, command, args, operation, target)
                    pause = decision["enforced"] and (
                        operation == "submit" or decision["verdict"] == "needs-approval"
                    )
                    if pause:  # the approval page (the notifier: a network send) goes out after
                        rid = self._store(actor, command, args, act, request, decision, page=False)
                        self.tokens.set_state(tok, "paused", paused_by=rid)
                        self.tokens.settle(tok, _stamp(self._now()))
                        self._audit_token(
                            actor, "token-pause", "ok", tok["claims"], rid, args={"paused_by": rid}
                        )
        if reason:
            self._token_refused(tok, command, operation, reason)
        answer = {"request_id": request["request_id"], "request_digest": request["digest"]}
        if target is not None:
            answer["target"] = target
        if pause:
            if decision["verdict"] == "needs-approval":
                self._approval_requested(request)
            return {"state": "pending", **answer}
        with self._as_token(tok):
            if not decision["enforced"]:
                return {"result": self._shadow(actor, act, request, decision, operation), **answer}
            if decision["verdict"] != "allow":  # a submit-only path never gets here
                raise _carry(Denied("needs approval", reason="approval-required"), request)
            return {"result": self._run_audited(actor, act, request, args, "call"), **answer}

    def token_call(self, token, command, args, *, target: str | None = None, sandbox_id=None):
        """``call`` as the token's actor, after the token checks and the count: ``{result,
        request_id, request_digest[, target]}``, or ``{state: pending, ...}`` when the call
        needs approval, which pauses the token."""
        return self._token_op(token, command, args, "call", target, sandbox_id)

    def token_submit(self, token, command, args, *, target: str | None = None, sandbox_id=None):
        """``submit`` as the token's actor: ``{state: pending, request_id, request_digest}``; the
        token is paused (the request waits for an approval and a run)."""
        return self._token_op(token, command, args, "submit", target, sandbox_id)

    def token_run(self, token, request_id, *, sandbox_id=None):
        """Run, as the token's actor, the request an earlier token of the same execution paused
        on, once it may run (approved, or needing none): ``{result, request_id,
        request_digest}``.  Past the binding check it counts against the cap, refused or not (so
        polling a request not approved yet spends the cap).  Everything after the
        binding check uses the broker's own record of that request id (``paused_by``), never the
        id the caller sent, which arrived in the same request body as the token's secret."""
        with self.tokens.locked():
            tok = self.tokens.by_secret(token)
            reason = self._token_problem(tok, None, sandbox_id)
            rec, rid = None, None
            if not reason:
                ex = self.tokens.execution(tok["exec_key"]) or {"tokens": []}
                paused_by = {
                    (self.tokens.token(t) or {}).get("paused_by")
                    for t in ex["tokens"]
                    if t != tok["claims"]["token_id"]
                }
                rid = next((r for r in paused_by if r and r == request_id), None)
                rec = self.state.get_request(rid) if rid is not None else None
                if rec is None or rec["request"]["actor"] != tok["claims"]["actor"]:
                    reason = "token-request-not-paused"
                elif rec["request"]["action"] not in tok["claims"]["actions"]:
                    reason = "token-action-not-allowed"
            if not reason:
                # past the binding, every token_run counts, a refused one too: a program polling
                # a request that is not approved yet spends its cap, so the polling is bounded
                self._count(tok)
                state = self._paused_state(rid, rec)
                if state == "denied":
                    reason = REQUEST_DENIED  # decided: named like any decided request
                elif state != "approved":
                    reason = "request-not-approved"
        action = rec["request"]["action"] if rec else ""
        if reason:
            decided = rec["request"] if reason == REQUEST_DENIED else None
            self._token_refused(tok, action, "run", reason, rid if rec else None, request=decided)
        req = rec["request"]
        answer = {"request_id": rid, "request_digest": req["digest"]}
        with self._as_token(tok):
            try:
                return {"result": self.run(req["actor"], rid), **answer}
            except BrokerError as exc:
                raise _carry(exc, req) from None

    def _paused_state(self, request_id: str, rec: Mapping[str, Any]) -> str:
        """A paused-on request as the runner needs it: ``pending``, ``approved`` (it may run now:
        approved, or needing no approval), ``denied``, or how its run ended (``done``, ...)."""
        state = self.state.state_of(request_id)
        if state != "pending":
            return state
        if rec["verdict"] != "needs-approval":
            return "approved"
        verdict = self.approval_state(request_id, rec["request"])
        # an approval that expired unused puts the request back to waiting (a fresh approval is
        # accepted, and it is paged again): "expired" tells the runner it waits on a new one
        return {"valid": "approved", "denied": "denied", "expired": "expired"}.get(
            verdict, "pending"
        )

    def _runner_token(self, who, token_id):
        """The token ``who`` holds (it issued it), or None: another runner's token reads as no
        token at all."""
        tok = self.tokens.token(token_id) if isinstance(token_id, str) else None
        return tok if tok is not None and tok.get("runner") == who else None

    def spend_token(self, runner, token_id, outcome: str = "finished") -> None:
        """End a token as ``finished`` (the run is over; the execution never resumes) or ``paused``
        (the run ended on its pause; the execution waits to be resumed).  Every later call on it
        is refused ``token-spent``."""
        who = runner if isinstance(runner, str) and runner else "<none>"
        reason = NOT_A_RUNNER if who not in self._runners else ""
        if outcome not in SPEND_OUTCOMES:
            raise _reasoned_invalid("outcome is finished or paused", "invalid-params")
        with self.tokens.locked():
            tok = None if reason else self._runner_token(who, token_id)
            if not reason and tok is None:
                reason = "unknown-token"
            elif (
                not reason
                and outcome == "paused"
                and tok["state"] != "paused"
                and tok.get("outcome") != "paused"
            ):
                reason = "token-not-paused"
            elif not reason and tok["state"] != "spent":
                self.tokens.set_state(tok, "spent", outcome=outcome)
                self.tokens.settle(tok, _stamp(self._now()))
        if reason:
            self._audit(who, CODEMODE_EXECUTE, "token-spend", "denied", reason=reason)
            raise Denied("no such token for this runner", reason=reason)
        self._audit_token(
            who,
            "token-spend",
            "ok",
            tok["claims"],
            tok["claims"]["request_id"],
            args={"outcome": outcome},
        )

    def token_status(self, runner, token_id) -> dict[str, Any]:
        """A runner's view of its token: its claims, ``state`` (``live``, ``paused``, ``spent``;
        ``expired`` when live past its expiry), ``outcome`` once spent, its calls, and the
        request a pause waits on with that request's state (``paused_by_state``: ``pending``,
        ``approved``, ``denied``, ``done``, ...) so the runner knows when to resume."""
        who = runner if isinstance(runner, str) and runner else "<none>"
        tok = self._runner_token(who, token_id) if who in self._runners else None
        if tok is None:
            reason = NOT_A_RUNNER if who not in self._runners else "unknown-token"
            raise Denied("no such token for this runner", reason=reason)
        state = tok["state"]
        if state == "live" and self._token_problem(tok, None, None) == "token-expired":
            state = "expired"
        out = {"claims": tok["claims"], "state": state, "calls": tok["calls"]}
        if tok.get("outcome"):
            out["outcome"] = tok["outcome"]
        if tok.get("paused_by"):
            rec = self.state.get_request(tok["paused_by"])
            out["paused_by"] = tok["paused_by"]
            out["paused_by_state"] = self._paused_state(tok["paused_by"], rec) if rec else "unknown"
        return out
