# SPDX-License-Identifier: Apache-2.0
"""The broker's request lifecycle: ``call`` and ``submit``, storing a request under the
pending quota, ``status``/``detail``, running an approved request once (``run``), ``cancel``, and
what a caller may see (``served_agents``, ``list_agents``, ``actions_for``).

A part of :class:`homelabnext.broker.service.BrokerService` (its module doc says how the parts
fit); the methods read and write the service's own attributes, set in its ``__init__``."""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

from conformance.protocols.broker import (
    ArgSpec,
    Denied,
    RequestStatus,
)

from . import (
    approver_kind,
    decide,
    decide_access,
)
from . import lanes as _lanes
from .common import (
    NOT_OWNER,
    TOO_MANY_PENDING,
    _carry,
    _contract_error,
    _reasoned,
    _Refused,
    _stamp,
    log,
)
from .state import (
    StateError,
    is_id,
    process_identity,
)


class _RequestsMixin:
    """Mixed into :class:`~homelabnext.broker.service.BrokerService`; not used on its own."""

    # ---------------------------------------------------------------- the contract: calls
    def call(self, caller, command, args, *, target: str | None = None):
        args = dict(args) if isinstance(args, Mapping) else args  # check and run one snapshot
        act, request, decision = self._admit(caller, command, args, "call", target)
        if not decision["enforced"]:
            return self._shadow(caller, act, request, decision, "call")
        if decision["verdict"] == "needs-approval":
            self._audit(
                caller,
                command,
                "call",
                "denied",
                reason="approval-required",
                args=args,
                spec=act.spec,
                request_id=request["request_id"],
                request_digest=request["digest"],
            )
            raise Denied(f"{command!r} needs approval: submit it", reason="approval-required")
        return self._run_audited(caller, act, request, args, "call")

    def submit(self, caller, command, args, *, target: str | None = None):
        # the copy that is checked is the copy that is kept: a caller's later change to its
        # mapping never reaches the handler
        args = dict(args) if isinstance(args, Mapping) else args
        act, request, decision = self._admit(caller, command, args, "submit", target)
        return self._store(caller, command, args, act, request, decision)

    def _store(self, caller, command, args, act, request, decision, *, page=True) -> str:
        """Keep an admitted request ``pending`` (the second half of ``submit``); ``page=False``
        leaves its approval request to the caller (one that holds a lock)."""
        rid = request["request_id"]
        secret = {}
        if act.kind == "callable":
            secret = {k: v for k, v in args.items() if act.spec.get(k, ArgSpec("str")).secret}
        record = {
            "request": request,
            "kind": act.kind,
            "verdict": decision["verdict"],
            "decision_reason": decision["reason"],
        }
        with self._submit_lock:
            if len(self._pending_of(request["actor"])) >= self.pending_per_actor:
                self._audit(
                    caller,
                    command,
                    "submit",
                    "denied",
                    reason=TOO_MANY_PENDING,
                    args=args,
                    spec=act.spec,
                    request_id=rid,
                    request_digest=request["digest"],
                )
                err = Denied(
                    f"{caller!r} has {self.pending_per_actor} requests pending: run, cancel or "
                    "wait for a decision on one first",
                    reason=TOO_MANY_PENDING,
                )
                raise _carry(err, request)
            self.state.put_request(rid, record)
        if secret:
            self._secret_args[rid] = secret
        self._audit(
            caller,
            command,
            "submit",
            "ok",
            args=args,
            spec=act.spec,
            request_id=rid,
            request_digest=request["digest"],
            decision_reason=decision["reason"],
        )
        if page and decision["verdict"] == "needs-approval":
            self._approval_requested(request)
        return rid

    def _pending_of(self, actor: str) -> list[dict[str, Any]]:
        """The stored records of ``actor``'s pending requests (the open index: O(open))."""
        out = []
        for rid in self.state.open_request_ids():
            rec = self.state.get_request(rid)
            if rec and rec["request"]["actor"] == actor:
                out.append(rec)
        return out

    def _awaiting(self, actor: str) -> list[dict[str, Any]]:
        """``actor``'s requests waiting for an approver (no valid approval yet), oldest first."""
        return [
            rec["request"]
            for rec in self._pending_of(actor)
            if rec["verdict"] == "needs-approval"
            and self.approval_state(rec["request"]["request_id"], rec["request"]) != "valid"
        ]

    def _owned(self, caller, request_id, operation):
        """The stored record when ``caller`` owns ``request_id``; otherwise audit and refuse.

        An unknown id and someone else's id get the same answer, so a foreign request's existence
        is not disclosed."""
        rec = self.state.get_request(request_id) if is_id(request_id) else None
        if rec is not None:
            op = "cancel" if operation == "cancel" else "read"
            access = decide_access(
                self.manifest, rec["request"], caller, op, now=_stamp(self._now())
            )
            if access["verdict"] == "allow":
                return rec
        action = rec["request"]["action"] if rec else ""
        self._audit(
            caller, action, operation, "denied", reason=NOT_OWNER, request_id=str(request_id)[:128]
        )
        raise Denied(f"no request {request_id!r} for {caller!r}", reason=NOT_OWNER)

    def status(self, caller, request_id):
        rec = self._owned(caller, request_id, "status")
        req = rec["request"]
        self._audit(caller, req["action"], "status", "ok", request_id=request_id)
        return RequestStatus(
            request_id, req["actor"], req["action"], self.state.state_of(request_id)
        )

    def detail(self, caller, request_id) -> dict[str, Any]:
        """The owner's full view: request, state, approvals and result (``hnx broker status``).
        Each approval carries ``approver_kind``: ``human``, ``agent`` or None (no longer an
        allowlisted approver), judged now against the manifest -- the authoritative answer to
        "did a person approve this", where an event's ``tier_used`` is only advisory."""
        st = self.status(caller, request_id)
        rec = self.state.get_request(request_id)
        view = self._view()
        approvals = [
            {**a, "approver_kind": approver_kind(view, a.get("approver") or {})}
            for a in self.state.approvals(request_id)
        ]
        return {
            "request": rec["request"],
            "state": st.state,
            "verdict": rec["verdict"],
            "approvals": approvals,
            "result": self.state.get_result(request_id),
        }

    def run(self, caller, request_id):
        rec = self._owned(caller, request_id, "run")
        req = rec["request"]
        extra = {"request_id": request_id, "request_digest": req["digest"]}
        state = self.state.state_of(request_id)
        if state != "pending":
            self._audit(caller, req["action"], "run", "invalid", reason="not-pending", **extra)
            raise _reasoned(f"request {request_id!r} is {state}, not pending", "not-pending")
        act = self._action(req["action"])
        args = {**req["params"], **self._secret_args.get(request_id, {})}
        approval = self._latest_approval(request_id)
        now = _stamp(self._now())
        view = self._view()
        # decide without consuming: the approval is consumed only once this run holds the
        # request's claim, so a refusal on the way (arguments, a lost claim) never burns it
        enforce = view.get("mode", "enforce") == "enforce"
        decision = decide(
            dict(view, mode="shadow") if enforce else view,
            req,
            approval,
            now=now,
            store=self.approvals,
        )
        if not enforce:
            return self._shadow(caller, act, req, decision, "run")
        if decision["verdict"] != "allow":
            reason = decision["reason"]
            self._audit(
                caller,
                req["action"],
                "run",
                "denied",
                reason=reason,
                args=req["params"],
                spec=act.spec if act else None,
                approval_id=decision.get("approval_id"),
                **extra,
            )
            raise Denied(f"request {request_id!r} may not run: {reason}", reason=reason)
        try:
            held = self._secret_args.get(request_id, {})
            if (
                act
                and act.kind == "callable"
                and any(
                    act.spec.get(k, ArgSpec("str")).secret and k not in held for k in req["params"]
                )
            ):
                raise _Refused("error", "secret-args-lost", "a secret argument is not held here")
            self._check_args(act, req["actor"], args, req["created"])
        except _Refused as exc:
            self._audit(
                caller,
                req["action"],
                "run",
                exc.outcome,
                reason=exc.reason,
                args=req["params"],
                spec=act.spec,
                **extra,
            )
            raise _contract_error(exc) from None
        # the intent is on record before anything changes: when it cannot be written, the request
        # stays pending and its approval unused, to run once the trail can take it
        self._started(caller, act, req, args, "run")
        claimed = self.state.claim(
            request_id,
            {
                "op": "run",
                "by": caller,
                "at": now,
                "instance": self.state.instance_id(),
                **process_identity(),
            },
        )
        if not claimed:
            self._audit(caller, req["action"], "run", "invalid", reason="not-pending", **extra)
            raise _reasoned(f"request {request_id!r} is no longer pending", "not-pending")
        aid = decision.get("approval_id")
        if decision["reason"] == "approved" and not self.approvals.consume(aid):
            # only a run holding the claim consumes, so this means the approval was used
            # outside this request's run: refuse, and end the claimed request as an error
            self._secret_args.pop(request_id, None)
            self._finish(request_id, {"state": "error", "at": now, "reason": "approval-replayed"})
            self._audit(
                caller,
                req["action"],
                "run",
                "denied",
                reason="approval-replayed",
                approval_id=aid,
                **extra,
            )
            raise Denied(
                f"request {request_id!r}: approval already used", reason="approval-replayed"
            )
        try:
            result = self._run_audited(caller, act, req, args, "run", started=True)
        except Exception as exc:  # whatever ends the run, it ends: never "running" forever
            reason = getattr(exc, "reason", "") or "internal-error"
            self._finish(request_id, {"state": "error", "at": now, "reason": reason})
            raise
        finally:
            self._secret_args.pop(request_id, None)
        done = {"state": "done", "at": _stamp(self._now())}
        if act.kind != "callable" and isinstance(result, Mapping):
            done["result"] = json.loads(json.dumps(result, default=repr))
        self._finish(request_id, done)
        return result

    def _finish(self, request_id: str, doc: dict[str, Any]) -> None:
        """Record how a claimed run ended.  When the result cannot be written (a full disk), the
        request reads ``interrupted`` rather than ``running`` forever; the audit trail holds what
        happened."""
        try:
            self.state.put_result(request_id, doc)
        except (OSError, StateError) as exc:
            self.state.mark_unfinished(request_id)
            log.error("request %s: its result cannot be written (%s)", request_id, exc)

    def cancel(self, caller, request_id):
        rec = self._owned(caller, request_id, "cancel")
        req = rec["request"]
        extra = {"request_id": request_id, "request_digest": req["digest"]}
        claimed = self.state.claim(
            request_id, {"op": "cancel", "by": caller, "at": _stamp(self._now())}
        )
        if not claimed:
            state = self.state.state_of(request_id)
            self._audit(caller, req["action"], "cancel", "invalid", reason="not-pending", **extra)
            raise _reasoned(f"request {request_id!r} is {state}, not pending", "not-pending")
        self._secret_args.pop(request_id, None)
        self._audit(caller, req["action"], "cancel", "ok", **extra)
        if rec["verdict"] == "needs-approval":  # withdrawn by its owner: closed without a message
            self._notify_settled(request_id, "cancelled by its owner", req["actor"], quiet=True)

    def served_agents(self) -> list[str]:
        """The agent keys this broker serves: each profile (``profile:<key>``) that the manifest
        both maps a transport peer to (``callers``) and grants something (``grants``), as
        ``<key>``, sorted.  Names only: no uid, grant, action or token (what an operator's
        ``agents`` answers, for the deploy's census; :meth:`list_agents` is the audited ask)."""
        peers = {c.get("profile") for c in self.manifest.get("callers", [])}
        granted = {g.get("profile") for g in self.manifest.get("grants", [])}
        return sorted(
            p.removeprefix("profile:")
            for p in peers & granted
            if isinstance(p, str) and p.startswith("profile:")
        )

    def list_agents(self, operator: str) -> list[str]:
        """:meth:`served_agents` for an operator over the socket (``uid:<n>``), audited as
        operation ``agents``, outcome ``ok``; the record names no key."""
        keys = self.served_agents()
        self._audit(operator, "", "agents", "ok")
        return keys

    def actions_for(self, caller: str) -> list[dict[str, Any]]:
        """What ``caller`` may ask for: every action a grant of its names that :func:`decide`
        would admit (``allow`` or ``needs-approval``), with its tier, kind and parameters.
        Derived by asking ``decide`` itself (shadow mode, nothing consumed), so it cannot
        disagree with what a call would get."""
        view = self._view()
        names = sorted({a for g in view["grants"] if g["profile"] == caller for a in g["actions"]})
        out = []
        for name in names:
            verdict = self._probe(view, caller, name)
            if verdict not in ("allow", "needs-approval"):
                continue
            entry = next(a for a in view["actions"] if a["action"] == name)
            act = self._action(name)
            row: dict[str, Any] = {
                "action": name,
                "tier": entry["tier"],
                "kind": act.kind,
                "needs_approval": verdict == "needs-approval",
            }
            if act.kind == "lane" and act.handler is not None:
                row["lane"] = act.handler.name
                row["params"] = _lane_params(act.handler)
            elif act.kind == "exec" and act.handler is not None:
                row["params_schema"] = act.handler["params_schema"]
                row["description"] = act.handler.get("description", "")
            out.append(row)
        return out


def _lane_params(lane: _lanes.Lane) -> dict[str, str]:
    """A caller's description of a lane action's params (``actions_for``)."""
    if lane.kind == "records-inbox":
        return {
            "note": "records note frontmatter: title, risk, rollback, ...; requesting_agent is "
            f"bound to the caller; type one of {', '.join(lane.note_types)}",
            "body": "optional Markdown body",
            "slug": "optional file name slug",
        }
    return {
        "name": f"file name matching {lane.filename_pattern}",
        "content": f"{lane.format}, at most {lane.max_bytes} bytes"
        + ("" if lane.overwrite else "; an existing file is never replaced"),
    }
