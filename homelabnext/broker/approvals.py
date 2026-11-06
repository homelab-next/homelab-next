# SPDX-License-Identifier: Apache-2.0
"""The broker's approval boundary: filing an approver's verdict (``approve``/``deny``, bound to
the request digest), what an approval's state is, the pending listings, and the
``decision.requested`` event with its link to the Approvals page.

A part of :class:`homelabnext.broker.service.BrokerService` (its module doc says how the parts
fit); the methods read and write the service's own attributes, set in its ``__init__``."""

from __future__ import annotations

import urllib.parse
from collections.abc import Callable, Mapping
from datetime import datetime, timedelta
from typing import Any

from conformance.protocols.broker import (
    Denied,
)
from homelabnext.agent.schemas import schema_errors

from . import (
    DEFAULT_APPROVAL_TTL_S,
    approval_note_max,
    approver_kind,
    approver_refusal,
    decide,
)
from .common import (
    _APPROVAL_STATES,
    _reasoned,
    _reasoned_invalid,
    _stamp,
    log,
)
from .state import (
    is_id,
    new_id,
)


class _ApprovalsMixin:
    """Mixed into :class:`~homelabnext.broker.service.BrokerService`; not used on its own."""

    # ---------------------------------------------------------------- approvals
    def _latest_approval(self, request_id: str) -> dict[str, Any] | None:
        approved = [a for a in self.state.approvals(request_id) if a["decision"] == "approved"]
        return approved[-1] if approved else None

    def approval_state(self, request_id: str, request: Mapping[str, Any]) -> str:
        """Where a request's latest approval stands, judged by :func:`decide` itself (shadow
        mode: nothing consumed): ``none`` (no approval filed), ``valid`` (it would let the
        request run now), ``expired`` (past its TTL: a fresh approval may be filed),
        ``consumed`` (already used), ``denied`` or ``invalid`` (it no longer matches the request
        or the manifest's approver rules)."""
        docs = self.state.approvals(request_id)
        if docs and docs[-1]["decision"] != "approved":
            return "denied"
        approval = self._latest_approval(request_id)
        if approval is None:
            return "none"
        probe = decide(
            dict(self._view(), mode="shadow"),
            request,
            approval,
            now=_stamp(self._now()),
            store=self.approvals,
        )
        return _APPROVAL_STATES.get(probe["reason"], "invalid")

    def _open_rows(self, keep: Callable[[Mapping[str, Any]], bool]) -> list[dict[str, Any]]:
        """One row per pending request whose stored record ``keep`` selects, oldest first.  Reads only the open-request index, so it costs O(open), not O(history)."""
        out = []
        for rid in self.state.open_request_ids():
            rec = self.state.get_request(rid)
            if not rec or not keep(rec):
                continue
            needs = rec["verdict"] == "needs-approval"
            state = self.approval_state(rid, rec["request"]) if needs else "not-required"
            req = rec["request"]
            out.append(
                {
                    "request_id": rid,
                    "action": req["action"],
                    "actor": req["actor"],
                    "target": req.get("target"),
                    "params": req["params"],
                    "created": req["created"],
                    "digest": req["digest"],
                    "approved": state == "valid",
                    "approval_state": state,
                    "awaiting_approval": needs and state != "valid",
                }
            )
        return out

    def pending(self) -> list[dict[str, Any]]:
        """Requests waiting for an approver: needs-approval and still pending.  ``approved`` is
        true while a valid, unconsumed approval is on file (it can run now); ``approval_state``
        says why not otherwise, and an ``expired`` one takes a fresh approval."""
        if self.notifier is not None:
            try:  # the hub lists this every few seconds: a deferred page is sent on time
                self.poll_pages()
            except Exception:
                log.exception("approval pages could not be polled")
        fields = (
            "request_id",
            "action",
            "actor",
            "target",
            "params",
            "created",
            "digest",
            "approved",
            "approval_state",
        )
        return [
            {k: r[k] for k in fields}
            for r in self._open_rows(lambda rec: rec["verdict"] == "needs-approval")
        ]

    def pending_for(self, caller: str) -> list[dict[str, Any]]:
        """``caller``'s own requests still ``pending`` (awaiting approval, or approved and not yet
        run, or allowed and not yet run): what an agent may still run or cancel."""
        fields = (
            "request_id",
            "action",
            "target",
            "created",
            "awaiting_approval",
            "approved",
            "approval_state",
        )
        return [
            {k: r[k] for k in fields}
            for r in self._open_rows(lambda rec: rec["request"]["actor"] == caller)
        ]

    def _decide_for_test(self, request_id: str, verdict: str) -> None:
        """The conformance hook ``approval-control`` (:func:`make` only): an approver's verdict
        on a pending request.  ``denied`` takes its one transition, as a denial filed through
        :meth:`deny` would; an in-process command needs no approval, so ``approved`` changes
        nothing."""
        if verdict == "denied":
            self.state.claim(
                request_id, {"op": "deny", "by": "conformance", "at": _stamp(self._now())}
            )

    def approve(self, request_id, approver: str, *, note: str | None = None) -> dict[str, Any]:
        """File an approval of ``request_id`` by ``approver`` (``issuer:subject``)."""
        return self._decide_request(request_id, approver, "approved", note)

    def deny(self, request_id, approver: str, *, note: str | None = None) -> dict[str, Any]:
        """File a denial: the request becomes ``denied`` and can never run."""
        return self._decide_request(request_id, approver, "denied", note)

    def _decide_request(self, request_id, approver, decision, note):
        op = "approve" if decision == "approved" else "deny"
        who = approver if isinstance(approver, str) else repr(approver)
        rec = self.state.get_request(request_id) if is_id(request_id) else None
        if rec is None:
            self._audit(
                who, "", op, "denied", reason="unknown-request", request_id=str(request_id)[:128]
            )
            raise Denied(f"no request {request_id!r}", reason="unknown-request")
        req = rec["request"]
        extra = {"request_id": request_id, "request_digest": req["digest"]}
        state = self.state.state_of(request_id)
        if rec["verdict"] != "needs-approval" or state != "pending":
            self._audit(who, req["action"], op, "invalid", reason="not-awaiting-approval", **extra)
            raise _reasoned(
                f"request {request_id!r} is not awaiting approval ({state})",
                "not-awaiting-approval",
            )
        issuer, sep, subject = who.partition(":")
        now = self._now()
        ttl = self.manifest.get("approval_ttl_s") or DEFAULT_APPROVAL_TTL_S
        doc: dict[str, Any] = {
            "approval_id": new_id("appr"),
            "request_id": request_id,
            "request_digest": req["digest"],
            "decision": decision,
            "approver": {"issuer": issuer, "subject": subject},
            "approved_at": _stamp(now),
            "expires_at": _stamp(now + timedelta(seconds=ttl)),
        }
        if note:
            doc["note"] = note
        limit = approval_note_max()
        if not sep:
            problems = ["approver is issuer:subject"]
        elif isinstance(note, str) and len(note) > limit:
            problems = [f"note is at most {limit} characters"]  # never echoed back
        else:
            problems = schema_errors("broker", "approval", doc)
        if problems:
            self._audit(who, req["action"], op, "invalid", reason="approval-invalid", **extra)
            raise _reasoned_invalid(f"approval: {problems[0]}", "approval-invalid")
        # an approval is judged by decide() itself: the approver rules (allowlist, self, agent)
        # and whether the request could run now.  A denial by the approver rules alone, the same
        # ones, so a stranger cannot deny someone's request either; but a request whose grant,
        # tier or handler was withdrawn can still be denied (that is when one most wants to)
        if decision == "approved":
            refused = decide(
                dict(self._view(), mode="shadow"),
                req,
                doc,
                now=doc["approved_at"],
                store=self.approvals,
            )["reason"]
            refused = None if refused == "approved" else refused
        else:
            refused = approver_refusal(self._view(), req, doc["approver"])
        if refused:
            self._audit(who, req["action"], op, "denied", reason=refused, **extra)
            raise Denied(f"{who!r} may not {op} {request_id!r}", reason=refused)
        if decision == "denied" and not self.state.claim(
            request_id, {"op": "deny", "by": who, "at": doc["approved_at"]}
        ):
            self._audit(who, req["action"], op, "invalid", reason="not-awaiting-approval", **extra)
            raise _reasoned(f"request {request_id!r} is no longer pending", "not-pending")
        self.state.put_approval(doc)
        self._audit(who, req["action"], op, "ok", approval_id=doc["approval_id"], **extra)
        # who decided: a person (``human``), or an approver of kind agent the manifest admits
        # (``allow_agent_approvers``): StackStorm's A03 acts on ``human`` only
        tier = "agent" if approver_kind(self._view(), doc["approver"]) == "agent" else "human"
        self._emit(
            "homelabnext.decision.returned",
            {
                "decision_id": request_id,
                "verdict": "accept" if decision == "approved" else "reject",
                "confidence": 1.0,
                "tier_used": tier,
            },
            request_id,
            key=f"returned:{doc['approval_id']}",
        )
        self._notify_settled(request_id, f"{decision} by {who}", req["actor"])
        if decision == "approved" and self.notifier is not None:
            # if it is not run before the approval expires, it waits again: page it then
            expires = datetime.fromisoformat(doc["expires_at"].replace("Z", "+00:00"))
            left = (expires - self._now()).total_seconds()
            self._wake_at(self._mono() + max(0.0, left) + 1.0)
        return doc

    # ---------------------------------------------------------------- events and notify
    def _emit(self, event_type: str, data: Mapping[str, Any], rid: str, *, key: str) -> None:
        from homelabnext.events.envelope import build_event, canonical_body

        ev = build_event(
            event_type, self.source, data, dedupe_key=key, subject=rid, time=_stamp(self._now())
        )
        if self.bus is None:
            self.state.put_outbox(ev)
        else:
            self.bus.publish(event_type, canonical_body(ev), msg_id=ev["id"])

    def approval_link(self, rid: str) -> str | None:
        """The hub Approvals page for one request, when ``approvals_url`` is configured."""
        if not self.approvals_url:
            return None
        return f"{self.approvals_url}?{urllib.parse.urlencode({'request': rid})}"

    def _approval_requested(self, request: Mapping[str, Any]) -> None:
        rid = request["request_id"]
        link = self.approval_link(rid)
        data = {
            "decision_id": rid,
            "spec": "broker-approval",
            "subject": f"requests/{rid}.json",
            "action": request["action"],
            "actor": request["actor"],
            "request_digest": request["digest"],
        }
        if link:
            data["link"] = link
        self._emit("homelabnext.decision.requested", data, rid, key=f"requested:{rid}")
        if self.notifier is not None:
            self.poll_pages()  # this actor's page among any other that is due


def check_approvals_url(url: str | None) -> str | None:
    """``url`` when it is an absolute http(s) URL of a page (no credentials, query or fragment),
    else :class:`ValueError`; None and "" pass as None (no link)."""
    if not url:
        return None
    parts = urllib.parse.urlsplit(url)
    if (
        parts.scheme not in ("http", "https")
        or not parts.hostname
        or parts.username
        or parts.password
        or parts.query
        or parts.fragment
        or any(c.isspace() for c in url)
    ):
        raise ValueError(f"approvals URL {url!r} is not an http(s) page URL")
    return url
