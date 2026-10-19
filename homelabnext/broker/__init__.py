# SPDX-License-Identifier: Apache-2.0
"""Reference evaluator for the broker contracts in ``schemas/broker/``.

This is the decision logic the schemas imply, kept small so the table-driven fixtures
(``tests/broker/fixtures/decision_table.yml``) have something to run against and so a real
broker can be tested against the same table.  Default deny: every path that is not an explicit
allow is a ``deny`` or ``needs-approval``.

Order of checks (first failure wins):

1. the action is in ``manifest.actions``            else ``default-deny``
2. the actor has a grant naming the action          else ``not-granted``
3. the action's tier is at or below the grant tier  else ``tier-exceeds-grant``
4. a handler is declared for the action             else ``handler-missing``
5. approval, when required (always for execute / privileged):

   - none -> ``needs-approval``;
   - wrong request id or digest -> ``approval-digest-mismatch``;
   - decision is not ``approved`` -> ``approval-denied``;
   - approver is the actor (compared normalized, see :func:`normalize_identity`)
     -> ``approval-self-approved``;
   - approver not in ``manifest.approvers`` (issuer and subject) -> ``approval-approver-not-allowed``;
   - approver is an agent and ``allow_agent_approvers`` is not true -> ``approval-agent-approver``;
   - ``approved_at`` before the request was created, or after ``now`` -> ``approval-time-invalid``;
   - ``now`` past ``expires_at`` or past ``approved_at + approval_ttl_s`` -> ``approval-expired``;
   - the approval id was already consumed -> ``approval-replayed``;
   - otherwise ``approved``, and the approval id is consumed.

Time: ``now`` defaults to the current UTC clock; it is never optional in effect.  A manifest
without ``approval_ttl_s`` gets :data:`DEFAULT_APPROVAL_TTL_S` (15 minutes); the stricter of the
TTL and the approval's own ``expires_at`` wins.

Approvers: a manifest without ``approvers`` accepts no approval at all (fail closed).  An
approver counts as an agent when its allowlist entry says ``kind: agent`` or when its normalized
subject is the name of any profile the manifest grants actions to.

Single use: an approval allows exactly one request.  :class:`ApprovalStore` is the interface a
broker implements over durable storage; :class:`MemoryApprovalStore` is the in-process default.
Pass one store per broker (``store=``); without one, a module-level in-memory store is used,
which only protects a single process.

In ``shadow`` mode the verdict is computed identically but ``enforced`` is false, and the
approval is not consumed (nothing runs).

Ownership: a request belongs to its ``actor``.  :func:`decide_access` is the verdict on a caller
reading or cancelling an existing request: only the owner (compared normalized) is allowed;
anyone else is ``deny`` / ``not-request-owner``.  The decision names the ``operation`` and the
``caller``, so the document itself is the audit record of the attempt.
"""

from __future__ import annotations

import re
import threading
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

from homelabnext.agent.digest import digest_of

TIER_RANK = {"read": 0, "write": 1, "execute": 2, "privileged": 3}
#: what a caller may do to a request that already exists (``execute`` is :func:`decide`)
ACCESS_OPERATIONS = ("read", "cancel")
DEFAULT_APPROVAL_TTL_S = 900
_DIGEST_FIELDS = ("action", "actor", "target", "params")
_SEP_RE = re.compile(r"[._\s]+")


class ApprovalStore(Protocol):
    """Records which approval ids have been used.  ``consume`` must be atomic."""

    def consume(self, approval_id: str) -> bool:
        """Mark ``approval_id`` used; True the first time, False on every later call."""
        ...

    def consumed(self, approval_id: str) -> bool:
        """True when ``approval_id`` has already been used (read only)."""
        ...


class MemoryApprovalStore:
    """Thread-safe in-memory :class:`ApprovalStore` (one process, lost on restart)."""

    def __init__(self) -> None:
        self._used: set[str] = set()
        self._lock = threading.Lock()

    def consume(self, approval_id: str) -> bool:
        with self._lock:
            if approval_id in self._used:
                return False
            self._used.add(approval_id)
            return True

    def consumed(self, approval_id: str) -> bool:
        with self._lock:
            return approval_id in self._used


_DEFAULT_STORE = MemoryApprovalStore()


def request_digest(request: Mapping[str, Any]) -> str:
    """sha256 of the canonical JSON of the fields an approval binds to."""
    return digest_of({k: request[k] for k in _DIGEST_FIELDS if k in request})


def normalize_identity(value: str) -> str:
    """Case-folded, with ``.``, ``_`` and whitespace runs folded to ``-``.

    ``ops_bot``, ``Ops.Bot`` and ``ops-bot`` are the same identity for every comparison the
    broker makes, so a spelling variant cannot pass as someone else.
    """
    return _SEP_RE.sub("-", value.strip().casefold()).strip("-")


def _qualified(issuer: str, subject: str) -> tuple[str, str]:
    return normalize_identity(issuer), normalize_identity(subject)


def _profile_name(profile_id: str) -> str:
    return normalize_identity(profile_id.split(":", 1)[-1])


def _ts(value: str) -> datetime:
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def _now_str() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def decide(
    manifest: Mapping[str, Any],
    request: Mapping[str, Any],
    approval: Mapping[str, Any] | None = None,
    *,
    now: str | None = None,
    store: ApprovalStore | None = None,
) -> dict[str, Any]:
    """Decision document (``schemas/broker/decision``) for ``request`` under ``manifest``.

    ``now`` defaults to the UTC clock.  ``store`` records consumed approvals (see module doc).
    """
    now = now or _now_str()
    actual = request_digest(request)
    mode = manifest.get("mode", "enforce")
    verdict, reason, approval_id = _evaluate(manifest, request, approval, actual, now)
    if reason == "approved":
        st = _DEFAULT_STORE if store is None else store
        fresh = st.consume(approval_id) if mode == "enforce" else not st.consumed(approval_id)
        if not fresh:
            verdict, reason = "deny", "approval-replayed"
    out = {
        "request_id": request["request_id"],
        "request_digest": actual,
        "verdict": verdict,
        "reason": reason,
        "mode": mode,
        "enforced": mode == "enforce",
        "decided_at": now,
    }
    if approval_id:
        out["approval_id"] = approval_id
    return out


def decide_access(
    manifest: Mapping[str, Any],
    request: Mapping[str, Any],
    caller: str,
    operation: str,
    *,
    now: str | None = None,
) -> dict[str, Any]:
    """Decision document for ``caller`` performing ``operation`` (read / cancel) on ``request``.

    A request is bound to its ``actor``: only that identity, compared with
    :func:`normalize_identity`, may read or cancel it.  Every other caller - another profile, an
    empty or non-string caller - is ``deny`` / ``not-request-owner``.  Being granted the same
    action, or being an approver, does not make a caller the owner.  The verdict follows the
    manifest's ``mode`` like :func:`decide`; it never consumes anything.
    """
    if operation not in ACCESS_OPERATIONS:
        raise ValueError(f"operation must be one of {ACCESS_OPERATIONS}, got {operation!r}")
    now = now or _now_str()
    mode = manifest.get("mode", "enforce")
    owner = normalize_identity(str(request["actor"]))
    is_owner = isinstance(caller, str) and bool(owner) and normalize_identity(caller) == owner
    verdict, reason = ("allow", "allowed") if is_owner else ("deny", "not-request-owner")
    return {
        "request_id": request["request_id"],
        "request_digest": request_digest(request),
        "verdict": verdict,
        "reason": reason,
        "mode": mode,
        "enforced": mode == "enforce",
        "decided_at": now,
        "operation": operation,
        "caller": caller if isinstance(caller, str) else repr(caller),
    }


def _evaluate(manifest, request, approval, actual, now):
    if manifest.get("default", "deny") != "deny":
        return "deny", "default-deny", None  # a manifest that is not default-deny is refused
    entry = next((a for a in manifest.get("actions", []) if a["action"] == request["action"]), None)
    if entry is None:
        return "deny", "default-deny", None
    grant = next(
        (
            g
            for g in manifest.get("grants", [])
            if g["profile"] == request["actor"] and request["action"] in g["actions"]
        ),
        None,
    )
    if grant is None:
        return "deny", "not-granted", None
    if TIER_RANK[entry["tier"]] > TIER_RANK[grant["max_tier"]]:
        return "deny", "tier-exceeds-grant", None
    if not entry.get("handler"):
        return "deny", "handler-missing", None
    needs = entry["requires_approval"] or entry["tier"] in ("execute", "privileged")
    if not needs:
        return "allow", "allowed", None
    if approval is None:
        return "needs-approval", "approval-required", None
    aid = approval.get("approval_id")
    if approval["request_digest"] != actual or approval["request_id"] != request["request_id"]:
        return "deny", "approval-digest-mismatch", aid
    if approval["decision"] != "approved":
        return "deny", "approval-denied", aid
    who = approval["approver"]
    issuer, subject = _qualified(who["issuer"], who["subject"])
    if subject == _profile_name(request["actor"]):
        return "deny", "approval-self-approved", aid
    allowed = next(
        (
            a
            for a in manifest.get("approvers", [])
            if _qualified(a["issuer"], a["subject"]) == (issuer, subject)
        ),
        None,
    )
    if allowed is None:
        return "deny", "approval-approver-not-allowed", aid
    agents = {_profile_name(g["profile"]) for g in manifest.get("grants", [])}
    is_agent = allowed.get("kind", "human") == "agent" or subject in agents
    if is_agent and manifest.get("allow_agent_approvers") is not True:
        return "deny", "approval-agent-approver", aid
    t_now, t_appr = _ts(now), _ts(approval["approved_at"])
    if t_appr > t_now or ("created" in request and t_appr < _ts(request["created"])):
        return "deny", "approval-time-invalid", aid
    ttl = manifest.get("approval_ttl_s") or DEFAULT_APPROVAL_TTL_S
    expiry = t_appr + timedelta(seconds=ttl)
    if approval.get("expires_at"):
        expiry = min(expiry, _ts(approval["expires_at"]))
    if t_now > expiry:
        return "deny", "approval-expired", aid
    return "allow", "approved", aid


def check_manifest_handlers(
    manifest: Mapping[str, Any], handlers: list[Mapping[str, Any]]
) -> list[str]:
    """Consistency between a manifest and the ``handler.json`` documents it points at.

    Every manifest action needs exactly one handler document with the same path and tier, and a
    handler may not be *less* demanding about approval than the manifest.  Handlers nobody
    allowlists are reported too: a handler that exists but is not in the manifest is dead code
    or a mistake, and default deny keeps it unreachable either way.
    """
    problems: list[str] = []
    by_action: dict[str, list[Mapping[str, Any]]] = {}
    for h in handlers:
        by_action.setdefault(h["action"], []).append(h)
    for a in manifest.get("actions", []):
        found = by_action.get(a["action"], [])
        if len(found) != 1:
            problems.append(
                f"{a['action']}: expected exactly one handler document, got {len(found)}"
            )
            continue
        h = found[0]
        if h["handler"] != a["handler"]:
            problems.append(
                f"{a['action']}: handler path {h['handler']!r} != manifest {a['handler']!r}"
            )
        if h["tier"] != a["tier"]:
            problems.append(
                f"{a['action']}: handler tier {h['tier']!r} != manifest tier {a['tier']!r}"
            )
        if a["requires_approval"] and not h["requires_approval"]:
            problems.append(
                f"{a['action']}: handler does not require approval but the manifest does"
            )
    listed = {a["action"] for a in manifest.get("actions", [])}
    for action in sorted(set(by_action) - listed):
        problems.append(f"{action}: handler present but not in the manifest")
    return problems
