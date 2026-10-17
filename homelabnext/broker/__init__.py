# SPDX-License-Identifier: Apache-2.0
"""Reference evaluator for the broker contracts in ``schemas/broker/``.

This is the decision logic the schemas imply, kept small and pure so the table-driven fixtures
(``tests/broker/fixtures/decision_table.yml``) have something to run against and so a real
broker can be tested against the same table.  Default deny: every path that is not an explicit
allow is a ``deny`` or ``needs-approval``.

Order of checks (first failure wins):

1. the action is in ``manifest.actions``            else ``default-deny``
2. the actor has a grant naming the action          else ``not-granted``
3. the action's tier is at or below the grant tier  else ``tier-exceeds-grant``
4. a handler is declared for the action             else ``handler-missing``
5. approval, when required (always for execute / privileged):
   none -> ``needs-approval``; wrong request digest -> ``approval-digest-mismatch``;
   denied -> ``approval-denied``; approver is the actor -> ``approval-self-approved``;
   past ``approval_ttl_s`` -> ``approval-expired``; otherwise ``approved``.

In ``shadow`` mode the verdict is computed identically but ``enforced`` is false.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from typing import Any

from homelabnext.agent.digest import digest_of

TIER_RANK = {"read": 0, "write": 1, "execute": 2, "privileged": 3}
_DIGEST_FIELDS = ("action", "actor", "target", "params")


def request_digest(request: Mapping[str, Any]) -> str:
    """sha256 of the canonical JSON of the fields an approval binds to."""
    return digest_of({k: request[k] for k in _DIGEST_FIELDS if k in request})


def _ts(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def decide(
    manifest: Mapping[str, Any],
    request: Mapping[str, Any],
    approval: Mapping[str, Any] | None = None,
    *,
    now: str | None = None,
) -> dict[str, Any]:
    """Decision document (``schemas/broker/decision``) for ``request`` under ``manifest``."""
    actual = request_digest(request)
    verdict, reason, approval_id = _evaluate(manifest, request, approval, actual, now)
    mode = manifest.get("mode", "enforce")
    out = {
        "request_id": request["request_id"],
        "request_digest": actual,
        "verdict": verdict,
        "reason": reason,
        "mode": mode,
        "enforced": mode == "enforce",
        "decided_at": now or request["created"],
    }
    if approval_id:
        out["approval_id"] = approval_id
    return out


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
    if approval["approver"]["subject"] == request["actor"].split(":", 1)[1]:
        return "deny", "approval-self-approved", aid
    ttl = manifest.get("approval_ttl_s")
    if ttl and now:
        age = (_ts(now) - _ts(approval["approved_at"])).total_seconds()
        if age > ttl:
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
