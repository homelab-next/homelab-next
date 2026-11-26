# SPDX-License-Identifier: Apache-2.0
"""Backup job list: which guests belong to which policy, with retention and export hooks.

A deploy that writes the real backup job (``pvesh set /cluster/backup/<id> --vmid ...``) reads
the vmid list from the same records as this generator, through :func:`members_on_node`, so the
hand list in `/etc/pve/jobs.cfg` no longer drifts from the guests the lab declares (B5).
"""

from __future__ import annotations

from homelabnext.compute.model import Fleet, Guest

from ._text import HEADER, q


def render(fleet: Fleet) -> dict[str, str]:
    by_policy: dict[str, list] = {}
    for g in fleet.sorted():
        if g.backup_policy != "none":
            by_policy.setdefault(g.backup_policy, []).append(g)
    L = [f"# {HEADER}", "jobs:"]
    if not by_policy:
        L[-1] = "jobs: []"
    for name in sorted(by_policy):
        pol = fleet.policies.get(name, {})
        L += [f"  - policy: {q(name)}"]
        if pol.get("schedule"):
            L.append(f"    schedule_utc: {q(pol['schedule'])}")
        L.append("    members:")
        for g in by_policy[name]:
            ret = g.backup.get("retain", {})
            L += [
                f"      - guest: {q(g.id)}",
                f"        node: {q(g.node)}",
                f"        vmid: {q(g.vmid)}",
                f"        include_memory: {q(g.backup.get('include_memory', False))}",
                "        retain: {" + ", ".join(f"{k}: {ret[k]}" for k in sorted(ret)) + "}",
                f"        export_hook: {q(g.backup.get('export_hook'))}",
            ]
    return {"backup-jobs.yml": "\n".join(L) + "\n"}


def members_on_node(fleet: Fleet, policy: str, node: str) -> list[Guest]:
    """Guests that belong to ``policy`` and are placed on ``node``, in guest-id order.

    Empty when the pair has no member or ``policy`` is not declared at all (the caller judges
    whether that is a usage error or a genuine "this node has nothing under this policy").
    ``policy`` is the lab's declared name (``g.backup_policy``), never the string ``"none"``: a
    guest opted out of backups is never in a job and ``members_on_node(..., "none", ...)`` is
    deliberately empty rather than a list of every guest that opted out.
    """
    if policy == "none":
        return []
    return [
        g
        for g in fleet.sorted()
        if g.backup_policy == policy and g.node == node and g.vmid is not None
    ]


def vmids_on_node(fleet: Fleet, policy: str, node: str) -> list[int]:
    """The sorted, unique vmids ``members_on_node(fleet, policy, node)`` returns."""
    return sorted({g.vmid for g in members_on_node(fleet, policy, node) if g.vmid is not None})
