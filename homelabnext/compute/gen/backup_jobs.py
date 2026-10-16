# SPDX-License-Identifier: Apache-2.0
"""Backup job list: which guests belong to which policy, with retention and export hooks."""

from __future__ import annotations

from homelabnext.compute.model import Fleet

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
