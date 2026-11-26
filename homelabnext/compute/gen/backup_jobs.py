# SPDX-License-Identifier: Apache-2.0
"""Backup job list: which guests belong to which policy, with retention and export hooks.

A VM or container member keeps its ``vmid`` (vzdump's handle).  A ``kind: host`` member
(``provisioning: host-only``: a physical sensor, a DNS Pi, the hypervisor's own config) has no
``vmid`` because there is no VM to snapshot; the job runner for its policy takes a file-level
copy instead (``proxmox-backup-client backup`` or a role export hook).  The render records the
distinction with ``kind: host-only`` in place of ``vmid`` so a consumer that dispatches jobs
sees which mechanism to run without inferring it from a missing field.
"""

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
            ]
            # A host-only guest has no vmid (no VM to snapshot): record the file-level mechanism
            # explicitly in its place. A vm/lxc keeps the existing vmid field unchanged.
            if g.kind == "host":
                L.append(f"        kind: {q('host-only')}")
            else:
                L.append(f"        vmid: {q(g.vmid)}")
            L += [
                f"        include_memory: {q(g.backup.get('include_memory', False))}",
                "        retain: {" + ", ".join(f"{k}: {ret[k]}" for k in sorted(ret)) + "}",
                f"        export_hook: {q(g.backup.get('export_hook'))}",
            ]
    return {"backup-jobs.yml": "\n".join(L) + "\n"}
