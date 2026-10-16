# SPDX-License-Identifier: Apache-2.0
"""Ansible inventory grouped by capability (``cap_*``) with per-host variables from the model.

Playbooks target groups, never hosts (docs/role-interface.md section 5).  Every guest appears,
including manual ones and physical hosts, because configuration management applies to all.
"""

from __future__ import annotations

from homelabnext.compute.model import Fleet, Guest

from ._text import HEADER, q, qlist


def host_vars(fleet: Fleet, g: Guest) -> str:
    v: dict[str, object] = {
        "ansible_host": g.ip,
        "hnx_guest_id": g.id,
        "hnx_kind": g.kind,
        "hnx_provisioning": g.provisioning,
        "hnx_zone": g.zone,
        "hnx_node": g.node,
        "hnx_capability": g.capability,
        "hnx_owner": g.owners["primary"],
        "hnx_backup_policy": g.backup_policy,
    }
    if g.cloudinit.get("user"):
        v["ansible_user"] = g.cloudinit["user"]
    if g.vmid is not None:
        v["hnx_vmid"] = g.vmid
    if g.owners.get("oncall"):
        v["hnx_oncall"] = g.owners["oncall"]
    if g.backup.get("export_hook"):
        v["hnx_export_hook"] = g.backup["export_hook"]
    L = [f"# {HEADER}"]
    for k in sorted(v):
        L.append(f"{k}: {q(v[k])}")
    L.append(f"hnx_tags: {qlist(sorted(g.tags))}")
    return "\n".join(L) + "\n"


def hosts_yml(fleet: Fleet) -> str:
    guests = fleet.sorted()
    groups: dict[str, list[str]] = {}
    for g in guests:
        for grp in g.groups:
            groups.setdefault(grp, []).append(fleet.fqdn(g))
        for t in g.tags:
            groups.setdefault(f"tag_{t.replace('-', '_')}", []).append(fleet.fqdn(g))
    L = [f"# {HEADER}", "all:", "  children:", "    guests:", "      hosts:"]
    L += [f"        {fleet.fqdn(g)}:" for g in guests]
    for grp in sorted(groups):
        L += [f"    {grp}:", "      hosts:"]
        L += [f"        {h}:" for h in sorted(groups[grp])]
    return "\n".join(L) + "\n"


def render(fleet: Fleet) -> dict[str, str]:
    out = {"hosts.yml": hosts_yml(fleet)}
    for g in fleet.sorted():
        out[f"host_vars/{fleet.fqdn(g)}.yml"] = host_vars(fleet, g)
    return out
