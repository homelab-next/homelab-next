# SPDX-License-Identifier: Apache-2.0
"""Ansible inventory grouped by capability (``cap_*``) with per-host variables from the model.

Playbooks target groups, never hosts (docs/role-interface.md section 5).  Every guest appears,
including manual ones and physical hosts, because configuration management applies to all.
With a baseline set, each guest is also in ``baseline_<name>`` for every baseline it resolves to
(``extends`` included) and ``control_<id>`` for every control it needs, and carries
``hnx_baselines`` / ``hnx_controls`` (the baseline-playbook target plays to those groups), and
the baseline settings (``with:``, baseline set 1.2) of its per-guest controls as the bound roles'
prefixed variables (``trivy_severity: "HIGH"``).
"""

from __future__ import annotations

import json

from homelabnext.compute.baselines import resolve, role_vars
from homelabnext.compute.model import Fleet, Guest

from ._text import HEADER, q, qlist
from .firewall_rules import resolve_addresses


def baseline_group(name: str) -> str:
    return "baseline_" + name.replace("-", "_")


def control_group(control: str) -> str:
    return "control_" + control.replace("-", "_")


def _fw_rules(fleet: Fleet, rule: dict, side: str) -> list[str]:
    """One row per address the rule names: a ``zone:`` with a ``subnet6`` is two rows of the same
    name, the IPv4 subnet's and the IPv6 prefix's."""
    out = []
    for addr in resolve_addresses(fleet, rule[side]):
        row = {"name": rule["name"], "proto": rule["proto"]}
        if rule.get("ports"):
            row["ports"] = rule["ports"]
        row[side] = addr or "any"
        out.append("{" + ", ".join(f"{k}: {q(v)}" for k, v in row.items()) + "}")
    return out


def firewall_vars(fleet: Fleet, g: Guest) -> list[str]:
    """``hnx_firewall``: the guest's firewall rules with zones resolved to subnets (and to the
    zone's IPv6 prefix as a second row of the same name, where it has one)."""
    L = ["hnx_firewall:", f"  policy_out: {q(g.policy_out)}"]
    for key, rules, side in (
        ("inbound_allow", g.firewall_rules, "source"),
        ("outbound_allow", g.outbound_rules, "dest"),
    ):
        if not rules:
            L.append(f"  {key}: []")
            continue
        L.append(f"  {key}:")
        L += [f"    - {row}" for r in rules for row in _fw_rules(fleet, dict(r), side)]
    return L


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
    L += firewall_vars(fleet, g)
    if fleet.baselines is not None:
        r = resolve(g, fleet.baselines)
        L.append(f"hnx_baselines: {qlist(list(r.baselines))}")
        L.append(f"hnx_controls: {qlist(list(r.controls))}")
        if r.exemption:
            L.append(f"hnx_baseline_exemption: {q(r.exemption['reason'])}")
        settings = role_vars(fleet.baselines, r)
        if settings:
            L.append("# baseline settings (with:) of the controls applied on this guest")
            L += [f"{k}: {json.dumps(v, sort_keys=True)}" for k, v in sorted(settings.items())]
    return "\n".join(L) + "\n"


def hosts_yml(fleet: Fleet) -> str:
    guests = fleet.sorted()
    groups: dict[str, list[str]] = {}
    for g in guests:
        for grp in g.groups:
            groups.setdefault(grp, []).append(fleet.fqdn(g))
        for t in g.tags:
            groups.setdefault(f"tag_{t.replace('-', '_')}", []).append(fleet.fqdn(g))
        if fleet.baselines is not None:
            r = resolve(g, fleet.baselines)
            for b in r.baselines:
                groups.setdefault(baseline_group(b), []).append(fleet.fqdn(g))
            for c in r.controls:
                groups.setdefault(control_group(c), []).append(fleet.fqdn(g))
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
