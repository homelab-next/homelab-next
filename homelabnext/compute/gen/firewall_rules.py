# SPDX-License-Identifier: Apache-2.0
"""Per-guest firewall rules files (Proxmox-style ``[OPTIONS]`` / ``[RULES]`` text).

Every vm and lxc whose NIC firewall flag is on gets ``firewall/<name>.fw``: inbound default
**drop**, outbound accept, and exactly the ``firewall_rules.inbound_allow`` entries of the guest
file, in file order.  A guest with no rules gets the drop policy and nothing else: silence is
never an implicit allow.  Rule sources are ``any``, ``zone:<id>`` (the zone's subnet from the
site model) or a CIDR.

Guests whose flag is off carry a documented exemption; they get no rules file and are listed with
their reason in ``firewall/EXEMPTIONS.md`` so the exception stays visible in review.
"""

from __future__ import annotations

from homelabnext.compute.model import Fleet, Guest

from ._text import HEADER


def _source(fleet: Fleet, rule: dict) -> str | None:
    src = rule["source"]
    if src == "any":
        return None
    if src.startswith("zone:"):
        return str(fleet.zones.zone(src[5:]).network)  # type: ignore[union-attr]
    return src


def _rule_line(fleet: Fleet, rule: dict) -> str:
    parts = ["IN ACCEPT", f"-p {rule['proto']}"]
    if rule.get("ports"):
        parts.append(f"-dport {rule['ports']}")
    src = _source(fleet, rule)
    if src:
        parts.append(f"-source {src}")
    parts.append("-log nolog")
    return " ".join(parts) + f" # {rule['name']}"


def guest_file(fleet: Fleet, g: Guest) -> str:
    L = [
        f"# {HEADER}",
        "[OPTIONS]",
        "enable: 1",
        "policy_in: DROP",
        "policy_out: ACCEPT",
        "log_level_in: nolog",
        "",
        "[RULES]",
    ]
    L += [_rule_line(fleet, dict(r)) for r in g.firewall_rules]
    return "\n".join(L) + "\n"


def exemptions(fleet: Fleet) -> str:
    L = [f"<!-- {HEADER} -->", "# Firewall exemptions", ""]
    exempt = [g for g in fleet.iac() if not g.nic_firewall]
    if not exempt:
        L.append("None. Every rendered guest NIC has the firewall flag on.")
    for g in exempt:
        ex = g.firewall_exemption or {}
        review = f" Review by {ex['review_by']}." if ex.get("review_by") else ""
        reason = str(ex.get("reason", "no reason recorded")).rstrip(".")
        L.append(f"* `{g.id}` (node `{g.node}`): {reason}.{review}")
    return "\n".join(L).rstrip("\n") + "\n"


def render(fleet: Fleet) -> dict[str, str]:
    out = {"firewall/EXEMPTIONS.md": exemptions(fleet)}
    for g in fleet.iac():
        if g.nic_firewall:
            out[f"firewall/{g.name}.fw"] = guest_file(fleet, g)
    return out
