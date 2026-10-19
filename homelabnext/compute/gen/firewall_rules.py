# SPDX-License-Identifier: Apache-2.0
"""Per-guest firewall rules files (Proxmox-style ``[OPTIONS]`` / ``[RULES]`` text).

Every vm and lxc whose NIC firewall flag is on gets ``firewall/<vmid>.fw``: the hypervisor reads
guest rules from ``/etc/pve/firewall/<VMID>.fw``, so a file named after the guest would be
silently ignored.  Inbound is default **drop**; outbound follows ``firewall_rules.policy_out``
(``ACCEPT`` unless the guest asks for default-deny egress with ``DROP`` or ``REJECT``); then
exactly the guest file's ``inbound_allow`` and ``outbound_allow`` entries, in file order.  A guest
with no rules gets the policies and nothing else: silence is never an implicit allow.  Rule
sources and destinations are ``any``, ``zone:<id>`` (the zone's subnet from the site model) or a
CIDR.

Guest rules only take effect while the datacenter firewall is on (``enable: 1`` in the
``[OPTIONS]`` of ``cluster.fw``).  That file also holds the operator's own cluster rules, so it is
not generated; ``firewall/verify-datacenter.sh`` checks the switch and that every rendered file is
installed unchanged, and exits non-zero otherwise.

Guests whose flag is off carry a documented exemption; they get no rules file and are listed with
their reason in ``firewall/EXEMPTIONS.md`` so the exception stays visible in review.
"""

from __future__ import annotations

from homelabnext.compute.model import ComputeError, Fleet, Guest
from homelabnext.generators.safe import checked

from ._text import HEADER


def _address(fleet: Fleet, ref: str) -> str | None:
    if ref == "any":
        return None
    if ref.startswith("zone:"):
        return str(fleet.zones.zone(ref[5:]).network)  # type: ignore[union-attr]
    return ref


def _rule_line(fleet: Fleet, rule: dict, direction: str) -> str:
    parts = [f"{direction} ACCEPT", f"-p {rule['proto']}"]
    if rule.get("ports"):
        parts.append(f"-dport {rule['ports']}")
    side, ref = ("-source", rule["source"]) if direction == "IN" else ("-dest", rule["dest"])
    addr = _address(fleet, ref)
    if addr:
        parts.append(f"{side} {addr}")
    parts.append("-log nolog")
    line = " ".join(parts) + f" # {rule['name']}"
    return checked(line, f"firewall rule {rule['name']}")


def fw_name(g: Guest) -> str:
    if g.vmid is None:
        raise ComputeError(f"{g.id}: firewall rules need placement.vmid (the file is <vmid>.fw)")
    return f"{g.vmid}.fw"


def guest_file(fleet: Fleet, g: Guest) -> str:
    L = [
        f"# {HEADER}",
        f"# {g.id} on {g.node}",
        "[OPTIONS]",
        "enable: 1",
        "policy_in: DROP",
        f"policy_out: {g.policy_out}",
        "log_level_in: nolog",
    ]
    if g.policy_out != "ACCEPT":
        L.append("log_level_out: nolog")
    L += ["", "[RULES]"]
    L += [_rule_line(fleet, dict(r), "IN") for r in g.firewall_rules]
    L += [_rule_line(fleet, dict(r), "OUT") for r in g.outbound_rules]
    return "\n".join(L) + "\n"


def verify_script(names: list[str]) -> str:
    L = [
        "#!/bin/sh",
        f"# {HEADER}",
        "# Guest .fw files are inert unless the datacenter firewall is on.  Run on a cluster node",
        "# (or point HNX_PVE_FIREWALL_DIR at a copy) after installing the files next to this script.",
        "set -eu",
        'FW_DIR="${HNX_PVE_FIREWALL_DIR:-/etc/pve/firewall}"',
        'HERE="$(cd "$(dirname "$0")" && pwd)"',
        "status=0",
        'if ! awk \'/^\\[/ { s = $0 } s == "[OPTIONS]" && /^enable:[ \\t]*1[ \\t]*$/ { ok = 1 }'
        ' END { exit !ok }\' "$FW_DIR/cluster.fw" 2>/dev/null; then',
        "  echo \"datacenter firewall is off: set 'enable: 1' under [OPTIONS] in $FW_DIR/cluster.fw\" >&2",
        "  status=1",
        "fi",
    ]
    if names:
        L.append(f"for f in {' '.join(names)}; do")
        L += [
            '  if ! cmp -s "$HERE/$f" "$FW_DIR/$f"; then',
            '    echo "$FW_DIR/$f is missing or differs from the render" >&2',
            "    status=1",
            "  fi",
            "done",
        ]
    L.append('exit "$status"')
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
    names = []
    for g in fleet.iac():
        if g.nic_firewall:
            name = fw_name(g)
            if f"firewall/{name}" in out:
                raise ComputeError(f"{g.id}: vmid {g.vmid} already has a firewall file")
            out[f"firewall/{name}"] = guest_file(fleet, g)
            names.append(name)
    out["firewall/verify-datacenter.sh"] = verify_script(sorted(names))
    return out
