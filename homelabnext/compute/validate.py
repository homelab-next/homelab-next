# SPDX-License-Identifier: Apache-2.0
"""Semantic validation of a fleet: everything JSON Schema cannot express."""

from __future__ import annotations

import ipaddress

from .model import Fleet, Guest, Problem, ZoneInfo, allowed_groups


def _known_caps() -> frozenset[str]:
    from .model import KNOWN_CAPABILITIES

    return frozenset(f"cap:{c}" for c in KNOWN_CAPABILITIES)


def _in_range(ip: ipaddress.IPv4Address, rng: tuple[str, str]) -> bool:
    lo, hi = ipaddress.ip_address(rng[0]), ipaddress.ip_address(rng[1])
    return lo <= ip <= hi


def _check_network(g: Guest, fleet: Fleet) -> list[Problem]:
    out: list[Problem] = []
    z: ZoneInfo | None = fleet.zones.zone(g.zone)
    if z is None:
        return [Problem(g.id, f"network.zone {g.zone!r} does not exist in the site model")]
    try:
        net = z.network
        ip = ipaddress.ip_address(g.ip)
    except ValueError as exc:
        return [Problem(g.id, f"bad address or subnet: {exc}")]
    if ip not in net:
        out.append(Problem(g.id, f"network.ip {g.ip} is outside zone {z.id} ({net})"))
        return out
    if ip in (net.network_address, net.broadcast_address):
        out.append(Problem(g.id, f"network.ip {g.ip} is the network or broadcast address"))
    if z.gateway and str(ip) == z.gateway:
        out.append(Problem(g.id, f"network.ip {g.ip} is the zone gateway"))
    if z.dhcp_range and _in_range(ip, z.dhcp_range):
        out.append(
            Problem(
                g.id,
                f"network.ip {g.ip} is inside the DHCP pool {z.dhcp_range[0]}-{z.dhcp_range[1]}",
            )
        )
    gw = g.network.get("gateway", "inherit")
    if gw == "inherit":
        if not z.gateway:
            out.append(Problem(g.id, f"gateway is 'inherit' but zone {z.id} declares none"))
    else:
        try:
            if ipaddress.ip_address(gw) not in net:
                out.append(Problem(g.id, f"network.gateway {gw} is outside zone {z.id}"))
        except ValueError as exc:
            out.append(Problem(g.id, f"bad gateway: {exc}"))
    if g.network.get("vlan_tag_mode") == "per_vlan_bridge" and z.vlan_id is None:
        out.append(Problem(g.id, "vlan_tag_mode per_vlan_bridge needs a zone with a vlan_id"))
    return out


def _check_firewall(g: Guest, fleet: Fleet) -> list[Problem]:
    """Firewall on by default: a NIC with the flag off needs a documented exemption.

    With a firewall enforced on the node, a guest NIC without the flag is not simply unfiltered:
    its routed replies can be dropped by the node, which looks like a connectivity fault, not a
    policy one.  So the off state must be a recorded decision, never an omission.
    """
    out: list[Problem] = []
    if g.kind in ("vm", "lxc"):
        if not g.nic_firewall:
            ex = g.firewall_exemption
            if fleet.node_firewall(g.node) and not ex:
                out.append(
                    Problem(
                        g.id,
                        f"network.firewall is disabled on node {g.node!r}, which enforces a "
                        "firewall: add network.firewall_exemption.reason or enable the flag",
                    )
                )
            if g.raw.get("firewall_rules"):
                out.append(
                    Problem(g.id, "firewall_rules are set but the NIC firewall flag is disabled")
                )
        elif g.firewall_exemption:
            out.append(
                Problem(g.id, "network.firewall_exemption is set but the NIC firewall is enabled")
            )
    elif g.raw.get("firewall_rules"):
        out.append(Problem(g.id, "firewall_rules apply to kind vm and lxc only"))
    names = [r["name"] for r in g.firewall_rules + g.outbound_rules]
    if len(names) != len(set(names)):
        out.append(Problem(g.id, "firewall_rules names must be unique"))
    if g.outbound_rules and g.policy_out == "ACCEPT":
        out.append(Problem(g.id, "firewall_rules.outbound_allow needs policy_out DROP or REJECT"))
    for r in g.firewall_rules + g.outbound_rules:
        where = f"firewall_rules.{r['name']}"
        if r["proto"] in ("tcp", "udp") and not r.get("ports"):
            out.append(Problem(g.id, f"{where}: ports are required for {r['proto']}"))
        if r["proto"] == "icmp" and r.get("ports"):
            out.append(Problem(g.id, f"{where}: icmp takes no ports"))
        ports = r.get("ports")
        if ports:
            nums = [int(x) for x in ports.split(":")]
            if any(not 1 <= n <= 65535 for n in nums) or nums != sorted(nums):
                out.append(Problem(g.id, f"{where}: bad port or range {ports!r}"))
        side = "source" if "source" in r else "dest"
        src = r[side]
        if src.startswith("zone:") and fleet.zones.zone(src[5:]) is None:
            out.append(Problem(g.id, f"{where}: {side} zone {src[5:]!r} does not exist"))
        elif "/" in src:
            try:
                ipaddress.ip_network(src, strict=True)
            except ValueError as exc:
                out.append(Problem(g.id, f"{where}: bad {side} CIDR: {exc}"))
    return out


def _check_guest(g: Guest, fleet: Fleet) -> list[Problem]:
    out = _check_network(g, fleet)
    if g.kind == "host" and g.provisioning != "host-only":
        out.append(Problem(g.id, "kind host must have provisioning host-only"))
    if g.kind != "host" and g.provisioning == "host-only":
        out.append(Problem(g.id, "provisioning host-only is only valid for kind host"))
    if g.kind in ("vm", "lxc"):
        if g.vmid is None:
            out.append(Problem(g.id, "placement.vmid is required for vm and lxc"))
        names = [d["name"] for d in g.disks]
        if len(names) != len(set(names)):
            out.append(Problem(g.id, "resources.disks names must be unique"))
        bm = g.memory.get("balloon_min_mb")
        if bm is not None and bm > g.memory.get("size_mb", 0):
            out.append(Problem(g.id, "balloon_min_mb exceeds memory.size_mb"))
        if g.kind == "lxc" and g.image.get("kind") == "iso-install":
            out.append(Problem(g.id, "an lxc cannot use image.kind iso-install"))
    if g.vmid_scheme == "octet" and g.vmid is not None:
        try:
            last = int(g.ip.rsplit(".", 1)[1])
        except (IndexError, ValueError):
            last = None
        if last is not None and g.vmid != last:
            out.append(
                Problem(g.id, f"vmid_scheme octet: vmid {g.vmid} must equal the last octet {last}")
            )
    if g.gpu is not None and g.kind != "vm":
        out.append(Problem(g.id, "gpu requires kind vm"))
    if g.provisioning == "manual" and not g.lifecycle.get("requires_root_steps"):
        out.append(
            Problem(
                g.id,
                "provisioning manual requires lifecycle.requires_root_steps (what to do by hand)",
            )
        )
    if g.capability not in _known_caps():
        out.append(Problem(g.id, f"capability {g.capability} is not a known capability"))
    ok_groups = allowed_groups()
    for grp in g.groups:
        if grp not in ok_groups:
            out.append(Problem(g.id, f"capability_groups: {grp} is not a known inventory group"))
    out += _check_firewall(g, fleet)
    pol = g.backup.get("policy")
    if pol and pol != "none" and pol not in fleet.policies:
        out.append(Problem(g.id, f"backup.policy {pol!r} is not defined in the policy set"))
    return out


def validate(fleet: Fleet, *, require_baselines: bool = True) -> list[Problem]:
    """Return every semantic problem in the fleet (empty list = valid).

    ``require_baselines=False`` leaves out only "this guest declares no baseline" (the coverage
    report lists those itself); every other baseline rule still applies."""
    from .baselines import guest_problems, set_problems

    out: list[Problem] = []
    if fleet.baselines is not None:
        out += set_problems(fleet.baselines)
    seen_id: dict[str, str] = {}
    seen_vmid: dict[tuple[str, int], str] = {}
    seen_ip: dict[str, str] = {}
    for g in fleet.sorted():
        if g.id in seen_id:
            out.append(Problem(g.id, f"duplicate id (also in {seen_id[g.id]})"))
        seen_id[g.id] = g.source
        if g.vmid is not None:
            key = (g.node, g.vmid)
            if key in seen_vmid:
                out.append(
                    Problem(
                        g.id, f"vmid {g.vmid} on node {g.node} already used by {seen_vmid[key]}"
                    )
                )
            seen_vmid[key] = g.id
        if g.ip in seen_ip:
            out.append(Problem(g.id, f"ip {g.ip} already used by {seen_ip[g.ip]}"))
        seen_ip[g.ip] = g.id
        out += _check_guest(g, fleet)
        if require_baselines or g.baseline:
            out += guest_problems(g, fleet.baselines)
    return out
