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
    pol = g.backup.get("policy")
    if pol and pol != "none" and pol not in fleet.policies:
        out.append(Problem(g.id, f"backup.policy {pol!r} is not defined in the policy set"))
    return out


def validate(fleet: Fleet) -> list[Problem]:
    """Return every semantic problem in the fleet (empty list = valid)."""
    out: list[Problem] = []
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
    return out
