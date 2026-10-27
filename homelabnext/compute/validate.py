# SPDX-License-Identifier: Apache-2.0
"""Semantic validation of a fleet: everything JSON Schema cannot express."""

from __future__ import annotations

import ipaddress
from typing import Any

from .model import Fleet, Guest, Problem, ZoneInfo, allowed_groups, group_for_capability

#: capabilities whose guests run model weights or model-written code: their outbound traffic is
#: default-deny (docs/compute-model.md, "Model runtimes")
MODEL_RUNTIMES: tuple[str, ...] = ("cap:inference", "cap:codemode-executor")


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
        by = (g.firewall_exemption or {}).get("filtered_by")
        if (
            by
            and by.startswith("guest:")
            and (by == g.id or by not in {x.id for x in fleet.guests})
        ):
            out.append(
                Problem(g.id, f"network.firewall_exemption.filtered_by: {by} is not another guest")
            )
        elif by and by.startswith("zone:") and fleet.zones.zone(by[5:]) is None:
            out.append(
                Problem(
                    g.id, f"network.firewall_exemption.filtered_by: zone {by[5:]!r} does not exist"
                )
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


def model_runtime(g: Guest) -> str | None:
    """The model runtime capability the guest's capability, or one of its inventory groups,
    names (one of :data:`MODEL_RUNTIMES`), or None: it serves no model and runs no model-written
    code."""
    for c in MODEL_RUNTIMES:
        if g.capability == c or group_for_capability(c) in g.groups:
            return c
    return None


def _internet_allows(g: Guest) -> list[str]:
    """Outbound allows that reach beyond the lab: ``any``, or a CIDR not inside the never-internet
    ranges (:data:`homelabnext.modules.egress.NOT_INTERNET`).  A ``zone:`` is a lab subnet."""
    from homelabnext.modules.egress import NOT_INTERNET

    out = []
    for r in g.outbound_rules:
        dest = r["dest"]
        if dest.startswith("zone:"):
            continue
        try:
            net = None if dest == "any" else ipaddress.ip_network(dest, strict=True)
        except ValueError:
            continue  # a bad CIDR is _check_firewall's problem
        if net is None or not any(
            net.version == n.version and net.subnet_of(n) for n in NOT_INTERNET
        ):
            out.append(
                f"firewall_rules.{r['name']}: dest {dest} reaches the internet; a model runtime's "
                "outbound_allow names zone:<id> or a lab CIDR (reach the internet through the gateway)"
            )
    return out


def _model_runtime_problems(g: Guest, fleet: Fleet) -> list[Problem]:
    """A model runtime's outbound traffic is default-deny: ``policy_out`` DROP or REJECT (the
    guest firewall then also logs what it drops), and, with a baseline set that defines the
    control, ``egress-filter`` among its controls.  A model's own reasoning is no boundary: a model
    asked to write a detection rule has tried to upload a file to a cloud bucket while its trace
    said it would call no tool."""
    runtime = model_runtime(g)
    if runtime is None or g.raw.get("status") == "retired":
        return []
    why = f"{runtime} runs models or model-written code"
    out: list[Problem] = []
    if g.kind in ("vm", "lxc") and not g.nic_firewall:
        # filtered elsewhere (a libvirt host, a zone's router) is a recorded, dated decision that
        # names the layer, never a free-text reason alone
        ex = g.firewall_exemption or {}
        if not ex.get("filtered_by") or not ex.get("review_by"):
            out.append(
                Problem(
                    g.id,
                    f"{why}: its NIC firewall is off, so network.firewall_exemption needs "
                    "filtered_by (the guest or zone that filters it) and review_by",
                )
            )
    elif g.kind in ("vm", "lxc"):
        if g.policy_out == "ACCEPT":
            out.append(
                Problem(
                    g.id,
                    f"{why}: firewall_rules.policy_out must be DROP or REJECT, with outbound_allow "
                    "naming what it needs (resolver, time, model store, gateway)",
                )
            )
        out += [Problem(g.id, f"{why}: {p}") for p in _internet_allows(g)]
    bs = fleet.baselines
    if bs is not None and "egress-filter" in bs.controls and g.baseline:
        from .baselines import resolve

        r = resolve(g, bs)
        if r.exemption is None and "egress-filter" not in r.controls:
            out.append(
                Problem(g.id, f"{why}: its baselines must include egress-filter (or not remove it)")
            )
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
        out += _model_runtime_problems(g, fleet)
    out += _power(fleet)
    out += _capacity(fleet)
    return out


def node_usage(fleet: Fleet) -> dict[str, dict[str, Any]]:
    """Per node, what its guests ask for: ``cores``, ``memory_mb`` and ``disk_gb`` per pool,
    over every guest not retired (a planned guest will be built, so it counts)."""
    usage: dict[str, dict[str, Any]] = {}
    for g in fleet.sorted():
        # a physical host's resources are its own, not drawn from a node
        if g.kind == "host" or g.raw.get("status") == "retired" or not g.raw.get("resources"):
            continue
        u = usage.setdefault(g.node, {"cores": 0, "memory_mb": 0, "disk_gb": {}, "guests": []})
        u["cores"] += int(g.cpu.get("cores", 0))
        u["memory_mb"] += int(g.memory.get("size_mb", 0))
        u["guests"].append(g.id)
        for d in g.disks:
            pool = str(d.get("pool"))
            u["disk_gb"][pool] = u["disk_gb"].get(pool, 0) + int(d.get("size_gb", 0))
    return usage


def _capacity(fleet: Fleet) -> list[Problem]:
    """A node that declares ``capacity`` holds its guests' cores (times ``cpu_overcommit``) and
    memory within what its reserve leaves; one that declares ``pools`` holds every disk on a pool
    it has, within the pool's size.  Memory is never overcommitted: a guest's ``size_mb`` is its
    ceiling, and ballooning only lends it back."""
    out: list[Problem] = []
    measured = any(s.get("capacity") or s.get("pools") for s in fleet.nodes.values())
    for node, u in sorted(node_usage(fleet).items()):
        spec = fleet.nodes.get(node) or {}
        where = f"_nodes.yml {node}"
        if measured and node not in fleet.nodes:  # a typo would escape every check below
            out.append(
                Problem(
                    where,
                    f"{len(u['guests'])} guest(s) are placed on {node!r}, which _nodes.yml does "
                    "not list, so their resources are checked against nothing",
                )
            )
            continue
        cap = spec.get("capacity")
        if cap:
            vcpus = cap["for_guests"]["vcpus"]
            if u["cores"] > vcpus:
                out.append(
                    Problem(
                        where,
                        f"guests ask for {u['cores']} cores, more than its {vcpus} "
                        f"({cap['for_guests']['threads']} threads after the reserve, times "
                        f"cpu_overcommit {cap['cpu_overcommit']:g})",
                    )
                )
            if u["memory_mb"] > cap["for_guests"]["memory_mb"]:
                out.append(
                    Problem(
                        where,
                        f"guests ask for {u['memory_mb']} MB of memory, more than the "
                        f"{cap['for_guests']['memory_mb']} MB its reserve leaves",
                    )
                )
        pools = spec.get("pools")
        if pools:
            for pool, gb in sorted(u["disk_gb"].items()):
                if pool not in pools:
                    out.append(
                        Problem(
                            where, f"guests put {gb} GB on pool {pool!r}, which it does not have"
                        )
                    )
                elif gb > pools[pool]["size_gb"]:
                    out.append(
                        Problem(
                            where,
                            f"guests put {gb} GB on pool {pool!r}, more than its "
                            f"{pools[pool]['size_gb']} GB",
                        )
                    )
    return out


def usage_lines(fleet: Fleet) -> list[str]:
    """One line per node that declares capacity or pools: what its guests use of it."""
    lines = []
    usage = node_usage(fleet)
    for node in sorted(fleet.nodes):
        spec = fleet.nodes[node]
        if not (spec.get("capacity") or spec.get("pools")):
            continue
        u = usage.get(node, {"cores": 0, "memory_mb": 0, "disk_gb": {}, "guests": []})
        parts = [f"{len(u['guests'])} guests"]
        cap = spec.get("capacity")
        if cap:
            vcpus = cap["for_guests"]["vcpus"]
            parts.append(f"cores {u['cores']}/{vcpus}")
            parts.append(
                f"memory {u['memory_mb'] // 1024}/{cap['for_guests']['memory_mb'] // 1024} GiB"
            )
        for pool, ps in sorted((spec.get("pools") or {}).items()):
            parts.append(f"{pool} {u['disk_gb'].get(pool, 0)}/{ps['size_gb']} GB")
        lines.append(f"{node}: " + ", ".join(parts))
    return lines


def _power(fleet: Fleet) -> list[Problem]:
    """Power declarations (homelabnext/power.py): a VM or container never has its own; with a
    site ``power`` section, every hypervisor and physical host is fed by a known UPS or says why
    not, and every UPS feeds something."""
    from homelabnext.power import fleet_problems

    msgs = fleet_problems(fleet.power, fleet.nodes, [g.raw for g in fleet.sorted()])
    return [Problem(m.split(": ", 1)[0], m.split(": ", 1)[1]) for m in msgs]
