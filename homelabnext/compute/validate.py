# SPDX-License-Identifier: Apache-2.0
"""Semantic validation of a fleet: everything JSON Schema cannot express."""

from __future__ import annotations

import contextlib
import datetime as dt
import ipaddress
import os
from typing import Any

from .model import (
    ComputeError,
    Fleet,
    Guest,
    Problem,
    ZoneInfo,
    allowed_groups,
    group_for_capability,
)

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
    elif g.raw.get("firewall_rules") and not _runs_host_ruleset(g, fleet):
        # a host has no hypervisor NIC firewall: its rules reach only its own nftables_host
        # ruleset (the inventory's hnx_firewall), so a host that runs none enforces nothing
        out.append(
            Problem(
                g.id,
                "firewall_rules on kind host need its baselines to resolve host-firewall or "
                "egress-filter (the host's own ruleset is the only thing that enforces them)",
            )
        )
    names = [r["name"] for r in g.firewall_rules + g.outbound_rules]
    if len(names) != len(set(names)):
        out.append(Problem(g.id, "firewall_rules names must be unique"))
    if g.outbound_rules and not _default_deny(g):
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
        z = fleet.zones.zone(src[5:]) if src.startswith("zone:") else None
        if src.startswith("zone:") and z is None:
            out.append(Problem(g.id, f"{where}: {side} zone {src[5:]!r} does not exist"))
        elif z is not None and z.subnet6 is not None:
            from homelabnext.network.validate import subnet6_problem

            _, why = subnet6_problem(z.subnet6)
            if why:  # the rule reaches the zone's IPv6 hosts by it, so it must read
                out.append(Problem(g.id, f"{where}: {side} zone {z.id!r} has a subnet6 that {why}"))
        elif "/" in src:
            try:
                ipaddress.ip_network(src, strict=True)
            except ValueError as exc:
                out.append(Problem(g.id, f"{where}: bad {side} CIDR: {exc}"))
    return out


#: the IPv4 ranges an extra address may be outside its zone's subnet in: zone-less overlays, where
#: a guest holds an address of its own (a tailnet's shared range, RFC 6598).  Never one that
#: falls inside a zone's subnet; nothing else outside the guest's own zone, since the site model
#: says who holds an address only by zone.
OVERLAY_V4: tuple[ipaddress.IPv4Network, ...] = (ipaddress.IPv4Network((0x6440_0000, 10)),)
#: the IPv6 ranges an extra address may come from when the guest's zone has no ``subnet6`` (site
#: 1.4): unique-local and documentation, and only outside every zone's prefix.  Nothing says which
#: guest owns one of these (operator review); a global IPv6 address (SLAAC included) needs the
#: zone's prefix to be held against, so without one it is refused.
UNOWNED_V6: tuple[ipaddress.IPv6Network, ...] = (
    ipaddress.IPv6Network((0xFC00 << 112, 7)),  # unique-local
    ipaddress.IPv6Network((0x2001_0DB8 << 96, 32)),  # documentation
    ipaddress.IPv6Network((0x3FFF << 112, 20)),  # documentation
)


#: RFC 2526's reserved subnet anycast interface identifiers: the top 128 of a /64, in EUI-64
#: form (the universal/local bit clear, so the identifier starts 0xfdff) and not
ANYCAST_EUI64 = 0xFDFF_FFFF_FFFF_FF80
ANYCAST_TOP = 0xFFFF_FFFF_FFFF_FF80


def _known_zones(fleet: Fleet) -> tuple[list[ZoneInfo], list[str]]:
    """Every zone of the site model (``ZoneLookup.all``), and the ids of zones a guest is in that
    the list leaves out (a lookup that answers ``zone(id)`` but cannot list them)."""
    found: dict[str, ZoneInfo] = {}
    listed = getattr(fleet.zones, "all", None)
    for z in listed() if callable(listed) else ():
        if isinstance(z, ZoneInfo):
            found.setdefault(z.id, z)
    missing = []
    for g in fleet.sorted():
        z = fleet.zones.zone(g.zone)
        if z is not None and z.id not in found:
            found[z.id] = z
            missing.append(z.id)
    # every zone, a bad subnet or subnet6 included: the IPv4 checks skip a subnet that does not
    # read (_net4; it is _check_network's problem), the IPv6 ones refuse to hold an address
    # against a zone list one of whose zones does not read
    return list(found.values()), sorted(set(missing))


def _net4(z: ZoneInfo) -> ipaddress.IPv4Network | None:
    """The zone's IPv4 subnet, or None when it does not read (``_check_network`` reports it)."""
    try:
        return z.network
    except ValueError:
        return None


def _taken_addresses(fleet: Fleet) -> dict[str, str]:
    """Addresses that belong to something other than a guest, address -> what holds it: the
    site's static DNS names and every guest's own ``network.gateway`` (a router).  A static name
    that is a guest's own fqdn is that guest's, and :func:`_extra_address_problem` lets it be."""
    out: dict[str, str] = {}
    for addr, names in fleet.site_addresses.items():
        out[addr] = "the site's DNS name " + ", ".join(names)
    for g in fleet.sorted():
        gw = g.network.get("gateway", "inherit")
        if isinstance(gw, str) and gw != "inherit":
            out.setdefault(gw, f"the gateway {g.id} names (network.gateway)")
    return out


def _extra_address_problem(
    raw: str, g: Guest, zones: list[ZoneInfo], taken: dict[str, str], fleet: Fleet
) -> tuple[str | None, str | None]:
    """``(canonical, None)`` for an extra address the runtime table can key, else ``(None, why)``.

    The table matches the observed address exactly and labels it as this guest, so an extra
    address must name this guest and no other wherever the collector sees it: never a loopback,
    link-local (unique only on its own link), multicast or metadata address, never one IPv6
    writes around an IPv4 one, never an address that moves (a DHCP lease) or that many guests
    leave by (a gateway), never another zone's or anything the site names, and in IPv4 always in
    the guest's own zone (or a zone-less overlay, :data:`OVERLAY_V4`)."""
    from homelabnext.modules.egress import METADATA
    from homelabnext.modules.scope import EMBEDDED_V4

    if not isinstance(raw, str):
        return None, "is not an IP address"
    if "%" in raw:  # Python parses a zone id into the address, and str() keeps it
        return None, "names an IPv6 zone id (%scope), which a collector never reports"
    try:
        ip = ipaddress.ip_address(raw)
    except ValueError:
        return None, "is not an IP address"
    if ip.version == 6 and (ip.ipv4_mapped is not None or any(ip in n for n in EMBEDDED_V4)):
        return None, "embeds an IPv4 address; write the IPv4 address"
    if str(ip) != raw:
        return None, f"is not in its canonical form; write {ip}"
    if ip in METADATA:
        return None, "is a cloud metadata address"
    if ip.is_loopback or ip.is_unspecified or ip.is_multicast or ip.is_reserved:
        return None, "is a loopback, unspecified, multicast or reserved address"
    if ip.is_link_local:
        return None, "is link-local, so it names no one guest beyond its own link"
    if ip.version == 4 and int(ip) >> 24 == 0:
        return None, "is in this-network (0.0.0.0/8)"
    nets4 = {z.id: n for z in zones if (n := _net4(z)) is not None}
    if ip.version == 4:
        other = next((zid for zid, n in nets4.items() if zid != g.zone and ip in n), None)
        if other is not None:
            return None, f"is inside zone {other}'s subnet, not zone {g.zone}'s"
        own = nets4.get(g.zone)
        if (own is None or ip not in own) and not any(ip in n for n in OVERLAY_V4):
            return None, f"is outside zone {g.zone}'s subnet (and in no zone-less overlay range)"
    else:
        why = _ipv6_ownership_problem(ip, g, zones)
        if why is not None:
            return None, why
    for z in zones:
        net = nets4.get(z.id)
        if ip.version != 4 or net is None or ip not in net:
            continue
        if ip in (net.network_address, net.broadcast_address):
            return None, f"is zone {z.id}'s network or broadcast address"
        if z.gateway and str(ip) == z.gateway:
            return None, f"is zone {z.id}'s gateway, which every guest it routes leaves by"
        if z.dhcp_range and _in_range(ip, z.dhcp_range):
            return None, f"is inside zone {z.id}'s DHCP pool, so another host may lease it"
    if g.network.get("gateway", "inherit") == str(ip):
        return None, "is this guest's own gateway (network.gateway), which it leaves by"
    holder = taken.get(str(ip))
    if holder is not None and fleet.fqdn(g) not in fleet.site_addresses.get(str(ip), ()):
        return None, f"is {holder}, not this guest's"
    return str(ip), None


def _ipv6_ownership_problem(
    ip: ipaddress.IPv6Address, g: Guest, zones: list[ZoneInfo]
) -> str | None:
    """Why the IPv6 extra address ``ip`` is not this guest's to name, or None.

    Every zone must read: its ``subnet`` and, when it gives one, its ``subnet6`` as ``hnx site
    validate`` requires it (otherwise no IPv6 address can be held against the zones, and it is
    refused, however the zone that does not read is used); the guest's own zone must be one of
    them; the address must not be an anycast address of its /64 (the subnet-router one, with no
    host part, or one RFC 2526 reserves at its top); it must not be inside another zone's prefix;
    with a prefix on the guest's own zone it must be inside it; without one, only unique-local or
    documentation IPv6 (:data:`UNOWNED_V6`) is accepted."""
    from homelabnext.network.validate import subnet6_problem

    prefixes: dict[str, ipaddress.IPv6Network] = {}
    for z in zones:
        if _net4(z) is None:
            return f"cannot be held against zone {z.id}: its subnet {z.subnet!r} does not read"
        if z.subnet6 is None:  # absent; any other value, falsy or not, must read as a prefix
            continue
        net6, bad = subnet6_problem(z.subnet6)
        if net6 is None:
            return f"cannot be held against zone {z.id}: its subnet6 {z.subnet6!r} {bad}"
        prefixes[z.id] = net6
    if g.zone not in {z.id for z in zones}:
        return f"cannot be held against zone {g.zone}: it is not in the site model"
    iid = int(ip) & (1 << 64) - 1  # the interface identifier: the low 64 bits
    if iid == 0:
        return "is the subnet-router anycast address of its /64 (no host part)"
    if iid >= ANYCAST_EUI64 and (iid <= ANYCAST_EUI64 | 0x7F or iid >= ANYCAST_TOP):
        return "is an anycast address RFC 2526 reserves at the top of its /64"
    other = next((zid for zid, n in prefixes.items() if zid != g.zone and ip in n), None)
    if other is not None:
        return f"is inside zone {other}'s IPv6 prefix, not zone {g.zone}'s"
    own = prefixes.get(g.zone)
    if own is not None:
        if ip not in own:
            return f"is outside zone {g.zone}'s IPv6 prefix {own} (subnet6)"
        return None
    if any(ip in n for n in UNOWNED_V6):
        return None
    if ip.is_global:
        return (
            f"is a global IPv6 address and zone {g.zone} gives no IPv6 prefix (subnet6, site "
            "1.4) to hold it against; add one, or use a unique-local or documentation address"
        )
    return "is a special-purpose IPv6 address, not a unique-local or documentation one"


def _check_extra_addresses(
    g: Guest, zones: list[ZoneInfo], taken: dict[str, str], fleet: Fleet
) -> tuple[list[Problem], list[str]]:
    """The guest's own problems with ``network.extra_addresses``, and the addresses that are
    sound and new (each once, never ``network.ip``), for the fleet-wide duplicate check."""
    out: list[Problem] = []
    keys: list[str] = []
    for raw in g.extra_addresses:
        key, why = _extra_address_problem(raw, g, zones, taken, fleet)
        if key is None:
            out.append(Problem(g.id, f"network.extra_addresses {raw} {why}"))
        elif key == g.ip:
            out.append(Problem(g.id, f"network.extra_addresses {raw} repeats network.ip"))
        elif key in keys:
            out.append(Problem(g.id, f"network.extra_addresses {raw} is named twice"))
        else:
            keys.append(key)
    return out, keys


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


def today(now: dt.date | None = None) -> dt.date:
    """The date reviews are judged against: ``now`` when given, else ``HNX_TODAY`` (YYYY-MM-DD)
    when set, so a test or a replay is deterministic, else the local date."""
    raw = os.environ.get("HNX_TODAY")
    if now is None and raw:
        try:
            now = dt.date.fromisoformat(raw)
        except ValueError:
            raise ComputeError(f"HNX_TODAY={raw!r} is not a YYYY-MM-DD date") from None
    return now or dt.date.today()


def _review_date(raw: Any) -> dt.date | None:
    try:
        return dt.date.fromisoformat(str(raw))
    except ValueError:
        return None


Net = ipaddress.IPv4Network | ipaddress.IPv6Network


def _dest_nets(r: Any, fleet: Fleet) -> list[Net]:
    """An outbound rule's destination as networks: ``any`` as the whole address space of both
    families; a CIDR as written; a ``zone:`` as the zone's subnet through the site model and its
    ``subnet6`` (site 1.4) where it has one.  Nothing that cannot be read: another rule reports
    that."""
    from homelabnext.network.validate import subnet6_problem

    dest = r["dest"]
    if dest == "any":
        return [ipaddress.ip_network("0.0.0.0/0"), ipaddress.ip_network("::/0")]
    if dest.startswith("zone:"):
        z = fleet.zones.zone(dest[5:])
        if z is None:
            return []
        nets: list[Net] = []
        with contextlib.suppress(ValueError):
            nets.append(z.network)
        net6, _ = subnet6_problem(z.subnet6) if z.subnet6 is not None else (None, None)
        return [*nets, net6] if net6 is not None else nets
    try:
        return [ipaddress.ip_network(dest, strict=True)]
    except ValueError:
        return []


def _metadata_allows(g: Guest, fleet: Fleet) -> list[Problem]:
    """An outbound allow that holds a cloud metadata address: the guest firewall refuses those
    addresses ahead of every allow, so the rule could only mislead a reader."""
    from homelabnext.modules.egress import METADATA

    out = []
    for r in g.outbound_rules:
        if r["dest"] == "any":
            continue
        nets = _dest_nets(r, fleet)
        held = [str(a) for net in nets for a in METADATA if a.version == net.version and a in net]
        if held:
            out.append(
                Problem(
                    g.id,
                    f"firewall_rules.{r['name']}: dest {r['dest']} holds the cloud metadata "
                    f"address {held[0]}, which the guest firewall always refuses; narrow it",
                )
            )
    return out


def _internet_allows(g: Guest, fleet: Fleet) -> list[str]:
    """Outbound allows that reach beyond the lab: ``any``, or a network (a CIDR, or a ``zone:``'s
    subnet from the site model) not inside the never-internet ranges
    (:data:`homelabnext.modules.egress.NOT_INTERNET`).  A ``zone:``'s IPv6 prefix is judged like
    its IPv4 subnet: a unique-local or documentation prefix is the lab's, a global-unicast one
    reaches the internet (nothing proves the site owns it; a typo or a copied prefix would
    otherwise open a model runtime's egress to third-party space)."""
    from homelabnext.modules.egress import NOT_INTERNET

    out = []
    for r in g.outbound_rules:
        nets = _dest_nets(r, fleet)
        # an unknown zone or a bad CIDR is _check_firewall's problem
        if any(
            not any(net.version == n.version and net.subnet_of(n) for n in NOT_INTERNET)
            for net in nets
        ):
            out.append(
                f"firewall_rules.{r['name']}: dest {r['dest']} reaches the internet; a model "
                "runtime's outbound_allow names a lab zone or CIDR (reach the internet through the "
                "gateway)"
            )
    return out


def _default_deny(g: Guest) -> bool:
    """Its outbound policy is one that denies by default (an allowlist, not a denylist: a value
    the schema does not know is never read as a deny)."""
    return g.policy_out in ("DROP", "REJECT")


def _runs_host_ruleset(g: Guest, fleet: Fleet) -> bool:
    """Its baselines resolve ``host-firewall`` or ``egress-filter``: the controls the guest's own
    ruleset (the nftables_host role, fed the inventory's hnx_firewall) implements."""
    bs = fleet.baselines
    if bs is None or not g.baseline:
        return False
    from .baselines import resolve

    return bool({"host-firewall", "egress-filter"} & set(resolve(g, bs).controls))


def _filters(t: Guest, fleet: Fleet) -> str | None:
    """Why guest ``t`` cannot be what filters another guest's traffic, or None when it can: its
    baselines resolve ``host-firewall`` or ``egress-filter`` (a guest's own NIC firewall filters
    only its own traffic, so it never counts), and its own outbound policy (where it states one) is DROP or REJECT; a guest
    that is itself exempted filters nothing, so no chain or cycle of pointers resolves."""
    if t.raw.get("status") == "retired":
        return "is retired"
    if t.firewall_exemption or (t.kind in ("vm", "lxc") and not t.nic_firewall):
        return "is itself exempted from its firewall"
    # a host states an outbound policy only when it carries firewall_rules (its own ruleset's);
    # one that carries none (a hypervisor) is judged by its baselines alone, as before
    if (t.kind in ("vm", "lxc") or "firewall_rules" in t.raw) and not _default_deny(t):
        return f"lets its own outbound traffic through (policy_out {t.policy_out})"
    if _runs_host_ruleset(t, fleet):
        return None
    return "runs no host firewall (its baselines resolve neither host-firewall nor egress-filter)"


def _filtered_by_problems(g: Guest, fleet: Fleet) -> list[Problem]:
    """``firewall_exemption.filtered_by`` and ``review_by`` on any guest kind: the pointer resolves
    to a guest that filters, or to a zone; the date is a real date."""
    ex = g.firewall_exemption or {}
    out: list[Problem] = []
    where = "network.firewall_exemption"
    if "review_by" in ex and _review_date(ex["review_by"]) is None:
        out.append(Problem(g.id, f"{where}.review_by: {ex['review_by']!r} is not a date"))
    by = ex.get("filtered_by")
    if not by:
        return out
    if by.startswith("guest:"):
        t = next((x for x in fleet.guests if x.id == by), None)
        if by == g.id or t is None:
            out.append(Problem(g.id, f"{where}.filtered_by: {by} is not another guest"))
        elif (why := _filters(t, fleet)) is not None:
            out.append(Problem(g.id, f"{where}.filtered_by: {by} {why}"))
    elif fleet.zones.zone(by[5:]) is None:
        out.append(Problem(g.id, f"{where}.filtered_by: zone {by[5:]!r} does not exist"))
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
        by, review = ex.get("filtered_by"), _review_date(ex.get("review_by"))
        if not by or not ex.get("review_by"):
            out.append(
                Problem(
                    g.id,
                    f"{why}: its NIC firewall is off, so network.firewall_exemption needs "
                    "filtered_by (the guest or zone that filters it) and review_by",
                )
            )
        if review is not None and review < today():
            out.append(
                Problem(
                    g.id,
                    f"{why}: network.firewall_exemption.review_by {review} has passed; review "
                    "where it is filtered and set a new date",
                )
            )
        if by and by.startswith("zone:"):
            # the only filtering the site model states for a zone is its router's egress.internet
            z = fleet.zones.zone(by[5:])
            if z is not None and z.internet != "deny":
                out.append(
                    Problem(
                        g.id,
                        f"{why}: filtered_by {by}, but the site model does not deny that zone's "
                        f"internet egress (egress.internet: {z.internet or 'not stated'})",
                    )
                )
    elif g.kind in ("vm", "lxc"):
        if not _default_deny(g):
            out.append(
                Problem(
                    g.id,
                    f"{why}: firewall_rules.policy_out must be DROP or REJECT, with outbound_allow "
                    "naming what it needs (resolver, time, model store, gateway)",
                )
            )
        out += [Problem(g.id, f"{why}: {p}") for p in _internet_allows(g, fleet)]
    if g.kind == "host":
        return out + _physical_runtime_problems(g, fleet, why)
    bs = fleet.baselines
    if bs is not None and "egress-filter" in bs.controls and g.baseline:
        from .baselines import resolve

        r = resolve(g, bs)
        if r.exemption is None and "egress-filter" not in r.controls:
            out.append(
                Problem(g.id, f"{why}: its baselines must include egress-filter (or not remove it)")
            )
    return out


def _physical_runtime_problems(g: Guest, fleet: Fleet, why: str) -> list[Problem]:
    """A physical model runtime (``kind: host``) has no hypervisor NIC firewall and nothing
    upstream the model states: its own ``nftables_host`` ruleset is its only outbound filter.  So
    its baselines resolve ``egress-filter`` (no baseline exemption, no filtered-elsewhere pointer
    stands in for it), its ``firewall_rules.policy_out`` is DROP or REJECT, and its outbound_allow
    names lab destinations only."""
    out: list[Problem] = []
    bs = fleet.baselines
    if bs is None or "egress-filter" not in bs.controls:
        out.append(
            Problem(
                g.id,
                f"{why} on a physical host: the baseline set must define egress-filter (the "
                "host's own nftables_host ruleset is its only outbound filter)",
            )
        )
    else:
        from .baselines import resolve

        r = resolve(g, bs) if g.baseline else None
        if r is None or r.exemption is not None or "egress-filter" not in r.controls:
            out.append(
                Problem(
                    g.id,
                    f"{why} on a physical host: its baselines must resolve egress-filter (no "
                    "exemption stands in for it; nothing else filters a host's outbound traffic)",
                )
            )
    if not _default_deny(g):
        out.append(
            Problem(
                g.id,
                f"{why}: firewall_rules.policy_out must be DROP or REJECT, with outbound_allow "
                "naming what it needs (resolver, time, model store, gateway)",
            )
        )
    out += [Problem(g.id, f"{why}: {p}") for p in _internet_allows(g, fleet)]
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
    zones, unlisted = _known_zones(fleet)
    taken = _taken_addresses(fleet)
    if unlisted and any(g.extra_addresses for g in fleet.guests):
        out.append(
            Problem(
                "site",
                f"the zone lookup does not list zone(s) {', '.join(unlisted)} (ZoneLookup.all), "
                "so network.extra_addresses cannot be held against every zone",
            )
        )
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
        seen_ip.setdefault(g.ip, g.id)  # the first holder, so a third claimant names it too
        out += _check_guest(g, fleet)
        extra, keys = _check_extra_addresses(g, zones, taken, fleet)
        out += extra
        for key in keys:  # one address names one guest, as network.ip or as an extra
            if key in seen_ip:
                out.append(
                    Problem(g.id, f"network.extra_addresses {key} already used by {seen_ip[key]}")
                )
            else:
                seen_ip[key] = g.id
        if require_baselines or g.baseline:
            out += guest_problems(g, fleet.baselines)
        out += _model_runtime_problems(g, fleet)
        out += _filtered_by_problems(g, fleet)
        out += _metadata_allows(g, fleet)
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
