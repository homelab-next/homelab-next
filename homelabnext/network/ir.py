# SPDX-License-Identifier: Apache-2.0
"""Vendor-neutral intermediate representation (IR) of a site.

Adapters render this and nothing else, so two adapters can never disagree about what the policy
*means*.  The IR is plain frozen dataclasses; :meth:`NetworkIR.to_dict` is its canonical,
JSON-serialisable form and is what the ``plan`` of a no-op change is compared against.

Firewall evaluation order (first match wins) is part of the contract:

1. ``service_exceptions``, in document order (host-specific, so they beat anything general);
2. ``zone_to_zone`` rules whose ``to`` is a zone, in document order;
3. ``zone_to_zone`` rules whose ``to`` is ``any`` (the one-way contracts);
4. internet egress, one rule per zone, from ``egress.internet``;
5. ``default_action`` (always deny).

Return traffic is allowed by connection state, not by rules: the IR carries no "reply" rules.

IPv6 (site 1.4 ``subnet6``): a zone with a prefix gets its router address at the prefix's
``::1`` (:func:`router_address6`), and :attr:`Policy.zones6` names the prefix.  The policy above
holds for both families: an adapter renders every rule once per family the rule can be written in,
the IPv6 form right after the IPv4 one, so first-match order is the same in each.  A zone side
needs the zone's prefix.  A ``host`` side has an IPv4 address only: an allow naming a host has no
IPv6 form (the default deny keeps IPv6 to the host closed), and a deny naming a host denies, in
IPv6, the same traffic to the host's whole zone, so a later, wider allow can never let through in
IPv6 what the deny refuses in IPv4.  An internet rule has an IPv6 form only for a routed (global)
prefix: nothing translates IPv6, and a unique-local or documentation source has no business there.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
from dataclasses import asdict, dataclass, field, replace
from typing import Any

from .validate import expand_ports, ref_id

DEFAULT_LEASE_HOURS = 12
DEFAULT_TTL = 60


@dataclass(frozen=True)
class Interface:
    zone: str
    vlan_id: int
    name: str
    address: str
    prefixlen: int
    subnet: str
    netmask: str
    purpose: str = ""
    address6: str = ""  # the router's address in the zone's subnet6, "" when the zone has none
    subnet6: str = ""


@dataclass(frozen=True)
class DhcpPool:
    zone: str
    start: str
    end: str
    netmask: str
    gateway: str
    lease_hours: int
    dns_servers: tuple[str, ...]
    domain: str


@dataclass(frozen=True)
class Reservation:
    host: str
    zone: str
    address: str
    mac: str | None


@dataclass(frozen=True)
class DnsRecord:
    fqdn: str
    type: str
    value: str
    origin: str  # registry.host | registry.service | static | split-horizon


@dataclass(frozen=True)
class Selector:
    """One side of a rule: a zone, a single host, anything, or "not in any zone"."""

    kind: str  # zone | host | any | internet
    name: str = ""
    cidrs: tuple[str, ...] = ()
    zone: str = ""  # a host side: the zone the host is in


@dataclass(frozen=True)
class Rule:
    id: str
    action: str  # allow | deny
    src: Selector
    dst: Selector
    protocol: str  # any | tcp | udp | icmp
    ports: tuple[int, ...] = ()
    service: str | None = None
    comment: str = ""


@dataclass(frozen=True)
class Policy:
    default_action: str
    zones: dict[str, str]  # zone id -> subnet
    rules: tuple[Rule, ...]
    zones6: dict[str, str] = field(default_factory=dict)  # zone id -> subnet6, zones with one


@dataclass(frozen=True)
class PortPlan:
    port: int
    kind: str  # access | trunk | mirror
    native_vlan: int | None
    tagged_vlans: tuple[int, ...]
    mirror_from: tuple[int, ...] = ()  # mirror: the source ports copied to this one


@dataclass(frozen=True)
class SwitchPlan:
    id: str
    model: str
    mac: str | None
    uplink_port: int | None
    ports: tuple[PortPlan, ...]


@dataclass(frozen=True)
class RouterPlan:
    id: str
    model: str
    mgmt_alias: str  # the alias FQDN of the console service, never an address
    tls_pin: str | None
    auth: dict[str, dict[str, str]]


@dataclass(frozen=True)
class Resolver:
    id: str
    model: str
    host: str
    address: str
    authoritative_for: tuple[str, ...]


@dataclass(frozen=True)
class NetworkIR:
    site_id: str
    domain: str
    timezone: str
    ttl: int
    split_horizon: bool
    interfaces: tuple[Interface, ...]
    pools: tuple[DhcpPool, ...]
    reservations: tuple[Reservation, ...]
    dns_records: tuple[DnsRecord, ...]
    resolvers: tuple[Resolver, ...]
    policy: Policy
    switches: tuple[SwitchPlan, ...]
    router: RouterPlan
    options: dict[str, Any] = field(default_factory=dict)
    digest: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


def service_l4(protocol: str) -> tuple[str, ...]:
    """Layer-4 protocols a registry service protocol travels over."""
    if protocol == "dns":
        return ("udp", "tcp")
    if protocol == "udp":
        return ("udp",)
    return ("tcp",)


def router_address6(subnet6: str) -> str:
    """The router's address in a zone's IPv6 prefix: the prefix's ``::1``, never the
    subnet-router anycast address (``::``) or one of the RFC 2526 anycast addresses at the top of
    the /64 a validated prefix leaves the last 64 bits of."""
    return str(ipaddress.IPv6Network(subnet6)[1])


def ipv6_form(rule: Rule, zones6: dict[str, str]) -> Rule | None:
    """The rule as it reads in IPv6, or ``None`` when it has no IPv6 form (see the module doc).

    The one rule every adapter renders from, so no two adapters can disagree about IPv6."""

    def side(sel: Selector) -> Selector | None:
        if sel.kind == "zone":
            return Selector("zone", sel.name, (zones6[sel.name],)) if sel.name in zones6 else None
        if sel.kind == "host":
            if rule.action != "deny" or sel.zone not in zones6:
                return None
            return Selector("zone", sel.zone, (zones6[sel.zone],))
        return sel  # any | internet

    src, dst = side(rule.src), side(rule.dst)
    if src is None or dst is None or "zone" not in (src.kind, dst.kind):
        return None
    if dst.kind == "internet" and not ipaddress.IPv6Network(zones6[src.name]).is_global:
        return None
    return replace(rule, id=f"{rule.id}:v6", src=src, dst=dst)


def _zone_selector(zid: str, nets: dict[str, str]) -> Selector:
    return Selector("zone", zid, (nets[zid],))


def build_ir(doc: dict, reg: Any) -> NetworkIR:
    """Build the IR from a *validated* document and its registry.

    Raises ``KeyError``/``ValueError`` if called with an unvalidated document; call
    :func:`homelabnext.network.validate.validate` first.
    """
    domain = doc["site"]["domain"]
    zones = doc["zones"]
    nets = {z["id"]: str(ipaddress.ip_network(z["subnet"])) for z in zones}
    nets6 = {z["id"]: str(ipaddress.IPv6Network(z["subnet6"])) for z in zones if "subnet6" in z}
    host_addr = {name: h.address for name, h in reg.hosts.items()}

    def svc_address(ref: str) -> str:
        return host_addr[reg.services[ref_id(ref)].host]

    interfaces = []
    pools = []
    for z in sorted(zones, key=lambda z: z["vlan_id"]):
        net = ipaddress.ip_network(z["subnet"])
        interfaces.append(
            Interface(
                z["id"],
                z["vlan_id"],
                f"vlan{z['vlan_id']}",
                z["gateway"],
                net.prefixlen,
                str(net),
                str(net.netmask),
                z.get("purpose", ""),
                router_address6(nets6[z["id"]]) if z["id"] in nets6 else "",
                nets6.get(z["id"], ""),
            )
        )
        dhcp = z.get("dhcp")
        if dhcp:
            dns_servers = tuple(
                dict.fromkeys(svc_address(r) for r in z.get("dns", {}).get("resolvers", []))
            )
            pools.append(
                DhcpPool(
                    z["id"],
                    dhcp["range"][0],
                    dhcp["range"][1],
                    str(net.netmask),
                    z["gateway"],
                    dhcp.get("lease_hours", DEFAULT_LEASE_HOURS),
                    dns_servers,
                    domain,
                )
            )
    pool_zones = {p.zone for p in pools}
    gateways = {z["id"]: z["gateway"] for z in zones}
    macs = {r["host"]: r["mac"] for r in doc.get("dhcp_reservations", [])}
    reservations = tuple(
        Reservation(name, h.zone, h.address, macs.get(name))
        for name, h in sorted(reg.hosts.items())
        if h.zone in pool_zones and h.address != gateways[h.zone]
    )

    ttl = doc.get("dns", {}).get("policy", {}).get("ttl_default", DEFAULT_TTL)
    split = doc.get("dns", {}).get("policy", {}).get("split_horizon", False)
    records: list[DnsRecord] = []
    for name, h in reg.hosts.items():
        records.append(DnsRecord(f"{name}.{domain}", "A", h.address, "registry.host"))
    for svc in reg.services.values():
        records.append(
            DnsRecord(
                reg.alias(svc.capability), "CNAME", f"{svc.host}.{domain}", "registry.service"
            )
        )
        if split and svc.public_hostname:
            records.append(
                DnsRecord(svc.public_hostname, "A", host_addr[svc.host], "split-horizon")
            )
    for rec in doc.get("dns", {}).get("records", {}).get("static", []):
        records.append(DnsRecord(rec["fqdn"], rec["type"], rec["value"], "static"))
    records.sort(key=lambda r: (r.fqdn, r.type, r.value))

    resolvers = tuple(
        Resolver(
            r["id"],
            r.get("model", ""),
            reg.services[ref_id(r["host"])].host,
            svc_address(r["host"]),
            tuple(r.get("authoritative_for", [])),
        )
        for r in doc.get("dns", {}).get("resolvers", [])
    )

    rules = _rules(doc, reg, nets, host_addr)
    switches = tuple(_switch(sw) for sw in doc.get("switches", []))

    router = doc["router"]
    pin = router.get("tls_pin", {}).get("sha256")
    options = {
        "linux": {
            "flavor": "networkd",
            "trunk_interface": "trunk0",
            "wan_interface": "wan0",
            **doc.get("adapters", {}).get("options", {}).get("linux", {}),
        },
        "zonefile": dict(doc.get("adapters", {}).get("options", {}).get("zonefile", {})),
    }
    ir = NetworkIR(
        site_id=doc["site"]["id"],
        domain=domain,
        timezone=doc["site"].get("timezone", "UTC"),
        ttl=ttl,
        split_horizon=split,
        interfaces=tuple(interfaces),
        pools=tuple(pools),
        reservations=reservations,
        dns_records=tuple(records),
        resolvers=resolvers,
        policy=Policy("deny", nets, tuple(rules), nets6),
        switches=switches,
        router=RouterPlan(
            router["id"],
            router["model"],
            reg.alias(reg.services[ref_id(router["mgmt_endpoint"])].capability),
            pin,
            {k: dict(v) for k, v in router.get("auth", {}).items()},
        ),
        options=options,
    )
    blob = json.dumps(ir.to_dict(), sort_keys=True, separators=(",", ":"))
    return replace(ir, digest=hashlib.sha256(blob.encode("utf-8")).hexdigest())


def _rules(doc: dict, reg: Any, nets: dict[str, str], host_addr: dict[str, str]) -> list[Rule]:
    fw = doc["firewall"]
    out: list[Rule] = []

    for i, exc in enumerate(fw.get("service_exceptions", [])):
        froms = exc["from"] if isinstance(exc["from"], list) else [exc["from"]]
        svc = reg.services[ref_id(exc["to"])]
        dst = Selector("host", svc.host, (f"{host_addr[svc.host]}/32",), reg.hosts[svc.host].zone)
        ports = tuple(sorted(exc.get("ports", [svc.port])))
        for fref in froms:
            fz = ref_id(fref)
            l4 = service_l4(svc.protocol)
            for proto in l4:
                suffix = f":{proto}" if len(l4) > 1 else ""
                out.append(
                    Rule(
                        f"service_exceptions[{i}]:{fz}{suffix}",
                        exc["action"],
                        _zone_selector(fz, nets),
                        dst,
                        proto,
                        ports,
                        service=ref_id(exc["to"]),
                        comment=f"{fz} -> svc:{ref_id(exc['to'])}",
                    )
                )

    def z2z(i: int, rule: dict) -> list[Rule]:
        src = _zone_selector(rule["from"], nets)
        dst = Selector("any") if rule["to"] == "any" else _zone_selector(rule["to"], nets)
        base = f"zone_to_zone[{i}]"
        text = f"{rule['from']} -> {rule['to']}"
        if "ports" in rule:
            ports = tuple(sorted(rule["ports"]))
            protos = [p for p in rule.get("protocols", ["tcp"]) if p != "icmp"]
            rows = [(p, ports) for p in protos]
        elif "protocols" in rule:
            rows = [(p, ()) for p in rule["protocols"]]
        else:
            rows = [("any", ())]
        return [
            Rule(
                f"{base}:{p}" if len(rows) > 1 else base,
                rule["action"],
                src,
                dst,
                p,
                pt,
                None,
                text,
            )
            for p, pt in rows
        ]

    rules = list(enumerate(fw.get("zone_to_zone", [])))
    for i, rule in rules:
        if rule["to"] != "any":
            out.extend(z2z(i, rule))
    for i, rule in rules:
        if rule["to"] == "any":
            out.extend(z2z(i, rule))

    for z in doc["zones"]:
        out.append(
            Rule(
                f"egress.internet:{z['id']}",
                z["egress"]["internet"],
                _zone_selector(z["id"], nets),
                Selector("internet"),
                "any",
                (),
                None,
                f"{z['id']} -> internet",
            )
        )
    return out


def _switch(sw: dict):
    ports: dict[int, PortPlan] = {}
    for pa in sw["port_assignments"]:
        for p in expand_ports(pa["ports"]):
            ports[p] = PortPlan(
                p,
                pa["kind"],
                pa.get("vlan"),
                tuple(sorted(pa.get("vlans", []))),
                tuple(sorted(expand_ports(pa.get("mirror_from", [])))),
            )
    return SwitchPlan(
        sw["id"],
        sw["model"],
        sw.get("device_mac"),
        sw.get("uplink_port"),
        tuple(ports[p] for p in sorted(ports)),
    )
