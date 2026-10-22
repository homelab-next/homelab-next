# SPDX-License-Identifier: Apache-2.0
"""Validation of a site document: JSON Schema (shape) then semantic rules (meaning).

The rules are the CI gate for the model.  They only ever *report*; nothing here repairs a
document, because a silently repaired firewall policy is a different policy.

Errors block ``plan`` and ``render``.  Warnings (a placeholder TLS pin, a redundant exception)
are reported and never block.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any

from homelabnext.generators.safe import control_char_paths

from .loader import schema

#: Field paths where an IPv4 literal is legitimate (everything else must be a reference).
_IP_FIELDS = (
    re.compile(r"^zones\[\d+\]\.(subnet|gateway|dhcp\.range\[\d+\])$"),
    re.compile(r"^dns\.records\.static\[\d+\]\.value$"),
)
_IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w])")
_URL = re.compile(r"[a-z][a-z0-9+.-]*://", re.I)


@dataclass
class Report:
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors

    def error(self, msg: str) -> None:
        self.errors.append(msg)

    def warn(self, msg: str) -> None:
        self.warnings.append(msg)

    def render(self) -> str:
        lines = [f"error: {e}" for e in self.errors] + [f"warning: {w}" for w in self.warnings]
        return "\n".join(lines)


def schema_problems(doc: Any) -> list[str]:
    import jsonschema

    validator = jsonschema.Draft202012Validator(schema())
    out = []
    for err in sorted(validator.iter_errors(doc), key=lambda e: [str(p) for p in e.absolute_path]):
        where = "/".join(str(p) for p in err.absolute_path) or "<root>"
        out.append(f"schema: {where}: {err.message}")
    return out


def expand_ports(spec: list[int | str]) -> list[int]:
    """``[1, "3-5"]`` -> ``[1, 3, 4, 5]``; raises ValueError on a reversed range."""
    out: list[int] = []
    for item in spec:
        if isinstance(item, int):
            out.append(item)
            continue
        lo_s, hi_s = item.split("-")
        lo, hi = int(lo_s), int(hi_s)
        if lo > hi or hi > 512:
            raise ValueError(f"bad port range {item!r}")
        out.extend(range(lo, hi + 1))
    return out


def ref_id(ref: str) -> str:
    """``svc:idp`` / ``zone:core`` -> ``idp`` / ``core``."""
    return ref.split(":", 1)[1]


def _walk_literals(node: Any, path: str, report: Report) -> None:
    if isinstance(node, dict):
        for k, v in node.items():
            _walk_literals(v, f"{path}.{k}" if path else str(k), report)
    elif isinstance(node, list):
        for i, v in enumerate(node):
            _walk_literals(v, f"{path}[{i}]", report)
    elif isinstance(node, str):
        if _URL.search(node):
            report.error(f"{path}: URL literal {node!r}; use a svc: reference")
        elif _IPV4.search(node) and not any(rx.match(path) for rx in _IP_FIELDS):
            report.error(f"{path}: IP literal {node!r}; use a svc:/zone: reference")


def validate(doc: Any, registry: Any) -> Report:
    """Full validation of ``doc`` against the JSON Schema and ``registry`` (a built Registry)."""
    report = Report()
    # adapters write line-oriented configs; Python's re lets a pattern's "$" match before a
    # trailing newline, so refuse control characters in any key or value before the schema
    for m in control_char_paths(doc):
        report.error(f"unsafe: {m}")
    for p in schema_problems(doc):
        report.error(p)
    if report.errors:
        return report  # semantic rules assume the shape is right
    _semantic(doc, registry, report)
    return report


def _semantic(doc: dict, reg: Any, r: Report) -> None:
    from .adapters import known_names

    adapter_names = known_names()
    _walk_literals(doc, "", r)

    zones = doc["zones"]
    zone_ids: dict[str, dict] = {}
    vlans: dict[int, str] = {}
    nets: dict[str, ipaddress.IPv4Network] = {}
    for z in zones:
        zid = z["id"]
        if zid in zone_ids:
            r.error(f"zone {zid}: duplicate zone id")
            continue
        zone_ids[zid] = z
        if z["vlan_id"] in vlans:
            r.error(
                f"zone {zid}: vlan_id {z['vlan_id']} already used by zone {vlans[z['vlan_id']]}"
            )
        vlans.setdefault(z["vlan_id"], zid)
        try:
            net = ipaddress.ip_network(z["subnet"], strict=True)
        except ValueError as exc:
            r.error(f"zone {zid}: bad subnet {z['subnet']!r}: {exc}")
            continue
        if net.prefixlen > 30:
            r.error(f"zone {zid}: subnet {net} is too small to hold a gateway and a host")
        nets[zid] = net
    ids = list(nets)
    for i, a in enumerate(ids):
        for b in ids[i + 1 :]:
            if nets[a].overlaps(nets[b]):
                r.error(f"zones {a} and {b}: subnets {nets[a]} and {nets[b]} overlap")

    for zid, net in nets.items():
        z = zone_ids[zid]
        try:
            gw = ipaddress.ip_address(z["gateway"])
        except ValueError:
            r.error(f"zone {zid}: bad gateway {z['gateway']!r}")
            continue
        if gw not in net:
            r.error(f"zone {zid}: gateway {gw} is outside subnet {net}")
        elif gw in (net.network_address, net.broadcast_address):
            r.error(f"zone {zid}: gateway {gw} is the network or broadcast address of {net}")
        dhcp = z.get("dhcp")
        if dhcp:
            lo, hi = (ipaddress.ip_address(x) for x in dhcp["range"])
            if lo > hi:
                r.error(f"zone {zid}: dhcp range start {lo} is after end {hi}")
            for end in (lo, hi):
                if end not in net:
                    r.error(f"zone {zid}: dhcp address {end} is outside subnet {net}")
                elif end in (net.network_address, net.broadcast_address):
                    r.error(f"zone {zid}: dhcp address {end} is the network or broadcast address")
            if lo <= gw <= hi:
                r.error(f"zone {zid}: dhcp range {lo}-{hi} contains the gateway {gw}")
        for ref in z.get("dns", {}).get("resolvers", []):
            _need_service(reg, ref, f"zone {zid}: dns resolver", r)

    # ---- registry cross-checks -------------------------------------------------------------
    router_id = doc["router"]["id"]
    for zname, rz in reg.zones.items():
        site_net = nets.get(zname)
        if zname not in zone_ids:
            r.error(f"registry zone {zname!r} is not a zone of this site")
        elif site_net is not None and ipaddress.ip_network(rz.cidr) != site_net:
            r.error(f"zone {zname}: site subnet {site_net} differs from registry cidr {rz.cidr}")
    for hname, h in reg.hosts.items():
        z = zone_ids.get(h.zone)
        if z is None or h.zone not in nets:
            continue
        addr = ipaddress.ip_address(h.address)
        if addr == ipaddress.ip_address(z["gateway"]) and hname != router_id:
            r.error(f"host {hname}: address {addr} is the gateway of zone {h.zone}")
        dhcp = z.get("dhcp")
        if dhcp:
            lo, hi = (ipaddress.ip_address(x) for x in dhcp["range"])
            if lo <= addr <= hi:
                r.error(
                    f"host {hname}: static address {addr} lies inside the dhcp range of zone {h.zone}"
                )

    # ---- router, switches -----------------------------------------------------------------
    router = doc["router"]
    if router["model"] not in adapter_names:
        r.error(
            f"router.model: unknown adapter {router['model']!r}; known: {', '.join(sorted(adapter_names))}"
        )
    _need_service(reg, router["mgmt_endpoint"], "router.mgmt_endpoint", r)
    pin = router.get("tls_pin", {}).get("sha256", "")
    if pin.startswith("REPLACE_WITH_"):
        r.warn(
            "router.tls_pin.sha256 is a placeholder; pin the console certificate before applying"
        )
    if "tls_pin" not in router:
        r.warn("router.tls_pin is absent; the console certificate will not be pinned")

    switch_ids: set[str] = set()
    macs: dict[str, str] = {}
    for sw in doc.get("switches", []):
        sid = sw["id"]
        if sid in switch_ids:
            r.error(f"switch {sid}: duplicate switch id")
        switch_ids.add(sid)
        if sw["model"] not in adapter_names:
            r.error(f"switch {sid}: unknown adapter {sw['model']!r}")
        mac = sw.get("device_mac")
        if mac:
            if mac in macs:
                r.error(f"switch {sid}: device_mac {mac} already used by switch {macs[mac]}")
            macs[mac] = sid
        seen_ports: dict[int, int] = {}
        trunk_ports: set[int] = set()
        for n, pa in enumerate(sw["port_assignments"]):
            where = f"switch {sid} port_assignments[{n}]"
            try:
                ports = expand_ports(pa["ports"])
            except ValueError as exc:
                r.error(f"{where}: {exc}")
                continue
            for p in ports:
                if p in seen_ports:
                    r.error(
                        f"{where}: port {p} already assigned by port_assignments[{seen_ports[p]}]"
                    )
                seen_ports[p] = n
                if pa["kind"] == "trunk":
                    trunk_ports.add(p)
            used = ([pa["vlan"]] if "vlan" in pa else []) + list(pa.get("vlans", []))
            for v in used:
                if v not in vlans:
                    r.error(f"{where}: vlan {v} is not a zone of this site")
        up = sw.get("uplink_port")
        if up is not None and up not in trunk_ports:
            r.error(f"switch {sid}: uplink_port {up} is not assigned as a trunk")

    # ---- dhcp reservations ----------------------------------------------------------------
    res_macs: dict[str, str] = {}
    res_hosts: set[str] = set()
    for res in doc.get("dhcp_reservations", []):
        h = res["host"]
        if h not in reg.hosts:
            r.error(f"dhcp_reservations: host {h!r} is not in the registry")
            continue
        if h in res_hosts:
            r.error(f"dhcp_reservations: host {h!r} listed twice")
        res_hosts.add(h)
        if res["mac"] in res_macs:
            r.error(f"dhcp_reservations: mac {res['mac']} used by {res_macs[res['mac']]} and {h}")
        res_macs[res["mac"]] = h
        z = zone_ids.get(reg.hosts[h].zone, {})
        if not z.get("dhcp"):
            r.warn(
                f"dhcp_reservations: host {h} is in zone {reg.hosts[h].zone}, which has no dhcp range"
            )

    _firewall(doc, reg, zone_ids, r)
    _dns(doc, reg, r)
    # 1.1: UPS ids, power declarations of the router, switches and edge (homelabnext/power.py);
    # the hypervisors and physical hosts are checked with the guests (hnx guests validate)
    from homelabnext.power import site_problems

    for msg in site_problems(doc):
        r.error(msg)
    # 1.2: the deploy's tailnet access (homelabnext/tailnet.py): zones by id, SSH unless a listed
    # exception gives its reason; the tailscale-acl target renders it
    from homelabnext.tailnet import deploy_problems

    for msg in deploy_problems(doc):
        r.error(msg)

    adapters = doc.get("adapters", {})
    for key in ("network", "dns"):
        if key in adapters and adapters[key] not in adapter_names:
            r.error(f"adapters.{key}: unknown adapter {adapters[key]!r}")


def _need_service(reg: Any, ref: str, where: str, r: Report) -> bool:
    name = ref_id(ref)
    if name not in reg.services:
        r.error(f"{where}: {ref} is not in the service registry")
        return False
    return True


def _firewall(doc: dict, reg: Any, zone_ids: dict[str, dict], r: Report) -> None:
    fw = doc["firewall"]
    z2z = fw.get("zone_to_zone", [])
    one_way = {zid for zid, z in zone_ids.items() if z["egress"].get("one_way")}
    contract_of: dict[str, int] = {}
    pairs: dict[tuple[str, str], int] = {}
    for i, rule in enumerate(z2z):
        where = f"firewall.zone_to_zone[{i}]"
        src, dst = rule["from"], rule["to"]
        if src not in zone_ids:
            r.error(f"{where}: from zone {src!r} does not exist")
        if dst != "any" and dst not in zone_ids:
            r.error(f"{where}: to zone {dst!r} does not exist")
        if src == dst:
            r.error(f"{where}: from and to are both {src!r}")
        if (src, dst) in pairs:
            r.error(
                f"{where}: duplicate of firewall.zone_to_zone[{pairs[(src, dst)]}] ({src}->{dst})"
            )
        pairs[(src, dst)] = i
        if rule["action"] == "deny" and ("ports" in rule or "protocols" in rule):
            r.error(f"{where}: a deny applies to the whole zone pair; remove ports/protocols")
        if "ports" in rule and set(rule.get("protocols", ["tcp"])) <= {"icmp"}:
            r.error(f"{where}: ports need tcp or udp in protocols")
        if rule["action"] == "allow" and src in one_way:
            r.error(f"{where}: one-way zone {src!r} may only send through service_exceptions")
        if rule["action"] == "allow" and dst in one_way:
            r.error(f"{where}: allow into one-way zone {dst!r} breaks its contract")
        if rule.get("one_way_contract"):
            if src not in one_way:
                r.error(f"{where}: one_way_contract on zone {src!r}, which is not egress.one_way")
            if rule["action"] != "deny" or dst != "any":
                r.error(f"{where}: one_way_contract must be a deny to 'any'")
            contract_of[src] = contract_of.get(src, 0) + 1
        if (
            dst == "any"
            and rule["action"] == "deny"
            and src in zone_ids
            and zone_ids[src]["egress"]["internet"] == "allow"
        ):
            r.error(f"{where}: deny to 'any' contradicts egress.internet=allow of zone {src!r}")
    for zid in sorted(one_way):
        z = zone_ids[zid]
        if z["egress"]["internet"] != "deny":
            r.error(f"zone {zid}: one_way requires egress.internet=deny")
        n = contract_of.get(zid, 0)
        if n == 0:
            r.error(
                f"zone {zid}: one_way has no firewall.zone_to_zone rule with one_way_contract: true"
            )
        elif n > 1:
            r.error(f"zone {zid}: more than one one_way_contract rule")

    seen: dict[tuple[str, str], int] = {}
    for i, exc in enumerate(fw.get("service_exceptions", [])):
        where = f"firewall.service_exceptions[{i}]"
        froms = exc["from"] if isinstance(exc["from"], list) else [exc["from"]]
        svc = ref_id(exc["to"])
        if not _need_service(reg, exc["to"], f"{where}: to", r):
            continue
        host = reg.hosts[reg.services[svc].host]
        for fref in froms:
            fz = ref_id(fref)
            if fz not in zone_ids:
                r.error(f"{where}: {fref} is not a zone of this site")
                continue
            if (fz, svc) in seen:
                r.error(
                    f"{where}: duplicate of service_exceptions[{seen[(fz, svc)]}] ({fref}->{exc['to']})"
                )
            seen[(fz, svc)] = i
            if fz == host.zone:
                r.warn(
                    f"{where}: {fref} is the zone of {exc['to']} itself; intra-zone traffic is not routed"
                )
            if host.zone in one_way and exc["action"] == "allow":
                r.error(
                    f"{where}: {exc['to']} lives in one-way zone {host.zone!r}; nothing may be allowed into it"
                )
            prior = pairs.get((fz, host.zone))
            if (
                prior is not None
                and z2z[prior]["action"] == "allow"
                and exc["action"] == "allow"
                and "ports" not in z2z[prior]
            ):
                r.warn(
                    f"{where}: redundant, firewall.zone_to_zone[{prior}] already allows {fz}->{host.zone}"
                )


def _dns(doc: dict, reg: Any, r: Report) -> None:
    domain = doc["site"]["domain"]
    dns = doc.get("dns", {})
    rids: set[str] = set()
    for res in dns.get("resolvers", []):
        if res["id"] in rids:
            r.error(f"dns.resolvers: duplicate id {res['id']!r}")
        rids.add(res["id"])
        _need_service(reg, res["host"], f"dns.resolvers[{res['id']}].host", r)
        for zone in res.get("authoritative_for", []):
            if not (zone == domain or zone.endswith("." + domain)):
                r.error(
                    f"dns.resolvers[{res['id']}]: authoritative_for {zone!r} is outside site domain {domain!r}"
                )
    generated = {f"{h}.{domain}" for h in reg.hosts}
    seen: set[tuple[str, str]] = set()
    for i, rec in enumerate(dns.get("records", {}).get("static", [])):
        where = f"dns.records.static[{i}]"
        fq = rec["fqdn"]
        if not (fq == domain or fq.endswith("." + domain)):
            r.error(f"{where}: {fq!r} is outside site domain {domain!r}")
        if (fq, rec["type"]) in seen:
            r.error(f"{where}: duplicate {rec['type']} record for {fq}")
        seen.add((fq, rec["type"]))
        if fq in generated:
            r.error(
                f"{where}: {fq} is generated from the registry host of that name; one source per fact"
            )
        if rec["type"] == "A":
            try:
                ipaddress.IPv4Address(rec["value"])
            except ValueError:
                r.error(f"{where}: A value {rec['value']!r} is not an IPv4 address")
        elif not re.fullmatch(
            r"[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+\.?", rec["value"]
        ):
            r.error(f"{where}: CNAME target {rec['value']!r} is not a hostname")
