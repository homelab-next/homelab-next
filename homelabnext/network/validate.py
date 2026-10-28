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

from homelabnext._schema_text import safe_message
from homelabnext.generators.safe import control_char_paths

from .loader import schema

#: Field paths where an IPv4 literal is legitimate (everything else must be a reference).
_IP_FIELDS = (
    re.compile(r"^zones\[\d+\]\.(subnet|subnet6|gateway|dhcp\.range\[\d+\])$"),
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


#: the IPv6 space a zone's prefix may come from: unique-local, global unicast and documentation
ZONE_V6: tuple[ipaddress.IPv6Network, ...] = (
    ipaddress.IPv6Network((0xFC00 << 112, 7)),  # unique-local
    ipaddress.IPv6Network((0x2000 << 112, 3)),  # global unicast (holds 2001:db8::/32, 3fff::/20)
)
#: ...less what no zone is numbered from and no ISP delegates: the IETF protocol assignments
#: (benchmarking, ORCHID, AMT, Teredo and the rest), the retired 6bone block and the reserved /16
#: at the start of global unicast
SPECIAL_V6: tuple[ipaddress.IPv6Network, ...] = (
    ipaddress.IPv6Network((0x2001 << 112, 23)),  # IETF protocol assignments
    ipaddress.IPv6Network((0x3FFE << 112, 16)),  # the 6bone, returned to IANA (RFC 3701)
    ipaddress.IPv6Network((0x2000 << 112, 16)),  # reserved by IANA, never allocated
)
#: how SPECIAL_V6 reads in a problem
SPECIAL_V6_TEXT = (
    "the IETF protocol assignments 2001::/23, the retired 6bone 3ffe::/16 or 2000::/16"
)


def _prefix6_problem(raw: Any, lo: int, hi: int) -> tuple[ipaddress.IPv6Network | None, str | None]:
    """The rules a zone's prefix and a delegated prefix share: one canonical IPv6 prefix (no host
    bits, lower case, compressed) of a /``lo`` to a /``hi``, with no zone id (``%scope``), that is
    not link-local, multicast, loopback or unspecified and writes no IPv4 address inside IPv6
    (mapped, compatible, translated, NAT64, 6to4, Teredo), where the address a collector sees is
    the IPv4 one."""
    from homelabnext.modules.scope import EMBEDDED_V4

    if not isinstance(raw, str):
        return None, "is not an IPv6 prefix written as text"
    if "%" in raw:  # Python parses a zone id into the prefix; no prefix of the site carries one
        return None, "names an IPv6 zone id (%scope), which a prefix never carries"
    try:
        net = ipaddress.ip_network(raw, strict=True)
    except ValueError as exc:
        return None, f"is not an IPv6 prefix without host bits: {exc}"
    if net.version != 6:
        return None, "is not an IPv6 prefix"
    if str(net) != raw:
        return None, f"is not in its canonical form; write {net}"
    if not lo <= net.prefixlen <= hi:
        return None, f"is a /{net.prefixlen}; it must be a /{lo} to a /{hi}"
    addr = net.network_address
    if addr.is_link_local or addr.is_multicast or addr.is_loopback or addr.is_unspecified:
        return None, "is link-local, multicast, loopback or unspecified"
    embedding = (
        *EMBEDDED_V4,
        ipaddress.IPv6Network((0x2002 << 112, 16)),  # 6to4
        ipaddress.IPv6Network((0x2001_0000 << 96, 32)),  # Teredo
    )
    if any(net.overlaps(e) for e in embedding):
        return None, "embeds IPv4 addresses (mapped, compatible, translated, NAT64, 6to4, Teredo)"
    return net, None  # type: ignore[return-value]


def subnet6_problem(raw: Any) -> tuple[ipaddress.IPv6Network | None, str | None]:
    """``(prefix, None)`` for a zone's ``subnet6`` (site 1.4), else ``(None, why)``.

    A guest's IPv6 extra address is held against it (``homelabnext.compute.validate``), so it must
    be one prefix that names this zone only: a /48 to a /64 that passes the shared prefix rules
    (canonical, no zone id, nothing special-purpose or IPv4-embedding) and comes from the space
    zones are numbered from (:data:`ZONE_V6` less :data:`SPECIAL_V6`)."""
    net, why = _prefix6_problem(raw, 48, 64)
    if net is None:
        return None, why
    if any(net.subnet_of(s) for s in SPECIAL_V6) or not any(net.subnet_of(a) for a in ZONE_V6):
        return None, (
            f"is not unique-local (fc00::/7), global unicast (2000::/3, less {SPECIAL_V6_TEXT}) "
            "or documentation space"
        )
    return net, None


#: documentation space (RFC 3849, RFC 9637): never a prefix an ISP delegates
DOC_V6: tuple[ipaddress.IPv6Network, ...] = (
    ipaddress.IPv6Network((0x2001_0DB8 << 96, 32)),
    ipaddress.IPv6Network((0x3FFF << 112, 20)),
)


def delegated_prefix6_problem(raw: Any) -> tuple[ipaddress.IPv6Network | None, str | None]:
    """``(prefix, None)`` for one ``delegated_prefixes6`` prefix (site 1.5), else ``(None, why)``.

    The site's statement that a global-unicast prefix is its own (an ISP delegation): a /48 to a
    /64, what an ISP delegates to one site (a /32 is an ISP's own allocation, 2^96 addresses of
    which the site holds a sliver), that passes the shared prefix rules and is global unicast
    (2000::/3) outside :data:`SPECIAL_V6` and documentation space, which is the lab's already and
    is never delegated.  Unique-local space needs no declaration.  A site that holds more than a
    /48 declares the /48s it numbers zones from."""
    net, why = _prefix6_problem(raw, 48, 64)
    if net is None:
        return None, why
    if any(net.subnet_of(s) for s in SPECIAL_V6) or not net.subnet_of(ZONE_V6[1]):
        return None, (
            f"is not global unicast (2000::/3, less {SPECIAL_V6_TEXT}); a unique-local prefix "
            "needs no declaration"
        )
    if any(net.overlaps(d) for d in DOC_V6):
        return None, "is documentation space, which is never delegated and needs no declaration"
    return net, None


def delegated_prefixes6(raw: Any) -> tuple[tuple[ipaddress.IPv6Network, ...], list[str]]:
    """``(prefixes, problems)`` for a site's ``delegated_prefixes6`` (site 1.5): absent (None) is
    no declaration; anything else must be a list of ``{prefix, why}`` whose prefixes each pass
    :func:`delegated_prefix6_problem` and do not overlap.  The prefixes come back only when there
    are no problems, so a caller that sees any problem holds nothing as delegated."""
    if raw is None:
        return (), []
    if not isinstance(raw, list):
        return (), ["delegated_prefixes6 is not a list of {prefix, why}"]
    nets: list[ipaddress.IPv6Network] = []
    problems: list[str] = []
    for i, entry in enumerate(raw):
        where = f"delegated_prefixes6[{i}]"
        if not isinstance(entry, dict):
            problems.append(f"{where} is not a {{prefix, why}} mapping")
            continue
        why = entry.get("why")
        if not isinstance(why, str) or not why.strip():
            problems.append(f"{where} gives no reason (why)")
        net, bad = delegated_prefix6_problem(entry.get("prefix"))
        if net is None:
            problems.append(f"{where}: prefix {entry.get('prefix')!r} {bad}")
            continue
        clash = next((n for n in nets if n.overlaps(net)), None)
        if clash is not None:
            problems.append(f"{where}: prefix {net} overlaps {clash}")
        nets.append(net)
    return (tuple(nets) if not problems else ()), problems


def _anycast64(addr: ipaddress.IPv6Address, net: ipaddress.IPv6Network) -> bool:
    """``addr`` is /64 ``net``'s subnet-router anycast address or an RFC 2526 one (its top 128)."""
    host = int(addr) - int(net.network_address)
    return host == 0 or host >= (1 << 64) - 128


def wan_network_unstated(doc: dict) -> str | None:
    """The warning for a site whose ``router.wan6`` the linux adapter renders as a networkd drop-in
    for a guessed file (``adapters.options.linux.wan_network`` unstated), else None.  networkd
    ignores a drop-in whose ``.network`` file does not exist, so a wrong guess leaves the WAN
    without IPv6 and nothing says so; stating the name, even the default, silences it."""
    linux = doc.get("adapters", {}).get("options", {}).get("linux", {})
    if (
        "wan6" not in doc.get("router", {})
        or linux.get("flavor", "networkd") != "networkd"
        or "wan_network" in linux
    ):
        return None
    return (
        "router.wan6 extends the WAN's networkd file by a drop-in, and "
        "adapters.options.linux.wan_network is not stated, so the default "
        f"10-{linux.get('wan_interface', 'wan0')}.network is assumed; networkd ignores a "
        "drop-in for a file that does not exist, so set adapters.options.linux.wan_network to "
        "the WAN's own file"
    )


def wan6_problems(raw: Any, zones6: Any = (), delegated6: Any = ()) -> list[str]:
    """The problems of a router's ``wan6`` (site 1.6); absent (None) is none.

    Exactly one of ``ra: true`` or ``static: {address, gateway}``.  A static ``address`` is the
    router's on the WAN with its /64, canonical with no zone id, inside a prefix
    :func:`delegated_prefix6_problem` would accept (global unicast, never unique-local,
    documentation, special-purpose or IPv4-embedding), neither the /64's subnet-router anycast
    address nor one of its RFC 2526 anycast addresses (the top 128), and overlapping no zone's
    ``subnet6`` (``zones6``, prefixes) or ``delegated_prefixes6`` prefix (``delegated6``) -- the
    WAN link is not a zone, and a delegated prefix numbers zones.  The ``gateway`` is
    canonical with no zone id (it is the WAN's) and either link-local (fe80::/10) or another
    usable address inside the WAN /64."""
    if raw is None:
        return []
    if not isinstance(raw, dict) or len(raw) != 1 or not {*raw} <= {"ra", "static"}:
        return ["router.wan6 is not exactly one of ra or static"]
    if "ra" in raw:
        return [] if raw["ra"] is True else ["router.wan6.ra is not true"]
    st = raw["static"]
    if not isinstance(st, dict):
        return ["router.wan6.static is not an {address, gateway} mapping"]
    out: list[str] = []
    a_raw, g_raw = st.get("address"), st.get("gateway")
    if not isinstance(a_raw, str) or "%" in a_raw or "/" not in a_raw:
        return [f"router.wan6.static.address {a_raw!r} is not an IPv6 address with its /64"]
    try:
        iface = ipaddress.IPv6Interface(a_raw)
    except ValueError as exc:
        return [f"router.wan6.static.address {a_raw!r} is not an IPv6 address: {exc}"]
    if str(iface) != a_raw:
        out.append(
            f"router.wan6.static.address {a_raw!r} is not in its canonical form; write {iface}"
        )
    net = iface.network
    if net.prefixlen != 64:
        return [
            *out,
            f"router.wan6.static.address {a_raw!r} is a /{net.prefixlen}; the WAN link is a /64",
        ]
    _, why = delegated_prefix6_problem(str(net))
    if why is not None:
        out.append(f"router.wan6.static.address {a_raw!r}: its /64 {why}")
    if _anycast64(iface.ip, net):
        out.append(
            f"router.wan6.static.address {a_raw!r} is the /64's subnet-router or an RFC 2526 "
            "anycast address, never a router's own"
        )
    for z in zones6:
        if net.overlaps(z):
            out.append(f"router.wan6.static.address {a_raw!r} lies in zone prefix {z}")
    for d in delegated6:
        if net.overlaps(d):
            out.append(f"router.wan6.static.address {a_raw!r} lies in delegated prefix {d}")
    if not isinstance(g_raw, str) or "%" in g_raw:
        return [
            *out,
            f"router.wan6.static.gateway {g_raw!r} is not an IPv6 address without a zone id",
        ]
    try:
        gw = ipaddress.IPv6Address(g_raw)
    except ValueError as exc:
        return [*out, f"router.wan6.static.gateway {g_raw!r} is not an IPv6 address: {exc}"]
    if str(gw) != g_raw:
        out.append(f"router.wan6.static.gateway {g_raw!r} is not in its canonical form; write {gw}")
    if gw.is_link_local:
        return out
    if gw not in net:
        out.append(
            f"router.wan6.static.gateway {g_raw!r} is neither link-local (fe80::/10) nor inside "
            f"the WAN's {net}"
        )
    elif gw == iface.ip:
        out.append(f"router.wan6.static.gateway {g_raw!r} is the router's own WAN address")
    elif _anycast64(gw, net):
        out.append(f"router.wan6.static.gateway {g_raw!r} is an anycast address of the WAN's {net}")
    return out


def schema_problems(doc: Any) -> list[str]:
    import jsonschema

    validator = jsonschema.Draft202012Validator(schema())
    out = []
    for err in sorted(validator.iter_errors(doc), key=lambda e: [str(p) for p in e.absolute_path]):
        where = "/".join(str(p) for p in err.absolute_path) or "<root>"
        out.append(f"schema: {where}: {safe_message(err)}")
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
    nets6: dict[str, ipaddress.IPv6Network] = {}
    for zid, z in zone_ids.items():
        if "subnet6" not in z:
            continue
        net6, why = subnet6_problem(z["subnet6"])
        if net6 is None:
            r.error(f"zone {zid}: subnet6 {z['subnet6']!r} {why}")
            continue
        clash = next((o for o, n in nets6.items() if n.overlaps(net6)), None)
        if clash is not None:
            r.error(f"zones {clash} and {zid}: subnet6 {nets6[clash]} and {net6} overlap")
        nets6[zid] = net6
    delegated6, problems = delegated_prefixes6(doc.get("delegated_prefixes6"))
    for msg in problems:
        r.error(msg)

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
    for msg in wan6_problems(router.get("wan6"), nets6.values(), delegated6):
        r.error(msg)
    network_adapter = doc.get("adapters", {}).get("network", router["model"])
    if "wan6" in router and network_adapter != "linux":
        r.warn(
            f"router.wan6 is rendered by the linux adapter only; {network_adapter} ignores it, "
            "so configure the router's WAN IPv6 on the router itself"
        )
    if network_adapter == "linux" and (msg := wan_network_unstated(doc)):
        r.warn(msg)

    switch_ids: set[str] = set()
    macs: dict[str, str] = {}
    # zones whose traffic a mirror port should not copy silently: management, and one-way zones
    sensitive = {
        z["vlan_id"]: z["id"]
        for z in zone_ids.values()
        if z.get("purpose") == "management" or z["egress"].get("one_way")
    }
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
        mirrors: list[tuple[str, list[int], list[int]]] = []  # (where, ports, sources)
        port_vlans: dict[int, list[int]] = {}
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
                port_vlans[p] = ([pa["vlan"]] if "vlan" in pa else []) + list(pa.get("vlans", []))
            if pa["kind"] == "mirror":
                if "vlan" in pa or "vlans" in pa:
                    r.error(f"{where}: a mirror port carries no vlan or vlans of its own")
                if "mirror_from" not in pa:
                    r.error(f"{where}: a mirror port needs mirror_from (the ports it copies)")
                else:
                    try:
                        mirrors.append((where, ports, expand_ports(pa["mirror_from"])))
                    except ValueError as exc:
                        r.error(f"{where}: mirror_from: {exc}")
            elif "mirror_from" in pa:
                r.error(f"{where}: mirror_from is only for kind: mirror")
            used = ([pa["vlan"]] if "vlan" in pa else []) + list(pa.get("vlans", []))
            for v in used:
                if v not in vlans:
                    r.error(f"{where}: vlan {v} is not a zone of this site")
        mirror_ports = {p for _, ports, _ in mirrors for p in ports}
        copied_to: dict[int, str] = {}
        for where, ports, sources in mirrors:
            if len(set(sources)) != len(sources):
                r.error(f"{where}: mirror_from lists a port twice")
            # a SPAN session copies sources to ONE destination; UniFi (the one switch adapter)
            # takes a single source port per destination port
            if sw["model"] == "unifi" and (len(ports) != 1 or len(sources) != 1):
                r.error(
                    f"{where}: the unifi adapter mirrors one source port to one port; "
                    "give each mirror port its own entry with one mirror_from port"
                )
            for src in sources:
                if src not in seen_ports:
                    r.error(f"{where}: mirror_from port {src} is not assigned on this switch")
                elif src in mirror_ports:
                    r.error(f"{where}: mirror_from port {src} is itself a mirror port")
                if src in copied_to and copied_to[src] != where:
                    r.error(f"{where}: port {src} is already mirrored by {copied_to[src]}")
                copied_to[src] = where
            # a copy of these zones' traffic leaves the isolation the firewall gives them: say so
            seen = {v for src in sources for v in port_vlans.get(src, []) if v in sensitive}
            if seen:
                names = ", ".join(sorted(sensitive[v] for v in seen))
                r.warn(
                    f"{where}: the mirror copies the traffic of {names} (management or one-way) "
                    "to its port; keep that port's sensor out of every zone and physically secure"
                )
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
