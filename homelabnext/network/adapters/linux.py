# SPDX-License-Identifier: Apache-2.0
"""Reference adapter: a plain Linux router.

Renders VLAN sub-interfaces (systemd-networkd by default, ``/etc/network`` ifupdown on request),
forwarding sysctl, and one nftables file that declares one set per zone and a default-drop
``forward`` chain.  It needs nothing but a Linux box with a trunk port, which is why it is the
reference every other adapter is compared against.

A zone with a ``subnet6`` gets the router's IPv6 address and router advertisements for the prefix
(SLAAC: networkd's own sender, or ``radvd`` for ifupdown), IPv6 forwarding, an ``ipv6_addr`` set,
and every rule again in its IPv6 form right after the IPv4 one (see the IR).  IPv6 has no
``rp_filter``, so a strict reverse-path check (``fib``) drops a forwarded IPv6 packet whose source
does not route back out the interface it came in on: without it a host could claim another zone's
source and match that zone's rules.  IPv6 is not translated: a zone allowed to the internet
reaches it from its own prefix, which only a routed (global) prefix can do.

``router.wan6`` (site 1.6) gives the router its own IPv6 on the WAN, which the zones' routed IPv6
leaves by: a static address and default gateway, or router advertisements accepted on the WAN and
only there (``accept_ra = 2`` for the WAN, so forwarding does not switch them off where the
kernel takes them, with ifupdown; networkd takes them itself; SLAAC only, no DHCPv6).  networkd gets a drop-in for the WAN's own ``.network`` file
(``<wan_network>.d/50-hnx-wan6.conf``, never a second file for the WAN: networkd applies only the
first ``.network`` file that matches an interface), ifupdown an ``inet6`` stanza for the WAN.  The
router's input takes the ICMPv6 a router must take once it has any IPv6, and a router
advertisement only on the WAN, from a link-local source at hop limit 255.  Zones never take one,
and the forward chain drops IPv6 to a zone's prefix that would leave by the WAN (a route a WAN
neighbour advertised), and so does an output chain for the router's own.
"""

from __future__ import annotations

from ..ir import NetworkIR, Rule, Selector, ipv6_form
from .base import Adapter, Rendered, header


def wan_network(opts: dict) -> str:
    """The WAN's own networkd ``.network`` file, which ``router.wan6``'s drop-in extends."""
    return opts.get("wan_network") or f"10-{opts['wan_interface']}.network"


def _sysctl_key(interface: str, key: str) -> str:
    """An IPv6 per-interface sysctl key; an interface name with a dot (a VLAN on the WAN) is
    written with slashes, which sysctl.d reads as the separator instead."""
    if "." in interface:
        return f"net/ipv6/conf/{interface}/{key}"
    return f"net.ipv6.conf.{interface}.{key}"


def nft_ident(zone: str, six: bool = False) -> str:
    return "z_" + zone.replace("-", "_") + ("_6" if six else "")


def _q(text: str) -> str:
    return text.replace("\\", "").replace('"', "'")


def _ports(ports: tuple[int, ...]) -> str:
    return str(ports[0]) if len(ports) == 1 else "{ " + ", ".join(str(p) for p in ports) + " }"


def _match(sel: Selector, direction: str, wan: str, six: bool = False) -> str:
    """nft match fragment for one side of a rule ('s' source, 'd' destination)."""
    if sel.kind == "any":
        return ""
    if sel.kind == "zone":
        return f"ip{'6' if six else ''} {direction}addr @{nft_ident(sel.name, six)}"
    if sel.kind == "host":
        return f"ip {direction}addr {sel.cidrs[0].split('/')[0]}"
    if sel.kind == "internet":
        return f'oifname "{wan}"'
    raise ValueError(f"unknown selector kind {sel.kind!r}")


def nft_rule(rule: Rule, wan: str, six: bool = False) -> str:
    """One nft rule; ``six`` renders a rule :func:`~homelabnext.network.ir.ipv6_form` returned."""
    parts = [_match(rule.src, "s", wan, six), _match(rule.dst, "d", wan, six)]
    if rule.protocol in ("tcp", "udp"):
        parts.append(
            f"{rule.protocol} dport {_ports(rule.ports)}"
            if rule.ports
            else f"meta l4proto {rule.protocol}"
        )
    elif rule.protocol == "icmp":
        parts.append("meta l4proto ipv6-icmp" if six else "ip protocol icmp")
    parts.append("accept" if rule.action == "allow" else "drop")
    parts.append(f'comment "{_q(rule.id)}: {_q(rule.comment)}"')
    return " ".join(p for p in parts if p)


# sources on-link control traffic comes from: duplicate-address detection uses the unspecified
# address, and neighbour discovery and MLD otherwise a link-local one
ONLINK_SOURCES = "{ ::, fe80::/10 }"
ICMPV6_INPUT = (
    "{ destination-unreachable, packet-too-big, time-exceeded, parameter-problem, echo-reply, "
    "nd-router-solicit, nd-neighbor-solicit, nd-neighbor-advert, mld-listener-query, "
    "mld2-listener-report }"
)


class LinuxAdapter(Adapter):
    name = "linux"
    summary = (
        "Linux router: VLAN interfaces (networkd or ifupdown), sysctl, nftables with zone sets"
    )

    def render(self, ir: NetworkIR) -> Rendered:
        opts = ir.options["linux"]
        wan, wan6 = opts["wan_interface"], ir.router.wan6
        files: Rendered = {}
        if opts["flavor"] == "ifupdown":
            files["etc/network/interfaces.d/hnx-vlans"] = self._ifupdown(
                ir, opts["trunk_interface"]
            )
            if any(i.subnet6 for i in ir.interfaces):
                files["etc/radvd.conf"] = self._radvd(ir)
            if wan6:
                files["etc/network/interfaces.d/hnx-wan6"] = self._ifupdown_wan6(wan, wan6)
        else:
            files.update(self._networkd(ir, opts["trunk_interface"], bool(wan6)))
            if wan6:
                files[f"etc/systemd/network/{wan_network(opts)}.d/50-hnx-wan6.conf"] = (
                    self._networkd_wan6(wan6)
                )
        sysctl = "net.ipv4.ip_forward = 1\nnet.ipv4.conf.all.rp_filter = 1\n"
        six = any(i.subnet6 for i in ir.interfaces)
        if six:
            sysctl += "net.ipv6.conf.all.forwarding = 1\n"
        if wan6:
            # an interface made later (a VLAN, a bridge) takes neither advertisements nor
            # redirects: without a zone prefix forwarding is off, and then it would take both
            sysctl += (
                "net.ipv6.conf.default.accept_ra = 0\nnet.ipv6.conf.default.accept_redirects = 0\n"
            )
        if six or wan6:
            # the router takes no advertisement from a zone it serves
            sysctl += "net.ipv6.conf.all.accept_ra = 0\n"
        if wan6:
            # the WAN takes no redirect and no route-information option (a more specific route
            # than a zone's prefix), and alone takes advertisements (2: even with forwarding on),
            # or none if static; accept_ra last, after "all"'s
            sysctl += (
                f"{_sysctl_key(wan, 'accept_redirects')} = 0\n"
                f"{_sysctl_key(wan, 'accept_ra_rt_info_max_plen')} = 0\n"
                f"{_sysctl_key(wan, 'accept_ra')} = {2 if 'ra' in wan6 else 0}\n"
            )
        files["etc/sysctl.d/90-hnx-routing.conf"] = header("linux") + sysctl
        files["etc/nftables.d/50-hnx-site.nft"] = self._nft(ir, wan)
        return dict(sorted(files.items()))

    # -- interfaces ------------------------------------------------------------------------
    def _networkd(self, ir: NetworkIR, trunk: str, wan6: bool = False) -> Rendered:
        files: Rendered = {}
        vlan_lines = "".join(f"VLAN={i.name}\n" for i in ir.interfaces)
        files[f"etc/systemd/network/10-{trunk}.network"] = (
            header("linux")
            + f"\n[Match]\nName={trunk}\n\n[Network]\nLinkLocalAddressing=no\n{vlan_lines}"
        )
        for i in ir.interfaces:
            files[f"etc/systemd/network/20-{i.name}.netdev"] = (
                header("linux")
                + f"# zone: {i.zone}\n\n[NetDev]\nName={i.name}\nKind=vlan\n\n[VLAN]\nId={i.vlan_id}\n"
            )
            network = (
                header("linux")
                + f"# zone: {i.zone}\n\n[Match]\nName={i.name}\n\n[Network]\nAddress={i.address}/{i.prefixlen}\n"
            )
            if i.subnet6:
                plen6 = i.subnet6.split("/")[1]
                network += (
                    f"Address={i.address6}/{plen6}\nIPv6AcceptRA=no\nIPv6SendRA=yes\n"
                    f"\n[IPv6Prefix]\nPrefix={i.subnet6}\n"
                )
            elif wan6:
                # networkd takes advertisements on a link by default while forwarding is off,
                # which it is when no zone has a prefix: a zone host's would route the router
                network += "IPv6AcceptRA=no\n"
            files[f"etc/systemd/network/20-{i.name}.network"] = network
        return files

    def _networkd_wan6(self, wan6: dict) -> str:
        """A drop-in for the WAN's own ``.network`` file: its IPv4 stays the operator's."""
        out = header("linux") + "# router.wan6: the router's IPv6 on the WAN\n\n[Network]\n"
        if "ra" in wan6:
            # SLAAC and the default route from the advertisement; no DHCPv6 (its replies are not
            # let in), and the site's resolvers stay the router's
            # and no on-link route from a prefix option: an advertised prefix inside a zone's
            # would pull that zone's traffic out the WAN (the forward chain drops it as well)
            return out + (
                "IPv6AcceptRA=yes\n\n[IPv6AcceptRA]\nDHCPv6Client=no\nUseDNS=no\n"
                "UseOnLinkPrefix=no\n"
            )
        st = wan6["static"]
        return (
            out + f"Address={st['address']}\nIPv6AcceptRA=no\n\n[Route]\nGateway={st['gateway']}\n"
        )

    def _ifupdown_wan6(self, wan: str, wan6: dict) -> str:
        """The WAN's ``inet6`` stanza; its ``auto`` line and IPv4 stanza are the operator's."""
        out = header("linux") + "# router.wan6: the router's IPv6 on the WAN\n"
        if "ra" in wan6:
            return out + f"iface {wan} inet6 auto\n    accept_ra 2\n    dhcp 0\n"
        st = wan6["static"]
        return out + (
            f"iface {wan} inet6 static\n    address {st['address']}\n"
            f"    gateway {st['gateway']}\n    accept_ra 0\n"
        )

    def _ifupdown(self, ir: NetworkIR, trunk: str) -> str:
        out = [header("linux"), f"auto {trunk}\niface {trunk} inet manual\n"]
        for i in ir.interfaces:
            out.append(
                f"\n# zone: {i.zone}\nauto {i.name}\niface {i.name} inet static\n"
                f"    address {i.address}/{i.prefixlen}\n    vlan-raw-device {trunk}\n"
            )
            if i.subnet6:
                out.append(
                    f"iface {i.name} inet6 static\n"
                    f"    address {i.address6}/{i.subnet6.split('/')[1]}\n    accept_ra 0\n"
                )
        return "".join(out)

    def _radvd(self, ir: NetworkIR) -> str:
        """Router advertisements for ifupdown, which has no sender of its own."""
        out = [header("linux")]
        for i in ir.interfaces:
            if i.subnet6:
                out.append(
                    f"\n# zone: {i.zone}\ninterface {i.name} {{\n    AdvSendAdvert on;\n"
                    f"    prefix {i.subnet6} {{\n        AdvOnLink on;\n        AdvAutonomous on;\n"
                    "    };\n};\n"
                )
        return "".join(out)

    # -- firewall --------------------------------------------------------------------------
    def _nft(self, ir: NetworkIR, wan: str) -> str:
        pol = ir.policy
        ra = "ra" in ir.router.wan6
        # a router advertisement, taken on the WAN only, and only from a link-local neighbour
        wan_ra = f'iifname "{wan}" ip6 saddr fe80::/10 ip6 hoplimit 255 icmpv6 type nd-router-advert accept'
        out = [header("linux"), "table inet hnx_site\ndelete table inet hnx_site\n\n"]
        out.append("table inet hnx_site {\n")
        for zid, subnet in pol.zones.items():
            out.append(
                f"    set {nft_ident(zid)} {{\n        type ipv4_addr\n        flags interval\n"
                f"        elements = {{ {subnet} }}\n    }}\n\n"
            )
        for zid, subnet6 in pol.zones6.items():
            out.append(
                f"    set {nft_ident(zid, True)} {{\n        type ipv6_addr\n        flags interval\n"
                f"        elements = {{ {subnet6} }}\n    }}\n\n"
            )
        if pol.zones6:
            # IPv6 has no rp_filter: a packet whose source does not route back out the interface
            # it came in on is dropped.  Only on-link control traffic skips the check: neighbour
            # discovery (hop limit 255) and MLD (hop limit 1) from the unspecified or a link-local
            # source, which duplicate-address detection needs and a router never forwards
            out.append(
                "    chain prerouting {\n"
                "        type filter hook prerouting priority filter; policy accept;\n"
                f"        ip6 saddr {ONLINK_SOURCES} ip6 hoplimit 255 icmpv6 type"
                " { nd-router-solicit, nd-neighbor-solicit, nd-neighbor-advert } accept\n"
                f"        ip6 saddr {ONLINK_SOURCES} ip6 hoplimit 1 icmpv6 type mld2-listener-report accept\n"
                + (f"        {wan_ra}\n" if ra else "")
                + "        meta nfproto ipv6 fib saddr . iif oif missing drop\n    }\n\n"
            )
        mgmt = [i.zone for i in ir.interfaces if i.purpose == "management"]
        out.append(
            "    chain input {\n        type filter hook input priority filter; policy drop;\n"
        )
        out.append("        ct state established,related accept\n        ct state invalid drop\n")
        out.append('        iifname "lo" accept\n        ip protocol icmp accept\n')
        if pol.zones6 or ir.router.wan6:
            # the ICMPv6 a router must take (RFC 4890 section 4.4): errors, neighbour discovery,
            # MLD, and echo at a limited rate; a router advertisement only on the WAN, when wan6
            # says to take one
            out.append(f"        icmpv6 type {ICMPV6_INPUT} accept\n")
            out.append("        icmpv6 type echo-request limit rate 10/second accept\n")
            if ra:
                out.append(f'        {wan_ra} comment "router.wan6.ra: the WAN only"\n')
        out.append('        iifname "vlan*" udp dport { 53, 67 } accept\n')
        out.append('        iifname "vlan*" tcp dport 53 accept\n')
        for z in mgmt:
            out.append(
                f'        ip saddr @{nft_ident(z)} tcp dport 22 accept comment "ssh from management zone {z}"\n'
            )
            if z in pol.zones6:
                out.append(
                    f'        ip6 saddr @{nft_ident(z, True)} tcp dport 22 accept comment "ssh from management zone {z}"\n'
                )
        out.append("    }\n\n")
        out.append(
            "    chain forward {\n        type filter hook forward priority filter; policy drop;\n"
        )
        # before established: a route a WAN neighbour advertised (a prefix inside a zone's) must
        # not carry a zone's traffic, return traffic included, out the WAN; nor the router's own
        guard = (
            f'        oifname "{wan}" ip6 daddr {{ {", ".join(pol.zones6.values())} }} drop'
            ' comment "router.wan6: a zone prefix never leaves by the WAN"\n'
            if ir.router.wan6 and pol.zones6
            else ""
        )
        out.append(guard)
        out.append("        ct state established,related accept\n        ct state invalid drop\n")
        for rule in pol.rules:
            if rule.dst.kind == "internet" and rule.action == "deny":
                continue  # the chain policy already drops it
            out.append("        " + nft_rule(rule, wan) + "\n")
            six = ipv6_form(rule, pol.zones6)
            if six:
                out.append("        " + nft_rule(six, wan, six=True) + "\n")
        out.append("    }\n")
        if guard:
            out.append(
                "\n    chain output {\n"
                "        type filter hook output priority filter; policy accept;\n"
                f"{guard}    }}\n"
            )
        out.append("}\n")
        masq = [
            pol.zones[r.src.name]
            for r in pol.rules
            if r.dst.kind == "internet" and r.action == "allow"
        ]
        out.append("\ntable ip hnx_nat\ndelete table ip hnx_nat\n\n")
        out.append("table ip hnx_nat {\n    chain postrouting {\n")
        out.append("        type nat hook postrouting priority srcnat; policy accept;\n")
        if masq:
            out.append(f'        oifname "{wan}" ip saddr {{ {", ".join(masq)} }} masquerade\n')
        out.append("    }\n}\n")
        return "".join(out)
