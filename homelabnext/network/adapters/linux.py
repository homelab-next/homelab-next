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
"""

from __future__ import annotations

from ..ir import NetworkIR, Rule, Selector, ipv6_form
from .base import Adapter, Rendered, header


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
        files: Rendered = {}
        if opts["flavor"] == "ifupdown":
            files["etc/network/interfaces.d/hnx-vlans"] = self._ifupdown(
                ir, opts["trunk_interface"]
            )
            if any(i.subnet6 for i in ir.interfaces):
                files["etc/radvd.conf"] = self._radvd(ir)
        else:
            files.update(self._networkd(ir, opts["trunk_interface"]))
        sysctl = "net.ipv4.ip_forward = 1\nnet.ipv4.conf.all.rp_filter = 1\n"
        if any(i.subnet6 for i in ir.interfaces):
            # forwarding on, and the router takes no advertisement from a zone it serves
            sysctl += "net.ipv6.conf.all.forwarding = 1\nnet.ipv6.conf.all.accept_ra = 0\n"
        files["etc/sysctl.d/90-hnx-routing.conf"] = header("linux") + sysctl
        files["etc/nftables.d/50-hnx-site.nft"] = self._nft(ir, opts["wan_interface"])
        return dict(sorted(files.items()))

    # -- interfaces ------------------------------------------------------------------------
    def _networkd(self, ir: NetworkIR, trunk: str) -> Rendered:
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
            files[f"etc/systemd/network/20-{i.name}.network"] = network
        return files

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
                "        meta nfproto ipv6 fib saddr . iif oif missing drop\n    }\n\n"
            )
        mgmt = [i.zone for i in ir.interfaces if i.purpose == "management"]
        out.append(
            "    chain input {\n        type filter hook input priority filter; policy drop;\n"
        )
        out.append("        ct state established,related accept\n        ct state invalid drop\n")
        out.append('        iifname "lo" accept\n        ip protocol icmp accept\n')
        if pol.zones6:
            # the ICMPv6 a router must take (RFC 4890 section 4.4): errors, neighbour discovery,
            # MLD, and echo at a limited rate; never a router advertisement (it takes none)
            out.append(f"        icmpv6 type {ICMPV6_INPUT} accept\n")
            out.append("        icmpv6 type echo-request limit rate 10/second accept\n")
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
        out.append("        ct state established,related accept\n        ct state invalid drop\n")
        for rule in pol.rules:
            if rule.dst.kind == "internet" and rule.action == "deny":
                continue  # the chain policy already drops it
            out.append("        " + nft_rule(rule, wan) + "\n")
            six = ipv6_form(rule, pol.zones6)
            if six:
                out.append("        " + nft_rule(six, wan, six=True) + "\n")
        out.append("    }\n}\n")
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
