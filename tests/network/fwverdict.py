# SPDX-License-Identifier: Apache-2.0
"""Read an adapter's rendered firewall back into a verdict, independently of the IR: the forward
chain of the router's nftables file, and the controller's rule sets in its payload.  Each reader
understands exactly the forms the adapters write and fails on anything else, so a rendering it
cannot read is a test failure, never a silent "no match".  (A uniquely named module: the parity
test in ``test_adapter_reach_parity.py`` uses it.)"""

from __future__ import annotations

import ipaddress
import json
import re

Addr = ipaddress.IPv4Address | ipaddress.IPv6Address

_PROTO = {"icmp": "icmp", "ipv6-icmp": "icmp", "tcp": "tcp", "udp": "udp"}


def _items(text: str) -> list[str]:
    text = text.strip()
    if text.startswith("{"):
        text = text[1:-1]
    return [t.strip() for t in text.split(",") if t.strip()]


def _ports(text: str) -> set[int]:
    out: set[int] = set()
    for item in _items(text):
        lo, _, hi = item.partition("-")
        out |= set(range(int(lo), int(hi or lo) + 1))
    return out


def _nets(items: list[str]) -> list:
    return [ipaddress.ip_network(i, strict=False) for i in items]


class Nft:
    """The ``table inet`` sets and the ``forward`` chain of a rendered nftables file."""

    def __init__(self, text: str) -> None:
        self.sets = {
            m.group(1): _nets(_items(m.group(2)))
            for m in re.finditer(r"set (\S+) \{[^}]*?elements = \{ ([^}]*) \}", text, re.S)
        }
        chain = text.split("chain forward {", 1)[1].split("\n    }", 1)[0]
        lines = [ln.strip() for ln in chain.splitlines() if ln.strip()]
        self.policy = re.search(r"policy (\w+);", chain).group(1)
        # the chain's header and the connection-state rules: not a new forwarded packet's match
        self.rules = [ln for ln in lines if not ln.startswith(("type ", "ct "))]

    def _addr(self, spec: str) -> list:
        if spec.startswith("@"):
            return self.sets[spec[1:]]
        return _nets(_items(spec))

    def verdict(self, src: Addr, dst: Addr, proto: str, port: int | None, iif: str, oif: str):
        """``accept`` or ``drop`` (and the rule) for one forwarded packet."""
        for line in self.rules:
            body = re.sub(r'\s*comment ".*"$', "", line)
            if self._matches(body, src, dst, proto, port, iif, oif):
                return body.rsplit(" ", 1)[1], line
        return self.policy, None

    def _matches(self, body, src, dst, proto, port, iif, oif) -> bool:
        rest = body
        fam = 6 if src.version == 6 else 4
        ok = True
        pattern = re.compile(
            r"^(?:(?P<fam>ip6?) (?P<side>saddr|daddr) (?P<addr>@\S+|\{[^}]*\}|\S+)"
            r"|(?P<ifside>[io]ifname) (?P<neg>!= )?(?P<ifs>\{[^}]*\}|\"[^\"]*\")"
            r"|(?P<l4>tcp|udp) dport (?P<dports>\{[^}]*\}|\S+)"
            r"|meta l4proto (?P<l4set>\{[^}]*\}|\S+)(?: th dport (?P<thports>\{[^}]*\}|\S+))?"
            r"|ip protocol (?P<ipproto>\S+)"
            r"|meta nfproto (?P<nfproto>ipv4|ipv6)"
            r"|(?P<verdict>accept|drop))\s*"
        )
        while rest:
            m = pattern.match(rest)
            if m is None:
                raise AssertionError(f"the forward-chain reader does not understand {rest!r}")
            rest = rest[m.end() :]
            if m.group("fam"):
                if (m.group("fam") == "ip6") != (fam == 6):
                    ok = False
                    continue
                addr = src if m.group("side") == "saddr" else dst
                ok &= any(addr in n for n in self._addr(m.group("addr")))
            elif m.group("ifside"):
                names = {n.strip('"') for n in _items(m.group("ifs"))}
                have = iif if m.group("ifside") == "iifname" else oif
                hit = any(have == n or (n.endswith("*") and have.startswith(n[:-1])) for n in names)
                ok &= hit != bool(m.group("neg"))
            elif m.group("l4"):
                ok &= proto == m.group("l4") and port in _ports(m.group("dports"))
            elif m.group("l4set"):
                protos = {_PROTO[p] for p in _items(m.group("l4set"))}
                ok &= proto in protos
                if m.group("thports"):
                    ok &= port in _ports(m.group("thports"))
            elif m.group("ipproto"):
                ok &= fam == 4 and proto == _PROTO[m.group("ipproto")]
            elif m.group("nfproto"):
                ok &= (m.group("nfproto") == "ipv6") == (fam == 6)
        return ok


class Controller:
    """The controller payload's ``LAN_IN``/``WAN_OUT`` rule sets (and their IPv6 twins)."""

    def __init__(self, rules_json: str, networks_json: str) -> None:
        doc = json.loads(rules_json)
        self.rules = sorted(doc["objects"], key=lambda r: (r["ruleset"], r["rule_index"]))
        self.groups = {g["name"]: _nets(g["group_members"]) for g in doc.get("groups", [])}
        self.networks: dict[str, dict[int, object]] = {}
        for n in json.loads(networks_json)["objects"]:
            fams = {4: ipaddress.ip_interface(n["ip_subnet"]).network}
            if n.get("ipv6_subnet"):
                fams[6] = ipaddress.ip_interface(n["ipv6_subnet"]).network
            self.networks[n["name"]] = fams

    def _side(self, r, side: str, addr: Addr) -> bool:
        net = r.get(f"{side}_networkconf_id")
        if net is not None:
            name = re.fullmatch(r"\$\{network:(.+)\}", net).group(1)
            n = self.networks[name].get(addr.version)
            if n is None or addr not in n:
                return False
        if f"{side}_address" in r and addr != ipaddress.ip_address(r[f"{side}_address"]):
            return False
        for g in r.get(f"{side}_firewallgroup_ids", []):
            name = re.fullmatch(r"\$\{firewallgroup:(.+)\}", g).group(1)
            if not any(addr in n for n in self.groups[name]):
                return False
        return True

    def _matches(self, r, src, dst, proto, port) -> bool:
        if r.get("state_established") or r.get("state_invalid"):
            return False  # connection state: not a new forwarded packet
        want = r.get("protocol_v6" if src.version == 6 else "protocol", "all")
        allowed = {"all": None, "tcp_udp": {"tcp", "udp"}}.get(want, {_PROTO.get(want, want)})
        if allowed is not None and proto not in allowed:
            return False
        if "dst_port" in r and port not in _ports(r["dst_port"].replace(":", "-")):
            return False
        known = {
            "name", "enabled", "ruleset", "rule_index", "action", "protocol", "protocol_v6",
            "logging", "description", "src_networkconf_type", "src_networkconf_id",
            "dst_networkconf_type", "dst_networkconf_id", "dst_address", "dst_port",
            "dst_firewallgroup_ids", "state_established", "state_related", "state_invalid",
        }  # fmt: skip
        unknown = set(r) - known
        if unknown:
            raise AssertionError(f"the controller reader does not understand {sorted(unknown)}")
        return self._side(r, "src", src) and self._side(r, "dst", dst)

    def _first(self, ruleset: str, src, dst, proto, port):
        for r in self.rules:
            if r["ruleset"] == ruleset and r["enabled"] and self._matches(r, src, dst, proto, port):
                return r
        return None

    def verdict(self, src: Addr, dst: Addr, proto: str, port: int | None, to_wan: bool):
        """``accept`` or ``drop`` (and the deciding rule): every packet a zone sends meets
        ``LAN_IN``; one leaving by the WAN also meets ``WAN_OUT``, which accepts by default."""
        v6 = "v6" if src.version == 6 else ""
        lan = self._first(f"LAN{v6}_IN", src, dst, proto, port)
        if lan is None or lan["action"] != "accept":
            return "drop", lan
        if to_wan:
            wan = self._first(f"WAN{v6}_OUT", src, dst, proto, port)
            if wan is not None and wan["action"] != "accept":
                return "drop", wan
        return "accept", lan
