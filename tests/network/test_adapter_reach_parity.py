# SPDX-License-Identifier: Apache-2.0
"""Reachability is checked on what the adapters render, not only on the site document: for every
pair of probe addresses (each zone, each host the policy names, an address on the internet), every
protocol and every port a rule names, the IR's first-match verdict
(:func:`homelabnext.network.ir.evaluate`, what ``hnx site query`` answers) equals the verdict read
back from the router's rendered nftables forward chain and from the controller's rendered rule
sets (:mod:`fwverdict`), in IPv4 and, where zones have prefixes, IPv6.  So an adapter that renders
a rule out of order, with the wrong ports or on the wrong side is caught here, where IR-level
invariants cannot see it."""

from __future__ import annotations

import copy
import ipaddress
from pathlib import Path

import pytest
from fwverdict import Controller, Nft
from netutil import render

from homelabnext.network import adapters, build_ir, load_site, validate
from homelabnext.network.ir import evaluate
from homelabnext.network.loader import load_registry

ROOT = Path(__file__).resolve().parents[2]
FOUR_BOX = ROOT / "examples" / "four-box-lab"
[CONTROLLER] = adapters.names_for("switch")
PREFIXES = {
    "mgmt": "2001:db8:0:10::/64",
    "data": "2001:db8:0:20::/64",
    "compute": "2001:db8:0:30::/64",
    "edge": "2001:db8:0:40::/64",
}
#: outside every example zone: the internet, in each family
INTERNET = {4: "203.0.113.200", 6: "2001:db8:ffff::1"}


def _probes(ir, fam: int) -> list[str]:
    """One address inside each zone of the family, each host a rule names, and the internet."""
    nets = ir.policy.zones if fam == 4 else ir.policy.zones6
    out = {str(ipaddress.ip_network(n)[20]) for n in nets.values()}
    for r in ir.policy.rules:
        for sel in (r.src, r.dst):
            if sel.kind == "host":
                out |= {c.split("/")[0] for c in sel.cidrs if ":" not in c or fam == 6}
    out = {a for a in out if ipaddress.ip_address(a).version == fam}
    for n in nets.values():
        assert ipaddress.ip_address(INTERNET[fam]) not in ipaddress.ip_network(n)
    return sorted(out | {INTERNET[fam]})


def _cases(ir):
    ports = sorted({p for r in ir.policy.rules for p in r.ports} | {1})
    for fam in (4, 6) if ir.policy.zones6 else (4,):
        nets = ir.policy.zones if fam == 4 else ir.policy.zones6
        probes = _probes(ir, fam)
        for src in probes:
            if not any(ipaddress.ip_address(src) in ipaddress.ip_network(n) for n in nets.values()):
                continue  # traffic a zone forwards: the internet's own is the WAN's inbound rules
            for dst in probes:
                if dst == src:
                    continue
                yield src, dst, "icmp", None
                for proto in ("tcp", "udp"):
                    for port in ports:
                        yield src, dst, proto, port


def _iface(ir, addr: str) -> str:
    a = ipaddress.ip_address(addr)
    for i in ir.interfaces:
        nets = [i.subnet] + ([i.subnet6] if i.subnet6 else [])
        if any(a in ipaddress.ip_network(n) for n in nets):
            return i.name
    return ir.options["linux"]["wan_interface"]


def _sites(doc, registry):
    doc6 = copy.deepcopy(doc)
    for z in doc6["zones"]:
        if z["id"] in PREFIXES:
            z["subnet6"] = PREFIXES[z["id"]]
    four = load_site(FOUR_BOX / "site.yml")
    return {
        "example": (doc, registry),
        "example-ipv6": (doc6, registry),
        "four-box-lab": (four, load_registry(FOUR_BOX / "services.yml")),
    }


@pytest.mark.parametrize("site", ["example", "example-ipv6", "four-box-lab"])
def test_every_adapter_renders_the_verdict_the_ir_gives(site, doc, registry):
    d, reg = _sites(doc, registry)[site]
    rep = validate(d, reg)
    assert rep.ok, rep.errors
    ir = build_ir(d, reg)
    ir.options.setdefault("linux", {}).setdefault("wan_interface", "wan0")
    nft = Nft(render("linux", ir)["etc/nftables.d/50-hnx-site.nft"])
    files = render(CONTROLLER, ir)
    ctl = Controller(files["firewall-rules.json"], files["networks.json"])
    wrong = []
    checked = 0
    for src, dst, proto, port in _cases(ir):
        want = "accept" if evaluate(ir.policy, src, dst, proto, port).action == "allow" else "drop"
        a, b = ipaddress.ip_address(src), ipaddress.ip_address(dst)
        iif, oif = _iface(ir, src), _iface(ir, dst)
        got_nft, rule = nft.verdict(a, b, proto, port, iif, oif)
        to_wan = oif == ir.options["linux"]["wan_interface"]
        got_ctl, crule = ctl.verdict(a, b, proto, port, to_wan)
        checked += 1
        if got_nft != want:
            wrong.append(f"linux {src}->{dst} {proto}/{port}: {got_nft} ({rule}), IR {want}")
        if got_ctl != want:
            wrong.append(
                f"controller {src}->{dst} {proto}/{port}: {got_ctl} ({crule and crule['name']}), "
                f"IR {want}"
            )
    assert checked > 100
    assert wrong == [], "\n".join(wrong[:20])


def test_the_readers_see_a_reordered_rule(doc, registry):
    """Negative: the parity check is not vacuous. An allow rendered ahead of the deny it should
    come after changes the verdict the reader gives, and a line it cannot read is a failure."""
    ir = build_ir(doc, registry)
    text = render("linux", ir)["etc/nftables.d/50-hnx-site.nft"]
    nft = Nft(text)
    src = next(r for r in ir.policy.rules if r.action == "deny" and r.dst.kind == "zone")
    a = ipaddress.ip_network(src.src.cidrs[0])[20]
    b = ipaddress.ip_network(src.dst.cidrs[0])[20]
    before, _ = nft.verdict(a, b, "tcp", 1, _iface(ir, str(a)), _iface(ir, str(b)))
    nft.rules.insert(0, f"ip saddr {a} ip daddr {b} accept")
    after, _ = nft.verdict(a, b, "tcp", 1, _iface(ir, str(a)), _iface(ir, str(b)))
    assert (before, after) == ("drop", "accept")
    with pytest.raises(AssertionError, match="does not understand"):
        Nft(
            text.replace("chain forward {\n", "chain forward {\n        bogus thing accept\n")
        ).verdict(a, b, "tcp", 1, "x", "y")
