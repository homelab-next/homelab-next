# SPDX-License-Identifier: Apache-2.0
"""A zone's ``subnet6`` (site 1.4) on the network side: the IR, the router's address and router
advertisements, and the policy in IPv6, closed by default exactly as IPv4 is.

The IPv4-only goldens (``test_adapters``) are unchanged by IPv6 support; these goldens render the
example site with prefixes on four of its zones.  Prefixes outside the documentation range are
built from integers, so no such literal is in the tree."""

from __future__ import annotations

import copy
import ipaddress
import json
import shutil
import subprocess
from dataclasses import replace
from pathlib import Path

import pytest
from netutil import check_golden, render

from homelabnext.network import adapters, build_ir, load_site, validate
from homelabnext.network.ir import Rule, Selector, ipv6_form, router_address6
from homelabnext.network.loader import load_registry
from homelabnext.network.plan import write_rendered

MINIMAL = Path(__file__).resolve().parents[2] / "examples" / "minimal"

#: a routed (global) prefix: never in a golden file (the leak scan refuses the literal)
EDGE6 = str(ipaddress.IPv6Network((0x2600_0000_0000_0040 << 64, 64)))
PREFIXES = {
    "mgmt": "2001:db8:0:10::/64",
    "data": "2001:db8:0:20::/64",
    "compute": "2001:db8:0:30::/64",
    "edge": "2001:db8:0:40::/64",
}


@pytest.fixture
def doc6(doc) -> dict:
    d = copy.deepcopy(doc)
    for z in d["zones"]:
        if z["id"] in PREFIXES:
            z["subnet6"] = PREFIXES[z["id"]]
    return d


@pytest.fixture
def ir6(doc6, registry):
    rep = validate(doc6, registry)
    assert rep.ok, rep.errors
    return build_ir(doc6, registry)


#: every ready adapter, by the registry (the controller's is not named here)
READY = [n for n, status, _ in adapters.listing() if status == "ready"]
#: the controller payload adapter: the ready one that renders firewall-rule objects
CONTROLLER = next(n for n, _, summary in adapters.listing() if "DRY-RUN" in summary)


def test_golden_ipv6(ir6):
    """The controller's IPv6 payloads are pinned by the assertions below, not a golden (its
    goldens name the product, and the product-name baseline only shrinks)."""
    check_golden("linux-ipv6", render("linux", ir6))


@pytest.mark.parametrize("name", ["dnsmasq", "zonefile"])
def test_dhcp_and_dns_output_is_the_same_with_prefixes(name, ir6, ir):
    """Addressing in IPv6 is the router's advertisements (SLAAC): no DHCPv6, and the registry's
    hosts have IPv4 addresses only, so no AAAA record."""
    assert render(name, ir6) == render(name, ir)


def test_golden_linux_ifupdown_ipv6(doc6, registry):
    doc6["adapters"]["options"]["linux"]["flavor"] = "ifupdown"
    check_golden("linux-ifupdown-ipv6", render("linux", build_ir(doc6, registry)))


def test_the_ir_carries_each_prefix_and_the_routers_address(ir6, ir):
    by_zone = {i.zone: i for i in ir6.interfaces}
    assert by_zone["mgmt"].subnet6 == "2001:db8:0:10::/64"
    assert by_zone["mgmt"].address6 == "2001:db8:0:10::1"
    assert by_zone["sandbox"].subnet6 == by_zone["sandbox"].address6 == ""
    assert ir6.policy.zones6 == PREFIXES
    # an IPv4-only site has none of it
    assert ir.policy.zones6 == {} and all(not i.subnet6 for i in ir.interfaces)
    assert ir6.digest != ir.digest


@pytest.mark.parametrize("plen", [48, 56, 64])
def test_the_routers_address_is_the_prefixs_first_host(plen):
    net = ipaddress.IPv6Network((0x2001_0DB8_0005 << 80, plen))
    assert router_address6(str(net)) == str(net[1])


ZONES6 = {"a": "2001:db8:0:a::/64", "b": "2001:db8:0:b::/64", "g": EDGE6}


def _rule(src: Selector, dst: Selector, action: str = "allow") -> Rule:
    return Rule("r", action, src, dst, "tcp", (22,), None, "")


def _z(name: str) -> Selector:
    return Selector("zone", name)  # the IPv4 side's cidrs play no part in the IPv6 form


def test_a_zone_to_zone_rule_has_an_ipv6_form_only_when_both_zones_have_prefixes():
    six = ipv6_form(_rule(_z("a"), _z("b")), ZONES6)
    assert six is not None and six.id == "r:v6"
    assert six.src.cidrs == (ZONES6["a"],) and six.dst.cidrs == (ZONES6["b"],)
    assert ipv6_form(_rule(_z("a"), _z("c")), ZONES6) is None  # c has no prefix
    assert ipv6_form(_rule(_z("c"), _z("a")), ZONES6) is None
    assert ipv6_form(_rule(_z("g"), Selector("any")), ZONES6).dst.kind == "any"


def test_an_allow_naming_a_host_has_no_ipv6_form():
    host = Selector("host", "h", (), "b")
    assert ipv6_form(_rule(_z("a"), host), ZONES6) is None


def test_a_deny_naming_a_host_denies_the_hosts_whole_zone_in_ipv6():
    """A deny with no IPv6 form would let a later, wider allow through in IPv6."""
    host = Selector("host", "h", (), "b")
    six = ipv6_form(_rule(_z("a"), host, "deny"), ZONES6)
    assert six.action == "deny" and six.dst == Selector("zone", "b", (ZONES6["b"],))
    # a host in a zone with no prefix has no IPv6 address to deny
    assert ipv6_form(_rule(_z("a"), replace(host, zone="c"), "deny"), ZONES6) is None


def test_the_internet_has_an_ipv6_form_only_from_a_routed_prefix():
    assert ipv6_form(_rule(_z("g"), Selector("internet")), ZONES6) is not None
    assert ipv6_form(_rule(_z("a"), Selector("internet")), ZONES6) is None  # documentation
    ula = {"u": str(ipaddress.IPv6Network((0xFD00_0000_0000_0001 << 64, 64)))}
    assert ipv6_form(_rule(_z("u"), Selector("internet")), ula) is None


def _forward(nft: str) -> list[str]:
    body = nft.split("chain forward {", 1)[1].split("\n    }", 1)[0]
    return [ln.strip() for ln in body.splitlines()[3:] if ln.strip()]


def test_every_ipv6_rule_follows_its_ipv4_rule_with_the_same_verdict(ir6):
    """First match wins in each family: the IPv6 form sits right after the IPv4 one."""
    lines = _forward(render("linux", ir6)["etc/nftables.d/50-hnx-site.nft"])

    def verdict(ln: str) -> str:
        return ln.split(" comment ")[0].split()[-1]

    for n, ln in enumerate(lines):
        if ":v6:" in ln:
            prev = lines[n - 1]
            assert prev.startswith("ip ") and ln.startswith("ip6 "), (prev, ln)
            assert verdict(prev) == verdict(ln)
            assert (
                prev.split('comment "')[1].split(":")[0] == ln.split('comment "')[1].split(":")[0]
            )
    six = [ln for ln in lines if ln.startswith("ip6 ")]
    assert six and all('comment "' in ln and ":v6:" in ln for ln in six)
    # documentation prefixes have no IPv6 internet rule
    assert not any("egress.internet" in ln for ln in six)


def test_a_routed_prefix_reaches_the_internet_in_ipv6_untranslated(doc6, registry):
    next(z for z in doc6["zones"] if z["id"] == "edge")["subnet6"] = EDGE6
    nft = render("linux", build_ir(doc6, registry))["etc/nftables.d/50-hnx-site.nft"]
    lines = _forward(nft)
    assert any(
        ln.startswith("ip6 saddr @z_edge_6") and 'oifname "wan0" accept' in ln for ln in lines
    )
    assert "ip6" not in nft.split("table ip hnx_nat", 1)[1]  # no IPv6 translation


def test_the_linux_router_takes_no_advertisement_and_checks_the_reverse_path(ir6, ir):
    files = render("linux", ir6)
    nft = files["etc/nftables.d/50-hnx-site.nft"]
    assert "meta nfproto ipv6 fib saddr . iif oif missing drop" in nft
    assert "meta l4proto ipv6-icmp accept" not in nft  # only the ICMPv6 a router must take
    assert "icmpv6 type { destination-unreachable, packet-too-big," in nft
    inp = nft.split("chain input {", 1)[1].split("\n    }", 1)[0]
    # echo has a budget per side, so a flood from the WAN does not starve the zones'
    assert 'iifname != "wan0" icmpv6 type echo-request limit rate 10/second accept' in inp
    assert 'iifname "wan0" icmpv6 type echo-request limit rate 5/second accept' in inp
    # a router solicitation only from a zone; an MLD query only from a link-local router
    assert 'iifname != "wan0" icmpv6 type nd-router-solicit accept' in inp
    assert "ip6 saddr fe80::/10 ip6 hoplimit 1 icmpv6 type mld-listener-query accept" in inp
    unfiltered = [ln for ln in inp.splitlines() if ln.strip().startswith("icmpv6 type")]
    assert not any(t in ln for ln in unfiltered for t in ("router-solicit", "listener-query"))
    assert not any("echo-request" in ln and "iifname" not in ln for ln in inp.splitlines())
    assert "nd-router-advert" not in nft.split("chain input {", 1)[1].split("}\n\n", 1)[0]
    assert "set z_mgmt_6 {" in nft and "type ipv6_addr" in nft
    sysctl = files["etc/sysctl.d/90-hnx-routing.conf"]
    assert "net.ipv6.conf.all.forwarding = 1" in sysctl and "accept_ra = 0" in sysctl
    net = files["etc/systemd/network/20-vlan10.network"]
    assert "Address=2001:db8:0:10::1/64" in net and "IPv6SendRA=yes" in net
    assert "IPv6AcceptRA=no" in net and "Prefix=2001:db8:0:10::/64" in net
    assert "IPv6" not in files["etc/systemd/network/20-vlan50.network"]  # sandbox has none
    # an IPv4-only site renders none of it
    v4 = render("linux", ir)
    assert "ip6" not in v4["etc/nftables.d/50-hnx-site.nft"]
    assert "ipv6" not in v4["etc/sysctl.d/90-hnx-routing.conf"]


def test_ifupdown_has_radvd_for_the_advertisements(doc6, registry):
    doc6["adapters"]["options"]["linux"]["flavor"] = "ifupdown"
    files = render("linux", build_ir(doc6, registry))
    assert "prefix 2001:db8:0:10::/64 {" in files["etc/radvd.conf"]
    assert "iface vlan10 inet6 static" in files["etc/network/interfaces.d/hnx-vlans"]


def test_the_controller_closes_ipv6_by_default_as_it_does_ipv4(ir6, ir):
    rules = json.loads(render(CONTROLLER, ir6)["firewall-rules.json"])["objects"]
    v6 = [r for r in rules if "v6" in r["ruleset"]]
    names = [r["name"] for r in v6]
    assert names[0] == "hnx-v6-allow-established" and names[1] == "hnx-v6-drop-invalid"
    assert names[-1] == "hnx-v6-default-deny" and v6[-1]["action"] == "drop"
    assert all(r.get("src_networkconf_type", "NETv6") == "NETv6" for r in v6)
    # every IPv6 rule is an IPv4 rule's form, in the same order
    v4_order = [r["name"] for r in rules if r["ruleset"] in ("LAN_IN", "WAN_OUT")]
    six_order = [n.removesuffix("-v6") for n in names if n.endswith("-v6")]
    assert six_order == [n for n in v4_order if n in six_order]
    nets = {n["name"]: n for n in json.loads(render(CONTROLLER, ir6)["networks.json"])["objects"]}
    assert nets["hnx-mgmt"]["ipv6_subnet"] == "2001:db8:0:10::1/64"
    assert "ipv6_subnet" not in nets["hnx-sandbox"]
    assert not any(
        "v6" in r["ruleset"]
        for r in json.loads(render(CONTROLLER, ir)["firewall-rules.json"])["objects"]
    )


def test_the_example_lab_renders_with_every_ready_adapter():
    """The example lab's zones have prefixes; no ready adapter drops or refuses them."""
    doc = load_site(MINIMAL / "site.yml")
    reg = load_registry(MINIMAL / "services.yml")
    assert validate(doc, reg).ok
    ir = build_ir(doc, reg)
    assert ir.policy.zones6
    for name in READY:
        assert render(name, ir)
    assert "ipv6_subnet" in render(CONTROLLER, ir)["networks.json"]


def _nft_can_check(tmp_path) -> bool:
    if not (shutil.which("nft") and shutil.which("unshare")):
        return False
    probe = tmp_path / "probe.nft"
    probe.write_text("table inet probe {\n}\n")
    r = subprocess.run(["unshare", "-rn", "nft", "-c", "-f", str(probe)], capture_output=True)
    return r.returncode == 0


def test_the_ipv6_nftables_file_passes_nft_check(ir6, tmp_path):
    if not _nft_can_check(tmp_path):
        pytest.skip("nft with an unprivileged network namespace is not available")
    write_rendered(render("linux", ir6), tmp_path / "root")
    f = tmp_path / "root/etc/nftables.d/50-hnx-site.nft"
    r = subprocess.run(
        ["unshare", "-rn", "nft", "-c", "-f", str(f)], capture_output=True, text=True
    )
    assert r.returncode == 0, r.stderr


def _first_match(rules: list[Rule], src: str, dst: str) -> str:
    """The verdict IPv6 first-match gives traffic from zone ``src`` to zone ``dst``."""
    for r in rules:
        if r.src.name == src and r.dst.kind == "zone" and r.dst.name == dst:
            return r.action
    return "deny"  # the default


def test_a_deny_with_no_ipv6_form_never_precedes_a_wider_ipv6_allow():
    """Mixed prefixes: a deny loses its IPv6 form only where the traffic it denies has no IPv6
    address in the first place, so the wider allow after it can never let that traffic through."""
    rules = [
        _rule(_z("a"), Selector("host", "h", (), "c"), "deny"),  # h's zone c has no prefix
        _rule(_z("c"), _z("b"), "deny"),  # source c has no prefix
        _rule(_z("a"), _z("b")),
        _rule(_z("c"), _z("a")),
    ]
    six = [f for f in (ipv6_form(r, ZONES6) for r in rules) if f]
    assert [(r.action, r.src.name, r.dst.name) for r in six] == [("allow", "a", "b")]
    # zone c has no IPv6 address, so nothing denied above exists in IPv6
    assert all("c" not in (r.src.name, r.dst.name) for r in six)


def test_a_host_deny_before_a_zone_allow_makes_ipv6_stricter_than_ipv4():
    """IPv4: deny a -> host h, then allow a -> zone b (h's zone): only h is closed.  IPv6 has no
    host address, so the deny closes the whole zone and the later allow is shadowed."""
    rules = [_rule(_z("a"), Selector("host", "h", (), "b"), "deny"), _rule(_z("a"), _z("b"))]
    six = [f for f in (ipv6_form(r, ZONES6) for r in rules) if f]
    assert [r.action for r in six] == ["deny", "allow"]
    assert _first_match(six, "a", "b") == "deny"


def test_the_reverse_path_exemption_covers_on_link_control_traffic_only(ir6):
    nft = render("linux", ir6)["etc/nftables.d/50-hnx-site.nft"]
    pre = nft.split("chain prerouting {", 1)[1].split("\n    }", 1)[0]
    accepts = [ln.strip() for ln in pre.splitlines() if ln.strip().endswith("accept")]
    assert accepts == [
        "ip6 saddr { ::, fe80::/10 } ip6 hoplimit 255 icmpv6 type"
        " { nd-router-solicit, nd-neighbor-solicit, nd-neighbor-advert } accept",
        "ip6 saddr { ::, fe80::/10 } ip6 hoplimit 1 icmpv6 type mld2-listener-report accept",
    ]
    assert pre.rstrip().endswith("meta nfproto ipv6 fib saddr . iif oif missing drop")


def test_no_router_advertisement_goes_out_the_wan(doc6, registry):
    ir = build_ir(doc6, registry)
    wan = ir.options["linux"]["wan_interface"]
    trunk = ir.options["linux"]["trunk_interface"]
    vlans = {i.name for i in ir.interfaces}
    files = render("linux", ir)
    senders = {
        p for p, text in files.items() if "IPv6SendRA=yes" in text and p.endswith(".network")
    }
    assert senders == {
        f"etc/systemd/network/20-{i.name}.network" for i in ir.interfaces if i.subnet6
    }
    assert not any(wan in p or trunk in p for p in senders)
    doc6["adapters"]["options"]["linux"]["flavor"] = "ifupdown"
    radvd = render("linux", build_ir(doc6, registry))["etc/radvd.conf"]
    named = {ln.split()[1] for ln in radvd.splitlines() if ln.startswith("interface ")}
    assert named <= vlans and wan not in named and trunk not in named


def test_the_controllers_ipv6_rules_stay_in_the_ipv4_index_range_and_name_protocol_v6(ir6):
    rules = json.loads(render(CONTROLLER, ir6)["firewall-rules.json"])["objects"]
    for r in rules:
        assert 2000 <= r["rule_index"] <= 2999, r
    v6 = [r for r in rules if "v6" in r["ruleset"]]
    assert v6 and all("protocol_v6" in r and "protocol" not in r for r in v6)
    assert all("protocol" in r and "protocol_v6" not in r for r in rules if r not in v6)
    assert {r["protocol_v6"] for r in v6} <= {"all", "tcp", "udp", "tcp_udp", "icmpv6"}


def test_an_ipv4_only_site_digests_as_before_ipv6(ir):
    """The IPv6 fields are left out of an IPv4-only site's IR, so its digest is unchanged."""
    d = ir.to_dict()
    assert "zones6" not in d["policy"]
    assert all("subnet6" not in i and "address6" not in i for i in d["interfaces"])
    assert all("zone" not in r["dst"] for r in d["policy"]["rules"])


ULA6 = str(ipaddress.IPv6Network((0xFD00_0000_0000_0082 << 64, 64)))


def _ula_any_ir(doc6, registry, action: str = "allow"):
    """The example lab with a unique-local prefix on zone compute and a rule from it to ``any``."""
    next(z for z in doc6["zones"] if z["id"] == "compute")["subnet6"] = ULA6
    doc6["firewall"]["zone_to_zone"].append({"from": "compute", "to": "any", "action": action})
    return build_ir(doc6, registry)


def test_an_ipv6_allow_to_any_from_a_non_global_prefix_cannot_leave_by_the_wan():
    """``any`` includes the internet; a unique-local source has no IPv6 form there (see
    ``ipv6_form``), so its form must say "anything but the internet", for every adapter."""
    ula = {"u": ULA6}
    six = ipv6_form(_rule(_z("u"), Selector("any")), ula)
    assert six.dst.kind == "intranet"
    # a global prefix may go anywhere, the internet included; a deny stays as wide as written
    assert ipv6_form(_rule(_z("g"), Selector("any")), ZONES6).dst.kind == "any"
    assert ipv6_form(_rule(_z("u"), Selector("any"), "deny"), ula).dst.kind == "any"
    # a documentation prefix is not global either
    assert ipv6_form(_rule(_z("a"), Selector("any")), ZONES6).dst.kind == "intranet"


def test_the_linux_router_never_forwards_a_ula_allow_to_any_out_the_wan(doc6, registry):
    nft = render("linux", _ula_any_ir(doc6, registry))["etc/nftables.d/50-hnx-site.nft"]
    six = [ln.strip() for ln in nft.splitlines() if "zone_to_zone[5]:v6" in ln]
    # named positively: the zones' own interfaces, so a second uplink or a tunnel is never "not
    # the WAN"
    assert len(six) == 1 and "oifname { " in six[0] and '"vlan10"' in six[0], six
    assert "wan0" not in six[0] and "!=" not in six[0]
    # IPv4 is untouched: any is any
    v4 = [ln for ln in nft.splitlines() if "ip saddr @z_compute " in ln and "any" in ln]
    assert v4 and not any("oifname" in ln for ln in v4)


def test_the_controller_keeps_a_ula_allow_to_any_off_the_internet(doc6, registry):
    """The legacy LANv6_IN also sees routed LAN-to-WAN traffic, so the accept is preceded by a
    WANv6_OUT drop for the same source."""
    rules = json.loads(render(CONTROLLER, _ula_any_ir(doc6, registry))["firewall-rules.json"])
    mine = [r for r in rules["objects"] if r["name"] == "hnx-zone_to_zone-5-v6"]
    assert len(mine) == 1 and mine[0]["ruleset"] == "LANv6_IN"
    assert "dst_address" not in mine[0] and "dst_networkconf_id" not in mine[0]
    drop = [r for r in rules["objects"] if r["name"] == "hnx-zone_to_zone-5-v6-wan"]
    assert len(drop) == 1 and (drop[0]["ruleset"], drop[0]["action"]) == ("WANv6_OUT", "drop")
    assert drop[0]["rule_index"] < mine[0]["rule_index"]
    assert not any(
        r["ruleset"] == "WANv6_OUT" and r["action"] == "accept" for r in rules["objects"]
    )


@pytest.mark.parametrize("adapter", ["linux", CONTROLLER])
def test_an_unknown_selector_kind_fails_in_every_rule_adapter(doc6, registry, adapter):
    """An adapter that met a kind it does not know and rendered it as ``any`` would widen it."""
    from homelabnext.network import ir as irmod

    real = irmod.ipv6_form

    def odd(rule, zones6):
        six = real(rule, zones6)
        return six and irmod.Rule(**{**six.__dict__, "dst": Selector("elsewhere")})

    import homelabnext.network.adapters.linux as lin
    import homelabnext.network.adapters.unifi as uni

    mp = pytest.MonkeyPatch()
    try:
        mp.setattr(lin, "ipv6_form", odd, raising=False)
        mp.setattr(uni, "ipv6_form", odd, raising=False)
        with pytest.raises(ValueError, match="unknown selector kind"):
            render(adapter, build_ir(doc6, registry))
    finally:
        mp.undo()


def test_the_controller_drops_a_ula_zones_ipv6_internet_deny(doc6, registry):
    """A deny always has an IPv6 form: with none, WANv6_OUT would be left to the controller's
    default for a zone the site says may not reach the internet."""
    next(z for z in doc6["zones"] if z["id"] == "sandbox")["subnet6"] = ULA6
    ir6 = build_ir(doc6, registry)
    objs = json.loads(render(CONTROLLER, ir6)["firewall-rules.json"])["objects"]
    out = [r for r in objs if r["ruleset"] == "WANv6_OUT"]
    v4 = [r for r in objs if r["ruleset"] == "WAN_OUT" and "sandbox" in r["name"]]
    assert v4, "the example lab denies sandbox the internet in IPv4"
    assert any(r["action"] == "drop" and "sandbox" in r["name"] for r in out), out
    # the linux chain policy already drops it: no rule is written
    nft = render("linux", ir6)["etc/nftables.d/50-hnx-site.nft"]
    assert "egress.internet:sandbox:v6" not in nft


def test_a_deny_to_the_internet_has_an_ipv6_form_from_any_prefix():
    ula = {"u": ULA6}
    assert ipv6_form(_rule(_z("u"), Selector("internet"), "deny"), ula) is not None
    assert ipv6_form(_rule(_z("a"), Selector("internet"), "deny"), ZONES6) is not None
    assert ipv6_form(_rule(_z("u"), Selector("internet"), "allow"), ula) is None
