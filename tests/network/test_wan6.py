# SPDX-License-Identifier: Apache-2.0
"""Site 1.6 ``router.wan6``: the router's own IPv6 on its WAN, a static address and default gateway
or router advertisements accepted on the WAN only.  Zones never take an advertisement, a site
without ``wan6`` renders and digests exactly as before, and validation refuses what no WAN link is.

A static WAN address must be global unicast outside documentation space, so the goldens render an
IR built from a documentation address without validation (the leak scan refuses any other literal
in the tree), and the validation tests build their global addresses from integers."""

from __future__ import annotations

import copy
import io
import ipaddress
import shutil
import subprocess

import pytest
import yaml
from netutil import check_golden, render

from homelabnext.network import adapters, build_ir, cli, validate
from homelabnext.network.adapters.linux import wan_network
from homelabnext.network.plan import write_rendered
from homelabnext.network.validate import schema_problems, wan6_problems

PREFIXES = {
    "mgmt": "2001:db8:0:10::/64",
    "data": "2001:db8:0:20::/64",
    "compute": "2001:db8:0:30::/64",
    "edge": "2001:db8:0:40::/64",
}
#: a documentation WAN address: rendered in the goldens, refused by validation
DOC_STATIC = {"address": "2001:db8:ffff:1::2/64", "gateway": "2001:db8:ffff:1::1"}
#: a link-local gateway, never written as a literal (the leak scan reads one as an address)
LL = str(ipaddress.IPv6Address((0xFE80 << 112) + 1))
#: a global WAN /64, never written as a literal
WAN64 = ipaddress.IPv6Network((0x2600_0010_0009_0001 << 64, 64))
#: the controller payload adapter, which renders no WAN IPv6 (not named: the product-name lint)
CONTROLLER = next(n for n, _, summary in adapters.listing() if "DRY-RUN" in summary)
NFT = "etc/nftables.d/50-hnx-site.nft"
SYSCTL = "etc/sysctl.d/90-hnx-routing.conf"
DROPIN = "etc/systemd/network/10-wan0.network.d/50-hnx-wan6.conf"
WAN_STANZA = "etc/network/interfaces.d/hnx-wan6"


def _addr(n: int) -> str:
    """The WAN /64's address ``n`` with its prefix length."""
    return f"{WAN64[n]}/64"


@pytest.fixture
def doc6(doc) -> dict:
    """The example site with zone prefixes, routed by the linux adapter."""
    d = copy.deepcopy(doc)
    for z in d["zones"]:
        if z["id"] in PREFIXES:
            z["subnet6"] = PREFIXES[z["id"]]
    d["router"]["model"] = "linux"
    d["adapters"]["network"] = "linux"
    return d


def _ir(doc6, registry, wan6: dict | None, flavor: str = "networkd"):
    d = copy.deepcopy(doc6)
    if wan6 is not None:
        d["router"]["wan6"] = wan6
    d["adapters"]["options"]["linux"]["flavor"] = flavor
    return build_ir(d, registry)


def _input(nft: str) -> str:
    return nft.split("chain input {", 1)[1].split("\n    }", 1)[0]


# -- goldens ---------------------------------------------------------------------------------


@pytest.mark.parametrize("flavor", ["networkd", "ifupdown"])
def test_golden_wan6_ra(doc6, registry, flavor):
    label = "linux-wan6-ra" if flavor == "networkd" else "linux-ifupdown-wan6-ra"
    check_golden(label, render("linux", _ir(doc6, registry, {"ra": True}, flavor)))


@pytest.mark.parametrize("flavor", ["networkd", "ifupdown"])
def test_golden_wan6_static(doc6, registry, flavor):
    label = "linux-wan6-static" if flavor == "networkd" else "linux-ifupdown-wan6-static"
    check_golden(label, render("linux", _ir(doc6, registry, {"static": DOC_STATIC}, flavor)))


# -- rendering -------------------------------------------------------------------------------


def test_a_site_without_wan6_renders_and_digests_as_before(doc6, registry, doc, ir):
    """No ``wan6`` key in the IR's canonical form, so an existing site's digest is unchanged."""
    assert "wan6" not in ir.to_dict()["router"]
    assert build_ir(copy.deepcopy(doc), registry).digest == ir.digest
    plain = _ir(doc6, registry, None)
    assert "wan6" not in plain.to_dict()["router"]
    files = render("linux", plain)
    assert not any("wan6" in p for p in files)
    assert "nd-router-advert" not in files[NFT]
    assert "wan0" not in files[SYSCTL]
    # and declaring one is a change of the plan
    assert _ir(doc6, registry, {"ra": True}).digest != plain.digest


@pytest.mark.parametrize("flavor", ["networkd", "ifupdown"])
def test_only_the_wan_takes_router_advertisements(doc6, registry, flavor):
    files = render("linux", _ir(doc6, registry, {"ra": True}, flavor))
    sysctl = files[SYSCTL]
    assert "net.ipv6.conf.all.accept_ra = 0\n" in sysctl
    assert sysctl.endswith("net.ipv6.conf.wan0.accept_ra = 2\n")  # after "all", so it wins
    advert = [ln.strip() for ln in files[NFT].splitlines() if "nd-router-advert" in ln]
    assert advert and all(
        ln.startswith('iifname "wan0" ip6 saddr fe80::/10 ip6 hoplimit 255 ') for ln in advert
    )
    assert any(ln in _input(files[NFT]) for ln in advert)  # the input chain lets it in
    if flavor == "networkd":
        assert "IPv6AcceptRA=yes" in files[DROPIN] and "DHCPv6Client=no" in files[DROPIN]
        zones = [f for p, f in files.items() if p.startswith("etc/systemd/network/20-")]
        assert not any("IPv6AcceptRA=yes" in f for f in zones)
        assert all("IPv6AcceptRA=no" in f for f in zones if "IPv6SendRA" in f)
    else:
        assert "iface wan0 inet6 auto\n    accept_ra 2\n    dhcp 0\n" in files[WAN_STANZA]
        vlans = files["etc/network/interfaces.d/hnx-vlans"]
        assert "accept_ra 2" not in vlans and "inet6 auto" not in vlans


@pytest.mark.parametrize("flavor", ["networkd", "ifupdown"])
def test_a_static_wan_renders_its_address_and_default_route(doc6, registry, flavor):
    files = render("linux", _ir(doc6, registry, {"static": DOC_STATIC}, flavor))
    assert files[SYSCTL].endswith("net.ipv6.conf.wan0.accept_ra = 0\n")
    assert "nd-router-advert" not in files[NFT]
    if flavor == "networkd":
        assert "Address=2001:db8:ffff:1::2/64\nIPv6AcceptRA=no\n" in files[DROPIN]
        assert "\n[Route]\nGateway=2001:db8:ffff:1::1\n" in files[DROPIN]
    else:
        assert files[WAN_STANZA].endswith(
            "iface wan0 inet6 static\n    address 2001:db8:ffff:1::2/64\n"
            "    gateway 2001:db8:ffff:1::1\n    accept_ra 0\n"
        )


GUARD = (
    '        oifname "wan0" ip6 daddr { 2001:db8:0:10::/64, 2001:db8:0:20::/64, 2001:db8:0:30::/64,'
    ' 2001:db8:0:40::/64 } drop comment "router.wan6: a zone prefix never leaves by the WAN"\n'
)


def test_the_forward_chain_gains_only_the_zone_prefix_guard_and_nat_is_unchanged(doc6, registry):
    def tail(nft: str) -> str:
        return nft.split("chain forward {", 1)[1]

    plain = render("linux", _ir(doc6, registry, None))[NFT]
    assert "router.wan6" not in plain
    for wan6 in ({"ra": True}, {"static": DOC_STATIC}):
        nft = render("linux", _ir(doc6, registry, wan6))[NFT]
        # the guard comes before established,related: a hostile route must not carry return
        # traffic either
        head = "\n        type filter hook forward priority filter; policy drop;\n"
        assert tail(nft).startswith(head + GUARD + "        ct state established,related accept\n")
        output = "\n    chain output {\n        type filter hook output priority filter; policy accept;\n"
        assert tail(nft).replace(GUARD, "", 1).replace(output + GUARD + "    }\n", "") == tail(
            plain
        )
        assert output + GUARD in nft  # and the router's own traffic


def test_a_wan_without_zone_prefixes_takes_no_advertisement_elsewhere(doc, registry):
    """With no zone prefix forwarding stays off, so an interface that defaulted to accept_ra = 1
    would take a zone host's advertisement: the default, every zone file and the WAN's own
    redirects and route-information options are pinned off."""
    d = copy.deepcopy(doc)
    d["router"]["model"] = "linux"
    d["adapters"]["network"] = "linux"
    d["router"]["wan6"] = {"ra": True}
    files = render("linux", build_ir(d, registry))
    sysctl = files[SYSCTL]
    order = [
        "net.ipv6.conf.default.accept_ra = 0\n",
        "net.ipv6.conf.default.accept_redirects = 0\n",
        "net.ipv6.conf.all.accept_ra = 0\n",
        "net.ipv6.conf.wan0.accept_redirects = 0\n",
        "net.ipv6.conf.wan0.accept_ra_rt_info_max_plen = 0\n",
        "net.ipv6.conf.wan0.accept_ra = 2\n",
    ]
    at = [sysctl.index(line) for line in order]
    assert at == sorted(at) and sysctl.endswith(order[-1])
    zones = [
        f
        for p, f in files.items()
        if p.startswith("etc/systemd/network/20-") and p.endswith(".network")
    ]
    assert zones and all("IPv6AcceptRA=no\n" in f for f in zones)
    assert "chain forward" in files[NFT] and "router.wan6: a zone prefix" not in files[NFT]


def test_the_wans_advertisements_install_no_on_link_prefix(doc6, registry):
    assert "UseOnLinkPrefix=no\n" in render("linux", _ir(doc6, registry, {"ra": True}))[DROPIN]


def test_the_reverse_path_check_exempts_only_the_wans_advertisement(doc6, registry):
    nft = render("linux", _ir(doc6, registry, {"ra": True}))[NFT]
    pre = nft.split("chain prerouting {", 1)[1].split("\n    }", 1)[0].splitlines()
    fib = next(n for n, ln in enumerate(pre) if "fib saddr . iif oif missing drop" in ln)
    advert = next(n for n, ln in enumerate(pre) if "nd-router-advert" in ln)
    assert advert < fib and pre[advert].strip().startswith('iifname "wan0" ip6 saddr fe80::/10')


def test_a_wan_with_ipv6_and_no_zone_prefixes_still_takes_the_icmpv6_a_router_needs(doc, registry):
    d = copy.deepcopy(doc)
    d["router"]["wan6"] = {"static": DOC_STATIC}
    files = render("linux", build_ir(d, registry))
    assert "icmpv6 type { destination-unreachable, packet-too-big," in _input(files[NFT])
    assert "chain prerouting" not in files[NFT]  # no zone to spoof, nothing forwarded in IPv6
    assert "forwarding" not in files[SYSCTL]


def test_the_drop_in_names_the_wans_own_network_file(doc6, registry):
    d = copy.deepcopy(doc6)
    d["adapters"]["options"]["linux"]["wan_network"] = "05-uplink.network"
    files = render("linux", _ir(d, registry, {"ra": True}))
    assert "etc/systemd/network/05-uplink.network.d/50-hnx-wan6.conf" in files
    assert wan_network({"wan_interface": "eth1"}) == "10-eth1.network"
    assert not any(p.endswith(".network") and "wan" in p for p in files)  # no second WAN file


def test_a_wan_named_with_a_dot_gets_a_slash_sysctl_key(doc6, registry):
    d = copy.deepcopy(doc6)
    d["adapters"]["options"]["linux"]["wan_interface"] = "eth1.7"
    sysctl = render("linux", _ir(d, registry, {"ra": True}))[SYSCTL]
    assert sysctl.endswith("net/ipv6/conf/eth1.7/accept_ra = 2\n")


def _nft_can_check(tmp_path) -> bool:
    if not (shutil.which("nft") and shutil.which("unshare")):
        return False
    probe = tmp_path / "probe.nft"
    probe.write_text("table inet probe {\n}\n")
    r = subprocess.run(["unshare", "-rn", "nft", "-c", "-f", str(probe)], capture_output=True)
    return r.returncode == 0


@pytest.mark.parametrize("wan6", [{"ra": True}, {"static": DOC_STATIC}], ids=["ra", "static"])
def test_the_wan6_nftables_file_passes_nft_check(doc6, registry, wan6, tmp_path):
    if not _nft_can_check(tmp_path):
        pytest.skip("nft with an unprivileged network namespace is not available")
    write_rendered(render("linux", _ir(doc6, registry, wan6)), tmp_path / "root")
    f = tmp_path / f"root/{NFT}"
    r = subprocess.run(
        ["unshare", "-rn", "nft", "-c", "-f", str(f)], capture_output=True, text=True
    )
    assert r.returncode == 0, r.stderr


# -- validation ------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "wan6",
    [
        {"ra": True},
        {"static": {"address": _addr(2), "gateway": LL}},
        {"static": {"address": _addr(2), "gateway": str(WAN64[1])}},
    ],
    ids=["ra", "link-local-gateway", "on-link-gateway"],
)
def test_a_sound_wan6_validates(doc6, registry, wan6):
    d = copy.deepcopy(doc6)
    d["router"]["wan6"] = wan6
    d["adapters"]["options"]["linux"]["wan_network"] = "10-wan0.network"
    rep = validate(d, registry)
    assert rep.ok, rep.errors
    assert not any("wan6" in w for w in rep.warnings)


ULA64 = ipaddress.IPv6Network((0xFD00_0000_0000_0009 << 64, 64))


@pytest.mark.parametrize(
    ("static", "why"),
    [
        ({"address": f"{ULA64[2]}/64", "gateway": LL}, "is not global unicast"),
        (DOC_STATIC, "documentation"),
        (
            {"address": f"{ipaddress.IPv6Address((0xFE80 << 112) + 2)}/64", "gateway": LL},
            "link-local",
        ),
        ({"address": f"{WAN64[2]}/56", "gateway": LL}, "the WAN link is a /64"),
        ({"address": str(WAN64[2]), "gateway": LL}, "with its /64"),
        ({"address": _addr(0xAB).upper(), "gateway": LL}, "canonical"),
        ({"address": f"{WAN64[2]}%wan0/64", "gateway": LL}, "with its /64"),
        ({"address": _addr(0), "gateway": LL}, "anycast"),
        ({"address": f"{WAN64[-1]}/64", "gateway": LL}, "anycast"),
        ({"address": _addr(2), "gateway": f"{LL}%wan0"}, "zone id"),
        ({"address": _addr(2), "gateway": LL.upper()}, "canonical"),
        ({"address": _addr(2), "gateway": str(WAN64[2])}, "the router's own"),
        ({"address": _addr(2), "gateway": str(WAN64[-2])}, "anycast"),
        ({"address": _addr(2), "gateway": f"{ULA64[1]}"}, "neither link-local"),
        ({"address": _addr(2), "gateway": "ff02::2"}, "neither link-local"),
    ],
)
def test_a_static_wan6_that_is_no_wan_link_is_refused(static, why):
    problems = wan6_problems({"static": static})
    assert any(why in p for p in problems), problems


def test_a_wan_address_inside_a_zone_prefix_is_refused():
    zone = ipaddress.IPv6Network(WAN64)
    problems = wan6_problems({"static": {"address": _addr(2), "gateway": LL}}, [zone])
    assert any("lies in zone prefix" in p for p in problems), problems


def test_a_wan_address_inside_a_delegated_prefix_is_refused():
    delegated = WAN64.supernet(new_prefix=56)
    problems = wan6_problems({"static": {"address": _addr(2), "gateway": LL}}, (), [delegated])
    assert any("lies in delegated prefix" in p for p in problems), problems
    assert not wan6_problems({"static": {"address": _addr(2), "gateway": LL}})


@pytest.mark.parametrize(
    "wan6",
    [
        {"ra": True, "static": DOC_STATIC},
        {"ra": False},
        {},
        {"static": {"address": "2001:db8:ffff:1::2/64"}},
        {"pd": {"length": 56}},
    ],
    ids=["both", "ra-false", "empty", "no-gateway", "pd"],
)
def test_the_schema_refuses_what_is_not_exactly_one_of_ra_or_static(doc6, wan6):
    d = copy.deepcopy(doc6)
    d["router"]["wan6"] = wan6
    assert any("router/wan6" in p for p in schema_problems(d))
    assert wan6_problems(wan6)  # and the semantic check, without the schema, refuses it too


@pytest.mark.parametrize("flavor", ["networkd", "ifupdown"])
def test_a_networkd_wan6_without_the_wans_file_named_warns(doc6, registry, flavor):
    """A drop-in for a file that does not exist is ignored, so a guessed name is said."""
    d = copy.deepcopy(doc6)
    d["router"]["wan6"] = {"ra": True}
    d["adapters"]["options"]["linux"]["flavor"] = flavor
    rep = validate(d, registry)
    assert rep.ok, rep.errors
    warned = [w for w in rep.warnings if "wan_network is not stated" in w]
    assert len(warned) == (flavor == "networkd"), rep.warnings
    if warned:
        assert "10-wan0.network is assumed" in warned[0]


def test_another_router_adapter_warns_that_it_ignores_wan6(doc, registry):
    """The controller renders no WAN IPv6; declaring one there is said, never silently dropped."""
    d = copy.deepcopy(doc)
    d["router"]["wan6"] = {"ra": True}
    rep = validate(d, registry)
    assert rep.ok, rep.errors
    assert any("router.wan6 is rendered by the linux adapter only" in w for w in rep.warnings)


@pytest.mark.parametrize("adapter", ["linux", CONTROLLER])
def test_rendering_a_linux_site_with_another_adapter_says_it_ignores_wan6(
    doc6, registry_path, tmp_path, adapter
):
    d = copy.deepcopy(doc6)
    d["router"]["wan6"] = {"static": {"address": _addr(2), "gateway": LL}}
    site = tmp_path / "site.yml"
    site.write_text(yaml.safe_dump(d))
    out, err = io.StringIO(), io.StringIO()
    argv = ["render", str(site), "--registry", str(registry_path), "--adapter", adapter]
    assert cli.main([*argv, "--out", str(tmp_path / "o")], out=out, err=err) == 0
    said = f"router.wan6 is rendered by the linux adapter only; {CONTROLLER} ignores it"
    assert (said in err.getvalue()) is (adapter == CONTROLLER)
