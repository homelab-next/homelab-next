# SPDX-License-Identifier: Apache-2.0
"""Declared egress as network policy (ADR-0027 follow-up 6): the nftables ruleset, service and
timer rendered from the three example sites, and every input that reaches the ruleset checked."""

from __future__ import annotations

import copy
import ipaddress
import itertools
import json
import re
from pathlib import Path

import jinja2
import pytest
import yaml

from homelabnext.modules import egress as eg
from homelabnext.modules import limits as ml
from homelabnext.modules import rules as mr
from homelabnext.modules.scope import EMBEDDED_V4

ROOT = Path(__file__).resolve().parents[2]
MODULES_DIR = ROOT / "examples/modules"


def load(p):
    return yaml.safe_load(Path(p).read_text())


MODULES = {p.parent.name: load(p) for p in sorted(MODULES_DIR.glob("*/module.yml"))}
SITES = {p.stem: load(p) for p in sorted((MODULES_DIR / "sites").glob("*.yml"))}


def rows(mod: str) -> dict:
    return mr._rows(MODULES[mod], MODULES_DIR / mod, load)


def render(site, mods=None):
    return eg.render(SITES[site] if isinstance(site, str) else site, mods or MODULES, rows)


def chain(nft: str, mod: str, role: str) -> list[str]:
    name = eg._chain(mod, role)
    body = nft.split(f"  chain {name} {{\n", 1)[1].split("\n  }\n", 1)[0]
    return [ln.strip() for ln in body.splitlines()]


@pytest.mark.parametrize("site", sorted(SITES))
def test_every_lab_placement_jumps_from_its_slice_to_its_chain(site):
    files = render(site)
    sel = mr.selected(SITES[site], MODULES)
    hosts = SITES[site]["hosts"]
    placed = [p for p in mr._placed(SITES[site], sel) if hosts[p[4]]["kind"] != "external"]
    assert placed
    for mod, _inst, role, _h, host in placed:
        nft = files[f"{host}/hnx-egress.nft"]
        path = f"hnx.slice/{ml.slice_name(mod)}/{ml.slice_name(mod, role)}"
        assert f'socket cgroupv2 level 3 "{path}" jump {eg._chain(mod, role)}\n' in nft
        assert chain(nft, mod, role)[-1] == "drop"
        svc = files[f"{host}/hnx-egress.service"]
        assert ml.slice_name(mod, role) in svc.split("Requires=")[1].split("\n")[0]
    for host in {p[4] for p in placed}:
        nft = files[f"{host}/hnx-egress.nft"]
        assert nft.index("ct state established,related accept") < nft.index("socket cgroupv2")
        assert nft.rstrip().endswith("}")
        assert '    socket cgroupv2 level 1 "hnx.slice" drop\n' in nft
        assert "table inet hnx_egress\ndelete table inet hnx_egress\n" in nft


def test_external_hosts_get_nothing():
    assert not any(k.startswith("collector-edge/") for k in render("small-lab"))


def test_a_required_slot_with_rows_allows_only_their_ports_and_dns_only_53():
    nft = render("small-lab")["data/hnx-egress.nft"]
    lake = chain(nft, "example-lake", "lake")
    assert "ip daddr 192.0.2.11 tcp dport 9000 accept" in lake  # the object store's row
    assert "ip6 daddr 2001:db8:20::11 tcp dport 9000 accept" in lake
    # the platform provides dns without rows: port 53 only, never the whole host
    assert "ip daddr 192.0.2.10 udp dport 53 accept" in lake
    assert "ip daddr 192.0.2.10 tcp dport 53 accept" in lake
    assert "ip daddr 192.0.2.10 accept" not in lake


def test_an_any_port_rule_absorbs_the_port_rules_of_its_address():
    receiver = chain(render("small-lab")["data/hnx-egress.nft"], "external-collector", "receiver")
    assert "ip daddr 192.0.2.11 accept" in receiver  # the lake catalog has no row
    assert "ip daddr 192.0.2.11 tcp dport 9000 accept" not in receiver


def test_a_svc_target_resolves_to_its_row_only():
    """A row target is its placed host's addresses at the row's port.  (In the example the edge
    role also requires the collector's slots, which already open the data host: requirements are
    the module's, not a role's.)"""
    s = eg._Site(SITES["small-lab"], MODULES, rows)
    got = s.service("t", "external-collector-receiver")
    assert sorted((a.family, a.addr, a.proto, a.port) for a in got) == [
        ("ip", "192.0.2.11", "tcp", 8443),
        ("ip6", "2001:db8:20::11", "tcp", 8443),
    ]
    assert {a.port for a in s.service("t", "samples")} == {9000}  # an instance name
    assert {a.port for a in s.service("t", "object-store")} == {9000}  # a slot name


def test_internet_is_everything_outside_the_lab_and_only_when_declared():
    files = render("full")
    host = SITES["full"]["features"]["publishing"]["placement"]["publisher"]
    nft = files[f"{host}/hnx-egress.nft"]
    pub = chain(nft, "publishing", "publisher")
    assert "ip daddr != @not_internet4 accept" in pub
    assert "ip6 daddr != @not_internet6 accept" in pub
    lab4 = re.search(r"set not_internet4 \{.*?elements = \{ (.*?) \}", nft, re.S).group(1)
    assert "192.0.2.0/24" in lab4 and "169.254.0.0/16" in lab4  # scope.trusted.nets is the lab
    for name in re.findall(r"chain (m_\S+) \{", nft):
        if name != eg._chain("publishing", "publisher"):
            assert "@not_internet4" not in nft.split(f"chain {name} {{")[1].split("}")[0], name


def test_an_isolated_role_may_reach_nothing():
    files = render("full")
    for mod, role in (("example-sandbox", "detonation"), ("example-detonation", "engine")):
        host = next(
            f.split("/")[0] for f, body in files.items() if eg._chain(mod, role) + " {" in body
        )
        assert chain(files[f"{host}/hnx-egress.nft"], mod, role)[-2:] == [
            f'limit rate 10/minute log prefix "hnx-egress {mod}/{role} " drop',
            "drop",
        ]
        assert len(chain(files[f"{host}/hnx-egress.nft"], mod, role)) == 2


def test_the_timer_reloads_and_the_service_holds_only_cap_net_admin():
    files = render("small-lab")
    assert f"OnUnitActiveSec={eg.RELOAD_S}s" in files["data/hnx-egress.timer"]
    svc = files["data/hnx-egress.service"]
    assert "CapabilityBoundingSet=CAP_NET_ADMIN\n" in svc and "NoNewPrivileges=yes" in svc
    assert "ExecStart=/usr/sbin/nft -f /etc/hnx/egress/hnx-egress.nft\n" in svc


def test_a_host_without_addresses_that_must_be_reached_is_refused():
    site = copy.deepcopy(SITES["small-lab"])
    del site["hosts"]["data"]["addresses"]
    with pytest.raises(eg.EgressError, match="host data has no addresses"):
        render(site)


@pytest.mark.parametrize(
    "bad",
    [
        "192.0.2.1; flush ruleset",
        "192.0.2.0/24",
        "not-an-address",
        7,
        "192.0.2.1\n",
        "fe80::1%x accept",  # scrub-allow: special-use addresses the policy must refuse
        "::ffff:192.0.2.1",
        "64:ff9b::c000:201",  # scrub-allow: special-use addresses the policy must refuse
        "127.0.0.1",
        "224.0.0.1",  # scrub-allow: special-use addresses the policy must refuse
        "::",
    ],
)
def test_a_bad_address_never_reaches_the_ruleset(bad):
    site = copy.deepcopy(SITES["small-lab"])
    site["hosts"]["data"]["addresses"] = [bad]
    with pytest.raises(eg.EgressError, match="host data"):
        render(site)


@pytest.mark.parametrize(
    ("key", "value", "match"),
    [
        ("port", 0, "port"),
        ("port", 70000, "port"),
        ("port", "9000", "port"),
        ("port", True, "port"),
        ("protocol", "ftp", "protocol"),
        ("host", "nowhere", "not placed"),
    ],
)
def test_a_bad_row_is_refused(key, value, match):
    def bad_rows(mod):
        r = copy.deepcopy(rows(mod))
        if mod == "example-object-store":
            r["object-store"][key] = value
        return r

    with pytest.raises(eg.EgressError, match=match):
        eg.render(SITES["small-lab"], MODULES, bad_rows)


def test_unknown_targets_and_names_are_refused():
    mods = copy.deepcopy(MODULES)
    mods["external-collector"]["egress"][0]["to"] = ["svc:no-such-row"]
    site = copy.deepcopy(SITES["small-lab"])
    site["hosts"]["collector-edge"]["kind"] = "vm"
    site["hosts"]["collector-edge"]["addresses"] = ["192.0.2.20"]
    with pytest.raises(eg.EgressError, match="svc:no-such-row"):
        render(site, mods)
    mods["external-collector"]["egress"][0]["to"] = ["svc:Bad Name"]
    with pytest.raises(eg.EgressError, match="service"):
        render(site, mods)
    mods["external-collector"]["egress"][0]["to"] = ["ftp://x"]
    with pytest.raises(eg.EgressError, match="egress target"):
        render(site, mods)


def test_a_bad_trusted_net_is_refused():
    site = copy.deepcopy(SITES["small-lab"])
    site["scope"]["trusted"]["nets"] = ["192.0.2.0/24 }"]
    with pytest.raises(eg.EgressError, match=r"trusted\.nets"):
        render(site)


def test_render_is_deterministic_and_the_readme_lists_every_role():
    assert render("full") == render("full")
    readme = render("small-lab")["README.md"]
    assert (
        "| data | example-lake | lake | 192.0.2.10 tcp/53, 192.0.2.10 udp/53, 192.0.2.11 tcp/9000"
        in readme
    )
    assert "| data | example-object-store | store | 192.0.2.10 (all ports) |" in readme
    assert "Not covered:" in readme


def _sets(nft: str) -> tuple[list, list]:
    out = []
    for name in ("not_internet4", "not_internet6"):
        body = re.search(rf"set {name} \{{.*?elements = \{{ (.*?) \}}", nft, re.S).group(1)
        out.append([ipaddress.ip_network(x) for x in body.split(", ")])
    return out[0], out[1]


@pytest.mark.parametrize(
    "nets",
    [
        ["10.1.2.0/24"],  # scrub-allow: special-use networks a site may trust
        ["192.168.1.0/24", "192.168.1.0/24"],  # scrub-allow: special-use networks a site may trust
        ["172.16.0.0/12"],  # scrub-allow: special-use networks a site may trust
    ],
)
def test_trusted_nets_inside_special_ranges_never_overlap_in_a_set(nets):
    """nftables refuses a whole interval set when one element overlaps another."""
    site = copy.deepcopy(SITES["small-lab"])
    site["scope"]["trusted"]["nets"] = nets
    for net_set in _sets(render(site)["data/hnx-egress.nft"]):
        for a, b in itertools.combinations(net_set, 2):
            assert not a.overlaps(b), (a, b)


def test_internet_is_global_unicast_and_never_a_lab_host():
    site = copy.deepcopy(SITES["full"])
    # the lab's hosts are not inside the trusted net
    private = str(ipaddress.ip_network((0x0A00_0000, 8)))  # the lab's hosts are not inside it
    site["scope"]["trusted"]["nets"] = [private]
    v4, v6 = _sets(render(site)["data-core/hnx-egress.nft"])

    def internet(addr):
        a = ipaddress.ip_address(addr)
        return not any(a in n for n in (v4 if a.version == 4 else v6))

    for host in site["hosts"].values():
        for a in host.get("addresses", []):
            assert not internet(a), a
    specials = [
        "224.0.0.1",  # scrub-allow: special-use addresses that are never the internet
        "255.255.255.255",
        "240.0.0.1",
        "198.18.0.1",
        "192.0.0.1",
        "ff02::1",
        "64:ff9b::a00:1",  # scrub-allow: special-use addresses that are never the internet
        "::",
        "2002::1",  # scrub-allow: special-use addresses that are never the internet
        "100.64.0.1",  # scrub-allow: special-use addresses that are never the internet
    ]
    for special in specials:
        assert not internet(special), special
    assert internet(str(ipaddress.ip_address(0x0808_0808)))  # a public address


@pytest.mark.parametrize("addr", [str(a) for a in eg.METADATA])
def test_a_cloud_metadata_service_is_never_a_hosts_address(addr):
    site = copy.deepcopy(SITES["small-lab"])
    site["hosts"]["data"]["addresses"] = [addr]
    with pytest.raises(eg.EgressError, match="cloud metadata service"):
        render(site)


def test_the_metadata_services_are_never_the_internet_and_match_the_guest_firewall():
    """No role reaches one over ``internet``, and the guest firewall refuses the same list."""
    for addr in eg.METADATA:
        assert any(addr in n for n in eg.NOT_INTERNET), addr
    role_vars = yaml.safe_load(
        (ROOT / "ansible/roles/nftables_host/vars/main.yml").read_text(encoding="utf-8")
    )
    guest = [
        jinja2.Template(t).render()
        for t in [*role_vars["nftables_host_refused_v4"], *role_vars["nftables_host_refused_v6"]]
    ]
    assert sorted(map(ipaddress.ip_address, guest), key=str) == sorted(eg.METADATA, key=str)


def test_not_internet_holds_no_global_address():
    """Every never-internet network is non-global, except the IPv4-embedding IPv6 prefixes and
    the broad IETF blocks that mix both (refused as a whole, on purpose)."""
    for net in eg.NOT_INTERNET:
        if net in EMBEDDED_V4 or net.prefixlen <= 23:
            continue
        assert not net.network_address.is_global, net


def test_dns_without_rows_is_port_53_only():
    got = chain(render("small-lab")["core/hnx-egress.nft"], "example-agent-runtime", "runtime")
    assert got[:2] == [
        "ip daddr 192.0.2.10 tcp dport 53 accept",
        "ip daddr 192.0.2.10 udp dport 53 accept",
    ]
    assert "ip daddr 192.0.2.10 accept" not in got


def test_a_fallback_is_reached_only_when_the_preferred_slot_is_absent():
    m = MODULES["external-collector"]
    prefs = m.get("prefers", {}).get("capabilities", [])
    assert prefs, "the example collector prefers a slot"
    pref = prefs[0]
    s = eg._Site(SITES["small-lab"], MODULES, rows)
    allows, _ = eg._role_policy(s, "external-collector", "receiver")
    to = pref["fallback"].get("to", "").removeprefix("cap:")
    if to and to in s.choices and pref["cap"].removeprefix("cap:") in s.choices:
        fallback_only = set(s.slot("t", to)) - set(s.slot("t", pref["cap"].removeprefix("cap:")))
        assert not (fallback_only & set(allows))


def test_fleet_units_start_only_after_the_policy():
    files = eg.render(
        SITES["full"], MODULES, rows, lambda m: {"publishing-run"} if m == "publishing" else set()
    )
    host = SITES["full"]["features"]["publishing"]["placement"]["publisher"]
    dropin = files[f"{host}/hnx-publishing-run.service.d/50-hnx-egress.conf"]
    assert "Requires=hnx-egress.service\nAfter=hnx-egress.service\n" in dropin


def test_the_service_fails_closed_before_loading():
    svc = render("small-lab")["data/hnx-egress.service"]
    assert "ExecStartPre=/usr/bin/test -f /sys/fs/cgroup/cgroup.controllers\n" in svc
    path = "hnx.slice/hnx-example_lake.slice/hnx-example_lake-lake.slice"
    assert f"ExecStartPre=/usr/bin/test -d /sys/fs/cgroup/{path}\n" in svc
    assert svc.index("ExecStartPre") < svc.index("ExecStart=/usr/sbin/nft")
    assert "Requires=hnx-example_lake-lake.slice" in svc and "Before=network-pre.target" in svc


def test_protocols_are_the_registry_s():
    schema = json.loads((ROOT / "schemas/platform/service.json").read_text())
    enum = None
    stack = [schema]
    while stack and enum is None:
        node = stack.pop()
        if isinstance(node, dict):
            if (
                "protocol" in node
                and isinstance(node["protocol"], dict)
                and "enum" in node["protocol"]
            ):
                enum = node["protocol"]["enum"]
            stack += list(node.values())
        elif isinstance(node, list):
            stack += node
    assert sorted(enum) == sorted(eg.PROTOCOLS)


def test_an_internet_role_never_reaches_dns_over_tls_or_quic_outside_the_lab():
    host = SITES["full"]["features"]["publishing"]["placement"]["publisher"]
    pub = chain(render("full")[f"{host}/hnx-egress.nft"], "publishing", "publisher")
    drop = pub.index("meta l4proto { tcp, udp } th dport 853 drop")
    assert drop < pub.index("ip daddr != @not_internet4 accept")
    assert drop < pub.index("ip6 daddr != @not_internet6 accept")
