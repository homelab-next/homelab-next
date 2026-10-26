# SPDX-License-Identifier: Apache-2.0
"""Declared egress as network policy (ADR-0027 follow-up 6): the nftables ruleset, service and
timer rendered from the three example sites, and every input that reaches the ruleset checked."""

from __future__ import annotations

import copy
import re
from pathlib import Path

import pytest
import yaml

from homelabnext.modules import egress as eg
from homelabnext.modules import limits as ml
from homelabnext.modules import rules as mr

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
        assert ml.slice_name(mod, role) in svc.split("Wants=")[1].split("\n")[0]
    for host in {p[4] for p in placed}:
        nft = files[f"{host}/hnx-egress.nft"]
        assert nft.index("ct state established,related accept") < nft.index("socket cgroupv2")
        assert nft.rstrip().endswith("}")
        assert '    socket cgroupv2 level 1 "hnx.slice" drop\n' in nft
        assert "table inet hnx_egress\ndelete table inet hnx_egress\n" in nft


def test_external_hosts_get_nothing():
    assert not any(k.startswith("collector-edge/") for k in render("small-lab"))


def test_a_required_slot_without_rows_allows_its_hosts_and_with_rows_only_their_ports():
    nft = render("small-lab")["data/hnx-egress.nft"]
    lake = chain(nft, "example-lake", "lake")
    assert "ip daddr 192.0.2.10 accept" in lake  # the platform (dns, secrets...): no rows
    assert "ip daddr 192.0.2.11 tcp dport 9000 accept" in lake  # the object store's row
    assert "ip6 daddr 2001:db8:20::11 tcp dport 9000 accept" in lake
    assert not any("dport" in r and "192.0.2.10" in r for r in lake)


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
    assert "ip daddr != @lab4 accept" in pub and "ip6 daddr != @lab6 accept" in pub
    lab4 = re.search(r"set lab4 \{.*?elements = \{ (.*?) \}", nft, re.S).group(1)
    assert "192.0.2.0/24" in lab4 and "169.254.0.0/16" in lab4  # scope.trusted.nets is the lab
    for name in re.findall(r"chain (m_\S+) \{", nft):
        if name != eg._chain("publishing", "publisher"):
            assert "@lab4" not in nft.split(f"chain {name} {{")[1].split("}")[0], name


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
    with pytest.raises(eg.EgressError, match="host data: no addresses"):
        render(site)


@pytest.mark.parametrize(
    "bad", ["192.0.2.1; flush ruleset", "192.0.2.0/24", "not-an-address", 7, "192.0.2.1\n"]
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
    assert "| data | example-lake | lake | 192.0.2.10, 192.0.2.11 tcp/9000" in readme
    assert "| data | example-object-store | store | 192.0.2.10 |" in readme
