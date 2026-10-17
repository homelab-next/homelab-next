# SPDX-License-Identifier: Apache-2.0
"""Firewall on by default: NIC flag rendering, the exemption rule, per-guest rules files."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest
import yaml

from homelabnext.compute import (
    ComputeError,
    MappingZones,
    ZoneInfo,
    load_fleet,
    load_nodes,
    render,
)

HERE = Path(__file__).resolve().parent
FLEET = HERE / "fleet"
STUB = MappingZones(
    [
        ZoneInfo("mgmt", "192.0.2.0/24", "192.0.2.1", None, 10),
        ZoneInfo(
            "data", "198.51.100.0/25", "198.51.100.1", ("198.51.100.100", "198.51.100.126"), 20
        ),
        ZoneInfo("compute", "198.51.100.128/25", "198.51.100.129", None, 30),
        ZoneInfo("edge", "203.0.113.0/24", "203.0.113.1", None, 40),
    ]
)
EXEMPT = {"reason": "Peers connect from changing addresses; the service authenticates itself."}


def fleet_dir(tmp_path: Path, name: str | None = None, edit=None, nodes: str | None = None) -> Path:
    d = tmp_path / "fleet"
    shutil.copytree(FLEET, d)
    if name:
        p = d / f"{name}.yml"
        doc = yaml.safe_load(p.read_text())
        edit(doc)
        p.write_text(yaml.safe_dump(doc, sort_keys=False))
    if nodes is not None:
        (d / "_nodes.yml").write_text(nodes)
    return d


def problems(d: Path) -> str:
    with pytest.raises(ComputeError) as ei:
        load_fleet(d, STUB)
    return str(ei.value)


@pytest.fixture(scope="module")
def good():
    return load_fleet(FLEET, STUB)


# ---------------------------------------------------------------- the NIC flag is always rendered
def test_every_rendered_nic_states_its_flag(good):
    tf = render(good, "terraform-proxmox")
    for name, text in tf.items():
        if name.startswith(("vm-", "ct-")):
            assert text.count("firewall = ") == 1, name


def test_absent_flag_renders_true_and_inherit_too(tmp_path):
    def drop(doc):
        doc["network"].pop("firewall", None)

    d = fleet_dir(tmp_path, "edge-core", drop)
    assert "firewall = true" in render(load_fleet(d, STUB), "terraform-proxmox")["vm-edge-core.tf"]
    d = fleet_dir(tmp_path / "b", "edge-core", lambda x: x["network"].update(firewall="inherit"))
    assert "firewall = true" in render(load_fleet(d, STUB), "terraform-proxmox")["vm-edge-core.tf"]


def test_exempt_guest_renders_false(good):
    assert "firewall = false" in render(good, "terraform-proxmox")["vm-bus-core.tf"]


def test_container_nic_gets_the_flag_too(good):
    assert "firewall = true" in render(good, "terraform-proxmox")["ct-idp-core.tf"]


# ---------------------------------------------------------------- the exemption rule
def test_flag_off_without_exemption_is_rejected(tmp_path):
    def off(doc):
        doc["network"].update(firewall="disabled")
        doc["network"].pop("firewall_exemption", None)

    out = problems(fleet_dir(tmp_path, "bus-core", off))
    assert "bus-core" in out and "firewall_exemption" in out and "hv-a" in out


def test_flag_off_with_exemption_is_accepted(tmp_path):
    d = fleet_dir(
        tmp_path,
        "infer-core",
        lambda x: x["network"].update(firewall="disabled", firewall_exemption=EXEMPT),
    )
    f = load_fleet(d, STUB)
    assert "firewall = false" in render(f, "terraform-proxmox")["vm-infer-core.tf"]


def test_flag_off_is_fine_on_a_node_without_a_firewall(tmp_path):
    def off(doc):
        doc["network"].update(firewall="disabled")
        doc["network"].pop("firewall_exemption", None)

    nodes = "nodes:\n  hv-a: {firewall: disabled}\n"
    f = load_fleet(fleet_dir(tmp_path, "bus-core", off, nodes), STUB)
    assert f.node_firewall("hv-a") is False
    assert "firewall = false" in render(f, "terraform-proxmox")["vm-bus-core.tf"]


def test_unlisted_node_is_assumed_to_run_a_firewall(good):
    assert good.node_firewall("hv-a") is True and good.node_firewall("anything") is True


def test_short_exemption_reason_is_a_schema_error(tmp_path):
    d = fleet_dir(
        tmp_path,
        "bus-core",
        lambda x: x["network"].update(firewall="disabled", firewall_exemption={"reason": "no"}),
    )
    assert "firewall_exemption" in problems(d)


def test_stale_exemption_on_an_enabled_nic_is_rejected(tmp_path):
    d = fleet_dir(tmp_path, "edge-core", lambda x: x["network"].update(firewall_exemption=EXEMPT))
    assert "exemption is set but the NIC firewall is enabled" in problems(d)


def test_rules_on_a_disabled_nic_are_rejected(tmp_path):
    def edit(doc):
        doc["network"].update(firewall="disabled", firewall_exemption=EXEMPT)
        doc["firewall_rules"] = {"inbound_allow": [{"name": "x", "proto": "icmp", "source": "any"}]}

    assert "flag is disabled" in problems(fleet_dir(tmp_path, "lake-core", edit))


def test_rules_on_a_host_are_rejected(tmp_path):
    d = fleet_dir(
        tmp_path,
        "hv-a",
        lambda x: x.update(
            firewall_rules={"inbound_allow": [{"name": "x", "proto": "icmp", "source": "any"}]}
        ),
    )
    assert "vm and lxc only" in problems(d)


# ---------------------------------------------------------------- rule semantics
def rules(*rs):
    return lambda doc: doc.update(firewall_rules={"inbound_allow": list(rs)})


@pytest.mark.parametrize(
    "rule,expect",
    [
        ({"name": "a", "proto": "tcp", "source": "any"}, "ports are required"),
        ({"name": "a", "proto": "icmp", "ports": "22", "source": "any"}, "icmp takes no ports"),
        ({"name": "a", "proto": "tcp", "ports": "0", "source": "any"}, "bad port"),
        ({"name": "a", "proto": "tcp", "ports": "9000:80", "source": "any"}, "bad port"),
        ({"name": "a", "proto": "tcp", "ports": "70000", "source": "any"}, "bad port"),
        ({"name": "a", "proto": "tcp", "ports": "22", "source": "zone:nowhere"}, "does not exist"),
        ({"name": "a", "proto": "tcp", "ports": "22", "source": "192.0.2.5/24"}, "bad source CIDR"),
    ],
)
def test_bad_rules_are_rejected(tmp_path, rule, expect):
    assert expect in problems(fleet_dir(tmp_path, "edge-core", rules(rule)))


def test_duplicate_rule_names_are_rejected(tmp_path):
    r = {"name": "a", "proto": "icmp", "source": "any"}
    assert "names must be unique" in problems(fleet_dir(tmp_path, "edge-core", rules(r, dict(r))))


# ---------------------------------------------------------------- the rules-file renderer
def test_rules_file_defaults_to_drop_inbound(good):
    fw = render(good, "firewall-rules")
    text = fw["firewall/lake-core.fw"]
    assert "policy_in: DROP" in text and "enable: 1" in text
    assert "IN ACCEPT -p tcp -dport 8443 -source 198.51.100.128/25 -log nolog # query-api" in text
    assert "IN ACCEPT -p icmp -source 192.0.2.0/24" in text  # a CIDR passes through


def test_zone_source_resolves_through_the_site_model(good):
    text = render(good, "firewall-rules")["firewall/edge-core.fw"]
    assert "-dport 22 -source 192.0.2.0/24" in text
    assert "-dport 443 -log nolog # https-public" in text  # `any` adds no -source


def test_rule_order_follows_the_file(good):
    lines = render(good, "firewall-rules")["firewall/lake-core.fw"].splitlines()
    assert [ln.rsplit("# ", 1)[1] for ln in lines if ln.startswith("IN ")] == [
        "query-api",
        "ssh-mgmt",
        "ping",
    ]


def test_guest_without_rules_gets_drop_and_nothing_else(good):
    text = render(good, "firewall-rules")["firewall/idp-core.fw"]
    assert "policy_in: DROP" in text and "IN ACCEPT" not in text


def test_exempt_and_non_iac_guests_get_no_file_but_are_listed(good):
    fw = render(good, "firewall-rules")
    assert "firewall/bus-core.fw" not in fw
    assert not any("secrets-core" in k or "hv-a" in k for k in fw)
    ex = fw["firewall/EXEMPTIONS.md"]
    assert "guest:bus-core" in ex and "2027-03-31" in ex and "authentication" in ex


def test_no_exemptions_says_none(tmp_path):
    d = fleet_dir(tmp_path, "bus-core", lambda x: x["network"].pop("firewall_exemption"))
    # drop the exemption AND re-enable the flag
    p = d / "bus-core.yml"
    doc = yaml.safe_load(p.read_text())
    doc["network"]["firewall"] = "enabled"
    p.write_text(yaml.safe_dump(doc, sort_keys=False))
    out = render(load_fleet(d, STUB), "firewall-rules")["firewall/EXEMPTIONS.md"]
    assert "None." in out


def test_render_is_deterministic(good):
    assert render(good, "firewall-rules") == render(good, "firewall-rules")


# ---------------------------------------------------------------- nodes file
def test_load_nodes_validates(tmp_path):
    p = tmp_path / "n.yml"
    p.write_text("nodes:\n  a: {firewall: enabled}\n  b: {}\n")
    assert load_nodes(p) == {"a": {"firewall": "enabled"}, "b": {"firewall": "enabled"}}
    p.write_text("nodes:\n  a: {firewall: maybe}\n")
    with pytest.raises(ComputeError):
        load_nodes(p)
    p.write_text("- not a mapping\n")
    with pytest.raises(ComputeError):
        load_nodes(p)
