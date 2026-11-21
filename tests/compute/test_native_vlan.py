# SPDX-License-Identifier: Apache-2.0
"""``network.vlan_tag_mode: native`` (guest 1.9): a NIC on the bridge's native (untagged) VLAN renders
no VLAN tag, and validation holds it to the node's ``native_vlans`` and to one native VLAN per
bridge (LL-025: tagging the native VLAN leaves a guest unreachable)."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest
import yaml

from homelabnext.compute import (
    TARGETS,
    ComputeError,
    MappingZones,
    ZoneInfo,
    load_fleet,
    load_nodes,
    render,
)

HERE = Path(__file__).resolve().parent
FLEET = HERE / "fleet"
ROWS = [
    ("mgmt", "192.0.2.0/24", "192.0.2.1", None, 10),
    ("data", "198.51.100.0/25", "198.51.100.1", ("198.51.100.100", "198.51.100.126"), 20),
    ("compute", "198.51.100.128/25", "198.51.100.129", None, 30),
    ("edge", "203.0.113.0/24", "203.0.113.1", None, 40),
]
ZONES = MappingZones([ZoneInfo(*r) for r in ROWS])
IAC = next(t for t in TARGETS if t.startswith("terraform-"))
NATIVE_10 = "nodes:\n  hv-a:\n    native_vlans: {default: 10}\n"


def fleet_dir(tmp_path: Path, edits: dict, nodes: str | None = None) -> Path:
    d = tmp_path / "fleet"
    shutil.copytree(FLEET, d)
    for name, edit in edits.items():
        p = d / f"{name}.yml"
        doc = yaml.safe_load(p.read_text())
        edit(doc)
        p.write_text(yaml.safe_dump(doc, sort_keys=False))
    if nodes is not None:
        (d / "_nodes.yml").write_text(nodes)
    return d


def native(**more):
    def edit(doc):
        doc["network"].update(vlan_tag_mode="native", **more)

    return edit


# both guests of the mgmt zone (VLAN 10), so no tagged NIC remains on the declared native VLAN
MGMT = {"idp-core": native(), "secrets-core": native()}


def tf(fleet, name: str) -> str:
    out = render(fleet, IAC)
    (key,) = [k for k in out if k.endswith(f"-{name}.tf")]
    return out[key]


def problems(d: Path) -> str:
    with pytest.raises(ComputeError) as ei:
        load_fleet(d, ZONES)
    return str(ei.value)


def test_a_native_nic_renders_no_vlan_tag_on_the_bridge(tmp_path):
    f = load_fleet(fleet_dir(tmp_path, MGMT, NATIVE_10), ZONES)
    body = tf(f, "idp-core")
    assert "vlan_id" not in body
    assert "bridge   = var.default_bridge" in body


def test_the_default_mode_still_tags_the_zone_vlan(tmp_path):
    f = load_fleet(fleet_dir(tmp_path, {}, "nodes:\n  hv-a: {}\n"), ZONES)
    assert "vlan_id  = 10" in tf(f, "idp-core")
    assert "vlan_id  = 20" in tf(f, "lake-core")


def test_a_native_nic_needs_the_node_to_declare_the_native_vlan(tmp_path):
    msg = problems(fleet_dir(tmp_path, MGMT, "nodes:\n  hv-a: {}\n"))
    assert "declares no native VLAN for bridge 'default'" in msg
    assert "idp-core" in msg


def test_a_native_nic_needs_a_node_entry_at_all(tmp_path):
    assert "declares no native VLAN" in problems(fleet_dir(tmp_path, MGMT))


def test_the_node_native_vlan_must_equal_the_zone_vlan(tmp_path):
    nodes = "nodes:\n  hv-a:\n    native_vlans: {default: 20}\n"
    msg = problems(fleet_dir(tmp_path, MGMT, nodes))
    assert "zone mgmt is VLAN 10 but node 'hv-a' declares VLAN 20 native" in msg


def test_a_native_nic_needs_a_zone_with_a_vlan(tmp_path):
    flat = MappingZones([ZoneInfo(*r[:4], None) for r in ROWS])
    with pytest.raises(ComputeError, match="native needs a zone with a vlan_id"):
        load_fleet(fleet_dir(tmp_path, MGMT, NATIVE_10), flat)


def test_one_native_vlan_per_bridge(tmp_path):
    # the mgmt guests (VLAN 10) and lake-core (data, VLAN 20) all native on the one default bridge
    msg = problems(fleet_dir(tmp_path, {**MGMT, "lake-core": native()}, NATIVE_10))
    assert "has one native VLAN" in msg
    assert "lake-core" in msg and "idp-core" in msg


def test_two_native_nics_of_one_vlan_are_fine(tmp_path):
    f = load_fleet(fleet_dir(tmp_path, MGMT, NATIVE_10), ZONES)
    assert "vlan_id" not in tf(f, "idp-core")


def test_two_bridges_may_carry_different_native_vlans(tmp_path):
    nodes = "nodes:\n  hv-a:\n    native_vlans: {default: 10, br1: 20}\n"
    edits = {**MGMT, "lake-core": native(bridge="br1")}
    f = load_fleet(fleet_dir(tmp_path, edits, nodes), ZONES)
    assert "vlan_id" not in tf(f, "lake-core")


def test_tagging_the_declared_native_vlan_is_refused(tmp_path):
    # LL-025: the node says VLAN 10 is untagged on the bridge, and the guests tag it anyway
    msg = problems(fleet_dir(tmp_path, {}, NATIVE_10))
    assert "native VLAN of bridge 'default'" in msg
    assert "set network.vlan_tag_mode: native" in msg
    assert "idp-core" in msg


def test_a_tagged_guest_on_another_vlan_is_unaffected(tmp_path):
    f = load_fleet(fleet_dir(tmp_path, MGMT, NATIVE_10), ZONES)
    assert "vlan_id  = 20" in tf(f, "lake-core")


@pytest.mark.parametrize(
    "raw",
    [
        "{}",
        "[10]",
        "{default: 0}",
        "{default: 4095}",
        "{default: '10'}",
        "{Br: 10}",
        "{default: true}",
    ],
)
def test_bad_native_vlans_are_refused_by_the_node_loader(tmp_path, raw):
    p = tmp_path / "_nodes.yml"
    p.write_text(f"nodes:\n  hv-a:\n    native_vlans: {raw}\n")
    with pytest.raises(ComputeError, match="native_vlans"):
        load_nodes(p)


def test_the_node_loader_keeps_native_vlans(tmp_path):
    p = tmp_path / "_nodes.yml"
    p.write_text("nodes:\n  hv-a:\n    native_vlans: {default: 10, br1: 20}\n")
    assert load_nodes(p)["hv-a"]["native_vlans"] == {"default": 10, "br1": 20}
