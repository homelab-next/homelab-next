# SPDX-License-Identifier: Apache-2.0
"""A guest's ``capability`` comes from the platform's one capability vocabulary, not from a third
hand-written list: the class table (which classes every capability the registry, the conformance
contracts, ``capabilities.yml`` and the module slots name) plus the conformance suites.  So an edge,
DNS or hypervisor guest says so, instead of borrowing the nearest of the eighteen core names."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest
import yaml

from homelabnext.cli import main as hnx
from homelabnext.compute import KNOWN_CAPABILITIES, load_fleet, open_site
from homelabnext.compute.gen import registry_hosts
from homelabnext.compute.model import allowed_groups, group_for_capability, guest_capabilities
from homelabnext.conform.registry import CAPABILITIES, EXTENDED

ROOT = Path(__file__).resolve().parents[2]
LABS = ("four-box-lab", "minimal", "lab-topology")


def test_the_core_list_is_the_harness_s_own_not_a_copy():
    assert KNOWN_CAPABILITIES is CAPABILITIES


def test_every_conformance_capability_and_module_slot_is_a_guest_capability():
    slots = yaml.safe_load((ROOT / "examples" / "modules" / "slots.yml").read_text())["slots"]
    named = {*CAPABILITIES, *EXTENDED, *slots}
    assert {f"cap:{c}" for c in named} <= guest_capabilities()


@pytest.mark.parametrize("cap", ["cap:edge", "cap:dns", "cap:backup", "cap:hypervisor"])
def test_a_guest_may_declare_a_capability_outside_the_core_eighteen(cap):
    assert cap.removeprefix("cap:") not in CAPABILITIES
    assert cap in guest_capabilities()
    assert group_for_capability(cap) in allowed_groups()


def _lab(tmp_path: Path, name: str = "four-box-lab") -> Path:
    shutil.copytree(ROOT / "examples" / name, tmp_path / "lab")
    return tmp_path / "lab"


def _set_capability(lab: Path, guest: str, cap: str) -> None:
    path = lab / "guests" / f"{guest}.yml"
    text = path.read_text(encoding="utf-8")
    old = next(ln for ln in text.splitlines() if ln.startswith("capability: "))
    path.write_text(text.replace(old, f"capability: {cap}", 1), encoding="utf-8")


def _validate(lab: Path) -> int:
    return hnx(["guests", "validate", str(lab / "guests"), "--site", str(lab / "site.yml")])


def test_an_edge_guest_validates_and_an_unknown_capability_is_still_refused(tmp_path, capsys):
    lab = _lab(tmp_path)
    _set_capability(lab, "proxy-1", "cap:edge")
    assert _validate(lab) == 0
    _set_capability(lab, "proxy-1", "cap:teleporter")
    assert _validate(lab) == 1
    assert "capability cap:teleporter is not a known capability" in capsys.readouterr().err


def _guests(lab: str) -> list[dict]:
    return [
        yaml.safe_load(p.read_text())
        for p in sorted((ROOT / "examples" / lab / "guests").glob("*.yml"))
        if not p.name.startswith("_")
    ]


@pytest.mark.parametrize("lab", LABS)
def test_example_hypervisors_declare_the_hypervisor_capability(lab):
    hosts = [g for g in _guests(lab) if "hypervisor" in (g.get("tags") or [])]
    assert hosts
    assert {g["id"]: g["capability"] for g in hosts} == {g["id"]: "cap:hypervisor" for g in hosts}


def test_the_example_proxy_is_registered_as_the_edge_not_the_identity_provider():
    lab = ROOT / "examples" / "four-box-lab"
    zones, domain = open_site(lab / "site.yml")
    fleet = load_fleet(lab / "guests", zones, domain=domain or "example.internal")
    flat = registry_hosts.fragment(fleet)["hosts"]
    assert flat["proxy-1"]["role"] == "edge"
    assert {flat[h]["role"] for h in ("dns-1", "dns-2")} == {"dns"}
