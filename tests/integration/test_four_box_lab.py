# SPDX-License-Identifier: Apache-2.0
"""The four-box lab (examples/four-box-lab, docs/four-box-lab.md) validates and renders end to end.

It is the example a new site copies, so it must keep working as the models change: the site
against its registry, the guests against the site and the node's capacity, every network adapter
and every guest target, and the few things the walkthrough promises about the result.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from homelabnext.compute import TARGETS, load_fleet, open_site, render
from homelabnext.compute.validate import usage_lines
from homelabnext.compute.validate import validate as validate_fleet
from homelabnext.network import adapters, build_ir, load_site, validate
from homelabnext.network.loader import load_registry

LAB = Path(__file__).resolve().parents[2] / "examples" / "four-box-lab"
SITE = LAB / "site.yml"
GUESTS = LAB / "guests"


@pytest.fixture(scope="module")
def site_doc():
    return load_site(SITE)


@pytest.fixture(scope="module")
def registry():
    return load_registry(LAB / "services.yml")


@pytest.fixture(scope="module")
def fleet():
    zones, domain = open_site(SITE)
    return load_fleet(GUESTS, zones, domain=domain, nodes_path=GUESTS / "_nodes.yml")


def test_the_site_validates_with_only_the_two_expected_warnings(site_doc, registry):
    report = validate(site_doc, registry)
    assert report.ok, report.errors
    assert len(report.warnings) == 2, report.warnings
    assert any("tls_pin" in w and "placeholder" in w for w in report.warnings)
    assert any("the mirror copies the traffic of mgmt, sandbox" in w for w in report.warnings)


def test_the_guests_validate_and_fit_the_one_node(fleet):
    assert validate_fleet(fleet) == []
    [line] = usage_lines(fleet)
    assert line.startswith("main-1: 7 guests, cores 32/496, memory 54/864 GiB")


def test_the_registry_and_the_guests_agree_on_every_address(fleet, registry):
    hosts = {h: str(v.address) for h, v in registry.hosts.items()}
    for g in fleet.guests:
        assert hosts[g.name] == str(g.ip), g.id


READY = sorted(n for n in adapters.known_names() if adapters.get(n).status == "ready")
#: the lab is Proxmox: libvirt wants per-VLAN bridges and host-filtered NICs, so it is left out
PROXMOX_TARGETS = sorted(set(TARGETS) - {"libvirt"})


@pytest.mark.parametrize("adapter", READY)
def test_every_ready_adapter_renders_the_site(site_doc, registry, adapter):
    assert adapters.get(adapter).render(build_ir(site_doc, registry))


@pytest.mark.parametrize("target", PROXMOX_TARGETS)
def test_every_guest_target_renders(fleet, target):
    assert render(fleet, target)


def test_the_switch_mirrors_the_uplink_to_the_sensor(site_doc, registry):
    out = adapters.get("unifi").render(build_ir(site_doc, registry))
    ports = {o["port_idx"]: o for o in json.loads(out["switch-ports.json"])["objects"]}
    assert ports[4]["op_mode"] == "mirror" and ports[4]["mirror_port_idx"] == 1


def test_main_1_mirrors_its_guests_to_its_spare_nic(fleet):
    out = render(fleet, "node-mirror")
    script = out["mirror/main-1/hnx-mirror.sh"]
    assert 'TO="enp65s0f1"' in script and 'BRIDGES="vmbr0"' in script


def test_every_rendered_guest_lets_ssh_in_from_mgmt_only(fleet):
    files = render(fleet, "firewall-rules")
    rules = {k: v for k, v in files.items() if k.endswith(".fw")}
    assert len(rules) == 7
    for name, text in rules.items():
        assert "IN ACCEPT -p tcp -dport 22 -source 192.0.2.0/26" in text, name
        assert "policy_in: DROP" in text, name


def test_the_vms_get_a_locked_deploy_account(fleet):
    out = render(fleet, "cloudinit")
    vms = sorted({k.split("/")[0] for k in out})
    assert vms == ["bus-1", "siem-1", "store-1"]
    for vm in vms:
        ud = out[f"{vm}/user-data"]
        assert 'name: "ansible"' in ud and "lock_passwd: true" in ud and "ssh_pwauth: false" in ud
