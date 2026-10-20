# SPDX-License-Identifier: Apache-2.0
"""One synthetic site, one fleet, one registry: load, validate and render everything together.

The network model (``homelabnext.network``) owns zones, the compute model (``homelabnext.compute``)
places guests in them, and the registry generators see both.  Each library is unit-tested on its
own; this file pins that they agree with each other.
"""

from __future__ import annotations

import ipaddress
import shutil
from pathlib import Path

import pytest
import yaml
from integration_golden import check_tree

from homelabnext.compute import ComputeError, load_fleet, open_site, render
from homelabnext.compute.gen import registry_hosts
from homelabnext.generators import flatten, generate
from homelabnext.network import adapters, build_ir, load_site, validate
from homelabnext.network.loader import load_registry
from homelabnext.registry.model import build_registry

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SITE = ROOT / "schemas" / "platform" / "examples" / "site.valid.yml"
REGISTRY = ROOT / "tests" / "network" / "fixtures" / "services.yml"
FLEET = HERE / "fleet"
KEYS = HERE / "keys.yml"


@pytest.fixture(scope="module")
def site_doc():
    return load_site(SITE)


@pytest.fixture(scope="module")
def fleet():
    zones, domain = open_site(SITE)
    assert domain == "example.internal"
    return load_fleet(FLEET, zones, domain=domain, keys_path=KEYS)


@pytest.fixture(scope="module")
def merged_registry_doc(fleet):
    base = yaml.safe_load(REGISTRY.read_text(encoding="utf-8"))
    return registry_hosts.merge_into_registry(base, registry_hosts.fragment(fleet))


def test_the_site_validates_against_its_registry(site_doc):
    report = validate(site_doc, load_registry(REGISTRY))
    assert report.ok, report.errors


def test_compute_reads_zones_through_the_network_loader(fleet, site_doc):
    ids = {z["id"] for z in site_doc["zones"]}
    assert {g.zone for g in fleet.guests} <= ids
    for g in fleet.guests:
        info = fleet.zone(g)
        zone = next(z for z in site_doc["zones"] if z["id"] == g.zone)
        assert info.subnet == zone["subnet"]
        assert info.vlan_id == zone["vlan_id"]
        assert ipaddress.ip_address(g.ip) in ipaddress.ip_network(zone["subnet"])
        assert g.ip != zone["gateway"]


def test_a_guest_outside_its_zone_is_rejected(tmp_path):
    d = tmp_path / "fleet"
    shutil.copytree(FLEET, d)
    p = d / "store-core.yml"
    p.write_text(p.read_text().replace("192.0.2.72", "198.51.100.72"), encoding="utf-8")
    zones, domain = open_site(SITE)
    with pytest.raises(ComputeError):
        load_fleet(d, zones, domain=domain, keys_path=KEYS)


def test_an_unreadable_site_is_a_compute_error(tmp_path):
    bad = tmp_path / "site.yml"
    bad.write_text("zones: [a, b]\nzones: []\n", encoding="utf-8")  # duplicate key
    with pytest.raises(ComputeError):
        open_site(bad)


def test_guest_addresses_do_not_collide_with_registry_hosts(merged_registry_doc):
    addresses = [h["address"] for h in merged_registry_doc["hosts"].values()]
    assert len(addresses) == len(set(addresses))


def test_merged_registry_builds_and_feeds_generators(merged_registry_doc):
    reg = build_registry(merged_registry_doc)
    for name in ("store-core", "batch-core", "proxy-core", "hv-b"):
        assert name in reg.hosts
    out = generate(reg, ["dns_zone", "hosts_file"])
    blob = "\n".join(text for tree in out.values() for text in tree.values())
    for ip in ("192.0.2.72", "192.0.2.141", "198.51.100.11"):
        assert ip in blob


def test_a_guest_that_disagrees_with_the_registry_is_a_clash(fleet):
    base = yaml.safe_load(REGISTRY.read_text(encoding="utf-8"))
    base["hosts"]["store-core"] = {"address": "192.0.2.99", "zone": "data", "role": "lake"}
    with pytest.raises(ComputeError, match="address"):
        registry_hosts.merge_into_registry(base, registry_hosts.fragment(fleet))


def test_end_to_end_goldens(site_doc, fleet, merged_registry_doc):
    # guests: every compute target, under one golden tree each
    targets = ("terraform-proxmox", "cloudinit", "inventory", "backup-jobs", "registry-hosts")
    for target in (*targets, "baseline-playbook"):
        check_tree(f"guests/{target}", render(fleet, target))
    # network: the same site rendered by two independent adapters
    ir = build_ir(site_doc, load_registry(REGISTRY))
    for name in ("linux", "dnsmasq", "zonefile"):
        check_tree(f"network/{name}", adapters.get(name).render(ir))
    # registry generators over the merged registry (guest hosts included)
    reg = build_registry(merged_registry_doc)
    check_tree("registry", flatten(generate(reg, ["dns_zone", "hosts_file"])))
