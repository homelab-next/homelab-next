# SPDX-License-Identifier: Apache-2.0
"""The four-box lab (examples/four-box-lab, docs/four-box-lab.md) validates and renders end to end.

It is the example a new site copies, so it must keep working as the models change: the site
against its registry, the guests against the site and the node's capacity, every network adapter
and every guest target, and the few things the walkthrough promises about the result.
"""

from __future__ import annotations

import ipaddress
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
    assert line.startswith("main-1: 8 guests,")


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
    assert len(rules) == 8
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


# ------------------------------------------------------------- what the router lets through
@pytest.fixture(scope="module")
def ir(site_doc, registry):
    return build_ir(site_doc, registry)


def _zone_of(ir, ip: str) -> str:
    addr = ipaddress.ip_address(ip)
    return next(z for z, net in ir.policy.zones.items() if addr in ipaddress.ip_network(net))


def passes(ir, src_zone: str, dst_ip: str, proto: str, port: int) -> bool:
    """Whether the router lets ``src_zone`` reach ``dst_ip`` on ``proto``/``port``: its rules in
    order, first match decides, else the default.  Traffic inside one zone never reaches it."""
    if src_zone == _zone_of(ir, dst_ip):
        return True
    dst = ipaddress.ip_address(dst_ip)
    for r in ir.policy.rules:
        src_ok = r.src.kind == "any" or (r.src.kind == "zone" and r.src.name == src_zone)
        dst_ok = (
            r.dst.kind == "any"
            or (r.dst.kind == "zone" and r.dst.name == _zone_of(ir, dst_ip))
            or (r.dst.kind == "host" and any(dst in ipaddress.ip_network(c) for c in r.dst.cidrs))
        )
        if not (src_ok and dst_ok):
            continue
        if r.protocol not in ("any", proto) or (r.ports and port not in r.ports):
            continue
        return r.action == "allow"
    return ir.policy.default_action == "allow"


def _sources(ir, source: str) -> list[str]:
    if source.startswith("zone:"):
        return [source[5:]]
    if source == "any":
        # the internet is not modelled here; of the lab's zones, the operator's (mgmt) uses it
        return ["mgmt"]
    return [_zone_of(ir, source.split("/")[0])]


def test_every_guest_allow_rule_is_one_the_router_lets_through(ir, fleet):
    """A guest that opens a port to another zone is useless unless the site lets that zone
    reach it: each such rule must pass the router at both ends of its port range."""
    dead = []
    for g in fleet.guests:
        for rule in g.firewall_rules:
            lo, _, hi = str(rule["ports"]).partition(":")
            for zone in _sources(ir, rule["source"]):
                for port in {int(lo), int(hi or lo)}:
                    if not passes(ir, zone, str(g.ip), rule["proto"], port):
                        dead.append(f"{g.name} {rule['name']}: {zone} -> {rule['proto']}/{port}")
    assert dead == []


PROBE_PORTS = (22, 53, 123, 443, 1514, 1515, 3142, 4222, 8000, 8090, 8889, 9000, 9443)


def test_the_sandbox_reaches_exactly_the_bus_and_the_dfir_server(ir, registry):
    reach = {
        (h, port)
        for h, host in registry.hosts.items()
        if host.zone != "sandbox"
        for proto in ("tcp", "udp")
        for port in PROBE_PORTS
        if passes(ir, "sandbox", str(host.address), proto, port)
    }
    assert reach == {("bus-1", 4222), ("sensor-1", 8000)}


def test_nothing_outside_reaches_into_the_sandbox(ir):
    for zone in ("mgmt", "services", "data", "edge"):
        for port in PROBE_PORTS:
            assert not passes(ir, zone, "203.0.113.20", "tcp", port), (zone, port)


@pytest.mark.parametrize("zone", ["mgmt", "services", "data", "edge"])
def test_every_zone_but_the_sandbox_has_names_packages_and_time(ir, zone):
    for resolver in ("192.0.2.5", "192.0.2.6"):
        assert passes(ir, zone, resolver, "udp", 53) and passes(ir, zone, resolver, "tcp", 53)
    if zone != "edge":  # the edge has the internet itself; egress-1 is in it
        assert passes(ir, zone, "198.51.100.11", "tcp", 3142)
        assert passes(ir, zone, "198.51.100.11", "udp", 123)


def test_the_resolvers_forward_through_the_edge(ir):
    assert passes(ir, "mgmt", "198.51.100.11", "udp", 53)


def test_the_edge_reaches_only_what_it_publishes_and_its_agents(ir, registry):
    reach = {
        (h, port)
        for h, host in registry.hosts.items()
        if host.zone in ("mgmt", "services", "data")
        for port in PROBE_PORTS
        if passes(ir, "edge", str(host.address), "tcp", port)
    }
    assert reach == {
        ("dns-1", 53),
        ("dns-2", 53),
        ("idp-1", 9443),
        ("hub-1", 8090),
        ("siem-1", 1514),
        ("siem-1", 1515),
        ("sensor-1", 8000),
    }
