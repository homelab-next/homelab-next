# SPDX-License-Identifier: Apache-2.0
"""Semantic validation: the example is clean; each mutation is caught with a specific message."""

from __future__ import annotations

import copy
import ipaddress
from pathlib import Path

import pytest
import yaml

from homelabnext.network import validate
from homelabnext.registry import model as regmodel

ROOT = Path(__file__).resolve().parents[2]
REGISTRY_PATH = Path(__file__).parent / "fixtures" / "services.yml"


def zone(d, zid):
    return next(z for z in d["zones"] if z["id"] == zid)


def errors(d, reg):
    return validate(d, reg).errors


def test_example_is_clean_apart_from_the_pin_placeholder(doc, registry):
    rep = validate(doc, registry)
    assert rep.ok, rep.errors
    assert [w for w in rep.warnings if "placeholder" in w]


def _dup_zone(d):
    d["zones"].append(copy.deepcopy(d["zones"][0]))


def _dup_vlan(d):
    d["zones"][1]["vlan_id"] = d["zones"][0]["vlan_id"]


def _overlap(d):
    d["zones"][1]["subnet"] = d["zones"][0]["subnet"]


def _gw_outside(d):
    d["zones"][0]["gateway"] = d["zones"][1]["gateway"]


def _gw_network_addr(d):
    z = d["zones"][0]
    z["gateway"] = str(ipaddress.ip_network(z["subnet"]).network_address)


def _dhcp_outside(d):
    zone(d, "compute")["dhcp"]["range"] = copy.deepcopy(zone(d, "mgmt")["dhcp"]["range"])


def _dhcp_reversed(d):
    zone(d, "mgmt")["dhcp"]["range"].reverse()


def _dhcp_has_gateway(d):
    z = zone(d, "mgmt")
    z["dhcp"]["range"][0] = z["gateway"]


def _dhcp_has_static_host(d, reg=None):
    z = zone(d, "compute")
    z["dhcp"]["range"][0] = "192.0.2.140"  # no-raw-endpoint: allow infer-core lives here


def _unknown_resolver(d):
    zone(d, "mgmt")["dns"]["resolvers"] = ["svc:nope"]


def _z2z_unknown_zone(d):
    d["firewall"]["zone_to_zone"][0]["to"] = "nowhere"


def _z2z_self(d):
    d["firewall"]["zone_to_zone"][0]["to"] = d["firewall"]["zone_to_zone"][0]["from"]


def _z2z_duplicate(d):
    d["firewall"]["zone_to_zone"].append(copy.deepcopy(d["firewall"]["zone_to_zone"][0]))


def _deny_with_ports(d):
    d["firewall"]["zone_to_zone"][3]["ports"] = [22]


def _ports_icmp(d):
    d["firewall"]["zone_to_zone"][1]["protocols"] = ["icmp"]


def _exc_unknown_zone(d):
    d["firewall"]["service_exceptions"][1]["from"] = ["zone:nowhere"]


def _exc_unknown_svc(d):
    d["firewall"]["service_exceptions"][1]["to"] = "svc:nope"


def _exc_duplicate(d):
    d["firewall"]["service_exceptions"].append(
        {"from": "zone:compute", "to": "svc:events", "action": "allow"}
    )


def _no_contract(d):
    d["firewall"]["zone_to_zone"] = [
        r for r in d["firewall"]["zone_to_zone"] if not r.get("one_way_contract")
    ]


def _contract_wrong_zone(d):
    d["firewall"]["zone_to_zone"].append(
        {"from": "edge", "to": "any", "action": "deny", "one_way_contract": True}
    )


def _contract_not_deny_any(d):
    r = next(r for r in d["firewall"]["zone_to_zone"] if r.get("one_way_contract"))
    r["to"] = "mgmt"


def _allow_into_one_way(d):
    d["firewall"]["zone_to_zone"].append({"from": "mgmt", "to": "sandbox", "action": "allow"})


def _allow_out_of_one_way(d):
    d["firewall"]["zone_to_zone"].append({"from": "sandbox", "to": "data", "action": "allow"})


def _one_way_internet(d):
    zone(d, "sandbox")["egress"]["internet"] = "allow"


def _any_deny_vs_internet_allow(d):
    d["firewall"]["zone_to_zone"].append({"from": "compute", "to": "any", "action": "deny"})


def _any_allow_vs_internet_deny(d):
    # data's internet egress is deny; the linux router renders an allow to 'any' with no outbound
    # interface match ahead of that deny, so data would reach the internet
    d["firewall"]["zone_to_zone"].append({"from": "data", "to": "any", "action": "allow"})


def _switch_unknown_vlan(d):
    d["switches"][0]["port_assignments"][1]["vlan"] = 99


def _switch_port_twice(d):
    d["switches"][0]["port_assignments"].append({"ports": [3], "kind": "access", "vlan": 20})


def _switch_reversed_range(d):
    d["switches"][0]["port_assignments"][1]["ports"] = ["4-2"]


def _uplink_not_trunk(d):
    d["switches"][0]["uplink_port"] = 2


def _res_unknown_host(d):
    d["dhcp_reservations"][0]["host"] = "ghost-core"


def _res_dup_mac(d):
    d["dhcp_reservations"].append({"host": "dns-core", "mac": d["dhcp_reservations"][0]["mac"]})


def _router_unknown_adapter(d):
    d["router"]["model"] = "acmerouter"


def _router_unknown_svc(d):
    d["router"]["mgmt_endpoint"] = "svc:nope"


def _adapter_pin_unknown(d):
    d["adapters"]["network"] = "acmerouter"


def _dns_outside_domain(d):
    d["dns"]["resolvers"][0]["authoritative_for"] = ["other.example.net"]


def _static_outside_domain(d):
    d["dns"]["records"]["static"][0]["fqdn"] = "router.example.net"


def _static_collides_with_host(d):
    d["dns"]["records"]["static"][0]["fqdn"] = "dns-core.example.internal"


def _static_bad_a(d):
    d["dns"]["records"]["static"][0]["value"] = "not-an-address"


def _ip_in_notes(d):
    spare = str(ipaddress.ip_network(d["zones"][0]["subnet"])[7])
    d["firewall"]["zone_to_zone"][0]["notes"] = f"temporary hole to {spare}"


def _url_in_notes(d):
    d["firewall"]["zone_to_zone"][0]["notes"] = "see https://wiki.example.org/net"


def _registry_cidr_differs(d):
    z = zone(d, "edge")
    z["subnet"] = "203.0.113.0/26"  # no-raw-endpoint: allow documentation range


def _site_missing_registry_zone(d):
    d["zones"] = [z for z in d["zones"] if z["id"] != "sandbox"]
    d["firewall"]["zone_to_zone"] = [
        r for r in d["firewall"]["zone_to_zone"] if r["from"] != "sandbox"
    ]
    d["firewall"]["service_exceptions"] = d["firewall"]["service_exceptions"][:3]


CASES = [
    (_dup_zone, "duplicate zone id"),
    (_dup_vlan, "vlan_id 10 already used"),
    (_overlap, "overlap"),
    (_gw_outside, "is outside subnet"),
    (_gw_network_addr, "network or broadcast"),
    (_dhcp_outside, "outside subnet"),
    (_dhcp_reversed, "is after end"),
    (_dhcp_has_gateway, "contains the gateway"),
    (_dhcp_has_static_host, "inside the dhcp range"),
    (_unknown_resolver, "svc:nope is not in the service registry"),
    (_z2z_unknown_zone, "to zone 'nowhere' does not exist"),
    (_z2z_self, "are both"),
    (_z2z_duplicate, "duplicate of firewall.zone_to_zone"),
    (_deny_with_ports, "whole zone pair"),
    (_ports_icmp, "ports need tcp or udp"),
    (_exc_unknown_zone, "zone:nowhere is not a zone"),
    (_exc_unknown_svc, "svc:nope is not in the service registry"),
    (_exc_duplicate, "duplicate of service_exceptions"),
    (_no_contract, "has no firewall.zone_to_zone rule with one_way_contract"),
    (_contract_wrong_zone, "not egress.one_way"),
    (_contract_not_deny_any, "must be a deny to 'any'"),
    (_allow_into_one_way, "allow into one-way zone"),
    (_allow_out_of_one_way, "may only send through service_exceptions"),
    (_one_way_internet, "one_way requires egress.internet=deny"),
    (_any_deny_vs_internet_allow, "contradicts egress.internet=allow"),
    (_any_allow_vs_internet_deny, "allow to 'any' contradicts egress.internet=deny"),
    (_switch_unknown_vlan, "vlan 99 is not a zone"),
    (_switch_port_twice, "port 3 already assigned"),
    (_switch_reversed_range, "bad port range"),
    (_uplink_not_trunk, "uplink_port 2 is not assigned as a trunk"),
    (_res_unknown_host, "not in the registry"),
    (_res_dup_mac, "mac"),
    (_router_unknown_adapter, "unknown adapter 'acmerouter'"),
    (_router_unknown_svc, "router.mgmt_endpoint"),
    (_adapter_pin_unknown, "adapters.network"),
    (_dns_outside_domain, "outside site domain"),
    (_static_outside_domain, "outside site domain"),
    (_static_collides_with_host, "one source per fact"),
    (_static_bad_a, "not an IPv4 address"),
    (_ip_in_notes, "IP literal"),
    (_url_in_notes, "URL literal"),
    (_registry_cidr_differs, "differs from registry cidr"),
    (_site_missing_registry_zone, "registry zone 'sandbox' is not a zone"),
]


@pytest.mark.parametrize(("mutate", "needle"), CASES, ids=[c[0].__name__.strip("_") for c in CASES])
def test_mutation_is_rejected(doc, registry, mutate, needle):
    mutate(doc)
    errs = errors(doc, registry)
    assert any(needle in e for e in errs), (needle, errs)


def test_exception_into_one_way_zone_is_rejected(doc, registry):
    raw = yaml.safe_load(REGISTRY_PATH.read_text(encoding="utf-8"))
    sandbox = ipaddress.ip_network(raw["zones"]["sandbox"]["cidr"])
    raw["hosts"]["sink-core"] = {"address": str(sandbox[10]), "zone": "sandbox"}
    raw["services"]["sink"] = {
        "capability": "sink",
        "host": "sink-core",
        "protocol": "tcp",
        "port": 9999,
        "owner": "x",
        "version": "1.0",
        "tls": "none",
    }
    reg = regmodel.build_registry(raw)
    doc["firewall"]["service_exceptions"].append(
        {"from": "zone:mgmt", "to": "svc:sink", "action": "allow"}
    )
    assert any("nothing may be allowed into it" in e for e in errors(doc, reg))


def test_redundant_exception_is_a_warning_not_an_error(doc, registry):
    doc["firewall"]["service_exceptions"].append(
        {"from": "zone:mgmt", "to": "svc:events", "action": "allow"}
    )
    rep = validate(doc, registry)
    assert rep.ok
    assert any("redundant" in w for w in rep.warnings)


def test_exception_inside_own_zone_is_a_warning(doc, registry):
    doc["firewall"]["service_exceptions"].append(
        {"from": "zone:data", "to": "svc:events", "action": "allow"}
    )
    rep = validate(doc, registry)
    assert rep.ok
    assert any("intra-zone" in w for w in rep.warnings)


def test_absent_pin_warns(doc, registry):
    del doc["router"]["tls_pin"]
    assert any("tls_pin is absent" in w for w in validate(doc, registry).warnings)


def test_schema_errors_stop_before_semantic_rules(doc, registry):
    doc["firewall"]["default_action"] = "allow"
    rep = validate(doc, registry)
    assert rep.errors and all(e.startswith("schema:") for e in rep.errors)


def test_default_is_deny_unless_listed(ir):
    """Every non-internet rule an author did not write is absent: the only fallthrough is deny."""
    assert ir.policy.default_action == "deny"
    listed = {(r.src.name, r.dst.name) for r in ir.policy.rules if r.dst.kind == "zone"}
    assert ("compute", "mgmt") not in listed
    assert ("edge", "mgmt") not in listed


def test_unresolved_references_against_the_stock_registry(doc):
    """The same site against the shipped example registry cannot resolve its own references."""
    stock = regmodel.load(ROOT / "schemas" / "platform" / "examples" / "service.valid.yml")
    errs = errors(doc, stock)
    assert any("svc:router-console is not in the service registry" in e for e in errs)
    assert any("differs from registry cidr" in e or "is not a zone of this site" in e for e in errs)


@pytest.mark.parametrize("value", ["lan\n", "lan\r", "a\nb"])
def test_control_characters_are_refused_before_the_schema(doc, registry, value):
    """Python's re lets a schema pattern's ``$`` match before a trailing newline; adapters write
    line-oriented configs, so the newline must never reach them."""
    d = copy.deepcopy(doc)
    d["zones"][0]["id"] = value
    errs = errors(d, registry)
    assert any(e.startswith("unsafe: zones/0/id: control character") for e in errs), errs
