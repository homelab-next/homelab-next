# SPDX-License-Identifier: Apache-2.0
"""The vendor-neutral IR: interface plan, DHCP, DNS records and firewall ordering."""

from __future__ import annotations

import ipaddress
import json

from homelabnext.network import build_ir


def test_interfaces_are_sorted_by_vlan_and_named_after_it(ir):
    assert [i.vlan_id for i in ir.interfaces] == [10, 20, 30, 40, 50]
    assert [i.name for i in ir.interfaces] == ["vlan10", "vlan20", "vlan30", "vlan40", "vlan50"]
    mgmt = ir.interfaces[0]
    assert (mgmt.zone, mgmt.prefixlen) == ("mgmt", 26)
    assert mgmt.netmask == str(ipaddress.ip_network(mgmt.subnet).netmask)


def test_pools_only_for_zones_with_dhcp(ir):
    assert [p.zone for p in ir.pools] == ["mgmt", "compute", "edge", "sandbox"]
    assert "data" not in {p.zone for p in ir.pools}
    compute = next(p for p in ir.pools if p.zone == "compute")
    assert compute.lease_hours == 24
    assert len(compute.dns_servers) == 1


def test_reservations_skip_the_gateway_host_and_use_macs_when_given(ir):
    names = {r.host: r for r in ir.reservations}
    assert "edge-router" not in names  # its address is the mgmt gateway
    assert names["infer-core"].mac == "00:00:5e:00:53:21"
    assert names["dns-core"].mac is None
    assert "lake-core" not in names  # data zone has no dhcp


def test_dns_records_come_from_registry_and_static_and_are_sorted(ir):
    keys = [(r.fqdn, r.type) for r in ir.dns_records]
    assert keys == sorted(keys)
    by_origin = {}
    for r in ir.dns_records:
        by_origin.setdefault(r.origin, []).append(r)
    assert len(by_origin["registry.host"]) == 7
    assert len(by_origin["registry.service"]) == 7
    assert {r.fqdn for r in by_origin["split-horizon"]} == {
        "login.lab.example",
        "portal.lab.example",
    }
    assert by_origin["static"][0].fqdn == "router.example.internal"
    alias = next(r for r in ir.dns_records if r.fqdn == "idp.svc.example.internal")
    assert (alias.type, alias.value) == ("CNAME", "idp-core.example.internal")


def test_split_horizon_off_drops_public_overrides(doc, registry):
    doc["dns"]["policy"]["split_horizon"] = False
    assert not [r for r in build_ir(doc, registry).dns_records if r.origin == "split-horizon"]


def test_rule_order_is_exceptions_then_zone_pairs_then_any_then_internet(ir):
    ids = [r.id.split("[")[0].split(":")[0] for r in ir.policy.rules]
    first_z2z = ids.index("zone_to_zone")
    assert set(ids[:first_z2z]) == {"service_exceptions"}
    tail = ids[ids.index("egress.internet") :]
    assert set(tail) == {"egress.internet"}
    any_rules = [i for i, r in enumerate(ir.policy.rules) if r.dst.kind == "any"]
    pair_rules = [
        i
        for i, r in enumerate(ir.policy.rules)
        if r.dst.kind == "zone" and r.id.startswith("zone_to_zone")
    ]
    assert max(pair_rules) < min(any_rules)


def test_one_way_zone_can_send_only_through_its_exception(ir):
    out = [r for r in ir.policy.rules if r.src.name == "sandbox" and r.action == "allow"]
    assert [(r.dst.kind, r.service, r.ports) for r in out] == [("host", "events", (4222,))]
    assert any(
        r.src.name == "sandbox" and r.dst.kind == "any" and r.action == "deny"
        for r in ir.policy.rules
    )


def test_dns_service_expands_to_both_transports(ir):
    protos = {r.protocol for r in ir.policy.rules if r.service == "dns" and r.src.name == "data"}
    assert protos == {"udp", "tcp"}


def test_rule_ids_are_unique(ir):
    ids = [r.id for r in ir.policy.rules]
    assert len(ids) == len(set(ids))


def test_router_plan_carries_references_only(ir):
    assert ir.router.mgmt_alias == "router-console.svc.example.internal"
    assert ir.router.auth["reads"]["secret_ref"].startswith("secret:")


def test_switch_ports_are_expanded(ir):
    sw = ir.switches[0]
    assert [p.port for p in sw.ports] == [1, 2, 3, 4, 5, 6, 7, 8]
    assert sw.ports[0].kind == "trunk" and sw.ports[0].tagged_vlans == (10, 20, 30, 40, 50)
    assert sw.ports[1].native_vlan == 20


def test_ir_is_json_serialisable_and_digest_is_stable(doc, registry):
    a, b = build_ir(doc, registry), build_ir(doc, registry)
    assert a == b and a.digest == b.digest and len(a.digest) == 64
    assert json.loads(json.dumps(a.to_dict()))["site_id"] == "northwind"


def test_digest_changes_with_policy(doc, registry):
    base = build_ir(doc, registry).digest
    doc["firewall"]["zone_to_zone"].append({"from": "data", "to": "mgmt", "action": "deny"})
    assert build_ir(doc, registry).digest != base
