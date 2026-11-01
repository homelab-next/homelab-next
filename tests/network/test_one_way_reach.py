# SPDX-License-Identifier: Apache-2.0
"""What a one-way zone can be reached by, and what the controller adapter's rule sets let a zone reach, read off
the rendered output rather than the site document."""

from __future__ import annotations

import ipaddress
import json
from dataclasses import replace
from pathlib import Path

import pytest
from netutil import render

from homelabnext.network import adapters, build_ir, load_site, validate
from homelabnext.network.adapters import AdapterError
from homelabnext.network.loader import load_registry

ROOT = Path(__file__).resolve().parents[2]
FOUR_BOX = ROOT / "examples" / "four-box-lab"
#: the controller adapter: the one that also renders switches (name the slot, not the product)
[CONTROLLER] = adapters.names_for("switch")


def _sites(doc, registry):
    four = load_site(FOUR_BOX / "site.yml")
    return [(doc, registry), (four, load_registry(FOUR_BOX / "services.yml"))]


def test_no_validated_allow_reaches_a_one_way_zone(doc, registry):
    """For every example site that validates, no IR allow has a destination covering a one-way
    zone's subnet: neither the zone itself nor ``any``."""
    for site, reg in _sites(doc, registry):
        rep = validate(site, reg)
        assert rep.ok, rep.errors
        ir = build_ir(site, reg)
        assert ir.policy.one_way, "the example has a one-way zone"
        nets = [ipaddress.ip_network(ir.policy.zones[z]) for z in ir.policy.one_way]
        for rule in ir.policy.rules:
            if rule.action != "allow":
                continue
            assert rule.dst.kind != "any", rule
            for cidr in rule.dst.cidrs:
                assert not any(ipaddress.ip_network(cidr).overlaps(n) for n in nets), rule


def test_an_allow_to_any_from_an_internet_zone_is_refused_on_a_one_way_site():
    site = load_site(FOUR_BOX / "site.yml")
    site["firewall"]["zone_to_zone"].append({"from": "edge", "to": "any", "action": "allow"})
    errs = validate(site, load_registry(FOUR_BOX / "services.yml")).errors
    assert any("allow to 'any' reaches one-way zone(s) sandbox" in e for e in errs), errs


def test_the_linux_router_answers_no_dns_to_a_one_way_zone(ir):
    nft = render("linux", ir)["etc/nftables.d/50-hnx-site.nft"]
    lines = [ln.strip() for ln in nft.splitlines()]
    drop = 'iifname "vlan50" meta l4proto { tcp, udp } th dport 53 drop'
    accept = 'iifname "vlan*" udp dport { 53, 67 } accept'
    [i] = [n for n, ln in enumerate(lines) if ln.startswith(drop)]
    assert i < lines.index(accept)


def test_the_controller_answers_no_dns_to_a_one_way_zone(ir):
    rules = json.loads(render(CONTROLLER, ir)["firewall-rules.json"])["objects"]
    local = [r for r in rules if r["ruleset"] == "LAN_LOCAL"]
    assert local == [
        {
            "name": "hnx-one-way-sandbox-no-dns",
            "enabled": True,
            "ruleset": "LAN_LOCAL",
            "rule_index": local[0]["rule_index"],
            "action": "drop",
            "protocol": "tcp_udp",
            "src_networkconf_type": "NETv4",
            "src_networkconf_id": "${network:hnx-sandbox}",
            "dst_port": "53",
            "logging": False,
            "description": "one-way zone sandbox: no resolver",
        }
    ]


def _lan_in(out: dict[str, str], src: str, dst: str | None) -> str:
    """First match over LAN_IN for a new connection from zone ``src`` to zone ``dst`` (``None``:
    a destination that is no zone, the internet), on the premise the adapter states: LAN_IN sees
    every packet a zone sends, routed LAN-to-WAN traffic included.  Port-specific rules are
    skipped: this asks about whole-zone reach."""
    doc = json.loads(out["firewall-rules.json"])
    groups = {g["name"]: g["group_members"] for g in doc["groups"]}
    for r in doc["objects"]:
        if r["ruleset"] != "LAN_IN" or r.get("state_established") or r.get("state_invalid"):
            continue
        if "src_networkconf_id" in r and r["src_networkconf_id"] != "${network:hnx-" + src + "}":
            continue
        if "dst_port" in r or "dst_address" in r or r.get("protocol") != "all":
            continue
        if "dst_networkconf_id" in r and r["dst_networkconf_id"] != f"${{network:hnx-{dst}}}":
            continue
        if "dst_firewallgroup_ids" in r:
            [ref] = r["dst_firewallgroup_ids"]
            if dst is None or not groups[ref[len("${firewallgroup:") : -1]]:
                continue
        return r["action"]
    raise AssertionError("no rule matched, not even the default-deny")


def test_controller_lan_in_lets_an_internet_zone_out_and_keeps_its_zone_policy(ir):
    """The default-deny has no destination, so the internet allow must be an explicit accept
    before it, and that accept must not open the zones the policy keeps closed."""
    out = render(CONTROLLER, ir)
    internet = {
        r.src.name for r in ir.policy.rules if r.dst.kind == "internet" and r.action == "allow"
    }
    assert internet == {"compute", "edge"}
    for z in ir.policy.zones:
        assert _lan_in(out, z, None) == ("accept" if z in internet else "drop"), z
    # edge reaches no zone as a whole: its allow to the internet must not open sandbox or mgmt
    for dst in ("sandbox", "mgmt", "compute", "data"):
        assert _lan_in(out, "edge", dst) == "drop", dst
    assert _lan_in(out, "mgmt", "data") == "accept"  # zone_to_zone[0]


def test_the_zones_group_is_every_zone_subnet(ir):
    [group] = json.loads(render(CONTROLLER, ir)["firewall-rules.json"])["groups"]
    assert group["name"] == "hnx-zones" and group["group_type"] == "address-group"
    assert sorted(group["group_members"]) == sorted(ir.policy.zones.values())


def test_controller_refuses_rules_that_would_land_behind_the_default_deny(ir):
    many = tuple(
        replace(ir.policy.rules[0], id=f"zone_to_zone[{n}]")
        for n in range(len(ir.policy.rules), 120)
    )
    big = replace(ir, policy=replace(ir.policy, rules=ir.policy.rules + many))
    with pytest.raises(AdapterError, match="land behind the default-deny at 2999"):
        render(CONTROLLER, big)
    indexes = [
        r["rule_index"]
        for r in json.loads(render(CONTROLLER, ir)["firewall-rules.json"])["objects"]
        if r["name"] != "hnx-default-deny"
    ]
    assert max(indexes) < 2999
