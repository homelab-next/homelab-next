# SPDX-License-Identifier: Apache-2.0
"""``hnx site query`` and :func:`homelabnext.network.ir.evaluate`: "can X reach Y" answered from
the policy before anything is deployed, by first match in the order the IR documents."""

from __future__ import annotations

import copy
import json
from dataclasses import replace
from pathlib import Path

import pytest
import yaml

from homelabnext.network import build_ir, load_site
from homelabnext.network.cli import main
from homelabnext.network.ir import Policy, Rule, Selector, evaluate
from homelabnext.network.loader import load_registry

ROOT = Path(__file__).resolve().parents[2]
FOUR_BOX = ROOT / "examples" / "four-box-lab"


@pytest.fixture(scope="module")
def four():
    return build_ir(load_site(FOUR_BOX / "site.yml"), load_registry(FOUR_BOX / "services.yml"))


def _addr(ir, zone, n=10):
    import ipaddress

    return str(ipaddress.ip_network(ir.policy.zones[zone])[n])


def test_a_zone_rule_allows_its_ports_only(four):
    v = evaluate(four.policy, _addr(four, "mgmt"), _addr(four, "services"), "tcp", 22)
    assert (v.action, v.rule.id) == ("allow", "zone_to_zone[0]")
    v = evaluate(four.policy, _addr(four, "mgmt"), _addr(four, "services"), "tcp", 23)
    assert (v.action, v.rule, v.reason) == ("deny", None, "firewall.default_action")
    assert (
        evaluate(four.policy, _addr(four, "mgmt"), _addr(four, "services"), "icmp").action == "deny"
    )


def test_a_host_exception_beats_a_wider_zone_rule_and_internet_egress_is_per_zone(four):
    sandbox, data = _addr(four, "sandbox"), _addr(four, "data")
    assert evaluate(four.policy, sandbox, data, "tcp", 22).rule.id == "zone_to_zone[4]"
    exc = next(r for r in four.policy.rules if r.id.startswith("service_exceptions[11]"))
    host = exc.dst.cidrs[0].split("/")[0]
    v = evaluate(four.policy, sandbox, host, "tcp", exc.ports[0])
    assert (v.action, v.rule.id) == ("allow", exc.id)  # first match: before the sandbox deny
    outside = "198.51.100.200"
    assert evaluate(four.policy, _addr(four, "edge"), outside, "tcp", 443).action == "allow"
    assert evaluate(four.policy, _addr(four, "mgmt"), outside, "tcp", 443).rule.id == (
        "egress.internet:mgmt"
    )


def test_ipv6_reads_each_rules_ipv6_form():
    zones = {"a": "192.0.2.0/26", "b": "192.0.2.64/26"}
    zones6 = {"a": "2001:db8:0:1::/64", "b": "2001:db8:0:2::/64"}
    z = {k: Selector("zone", k, (v,)) for k, v in zones.items()}
    host = Selector("host", "h", ("192.0.2.70/32",), "b")
    rules = (
        Rule("deny-h", "deny", z["a"], host, "any"),
        Rule("a-b", "allow", z["a"], z["b"], "tcp", (443,)),
    )
    pol = Policy("deny", zones, rules, zones6)
    # IPv4: only the host is closed; IPv6 has no host address, so the deny closes zone b
    assert evaluate(pol, "192.0.2.1", "192.0.2.65", "tcp", 443).rule.id == "a-b"
    assert evaluate(pol, "192.0.2.1", "192.0.2.70", "tcp", 443).rule.id == "deny-h"
    v = evaluate(pol, "2001:db8:0:1::5", "2001:db8:0:2::5", "tcp", 443)
    assert (v.action, v.rule.id) == ("deny", "deny-h:v6")
    no_deny = replace(pol, rules=rules[1:])
    assert evaluate(no_deny, "2001:db8:0:1::5", "2001:db8:0:2::5", "tcp", 443).rule.id == "a-b:v6"


@pytest.mark.parametrize(
    ("args", "why"),
    [
        (("192.0.2.1", "2001:db8::1", "icmp", None), "not one address family"),
        (("192.0.2.1", "192.0.2.65", "tcp", None), "need a port"),
        (("192.0.2.1", "192.0.2.65", "icmp", 7), "need a port"),
        (("192.0.2.1", "192.0.2.65", "sctp", 1), "protocol 'sctp'"),
    ],
)
def test_a_query_that_cannot_be_asked_is_refused(four, args, why):
    with pytest.raises(ValueError, match=why):
        evaluate(four.policy, *args)


def _run(capsys, *argv):
    code = main(["query", str(FOUR_BOX / "site.yml"), *argv])
    out = capsys.readouterr()
    return code, out.out, out.err


def test_the_cli_answers_with_the_deciding_rule(four, capsys):
    code, out, _ = _run(capsys, _addr(four, "mgmt"), _addr(four, "services"), "tcp", "22")
    assert code == 0
    assert out.strip() == (
        f"allow: {_addr(four, 'mgmt')} -> {_addr(four, 'services')} tcp/22 "
        "(zone_to_zone[0]: mgmt -> services)"
    )
    exc = next(r for r in four.policy.rules if r.dst.kind == "host")
    code, out, _ = _run(
        capsys, _addr(four, exc.src.name), exc.dst.name, exc.protocol, str(exc.ports[0]), "--json"
    )
    doc = json.loads(out)
    assert (code, doc["action"], doc["rule"]) == (0, "allow", exc.id)
    assert doc["to"] == exc.dst.cidrs[0].split("/")[0]  # the host's name resolved


def test_the_cli_refuses_an_unknown_host_or_a_portless_tcp_query(four, capsys):
    code, _, err = _run(capsys, "no-such-host", _addr(four, "data"), "icmp")
    assert code == 2 and "neither an address nor a host the site names" in err
    code, _, err = _run(capsys, _addr(four, "mgmt"), _addr(four, "data"), "tcp")
    assert code == 2 and "need a port" in err


def test_the_cli_refuses_an_invalid_site(tmp_path, capsys):
    site = copy.deepcopy(load_site(FOUR_BOX / "site.yml"))
    site["zones"][0]["subnet"] = "not-a-network"

    path = tmp_path / "site.yml"
    path.write_text(yaml.safe_dump(site), encoding="utf-8")
    code = main(
        [
            "query",
            str(path),
            "--registry",
            str(FOUR_BOX / "services.yml"),
            "192.0.2.1",
            "192.0.2.2",
            "icmp",
        ]
    )
    assert code == 1
