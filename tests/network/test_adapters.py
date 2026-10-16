# SPDX-License-Identifier: Apache-2.0
"""Golden files, determinism and idempotency for every ready adapter."""

from __future__ import annotations

import copy
import ipaddress
import json

import pytest
from netutil import check_golden, render

from homelabnext.network import adapters, build_ir
from homelabnext.network.plan import compute_plan, write_rendered

READY = ["linux", "dnsmasq", "zonefile", "unifi"]


@pytest.mark.parametrize("name", READY)
def test_golden(name, ir):
    check_golden(name, render(name, ir))


def test_golden_linux_ifupdown(doc, registry):
    doc["adapters"]["options"]["linux"]["flavor"] = "ifupdown"
    check_golden("linux-ifupdown", render("linux", build_ir(doc, registry)))


@pytest.mark.parametrize("name", READY)
def test_render_is_deterministic(name, doc, registry):
    a = render(name, build_ir(copy.deepcopy(doc), registry))
    b = render(name, build_ir(copy.deepcopy(doc), registry))
    assert a == b
    assert list(a) == sorted(a), "file order must be stable"


@pytest.mark.parametrize("name", READY)
def test_render_twice_writes_nothing_the_second_time(name, ir, tmp_path):
    rendered = render(name, ir)
    first = write_rendered(rendered, tmp_path)
    assert sorted(first) == sorted(rendered)
    mtimes = {p: (tmp_path / p).stat().st_mtime_ns for p in rendered}
    assert write_rendered(rendered, tmp_path) == []
    assert {p: (tmp_path / p).stat().st_mtime_ns for p in rendered} == mtimes


@pytest.mark.parametrize("name", READY)
def test_plan_against_own_output_is_empty(name, ir, tmp_path):
    rendered = render(name, ir)
    write_rendered(rendered, tmp_path)
    plan = compute_plan(name, rendered, tmp_path)
    assert not plan.changed
    assert plan.counts()["unchanged"] == len(rendered)


def test_no_adapter_output_contains_a_secret_or_url(ir):
    for name in READY:
        for path, text in render(name, ir).items():
            assert "://" not in text, (name, path)
            assert "hunter" not in text


def test_unifi_payloads_have_unique_object_names(ir):
    for path, text in render("unifi", ir).items():
        objs = json.loads(text).get("objects")
        if objs:
            names = [o["name"] for o in objs]
            assert len(names) == len(set(names)), path


def test_unifi_is_marked_dry_run_everywhere(ir):
    for path, text in render("unifi", ir).items():
        body = json.loads(text)
        assert body["dry_run"] is True, path
        assert "SERVER-only" in body["note"], path


def test_unifi_controller_holds_references_not_secrets(ir):
    ctl = json.loads(render("unifi", ir)["controller.json"])["controller"]
    assert ctl["endpoint"].endswith(".svc.example.internal")
    refs = [v["secret_ref"] for v in ctl["auth"].values()]
    assert refs and all(r.startswith("secret:") for r in refs)


def test_unifi_last_firewall_rule_is_default_deny(ir):
    rules = json.loads(render("unifi", ir)["firewall-rules.json"])["objects"]
    assert rules[-1]["name"] == "hnx-default-deny" and rules[-1]["action"] == "drop"
    assert [r["rule_index"] for r in rules] == sorted(r["rule_index"] for r in rules)


def test_nft_policy_is_drop_and_sandbox_is_dropped_after_its_pipe(ir):
    text = render("linux", ir)["etc/nftables.d/50-hnx-site.nft"]
    assert text.count("policy drop;") == 2  # input and forward
    lines = [ln.strip() for ln in text.splitlines()]
    pipe = next(i for i, ln in enumerate(lines) if "service_exceptions[3]" in ln)
    drop = next(i for i, ln in enumerate(lines) if "zone_to_zone[4]" in ln and " drop " in ln)
    assert pipe < drop


def test_dnsmasq_uses_mac_reservation_when_given(ir):
    text = render("dnsmasq", ir)["etc/dnsmasq.d/20-hnx-reservations.conf"]
    assert "dhcp-host=00:00:5e:00:53:21,infer-core," in text
    assert "dhcp-host=dns-core," in text


def test_zonefile_requires_a_resolver(doc, registry):
    del doc["dns"]["resolvers"]
    with pytest.raises(adapters.AdapterError, match=r"no dns\.resolvers"):
        render("zonefile", build_ir(doc, registry))


def test_zonefile_serial_is_content_derived_when_not_pinned(doc, registry):
    del doc["adapters"]["options"]["zonefile"]
    a = render("zonefile", build_ir(doc, registry))["var/lib/hnx/zones/example.internal.zone"]
    doc["firewall"]["zone_to_zone"].append({"from": "data", "to": "mgmt", "action": "deny"})
    b = render("zonefile", build_ir(doc, registry))["var/lib/hnx/zones/example.internal.zone"]
    assert a == b, "a firewall change must not bump DNS serials"
    spare = str(ipaddress.ip_network(doc["zones"][0]["subnet"])[9])
    doc["dns"]["records"]["static"].append(
        {"fqdn": "extra.example.internal", "type": "A", "value": spare}
    )
    c = render("zonefile", build_ir(doc, registry))["var/lib/hnx/zones/example.internal.zone"]
    assert a.splitlines()[3] != c.splitlines()[3]


def test_zone_files_are_structurally_sound(ir):
    """No zone-file parser in the standard library: check the shape RFC 1035 tools require."""
    for path, text in render("zonefile", ir).items():
        body = [ln for ln in text.splitlines() if ln and not ln.startswith(";")]
        assert body[0].startswith("$ORIGIN ") and body[0].endswith(".")
        assert body[1].startswith("$TTL ")
        assert body[2].startswith("@ IN SOA ") and body[2].rstrip().endswith(")")
        assert any(ln.startswith("@ IN NS ") for ln in body), path
        for ln in body[3:]:
            _owner, cls, rtype, *value = ln.split()
            assert cls == "IN" and rtype in {"NS", "A", "CNAME"} and value, ln
            if rtype == "CNAME":
                assert value[0].endswith("."), "CNAME targets must be absolute"
