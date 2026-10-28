# SPDX-License-Identifier: Apache-2.0
"""Bound products (ADR-0016 decision 7): guest and central bindings, the playbook plays they
render, the coverage report, the site's zone flows and the generated Tailscale policy."""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
from dataclasses import replace
from pathlib import Path

import pytest
import yaml

from homelabnext import cli as hnx
from homelabnext.compute import ComputeError, ZoneFlow, load_fleet, open_site, render, site_flows
from homelabnext.compute.baselines import coverage, set_problems
from homelabnext.compute.gen.tailscale_acl import policy
from homelabnext.compute.zones import flows_from_site, site_deploy

HERE = Path(__file__).resolve().parent
FLEET = HERE / "fleet"
SITE = HERE / "site.yml"
SITE_FLOWS = HERE / "site-flows.yml"
GOLDEN_FLOWS = HERE / "golden" / "tailscale-acl-flows" / "tailscale-policy.hujson"
REPO = HERE.parents[1]
EXAMPLE = REPO / "examples" / "minimal" / "guests"
EXAMPLE_SITE = REPO / "examples" / "minimal" / "site.yml"


def fleet_at(d: Path, site: Path = SITE, **kw):
    zones, domain = open_site(site)
    return load_fleet(
        d, zones, domain=domain, flows=site_flows(site), deploy=site_deploy(site), **kw
    )


@pytest.fixture(scope="module")
def fleet():
    return fleet_at(FLEET)


def copy_fleet(tmp_path: Path, *, baselines=None, guests=None) -> Path:
    d = tmp_path / "fleet"
    shutil.copytree(FLEET, d)
    for name, edit in (guests or {}).items():
        p = d / f"{name}.yml"
        doc = yaml.safe_load(p.read_text())
        edit(doc)
        p.write_text(yaml.safe_dump(doc, sort_keys=False))
    if baselines is not None:
        p = d / "_baselines.yml"
        doc = yaml.safe_load(p.read_text())
        baselines(doc)
        p.write_text(yaml.safe_dump(doc, sort_keys=False))
    return d


# ---------------------------------------------------------------- the set's new rules
APPLY_CASES = [
    (
        "central-without-group",
        lambda d: d["controls"]["vuln-scan"].pop("group"),
        "control 'vuln-scan' is applied centrally but names no group",
    ),
    (
        "group-on-a-guest-control",
        lambda d: d["controls"]["siem-agent"].update(group="cap_siem"),
        "control 'siem-agent' names group 'cap_siem' but is applied per guest",
    ),
    (
        "unknown-group",
        lambda d: d["controls"]["vuln-scan"].update(group="cap_moat"),
        "group 'cap_moat' is not a known inventory group",
    ),
    (
        "apply-not-guest-or-central",
        lambda d: d["controls"]["vuln-scan"].update(apply="everywhere"),
        "controls/vuln-scan/apply",
    ),
    (
        "group-not-a-cap-group",
        lambda d: d["controls"]["vuln-scan"].update(group="scanner-01"),
        "controls/vuln-scan/group",
    ),
]


@pytest.mark.parametrize(("label", "edit", "expect"), APPLY_CASES, ids=[c[0] for c in APPLY_CASES])
def test_apply_rule_fails(tmp_path, label, edit, expect):
    with pytest.raises(ComputeError) as ei:
        fleet_at(copy_fleet(tmp_path, baselines=edit))
    assert expect in str(ei.value), str(ei.value)


def test_the_repository_sets_pass_the_apply_rules(fleet):
    assert set_problems(fleet.baselines) == []
    ex = fleet_at(EXAMPLE, EXAMPLE_SITE)
    assert set_problems(ex.baselines) == []
    roles = {c: ex.baselines.role(c) for c in ex.baselines.controls}
    assert {roles[c] for c in ("siem-agent", "network-sensor", "vuln-scan", "remote-access")} == {
        "wazuh_agent",
        "suricata_enroll",
        "greenbone_target",
        "tailscale_node",
    }
    assert ex.baselines.apply("network-sensor") == "central" == ex.baselines.apply("vuln-scan")
    assert ex.baselines.apply("siem-agent") == "guest" == ex.baselines.apply("remote-access")


def test_a_1_0_control_is_applied_per_guest(fleet):
    assert "apply" not in fleet.baselines.controls["ssh-hardening"]
    assert fleet.baselines.apply("ssh-hardening") == "guest"
    assert fleet.baselines.group("ssh-hardening") is None


# ---------------------------------------------------------------- the playbook
def _sensor_rows(d: Path, site: Path = SITE) -> list[dict]:
    plays = {
        p["name"]: p
        for p in yaml.safe_load(render(fleet_at(d, site), "baseline-playbook")["baseline.yml"])
    }
    (role,) = plays["control network-sensor (detection, central)"]["roles"]
    (enrolled,) = [v for k, v in role.items() if k.endswith("_guests")]
    return enrolled


def _enroll_problems(rows: list[dict]) -> list[str]:
    spec = importlib.util.spec_from_file_location(
        "hnx_address", REPO / "ansible" / "plugins" / "filter" / "hnx_address.py"
    )
    plugin = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(plugin)
    return plugin.enroll_address_problems(rows)


def test_a_central_role_receives_a_guests_extra_addresses(tmp_path):
    """A guest that names other addresses it sends from (guest 1.6) passes them to the central
    role after its ip, so the sensor's HOME_NET holds them, with its zone's subnet after its zone,
    so the role holds them to that zone; a guest naming none has neither key.  The rows pass the
    role's own address checks (ansible/plugins/filter/hnx_address.py)."""
    extra = [
        {"address": "203.0.113.11", "why": "its second NIC, on the same edge segment"},
        {"address": "2001:db8:0:28::a", "why": "the address SLAAC gave it on the edge segment"},
    ]
    d = copy_fleet(
        tmp_path, guests={"edge-core": lambda g: g["network"].update(extra_addresses=extra)}
    )
    enrolled = _sensor_rows(d)
    rows = {r["name"]: r for r in enrolled}
    assert list(rows["edge-core"]) == [
        "id",
        "name",
        "fqdn",
        "ip",
        "extra_addresses",
        "zone",
        "subnet",
        "gateway",
    ]
    assert rows["edge-core"]["gateway"] == "203.0.113.1"
    assert rows["edge-core"]["extra_addresses"] == ["203.0.113.11", "2001:db8:0:28::a"]
    assert rows["edge-core"]["subnet"] == "203.0.113.0/24"
    assert "extra_addresses" not in rows["secrets-core"] and "subnet" not in rows["secrets-core"]
    assert "gateway" not in rows["secrets-core"]
    assert _enroll_problems(enrolled) == []


def test_a_central_role_receives_the_zones_ipv6_prefix(tmp_path):
    """Where the guest's zone gives an IPv6 prefix (site 1.4), the row carries it as ``subnet6``
    after ``subnet``, so the role accepts a global IPv6 extra address inside it, as validation
    did, and refuses one outside it."""
    site = tmp_path / "site.yml"
    doc = yaml.safe_load(SITE.read_text())
    (edge,) = [z for z in doc["zones"] if z["id"] == "edge"]
    edge["subnet6"] = "2001:db8:0:28::/64"
    site.write_text(yaml.safe_dump(doc, sort_keys=False))
    extra = [{"address": "2001:db8:0:28::a", "why": "the address SLAAC gave it on the edge"}]
    d = copy_fleet(
        tmp_path, guests={"edge-core": lambda g: g["network"].update(extra_addresses=extra)}
    )
    enrolled = _sensor_rows(d, site)
    rows = {r["name"]: r for r in enrolled}
    assert list(rows["edge-core"])[-3:] == ["subnet", "subnet6", "gateway"]
    assert rows["edge-core"]["subnet6"] == "2001:db8:0:28::/64"
    assert "subnet6" not in rows["secrets-core"]
    assert _enroll_problems(enrolled) == []
    rows["edge-core"]["extra_addresses"] = ["2001:db8:0:29::a"]  # another /64
    (msg,) = _enroll_problems(enrolled)
    assert "outside the zone's IPv6 prefix 2001:db8:0:28::/64" in msg


def test_a_central_role_receives_the_zones_gateway_and_dhcp_pool(tmp_path):
    """The row carries the zone's ``gateway`` and ``dhcp_range`` (``[first, last]``) after
    ``subnet``, so the role refuses, as validation does, an extra address that is the gateway or
    inside the pool."""
    site = tmp_path / "site.yml"
    doc = yaml.safe_load(SITE.read_text())
    (edge,) = [z for z in doc["zones"] if z["id"] == "edge"]
    edge["dhcp"] = {"range": ["203.0.113.100", "203.0.113.150"]}
    site.write_text(yaml.safe_dump(doc, sort_keys=False))
    extra = [{"address": "203.0.113.11", "why": "its second NIC, on the same edge segment"}]
    d = copy_fleet(
        tmp_path, guests={"edge-core": lambda g: g["network"].update(extra_addresses=extra)}
    )
    enrolled = _sensor_rows(d, site)
    rows = {r["name"]: r for r in enrolled}
    assert rows["edge-core"]["gateway"] == "203.0.113.1"
    assert rows["edge-core"]["dhcp_range"] == ["203.0.113.100", "203.0.113.150"]
    assert "dhcp_range" not in rows["secrets-core"]
    assert _enroll_problems(enrolled) == []
    for bad, why in (("203.0.113.1", "gateway"), ("203.0.113.120", "DHCP pool")):
        rows["edge-core"]["extra_addresses"] = [bad]
        (msg,) = _enroll_problems(enrolled)
        assert why in msg, msg


def test_central_controls_render_one_play_on_the_product_host(fleet):
    plays = {
        p["name"]: p for p in yaml.safe_load(render(fleet, "baseline-playbook")["baseline.yml"])
    }
    sensor = plays["control network-sensor (detection, central)"]
    assert sensor["hosts"] == "cap_sensor"
    (role,) = sensor["roles"]
    assert role["role"] == "suricata_enroll"
    assert role["suricata_enroll_guests"] == [
        {
            "id": "guest:edge-core",
            "name": "edge-core",
            "fqdn": "edge-core.example.internal",
            "ip": "203.0.113.10",
            "zone": "edge",
        },
        {
            "id": "guest:secrets-core",
            "name": "secrets-core",
            "fqdn": "secrets-core.example.internal",
            "ip": "192.0.2.31",
            "zone": "mgmt",
        },
    ]
    scan = plays["control vuln-scan (detection, central)"]
    assert scan["hosts"] == "cap_scanner"
    assert [g["name"] for g in scan["roles"][0]["greenbone_target_guests"]] == [
        "bus-core",
        "edge-core",
        "idp-core",
        "infer-core",
        "lake-core",
        "secrets-core",
    ]
    ts = plays["control remote-access (identity)"]
    assert ts["hosts"] == "control_remote_access" and ts["roles"] == [{"role": "tailscale_node"}]


def test_a_central_play_with_no_host_says_so(fleet):
    text = render(fleet, "baseline-playbook")["baseline.yml"]
    assert "# NO HOST: no guest of the model is in cap_scanner; this play is a no-op" in text
    assert "NO HOST: no guest of the model is in cap_sensor" not in text  # edge-core holds it


def test_an_unbound_central_control_names_its_host_group(tmp_path):
    d = copy_fleet(tmp_path, baselines=lambda x: x["controls"]["vuln-scan"].update(role=None))
    text = render(fleet_at(d), "baseline-playbook")["baseline.yml"]
    assert "# control vuln-scan (detection, central): NOT BOUND to a product yet" in text
    assert "#   hosts: cap_scanner" in text


# ---------------------------------------------------------------- coverage and CLI
def test_coverage_reports_apply_group_and_unplaced(fleet):
    rep = coverage(fleet.sorted(), fleet.baselines)
    assert rep["controls"]["network-sensor"]["apply"] == "central"
    assert rep["controls"]["network-sensor"]["group"] == "cap_sensor"
    assert rep["controls"]["siem-agent"]["apply"] == "guest"
    assert rep["unplaced"] == ["vuln-scan"]
    assert rep["summary"]["unplaced_needed"] == 1


def test_require_bound_fails_on_a_central_control_with_no_host(tmp_path, capsys):
    def bind_all(doc):
        for name, c in doc["controls"].items():
            if c["role"] is None:
                c["role"] = name.replace("-", "_")

    d = copy_fleet(tmp_path, baselines=bind_all)
    args = ["guests", "baselines", str(d), "--site", str(SITE), "--require-bound"]
    assert hnx.main(args) == 1
    err = capsys.readouterr().err
    assert "group holds no guest (nowhere to run): vuln-scan (cap_scanner)" in err
    placed = copy_fleet(
        tmp_path / "p",
        baselines=bind_all,
        guests={"lake-core": lambda x: x["capability_groups"].append("cap_scanner")},
    )
    assert (
        hnx.main(["guests", "baselines", str(placed), "--site", str(SITE), "--require-bound"]) == 0
    )
    assert "vuln-scan: greenbone_target on cap_scanner, 6 guests\n" in capsys.readouterr().out


def test_the_hub_page_shows_central_bindings(tmp_path):
    from homelabnext.compute.pages import BaselineSite
    from homelabnext.registry.model import load
    from homelabnext.status.model import sources_from_registry
    from homelabnext.status.views import build_status, load_views

    reg = load(REPO / "examples/services.yml")
    views = load_views(REPO / "examples/status/views.yml", reg, sources_from_registry(reg))
    doc = build_status({"now": "2026-10-20T13:10:00Z", "observations": [], "sources": []},
                       views, reg, [], baselines=True)  # fmt: skip
    html = BaselineSite(FLEET, SITE).handle("/baselines", "", doc)[2].decode()
    assert "<code>suricata_enroll</code> central on <code>cap_sensor</code>" in html
    assert "no host in <code>cap_scanner</code>" in html


# ---------------------------------------------------------------- site flows
def test_flows_follow_the_network_models_order():
    doc = yaml.safe_load(SITE_FLOWS.read_text())
    assert flows_from_site(doc) == (
        ZoneFlow("mgmt", "edge", ("icmp",)),
        ZoneFlow("mgmt", "edge", ("tcp",), (22, 443)),
        ZoneFlow("mgmt", "data"),
        ZoneFlow("mgmt", "compute", ("icmp",)),
    )  # edge -> mgmt port 53 is shadowed by the earlier deny


Z4 = [{"id": z} for z in ("mgmt", "data", "compute", "edge")]


def z2z(*rules):
    return {"zones": Z4, "firewall": {"default_action": "deny", "zone_to_zone": list(rules)}}


@pytest.mark.parametrize(
    ("rules", "flows"),
    [
        # ports without protocols are tcp only (the IR's default), not tcp+udp+icmp
        ([{"from": "mgmt", "to": "data", "action": "allow", "ports": [53]}],
         (ZoneFlow("mgmt", "data", ("tcp",), (53,)),)),
        # icmp beside ports is dropped, as the IR drops it
        ([{"from": "mgmt", "to": "data", "action": "allow", "ports": [22],
           "protocols": ["tcp", "icmp"]}],
         (ZoneFlow("mgmt", "data", ("tcp",), (22,)),)),
        # a deny of one protocol leaves the others to later rules
        ([{"from": "mgmt", "to": "data", "action": "deny", "protocols": ["udp"]},
          {"from": "mgmt", "to": "any", "action": "allow"}],
         (ZoneFlow("mgmt", "data", ("tcp", "icmp")), ZoneFlow("mgmt", "compute"),
          ZoneFlow("mgmt", "edge"))),
    ],
)  # fmt: skip
def test_flows_take_the_irs_protocol_defaults(rules, flows):
    assert flows_from_site(z2z(*rules)) == flows


def test_an_allow_after_a_port_level_deny_is_refused():
    deny = {"from": "mgmt", "to": "data", "action": "deny", "ports": [22]}
    with pytest.raises(ComputeError, match="mgmt -> data allows tcp on every port but"):
        flows_from_site(z2z(deny, {"from": "mgmt", "to": "any", "action": "allow"}))
    narrow = {"from": "mgmt", "to": "any", "action": "allow", "ports": [22, 443]}
    assert ZoneFlow("mgmt", "data", ("tcp",), (443,)) in flows_from_site(z2z(deny, narrow))


PORTS = (22, 53, 443, 9000)


def _random_rules(rng):
    rules = []
    for _ in range(rng.randint(1, 6)):
        src = rng.choice(Z4)["id"]
        r = {"from": src, "to": rng.choice([z["id"] for z in Z4 if z["id"] != src] + ["any"]),
             "action": rng.choice(["allow", "deny"])}  # fmt: skip
        if rng.random() < 0.5:
            r["ports"] = rng.sample(PORTS, rng.randint(1, 3))
        if rng.random() < 0.5:
            r["protocols"] = rng.sample(["tcp", "udp", "icmp"], rng.randint(1, 3))
        rules.append(r)
    return rules


def _ir_allows(rules, src, dst, proto, port):
    """First match over the network IR's own rules (default deny)."""
    for r in rules:
        if r.src.kind != "zone" or r.src.name != src:
            continue
        if r.dst.kind != "any" and not (r.dst.kind == "zone" and r.dst.name == dst):
            continue
        if r.protocol not in ("any", proto) or (r.ports and port not in r.ports):
            continue
        return r.action == "allow"
    return False


def _flows_allow(flows, src, dst, proto, port):
    return any(
        f.src == src and f.dst == dst
        and (not f.protocols or proto in f.protocols)
        and (not f.ports or (proto != "icmp" and port in f.ports))
        for f in flows
    )  # fmt: skip


def _policy_allows(acls, src, dst, proto, port):
    from homelabnext.compute.gen.tailscale_acl import zone_tag

    for a in acls:
        if a["src"] != [zone_tag(src)] or a.get("proto", proto) != proto:
            continue
        for d in a["dst"]:
            tag, _, ports = d.rpartition(":")
            if tag == zone_tag(dst) and (ports == "*" or str(port) in ports.split(",")):
                return True
    return False


def test_tailnet_flows_allow_exactly_what_the_ir_allows(fleet):
    """Property: over random site rules, every (src zone, dst zone, proto, port) the flows, and
    the rendered tailnet policy, allow is allowed by the IR's first-match evaluation, and every
    one the IR allows between two zones is allowed by them."""
    import random

    from homelabnext.compute.gen.tailscale_acl import tailnet_guests
    from homelabnext.network.ir import _rules

    tailnet = sorted({g.zone for g in tailnet_guests(fleet)})
    assert tailnet == ["edge", "mgmt"]
    nets = {z["id"]: "" for z in Z4}
    checked = refused = 0
    for seed in range(300):
        rules = _random_rules(random.Random(seed))
        doc = z2z(*rules)
        try:
            flows = flows_from_site(doc)
        except ComputeError:
            assert any(r["action"] == "deny" and "ports" in r for r in rules), rules
            refused += 1
            continue
        ir = _rules({"firewall": doc["firewall"], "zones": []}, None, nets, {})
        acls = policy(replace(fleet, flows=flows))["acls"]
        for src in nets:
            for dst in nets:
                if src == dst:
                    continue
                for proto in ("tcp", "udp", "icmp"):
                    for port in (None,) if proto == "icmp" else (*PORTS, 8080):
                        want = _ir_allows(ir, src, dst, proto, port)
                        got = _flows_allow(flows, src, dst, proto, port)
                        assert got == want, (seed, rules, src, dst, proto, port, flows)
                        if src in tailnet and dst in tailnet:
                            ts = _policy_allows(acls, src, dst, proto, port)
                            assert ts == want, (seed, rules, src, dst, proto, port, acls)
                        checked += 1
    assert checked > 30_000 and refused < 30, (checked, refused)  # most cases are expressible


def test_a_zones_only_site_has_no_flows():
    assert site_flows(SITE) == ()
    assert flows_from_site({"zones": []}) == ()


def test_the_example_sites_flows():
    assert site_flows(EXAMPLE_SITE) == (
        ZoneFlow("mgmt", "data"),
        ZoneFlow("mgmt", "compute", ("tcp",), (22, 443)),
        ZoneFlow("compute", "data", ("tcp",), (9000,)),
    )  # sandbox -> any is a deny; edge -> data is a deny; ports alone are tcp


# ---------------------------------------------------------------- Tailscale policy
def test_minimal_default_without_flows(fleet):
    assert policy(fleet) == {
        "tagOwners": {
            "tag:zone-edge": ["autogroup:admin"],
            "tag:zone-mgmt": ["autogroup:admin"],
        },
        "acls": [
            {
                "action": "accept",
                "src": ["autogroup:admin"],
                "proto": "tcp",
                "dst": ["tag:zone-edge:22", "tag:zone-mgmt:22"],
            }
        ],
    }
    text = render(fleet, "tailscale-acl")["tailscale-policy.hujson"]
    assert "// the site model lists no zone-to-zone allows: admins on SSH only" in text
    assert "//   tag:zone-mgmt: idp-core" in text


def _hujson(text: str):
    return json.loads("\n".join(x for x in text.splitlines() if not x.startswith("//")))


def test_policy_follows_the_site_flows_golden():
    f = fleet_at(FLEET, SITE_FLOWS)
    text = render(f, "tailscale-acl")["tailscale-policy.hujson"]
    if os.environ.get("HNX_UPDATE_GOLDEN") == "1":
        GOLDEN_FLOWS.parent.mkdir(parents=True, exist_ok=True)
        GOLDEN_FLOWS.write_text(text, encoding="utf-8")
    assert text == GOLDEN_FLOWS.read_text(encoding="utf-8")
    acls = _hujson(text)["acls"]
    assert {"action": "accept", "src": ["tag:zone-mgmt"], "proto": "tcp",
            "dst": ["tag:zone-edge:22,443"]} in acls  # fmt: skip
    assert {"action": "accept", "src": ["tag:zone-mgmt"], "proto": "icmp",
            "dst": ["tag:zone-edge:*"]} in acls  # fmt: skip
    assert not [a for a in acls if a["src"] == ["tag:zone-edge"]]  # the deny matched first
    # no node in data: only the deploy's declared access names it
    assert [a["src"] for a in acls if any("zone-data" in d for d in a["dst"])] == [
        ["tag:ci-deploy"]
    ]


def test_cli_renders_the_policy_with_the_sites_flows(tmp_path):
    out = tmp_path / "o"
    args = ["guests", "render", str(FLEET), "--site", str(SITE_FLOWS), "--target", "tailscale-acl"]
    assert hnx.main([*args, "--out", str(out)]) == 0
    assert (out / "tailscale-policy.hujson").read_text() == GOLDEN_FLOWS.read_text()


def test_no_tailscale_binding_means_an_empty_policy(tmp_path):
    d = copy_fleet(tmp_path, baselines=lambda x: x["controls"]["remote-access"].update(role=None))
    f = replace(fleet_at(d, SITE_FLOWS), deploy=None)
    assert policy(f) == {"tagOwners": {}, "acls": []}
    assert "nothing is reachable" in render(f, "tailscale-acl")["tailscale-policy.hujson"]
    assert policy(replace(f, baselines=None)) == {"tagOwners": {}, "acls": []}


# ---------------------------------------------------------------- the example lab's playbook
@pytest.mark.skipif(
    shutil.which("ansible-playbook") is None, reason="ansible-playbook not installed"
)
def test_the_example_labs_playbook_passes_ansible_syntax_check(tmp_path):
    f = fleet_at(EXAMPLE, EXAMPLE_SITE)
    for target in ("baseline-playbook", "inventory"):
        for rel, text in render(f, target).items():
            (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
            (tmp_path / rel).write_text(text)
    env = dict(
        os.environ,
        ANSIBLE_ROLES_PATH=str(REPO / "ansible" / "roles"),
        ANSIBLE_LOOKUP_PLUGINS=str(REPO / "ansible" / "plugins" / "lookup"),
        ANSIBLE_HOME=str(tmp_path / ".ansible"),
        ANSIBLE_NOCOLOR="1",
    )
    r = subprocess.run(
        ["ansible-playbook", "--syntax-check", "-i", str(tmp_path / "hosts.yml"),
         str(tmp_path / "baseline.yml")],
        capture_output=True, text=True, env=env, cwd=tmp_path,
    )  # fmt: skip
    assert r.returncode == 0, r.stdout + r.stderr
    plays = yaml.safe_load((tmp_path / "baseline.yml").read_text())
    # every control of base, server and model-runtime (infer-core) is bound; network-sensor,
    # remote-access and the rest come with `exposed`, `sensitive` or no default baseline, which no
    # example guest has
    assert {p["roles"][0]["role"] for p in plays} == {
        "chrony", "unattended_upgrades", "needrestart", "ssh_hardening", "sssd_ldap", "lynis", "nftables_host",
        "rsyslog_forward", "wazuh_agent", "auditd", "greenbone_target", "trivy", "rkhunter",
        "restore_drill", "etckeeper", "os_hardening",
    }  # fmt: skip
    central = [p for p in plays if p["name"].endswith(", central)")]
    assert [(p["hosts"], len(p["roles"][0][p["roles"][0]["role"] + "_guests"])) for p in central] == [
        ("cap_scanner", 4), ("cap_backup", 3)]  # fmt: skip
