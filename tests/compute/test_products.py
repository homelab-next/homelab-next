# SPDX-License-Identifier: Apache-2.0
"""Bound products (ADR-0016 decision 7): guest and central bindings, the playbook plays they
render, the coverage report, the site's zone flows and the generated Tailscale policy."""

from __future__ import annotations

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
from homelabnext.compute.zones import flows_from_site

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
    return load_fleet(d, zones, domain=domain, flows=site_flows(site), **kw)


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
        ZoneFlow("mgmt", "edge", ("tcp",), (22, 443)),
        ZoneFlow("mgmt", "data"),
        ZoneFlow("mgmt", "data", ("icmp",)),
        ZoneFlow("mgmt", "compute", ("icmp",)),
        ZoneFlow("mgmt", "edge", ("icmp",)),
    )  # edge -> mgmt port 53 is shadowed by the earlier deny


def test_a_zones_only_site_has_no_flows():
    assert site_flows(SITE) == ()
    assert flows_from_site({"zones": []}) == ()


def test_the_example_sites_flows():
    assert site_flows(EXAMPLE_SITE) == (
        ZoneFlow("mgmt", "data"),
        ZoneFlow("mgmt", "compute", ("tcp",), (22, 443)),
        ZoneFlow("compute", "data", (), (9000,)),
    )  # sandbox -> any is a deny; edge -> data is a deny


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
    assert not [a for a in acls if any("zone-data" in d for d in a["dst"])]  # no node in data


def test_cli_renders_the_policy_with_the_sites_flows(tmp_path):
    out = tmp_path / "o"
    args = ["guests", "render", str(FLEET), "--site", str(SITE_FLOWS), "--target", "tailscale-acl"]
    assert hnx.main([*args, "--out", str(out)]) == 0
    assert (out / "tailscale-policy.hujson").read_text() == GOLDEN_FLOWS.read_text()


def test_no_tailscale_binding_means_an_empty_policy(tmp_path):
    d = copy_fleet(tmp_path, baselines=lambda x: x["controls"]["remote-access"].update(role=None))
    f = fleet_at(d, SITE_FLOWS)
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
    # network-sensor and remote-access come with `exposed`, which no example guest has yet
    assert {p["roles"][0]["role"] for p in plays} == {"wazuh_agent", "greenbone_target"}
