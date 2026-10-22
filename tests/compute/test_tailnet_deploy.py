# SPDX-License-Identifier: Apache-2.0
"""The deploy's tailnet access (site 1.2 ``tailnet.deploy``, homelabnext/tailnet.py): each rule
fails on a bad declaration and passes on the repository's sites, and the ``tailscale-acl`` target
renders exactly the declared access with policy tests that hold against its own rules."""

from __future__ import annotations

import copy
from dataclasses import replace
from pathlib import Path

import pytest
import yaml

from homelabnext import cli as hnx
from homelabnext.compute import ComputeError, load_fleet, open_site, site_flows
from homelabnext.compute.gen.tailscale_acl import PROBE_PORTS, policy
from homelabnext.compute.zones import site_deploy
from homelabnext.network import validate
from homelabnext.registry import model as regmodel
from homelabnext.tailnet import deploy_problems

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
FLEET = HERE / "fleet"
SITE_FLOWS = HERE / "site-flows.yml"
SITES = (
    REPO / "examples" / "minimal" / "site.yml",
    REPO / "schemas" / "platform" / "examples" / "site.tailnet-deploy.yml",
    SITE_FLOWS,
)
DEPLOY = {"owners": ["autogroup:admin"], "zones": ["mgmt", "data"]}


def site(**deploy) -> dict:
    doc = yaml.safe_load(SITE_FLOWS.read_text())
    doc["tailnet"] = {"deploy": {**copy.deepcopy(DEPLOY), **deploy}}
    return doc


BAD = [
    ("wildcard zone", {"zones": ["*"]}, "'*' is a wildcard or not a zone id"),
    ("any", {"zones": ["mgmt", "any"]}, "'any' is a wildcard or not a zone id"),
    ("a tag as a zone", {"zones": ["tag:zone-edge"]}, "is a wildcard or not a zone id"),
    ("unknown zone", {"zones": ["lab"]}, "'lab' is not a zone of the site"),
    ("twice", {"zones": ["mgmt", "mgmt"]}, "'mgmt' listed twice"),
    ("no zones", {"zones": []}, "list the zones the deploy reaches"),
    ("no owners", {"owners": []}, "name who may mint keys"),
    ("bad owner", {"owners": ["*"]}, "is not a user, group: or admin autogroup: owner"),
    ("owns itself", {"owners": ["tag:ci-deploy"]}, "is a tag"),
    # a tag owner lets that tag's nodes mint the deploy key: a zone tag would let a zone's
    # nodes tag themselves tag:ci-deploy, any other tag hands it to whatever carries that one
    ("zone tag owner", {"owners": ["autogroup:admin", "tag:zone-mgmt"]}, "is a tag"),
    ("tag owner", {"owners": ["tag:anything"]}, "is a tag"),
    ("member autogroup", {"owners": ["autogroup:member"]}, "is not a user, group: or admin"),
    ("zone tag", {"tag": "tag:zone-mgmt"}, "is a zone tag"),
    ("bad tag", {"tag": "ci-deploy"}, "is not a tag"),
    (
        "port without a reason",
        {"exceptions": [{"zones": ["mgmt"], "ports": [443]}]},
        "a port beyond SSH needs a reason",
    ),
    (
        "every port without a reason",
        {"exceptions": [{"zones": ["mgmt"], "ports": "*", "reason": "x"}]},
        "a port beyond SSH needs a reason",
    ),
    (
        "exception off the deploy zones",
        {"exceptions": [{"zones": ["edge"], "ports": [443], "reason": "fictional: a reason"}]},
        "'edge' is not one of tailnet.deploy.zones",
    ),
    (
        "exception to every zone",
        {"exceptions": [{"zones": ["*"], "ports": [443], "reason": "fictional: a reason"}]},
        "'*' is not one of tailnet.deploy.zones",
    ),
    (
        "ssh as an exception",
        {"exceptions": [{"zones": ["mgmt"], "ports": [22], "reason": "fictional: a reason"}]},
        "22 is the default",
    ),
]


@pytest.mark.parametrize("label,deploy,expect", BAD, ids=[b[0] for b in BAD])
def test_a_bad_deploy_declaration_fails(label, deploy, expect, tmp_path):
    doc = site(**deploy)
    assert any(expect in p for p in deploy_problems(doc)), deploy_problems(doc)
    p = tmp_path / "site.yml"
    p.write_text(yaml.safe_dump(doc, sort_keys=False))
    with pytest.raises(ComputeError, match=r"invalid tailnet\.deploy"):
        site_deploy(p)  # the guests side refuses it too: never read as "no deploy access"


@pytest.mark.parametrize("path", SITES, ids=lambda p: p.relative_to(REPO).as_posix())
def test_the_repositorys_sites_pass(path):
    doc = yaml.safe_load(path.read_text())
    assert doc["tailnet"]["deploy"]["zones"]
    assert deploy_problems(doc) == []


def test_owners_may_be_users_groups_and_admin_autogroups():
    owners = ["autogroup:admin", "autogroup:owner", "group:deployers", "ops@example.com"]
    assert deploy_problems(site(owners=owners)) == []


@pytest.mark.parametrize("owner", ["tag:zone-mgmt", "tag:anything", "tag:ci-deploy"])
def test_the_site_schema_refuses_a_tag_owner(owner):
    import json

    import jsonschema

    schema = json.loads((REPO / "schemas" / "platform" / "site.schema.json").read_text())
    item = schema["$defs"]["deploy_access"]["properties"]["owners"]["items"]
    assert not jsonschema.Draft202012Validator(item).is_valid(owner)
    assert jsonschema.Draft202012Validator(item).is_valid("group:deployers")


def test_hnx_site_validate_reports_it():
    doc = yaml.safe_load(SITES[0].read_text())
    reg = regmodel.load(REPO / "examples" / "minimal" / "services.yml")
    assert validate(doc, reg).ok
    doc["tailnet"]["deploy"]["zones"] = ["*"]  # the schema refuses a wildcard first
    assert validate(doc, reg).errors == [
        "schema: tailnet/deploy/zones/0: '*' does not match '^[a-z][a-z0-9]*(-[a-z0-9]+)*$'"
    ]
    doc["tailnet"]["deploy"]["zones"] = ["mgmt", "lab"]
    assert validate(doc, reg).errors == ["tailnet.deploy.zones: 'lab' is not a zone of the site"]


def test_no_declaration_is_no_access():
    doc = yaml.safe_load(SITE_FLOWS.read_text())
    del doc["tailnet"]
    assert deploy_problems(doc) == []


# ---------------------------------------------------------------- the rendered policy
def fleet_with(deploy=None):
    zones, domain = open_site(SITE_FLOWS)
    f = load_fleet(FLEET, zones, domain=domain, flows=site_flows(SITE_FLOWS))
    return replace(f, deploy=deploy if deploy is not None else site_deploy(SITE_FLOWS))


def _allows(acls, src: str, dst: str, proto: str = "tcp") -> bool:
    """Tailscale's accept-only evaluation of ``src`` -> ``tag:port`` (the rule shapes we emit)."""
    tag, _, port = dst.rpartition(":")
    for a in acls:
        if src not in a["src"] or a.get("proto", proto) != proto:
            continue
        for d in a["dst"]:
            t, _, ports = d.rpartition(":")
            if t == tag and (ports == "*" or port in ports.split(",")):
                return True
    return False


def test_the_policy_tests_hold_against_its_rules():
    doc = policy(fleet_with())
    assert doc["tests"]
    for t in doc["tests"]:
        for dst in t.get("accept", []):
            assert _allows(doc["acls"], t["src"], dst, t["proto"]), (t["src"], dst)
        for dst in t.get("deny", []):
            assert not _allows(doc["acls"], t["src"], dst, t["proto"]), (t["src"], dst)


def test_the_deploy_reaches_exactly_the_declared_zones_on_ssh():
    doc = policy(fleet_with())
    acls, owners = doc["acls"], doc["tagOwners"]
    assert owners["tag:ci-deploy"] == ["autogroup:admin"]
    assert owners["tag:zone-data"] == ["autogroup:admin"]  # declared, no node yet: still owned
    reached = {
        (t, p)
        for t in owners
        for p in (22, 9443, *PROBE_PORTS)
        if _allows(acls, "tag:ci-deploy", f"{t}:{p}")
    }
    assert reached == {("tag:zone-mgmt", 22), ("tag:zone-data", 22), ("tag:zone-mgmt", 9443)}
    assert not any("*" in d for a in acls if a["src"] == ["tag:ci-deploy"] for d in a["dst"])
    first = doc["tests"][0]
    assert first["src"] == "tag:ci-deploy"
    assert first["accept"] == ["tag:zone-mgmt:22", "tag:zone-mgmt:9443", "tag:zone-data:22"]
    assert "tag:zone-edge:22" in first["deny"]  # the tailnet's other tag
    assert "tag:zone-mgmt:443" in first["deny"] and "tag:zone-mgmt:9443" not in first["deny"]
    back = {t["src"] for t in doc["tests"][1:]}
    assert back == {"tag:zone-data", "tag:zone-edge", "tag:zone-mgmt"}
    assert all(t["deny"][0] == "tag:ci-deploy:22" for t in doc["tests"][1:])


def test_an_every_port_exception_is_rendered_and_tested():
    dep = dict(site_deploy(SITE_FLOWS) or {})
    dep["exceptions"] = ({"zones": ("data",), "ports": "*", "reason": "fictional: a reason"},)
    doc = policy(fleet_with(dep))
    assert {"action": "accept", "src": ["tag:ci-deploy"], "proto": "tcp",
            "dst": ["tag:zone-data:*"]} in doc["acls"]  # fmt: skip
    assert not [d for d in doc["tests"][0]["deny"] if d.startswith("tag:zone-data:")]


def test_without_a_declaration_the_policy_has_no_deploy_tag_or_tests():
    zones, domain = open_site(SITE_FLOWS)
    doc = policy(load_fleet(FLEET, zones, domain=domain, flows=site_flows(SITE_FLOWS)))
    assert "tests" not in doc and "tag:ci-deploy" not in doc["tagOwners"]
    assert not [a for a in doc["acls"] if a["src"] == ["tag:ci-deploy"]]


def test_guests_render_refuses_a_bad_declaration(tmp_path, capsys):
    p = tmp_path / "site.yml"
    p.write_text(yaml.safe_dump(site(zones=["*"]), sort_keys=False))
    args = ["guests", "render", str(FLEET), "--site", str(p), "--target", "tailscale-acl"]
    assert hnx.main([*args, "--out", str(tmp_path / "o")]) != 0
    assert "tailnet.deploy.zones" in capsys.readouterr().err
    assert not (tmp_path / "o" / "tailscale-policy.hujson").exists()
