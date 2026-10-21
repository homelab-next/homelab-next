# SPDX-License-Identifier: Apache-2.0
"""Power: the site's UPSes and what each device draws from (site schema 1.1, guest 1.4
``power``; :mod:`homelabnext.power`).  Every rule fails on a bad input and passes on the
example lab; a site without a ``power`` section asks nothing."""

from __future__ import annotations

import copy
import shutil
from pathlib import Path

import pytest
import yaml

from homelabnext import power
from homelabnext.cli import main as hnx
from homelabnext.network.loader import load_site
from homelabnext.network.validate import validate
from homelabnext.registry.model import load

ROOT = Path(__file__).resolve().parents[2]
LAB = ROOT / "examples" / "lab-topology"
SITE = load_site(LAB / "site.yml")
REG = load(LAB / "services.yml")
NODES = {"hv-1": {"power": {"ups": "ups-a"}}, "hv-2": {"power": {"ups": "ups-b"}}}
HOST = {"id": "guest:nas-1", "kind": "host", "power": {"ups": "ups-b"}}
VM = {"id": "guest:app-1", "kind": "vm", "placement": {"node": "hv-1"}}
WHY = "A desk machine; shut down, not kept up."


def _site(**changes):
    doc = copy.deepcopy(SITE)
    for path, value in changes.items():
        node = doc
        *head, last = path.split(".")
        for k in head:
            node = node[int(k)] if isinstance(node, list) else node[k]
        if value is None:
            del node[last]
        else:
            node[last] = value
    return doc


# --------------------------------------------------------------------------- the site rules
def test_the_example_site_passes_and_a_site_without_power_asks_nothing():
    assert validate(SITE, REG).errors == []
    bare = _site(power=None)
    for d in [bare["router"], *bare["switches"], *bare["edge"]]:
        d.pop("power", None)
    assert power.site_problems(bare) == [] and power.site_power(bare) is None
    assert power.fleet_problems(None, {"hv-1": {}}, [{"id": "guest:h", "kind": "host"}]) == []


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"router.power": {"ups": "ups-z"}}, "router:harbor-gw: power.ups 'ups-z' is not a UPS"),
        ({"router.power": {"ups": "none"}}, "router:harbor-gw: power.ups none needs a reason"),
        ({"power.default": None}, "edge:cable-modem: no power declaration and no power.default"),
        ({"power.ups": [{"id": "ups-a"}, {"id": "ups-a"}]}, "duplicate UPS id 'ups-a'"),
        ({"power.ups": [{"id": "ups-a"}, {"id": "none"}]}, "'none' is reserved"),
        ({"edge.2.power": {"ups": "ups-a"}}, "edge harbor-gw: declare its power once"),
        ({"edge.0.power": {"ups": "ups-a"}}, "edge internet: the internet has no power"),
        ({"edge.1.id": "harbor-gw"}, "duplicate edge id 'harbor-gw'"),
        ({"power.default": {"ups": ["ups-a", "ups-q"]}}, "power.default: power.ups 'ups-q'"),
    ],
    ids=[
        "unknown-ups",
        "none-no-reason",
        "no-default",
        "dup-ups",
        "reserved-none",
        "declared-twice",
        "internet-powered",
        "dup-edge",
        "default-unknown",
    ],
)
def test_a_site_power_rule_fails_on_a_bad_input(changes, message):
    problems = power.site_problems(_site(**changes))
    assert any(message in p for p in problems), problems


def test_hnx_site_validate_reports_power_errors():
    report = validate(_site(**{"router.power": {"ups": "ups-z"}}), REG)
    assert any("'ups-z' is not a UPS of the site" in e for e in report.errors)


# -------------------------------------------------------------------------- the guest rules
FACTS = power.site_power(SITE)


def test_the_example_guests_pass():
    hosts = [
        {"id": "guest:hv-1", "kind": "host"},
        {"id": "guest:hv-2", "kind": "host"},
        HOST,
        {"id": "guest:bench-1", "kind": "host", "power": {"ups": "none", "reason": WHY}},
        VM,
    ]
    assert power.fleet_problems(FACTS, NODES, hosts) == []


@pytest.mark.parametrize(
    ("nodes", "guests", "message"),
    [
        (NODES, [HOST, {**VM, "power": {"ups": "ups-a"}}], "a vm has no power of its own"),
        ({**NODES, "hv-2": {"power": {"ups": "ups-z"}}}, [HOST], "'ups-z' is not a UPS"),
        (NODES, [{**HOST, "power": {"ups": "none"}}], "none needs a reason"),
        ({**NODES, "nas-1": {"power": {"ups": "ups-a"}}}, [HOST], "differs from _nodes.yml"),
    ],
    ids=["vm-own-power", "unknown-ups", "none-no-reason", "declared-twice"],
)
def test_a_guest_power_rule_fails_on_a_bad_input(nodes, guests, message):
    problems = power.fleet_problems(FACTS, nodes, guests)
    assert any(message in p for p in problems), problems


def test_a_ups_that_feeds_nothing_is_an_error():
    facts = {**FACTS, "ups": {**FACTS["ups"], "ups-c": {"id": "ups-c"}}}
    assert "power.ups ups-c: feeds nothing (wire it to a device, or remove it)" in (
        power.fleet_problems(facts, NODES, [HOST])
    )


def test_a_device_without_a_declaration_needs_the_default():
    facts = {**FACTS, "default": None}
    problems = power.fleet_problems(facts, {**NODES, "hv-3": {}}, [HOST])
    assert "node:hv-3: no power declaration and no power.default" in problems
    assert not any("hv-3" in p for p in power.fleet_problems(FACTS, {**NODES, "hv-3": {}}, [HOST]))


def test_resolution_and_inheritance():
    hosts = {"nas-1": HOST, "hv-1": {"id": "guest:hv-1", "kind": "host"}}
    got = power.resolve(FACTS, NODES, hosts)
    assert got["guest:hv-1"] == {"ups": ["ups-a"], "none": False, "reason": None, "source": "own"}
    assert got["node:hv-2"]["ups"] == ["ups-b"]
    assert got["edge:cable-modem"]["source"] == "default"
    assert got["switch:core-sw"]["ups"] == ["ups-a", "ups-b"]
    assert power.of_guest(VM, got) == ("guest:hv-1", got["guest:hv-1"])  # a VM: its node's
    fed = power.feeds(got, FACTS["ups"])
    assert fed["ups-b"] == ["guest:nas-1", "node:hv-2", "switch:core-sw"]


# ------------------------------------------------------------------- end to end, the CLI
def test_hnx_guests_validate_checks_power(tmp_path, capsys):
    lab = tmp_path / "lab"
    shutil.copytree(LAB, lab)
    args = ["guests", "validate", str(lab / "guests"), "--site", str(lab / "site.yml")]
    assert hnx(args) == 0
    nodes = lab / "guests" / "_nodes.yml"
    doc = yaml.safe_load(nodes.read_text())
    doc["nodes"]["hv-2"]["power"] = {"ups": "ups-z"}
    nodes.write_text(yaml.safe_dump(doc))
    assert hnx(args) != 0
    assert "'ups-z' is not a UPS of the site" in capsys.readouterr().err
