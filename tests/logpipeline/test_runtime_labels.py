# SPDX-License-Identifier: Apache-2.0
"""The runtime label (docs/log-pipeline.md): the table, the enrichment rule, and the evasion
fixtures that run the enrichment and then the model-runtime detections on what it produced."""

from __future__ import annotations

import copy
import ipaddress
import json
from pathlib import Path

import pytest

from homelabnext.compute.loader import load_fleet
from homelabnext.compute.model import ComputeError
from homelabnext.compute.render import render
from homelabnext.compute.zones import open_site
from homelabnext.detections.runner import FakeGenericEngine
from homelabnext.detections.sigma import load_mapping, load_rules
from homelabnext.logpipeline import (
    FLAT_KEY,
    LABEL,
    SCHEMA,
    RuntimeTable,
    TableError,
    canonical_address,
    enrich,
    table_doc,
)

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
EXAMPLE = REPO / "examples" / "log-pipeline" / "runtime-labels.json"
MINIMAL = REPO / "examples" / "minimal"
DET = REPO / "detections"
EVASION = sorted((HERE / "evasion").glob("*.json"))
MODEL_RULES = (
    "model-runtime-egress-drop",
    "model-runtime-object-store-lookup",
    "model-runtime-object-store-request",
)

ROWS = [
    ("198.51.100.130", "model", "guest:infer-core", "cap:inference"),
    ("2001:db8::5", "model", "guest:exec-core", "cap:codemode-executor"),
    ("198.51.100.40", "none", "guest:lake-core", "cap:lake-query"),
]


def _table() -> RuntimeTable:
    return RuntimeTable.from_doc(table_doc(ROWS))


# ---------------------------------------------------------------- addresses
@pytest.mark.parametrize(
    ("raw", "want"),
    [
        ("198.51.100.130", "198.51.100.130"),
        ("::ffff:198.51.100.130", "198.51.100.130"),
        (ipaddress.ip_address("2001:db8::5").exploded.upper(), "2001:db8::5"),
        ("198.51.100.130:514", None),
        ("2001:db8::5%eth0", None),
        (" 198.51.100.130", None),
        ("198.51.100.0/24", None),
        ("infer-core.example.internal", None),
        ("", None),
        (None, None),
        (3326239874, None),
    ],
)
def test_canonical_address(raw, want):
    assert canonical_address(raw) == want


# ---------------------------------------------------------------- the table
def test_table_doc_is_ordered_by_address_and_round_trips():
    doc = table_doc(reversed(ROWS))
    assert list(doc["addresses"]) == ["198.51.100.40", "198.51.100.130", "2001:db8::5"]
    assert doc["schema"] == SCHEMA and doc["label"] == LABEL
    assert RuntimeTable.from_doc(json.loads(json.dumps(doc))).values == {
        "198.51.100.130": "model",
        "2001:db8::5": "model",
        "198.51.100.40": "none",
    }


@pytest.mark.parametrize(
    ("rows", "message"),
    [
        ([("198.51.100.1", "model", "a", "c"), ("198.51.100.1", "none", "b", "c")], "claimed by"),
        ([("2001:db8::5".upper(), "model", "a", "c")], "not a canonical"),
        ([("::ffff:198.51.100.1", "model", "a", "c")], "not a canonical"),
        ([("infer-core", "model", "a", "c")], "not a canonical"),
        ([("198.51.100.1", "maybe", "a", "c")], "is not one of"),
    ],
)
def test_table_doc_refuses(rows, message):
    with pytest.raises(TableError, match=message):
        table_doc(rows)


def _doc(**change):
    doc = table_doc(ROWS)
    doc.update(change)
    return doc


@pytest.mark.parametrize(
    ("doc", "message"),
    [
        ([], "JSON object"),
        (_doc(schema="homelabnext.logpipeline.runtime_labels/v2"), "schema"),
        (_doc(label="runtime"), "label"),
        (_doc(addresses=[]), "not an object"),
        (_doc(extra=1), "unknown keys"),
        (_doc(addresses={"2001:db8::5".upper(): {"value": "model"}}), "canonical"),
        (_doc(addresses={"198.51.100.1": {"value": "model", "why": "x"}}), "holds value"),
        (_doc(addresses={"198.51.100.1": "model"}), "holds value"),
        (_doc(addresses={"198.51.100.1": {"value": "MODEL"}}), "is not one of"),
    ],
)
def test_from_doc_refuses(doc, message):
    with pytest.raises(TableError, match=message):
        RuntimeTable.from_doc(doc)


def test_load_reports_the_path(tmp_path):
    bad = tmp_path / "t.json"
    bad.write_text("{", encoding="utf-8")
    with pytest.raises(TableError, match=r"t\.json"):
        RuntimeTable.load(bad)
    with pytest.raises(TableError, match=r"missing\.json"):
        RuntimeTable.load(tmp_path / "missing.json")


# ---------------------------------------------------------------- the rule
@pytest.mark.parametrize(
    ("event", "observed", "want"),
    [
        ({}, "198.51.100.130", "model"),
        ({"labels": {LABEL: "none"}}, "198.51.100.130", "model"),
        ({"labels": {LABEL: "model"}}, "198.51.100.40", "none"),
        ({"labels": {LABEL: "model"}}, "203.0.113.9", None),
        ({"labels": {LABEL: "model"}}, None, None),
        ({FLAT_KEY: "none"}, "198.51.100.130", "model"),
        ({"labels": "hnx_runtime=none"}, "198.51.100.130", "model"),
        ({"labels": {LABEL: ["none", "model"]}}, "198.51.100.40", "none"),
        ({"source": {"ip": "198.51.100.130"}}, "198.51.100.40", "none"),
        ({}, "::ffff:198.51.100.130", "model"),
        ({}, "2001:0db8::0005", "model"),
    ],
)
def test_enrich_sets_the_table_value_only(event, observed, want):
    out = enrich(event, observed, _table())
    assert FLAT_KEY not in out
    labels = out.get("labels")
    assert (labels.get(LABEL) if isinstance(labels, dict) else None) == want


def test_enrich_changes_nothing_else_and_copies():
    event = {"labels": {"site": "lab-a", LABEL: "none"}, "dns": {"question": {"name": "a"}}}
    before = copy.deepcopy(event)
    out = enrich(event, "198.51.100.130", _table())
    assert event == before
    assert out == {"labels": {"site": "lab-a", LABEL: "model"}, "dns": {"question": {"name": "a"}}}
    out["dns"]["question"]["name"] = "b"
    assert event == before, "the result shares structure with the input"


def test_enrich_keeps_a_malformed_labels_value_when_there_is_nothing_to_set():
    assert enrich({"labels": "x"}, "203.0.113.9", _table()) == {"labels": "x"}


# ---------------------------------------------------------------- the generator
def _example_fleet():
    zones, domain = open_site(MINIMAL / "site.yml")
    return load_fleet(MINIMAL / "guests", zones, domain=domain or "example.internal")


def test_committed_example_table_matches_the_example_guests():
    (text,) = render(_example_fleet(), "runtime-labels").values()
    assert EXAMPLE.read_text(encoding="utf-8") == text, (
        "regenerate: hnx guests render examples/minimal/guests --site examples/minimal/site.yml "
        "--target runtime-labels --out examples/log-pipeline"
    )


def test_example_table_labels_the_model_runtime_and_nothing_else():
    table = RuntimeTable.load(EXAMPLE)
    models = {a for a, v in table.values.items() if v == "model"}
    assert models == {"192.0.2.140"}
    assert set(table.values.values()) == {"model", "none"}


def test_generator_refuses_two_guests_on_one_address(monkeypatch):
    from homelabnext.compute.gen import runtime_labels

    fleet = _example_fleet()
    twin = fleet.sorted()[0]
    monkeypatch.setattr(type(fleet), "sorted", lambda self: [twin, twin])
    with pytest.raises(ComputeError, match="claimed by"):
        runtime_labels.render(fleet)


# ---------------------------------------------------------------- evasion, end to end
def test_there_are_evasion_fixtures():
    assert len(EVASION) >= 5


@pytest.mark.parametrize("path", EVASION, ids=lambda p: p.stem)
def test_evasion_fixture(path):
    """The enrichment overrides what the event says, then the rule fires (or stays silent) on
    the guest model's answer: a self-set label changes nothing."""
    fx = json.loads(path.read_text(encoding="utf-8"))
    assert fx["schema"] == "homelabnext.logpipeline.evasion/v1" and fx["rule"] in MODEL_RULES
    out = enrich(fx["event"], fx["observed"], RuntimeTable.load(EXAMPLE))
    labels = out.get("labels") or {}
    assert FLAT_KEY not in out and labels.get(LABEL) == fx["label"], out
    rule = next(r for r in load_rules(DET) if r.slug == fx["rule"])
    engine = FakeGenericEngine(load_mapping(DET / "mappings" / "generic.yml"))
    assert engine.matches(rule, out) is fx["fires"], (fx["name"], out)
    if fx["fires"]:
        # the label is what fires it: the same event as it arrived would not
        assert not engine.matches(rule, fx["event"]), f"{fx['name']} fires without enrichment"


@pytest.mark.parametrize("slug", MODEL_RULES)
def test_model_runtime_rules_are_armed(slug):
    rule = next(r for r in load_rules(DET) if r.slug == slug)
    assert rule.status == "experimental" and rule.deployable
