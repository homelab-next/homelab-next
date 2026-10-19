# SPDX-License-Identifier: Apache-2.0
"""T-04: enrichment adds asset owner and criticality; the coverage metric over a fake stream."""

from __future__ import annotations

import json
import random
from pathlib import Path

import pytest

from homelabnext.compute.loader import load_guests
from homelabnext.events import EventError, build_event, validate_event
from homelabnext.events.enrich import (
    Asset,
    AssetInventory,
    criticality_for,
    enrich_event,
    enrichment_coverage,
    resolve_asset,
)
from homelabnext.registry.model import load

REPO = Path(__file__).resolve().parents[2]
FIX = Path(__file__).parent / "fixtures" / "enrichment"
T = "2026-01-01T00:00:00Z"


@pytest.fixture(scope="module")
def inventory():
    guests, problems = load_guests(REPO / "examples" / "minimal" / "guests")
    assert not problems
    return AssetInventory.from_models(load(REPO / "examples" / "services.yml"), guests)


def test_fixture_stream_is_enriched_as_expected(inventory):
    events = json.loads((FIX / "input.json").read_text())
    expected = json.loads((FIX / "expected.json").read_text())
    assert [e["id"] for e in events] == list(expected)
    for ev in events:
        validate_event(ev)
        assert "assetowner" not in ev or ev["id"] == "evt-enrich-09"  # the input is raw
        out = enrich_event(ev, inventory)
        want = expected[ev["id"]]
        got = {k: out.get(k) for k in ("assetid", "assetowner", "assetcriticality")}
        assert (got if out.get("assetid") else None) == want, ev["id"]
        validate_event(out)  # the enriched envelope still satisfies its schemas
        assert out["data"] == ev["data"]


def test_inventory_comes_from_registry_and_guest_model(inventory):
    # the host runs data-team services but the guest model names its owner: the guest wins
    assert inventory.lookup("bus-core") == Asset("host:bus-core", "platform-team", "high")
    assert inventory.lookup("svc:events").owner == "data-team"
    assert inventory.lookup("cap:lake-query").id == "svc:lake-query"  # unique provider
    assert inventory.lookup("host:secrets-core").criticality == "critical"
    assert inventory.lookup("app-01") is None
    assert inventory.lookup("") is None


def test_unknown_named_target_is_not_attributed_to_the_emitter(inventory):
    ev = build_event(
        "homelabnext.alert.created",
        "svc:inference",  # a known emitter
        {
            "alert_id": "ALT-0002",
            "detection": "det:auth-failure-burst",
            "title": "t",
            "severity": "low",
            "observed_at": T,
            "entities": [{"kind": "host", "value": "app-01"}],
        },
        id="evt-x",
        time=T,
    )
    assert resolve_asset(ev, inventory) is None
    assert enrich_event(ev, inventory) == ev
    del ev["data"]["entities"]
    assert resolve_asset(ev, inventory).id == "svc:inference"  # no target named: the emitter


def test_publisher_values_are_kept(inventory):
    ev = build_event(
        "homelabnext.task.queued",
        "svc:inference",
        {"task_id": "T-1", "profile": "profile:reader", "priority": 1, "idempotency_key": "k"},
        id="evt-y",
        time=T,
    )
    ev["assetowner"] = "ml-ops"
    out = enrich_event(ev, inventory)
    assert out["assetowner"] == "ml-ops"
    assert out["assetcriticality"] == "medium"


def test_overrides_and_tag_table():
    assert criticality_for(["ops", "ui"]) == "low"
    assert criticality_for(["data", "secrets"]) == "critical"
    assert criticality_for(["x"], {"x": "medium"}) == "medium"
    guests, _ = load_guests(REPO / "examples" / "minimal" / "guests")
    inv = AssetInventory.from_models(
        load(REPO / "examples" / "services.yml"), guests, overrides={"svc:dashboards": "high"}
    )
    assert inv.lookup("svc:dashboards").criticality == "high"
    with pytest.raises(ValueError):
        AssetInventory([Asset("svc:a", "t", "urgent")])
    with pytest.raises(ValueError):
        AssetInventory([Asset("a", "t", "low")])


def test_schema_rejects_a_bad_enrichment(inventory):
    ev = json.loads((FIX / "input.json").read_text())[0]
    out = enrich_event(ev, inventory)
    out["assetcriticality"] = "urgent"
    with pytest.raises(EventError):
        validate_event(out)


def _fake_stream(inventory, n, unknown_share, seed):
    """``n`` alert events about seeded-random hosts; ``unknown_share`` name a host nobody owns."""
    rng = random.Random(seed)
    hosts = [a.id.removeprefix("host:") for a in inventory if a.id.startswith("host:")]
    for i in range(n):
        host = f"unknown-{i}" if rng.random() < unknown_share else rng.choice(hosts)
        yield build_event(
            "homelabnext.alert.created",
            "svc:siem",
            {
                "alert_id": f"ALT-{i:05d}",
                "detection": "det:auth-failure-burst",
                "title": "fake",
                "severity": "low",
                "observed_at": T,
                "entities": [{"kind": "host", "value": host}],
            },
            id=f"evt-{i:05d}",
            time=T,
            validate=False,
        )


def test_coverage_metric_on_a_fake_stream(inventory):
    good = [enrich_event(e, inventory) for e in _fake_stream(inventory, 400, 0.02, seed=7)]
    cov = enrichment_coverage(good)
    assert cov.total == 400
    assert cov.ok, cov.render()
    assert cov.ratio >= 0.95

    bad = [enrich_event(e, inventory) for e in _fake_stream(inventory, 400, 0.20, seed=7)]
    cov = enrichment_coverage(bad)
    assert not cov.ok
    assert cov.missing_by_type == {"homelabnext.alert.created": cov.total - cov.enriched}
    assert "BELOW TARGET" in cov.render()


def test_coverage_edge_cases():
    assert not enrichment_coverage([]).ok  # no events is no evidence
    cov = enrichment_coverage([{"type": "homelabnext.a.b"}, "not-an-event"])
    assert cov.enriched == 0
    assert cov.missing_by_type == {"homelabnext.a.b": 1, "?": 1}
    full = {"assetowner": "t", "assetcriticality": "low"}
    assert enrichment_coverage([full], threshold=1.0).ok
    assert not enrichment_coverage([{"assetowner": "t", "assetcriticality": "urgent"}]).ok
    with pytest.raises(ValueError):
        enrichment_coverage([], threshold=0)
