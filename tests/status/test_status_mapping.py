# SPDX-License-Identifier: Apache-2.0
"""The mapping engine: selectors, state tables (unmapped is never ok) and the built-in mappers
against the repository's own example data."""

from __future__ import annotations

import json

import pytest
from status_helpers import ROOT, T0, spec

from homelabnext.status import CollectContext, MappingError, apply_mapping, select_pairs
from homelabnext.status.collectors import COLLECTORS, CollectError
from homelabnext.status.model import parse_iso

ALERTS = {
    "data": {
        "alerts": [
            {"labels": {"alertname": "DiskFull"}, "state": "firing", "annotations": {"summary": "/ at 97%"}},
            {"labels": {"alertname": "Slow"}, "state": "pending", "annotations": {"summary": "p95 2s"}},
            {"labels": {"alertname": "Quiet"}, "state": "inactive"},
        ]
    }
}  # fmt: skip
ALERT_MAP = {
    "items": "$.data.alerts[*]",
    "item": "labels.alertname",
    "state": "state",
    "states": {"firing": "fail", "pending": "warn", "inactive": "ok"},
    "summary": "annotations.summary",
}


def _map(payload, mapping):
    return apply_mapping(payload, mapping, now=T0, fallback_item="src")


def test_selectors():
    doc = {"a": [{"b": 1}, {"b": 2}], "m": {"x": {"v": 1}, "y": {"v": 2}}}
    assert [v for _, v in select_pairs(doc, "$.a[*].b")] == [1, 2]
    assert [v for _, v in select_pairs(doc, "a[1].b")] == [2]
    assert select_pairs(doc, "m.*.v") == [("v", 1), ("v", 2)]
    assert select_pairs(doc, "a[5]") == [] and select_pairs(doc, "nope.x") == []
    with pytest.raises(MappingError):
        select_pairs(doc, "a..[")


def test_declarative_list_mapping():
    drafts = _map(ALERTS, ALERT_MAP)
    assert [(d.item, d.state, d.summary) for d in drafts] == [
        ("DiskFull", "fail", "/ at 97%"),
        ("Slow", "warn", "p95 2s"),
        ("Quiet", "ok", "inactive"),  # no summary -> the raw state
    ]


def test_mapping_keyed_items_and_at_key():
    payload = {"queues": {"ingest": {"h": "healthy"}, "enrich": {"h": "stalled"}}}
    m = {
        "items": "queues",
        "item": "@key",
        "state": "h",
        "states": {"healthy": "ok", "stalled": "fail"},
    }
    assert [(d.item, d.state) for d in _map(payload, m)] == [("ingest", "ok"), ("enrich", "fail")]


def test_single_item_payload_named_after_the_source_and_booleans():
    m = {"state": "healthy", "states": {"true": "ok", "false": "fail"}}
    assert [(d.item, d.state) for d in _map({"healthy": True}, m)] == [("src", "ok")]
    assert _map({"healthy": False}, m)[0].state == "fail"


@pytest.mark.parametrize(
    "raw, want", [("weird", "unknown"), (None, "unknown"), ("WARN", "warn"), ("ok", "ok")]
)
def test_unmapped_raw_state_is_never_ok(raw, want):
    assert _map({"s": raw}, {"state": "s", "states": {"up": "ok"}})[0].state == want


def test_items_selector_that_matches_nothing_is_a_defect_but_an_empty_wildcard_is_not():
    with pytest.raises(MappingError, match="matched nothing"):
        _map({"x": 1}, {"items": "data.alerts", "state": "s"})
    assert _map({"data": {"alerts": []}}, ALERT_MAP) == []


def test_unsafe_item_and_summary_text_is_cleaned():
    d = _map(
        [{"n": "a b\n<c>", "s": "ok", "t": "line1\nline2\x00"}],
        {"items": "$", "item": "n", "state": "s", "summary": "t"},
    )[0]
    assert d.item == "a-b-c" and d.summary == "line1 line2"


def test_invariants_results_builtin_on_the_example_register():
    doc = json.loads((ROOT / "examples/registers/invariants.results.json").read_text())
    doc["results"]["X-99"] = {"status": "fail", "evidence": "[exit 1] broken\nmore"}
    doc["results"]["X-98"] = {"status": "error", "evidence": "could not measure"}
    drafts = {d.item: d for d in _map(doc, {"builtin": "invariants-results"})}
    assert drafts["X-99"].state == "fail" and drafts["X-99"].summary == "fail: [exit 1] broken"
    assert drafts["X-98"].state == "unknown" and drafts["X-99"].link == "inv:X-99"
    assert all(d.state == "ok" for k, d in drafts.items() if not k.startswith("X-9"))
    with pytest.raises(MappingError):
        _map({"results": {}}, {"builtin": "invariants-results"})


def test_records_lanes_builtin_reads_the_example_lanes():
    s = spec("proposals", kind="poll-file", file="examples/status/records", path=None,
             mapping={"builtin": "records-lanes", "warn_after_s": 7 * 86400})  # fmt: skip
    now = parse_iso("2026-10-20T09:00:00Z")
    ctx = CollectContext(clock=lambda: now, root=ROOT)
    got = {d.item: d for d in COLLECTORS["poll-file"].collect(s, ctx)}
    assert got["inbox"].value == 1 and got["inbox"].state == "ok" and got["inbox"].work
    late = got["approved-not-completed"]
    assert late.value == 1 and late.state == "warn" and "oldest 8d 0h" in late.summary


def test_broker_pending_from_a_file_and_from_a_store():
    s = spec("approvals", kind="poll-file", file="examples/status/broker-pending.json", path=None,
             mapping={"builtin": "broker-pending", "warn_after_s": 3600})  # fmt: skip
    now = parse_iso("2026-10-19T23:00:00Z")
    (d,) = COLLECTORS["poll-file"].collect(s, CollectContext(clock=lambda: now, root=ROOT))
    assert (d.item, d.state, d.value) == ("pending-approvals", "ok", 1)

    class Store:
        def pending(self):
            return [{"request_id": "r1", "created": "2026-10-19T20:00:00Z"}]

    ctx = CollectContext(clock=lambda: now, root=ROOT, broker=Store())
    (d,) = COLLECTORS["poll-file"].collect(s, ctx)
    assert d.state == "warn" and "3h 0m" in d.summary
    assert _map({"requests": []}, {"builtin": "broker-pending"})[0].state == "ok"


def test_poll_file_stays_inside_its_root(tmp_path):
    (tmp_path / "root").mkdir()
    (tmp_path / "secret.json").write_text("{}")
    s = spec(kind="poll-file", file="link.json", path=None)
    (tmp_path / "root" / "link.json").symlink_to(tmp_path / "secret.json")
    with pytest.raises(CollectError, match="outside the status root"):
        COLLECTORS["poll-file"].collect(s, CollectContext(root=tmp_path / "root"))


def test_poll_http_json_maps_and_refuses_non_2xx(http):
    from status_helpers import endpoint

    s = spec(path="/api/v1/alerts", mapping=ALERT_MAP)
    http.routes["http://svc-a.status.invalid/api/v1/alerts"] = (200, ALERTS)
    ctx = CollectContext(clock=lambda: T0, http=http, endpoint=endpoint)
    assert len(COLLECTORS["poll-http-json"].collect(s, ctx)) == 3
    http.routes["http://svc-a.status.invalid/api/v1/alerts"] = (503, {})
    with pytest.raises(CollectError, match="HTTP 503"):
        COLLECTORS["poll-http-json"].collect(s, ctx)
