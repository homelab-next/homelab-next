# SPDX-License-Identifier: Apache-2.0
"""Measures read from each binding type at an injected time, are recorded as append-only value
events (a repeat adds nothing), and roll up MOP -> MOE -> objective -> SO."""

import datetime as dt
import json

import pytest
from strategy_helpers import NOW, edit

from homelabnext.strategy import Context, grade_all, load_doctrine, load_tree, read, rollup
from homelabnext.strategy.measure import Grade, measure_all, value_event

RESULTS = {
    "results": {
        "L-05": {"status": "pass", "checked_at": "2026-10-20T13:00:00+00:00"},
        "D-02": {"status": "fail", "checked_at": "2026-10-20T13:01:00+00:00"},
        "M-03": {"status": "error", "checked_at": "2026-10-20T13:02:00+00:00"},
    }
}


def obs(source, item, state, value=None, at="2026-10-20T13:03:00Z"):
    o = {"source": source, "module": "m", "item": item, "state": state, "observed_at": at}
    return o | ({"value": value} if value is not None else {})


SNAPSHOT = {
    "observations": [
        obs("uptime-monitors", "dns", "ok"),
        obs("uptime-monitors", "proxy", "fail"),
        obs("uptime-monitors", "vault", "ok"),
        obs("proposals", "approved-not-completed", "warn", 4),
    ],
    "sources": [{"id": "metrics-alerts", "state": "stale"}],
}


@pytest.mark.parametrize(
    ("source", "value", "finding", "at", "sample"),
    [
        ("invariant:L-05", 1.0, None, "2026-10-20T13:00:00+00:00", 1),
        ("invariant:D-02", 0.0, None, "2026-10-20T13:01:00+00:00", 1),
        ("invariant:M-03", None, "invariant M-03 is error, not pass or fail", "2026-10-20T13:02:00+00:00", 0),
        ("invariant:X-01", None, "no result for invariant X-01 in results.json", "2026-10-20T13:10:00Z", 0),
        ("status:uptime-monitors", 2 / 3, None, "2026-10-20T13:03:00Z", 3),
        ("status:uptime-monitors/proxy", 0.0, None, "2026-10-20T13:03:00Z", 1),
        ("status:proposals/approved-not-completed", 4.0, None, "2026-10-20T13:03:00Z", 1),
        ("status:metrics-alerts", None, "status source metrics-alerts has no reading (source stale)", "2026-10-20T13:10:00Z", 0),
        ("records:inbox", 2.0, None, "2026-10-20T13:10:00Z", 1),
        ("records:inbox?type=proposal", 1.0, None, "2026-10-20T13:10:00Z", 1),
        ("records:decided/completed", 0.0, None, "2026-10-20T13:10:00Z", 1),
        ("none", None, "no denominator yet", "2026-10-20T13:10:00Z", 0),
    ],
)  # fmt: skip
def test_each_binding_reads_at_the_injected_time(records, source, value, finding, at, sample):
    from homelabnext.records import Records

    rec = Records(records, lambda: NOW, agent="profile:example-checker")
    rec.propose({"title": "Raise the threshold", "risk": "low", "rollback": "revert the change"})
    rec.submit(
        {"type": "finding", "title": "Disk is filling", "area": "storage", "severity": "low"}
    )
    ctx = Context(NOW, results=RESULTS, results_name="results.json", snapshot=SNAPSHOT, records_root=records)  # fmt: skip
    m = {"source": source, "not_measurable": "no denominator yet\n\nmore detail"}
    r = read(m, ctx)
    assert (r.value, r.finding, r.observed_at, r.sample) == (value, finding, at, sample)
    assert r.evidence.startswith(source)


def test_manual_is_not_read_and_a_missing_input_is_a_finding():
    assert read({"source": "manual"}, Context(NOW)) is None
    ctx = Context(NOW)
    assert read({"source": "invariant:L-05"}, ctx).finding == "no invariants results to read"
    assert read({"source": "status:proposals"}, ctx).finding == "no status hub state to read"
    assert read({"source": "records:inbox"}, ctx).finding == "no records root to count"


def test_measure_records_value_events_and_a_repeat_adds_nothing(lab, records):
    ctx = Context(NOW, results=RESULTS, snapshot=SNAPSHOT, records_root=records)
    later = NOW + dt.timedelta(minutes=5)
    ctx.now = later
    before = set(lab.rglob("*-value-*.yml"))
    written, tree = measure_all(lab, ctx, by="profile:example-checker")
    new = {p.name for p in set(lab.rglob("*-value-*.yml")) - before}
    assert sorted(k for k, e in written.items() if e) == ["MOE-001", "MOE-002", "MOE-003", "MOE-006", "MOP-001", "MOP-002"]  # fmt: skip
    assert len(set(lab.rglob("*-value-*.yml")) - before) == 6 and new == {"20261020T131500Z-value-profile-example-checker.yml"}  # fmt: skip
    moe6 = tree.of("measures")["MOE-006"]["values"][-1]
    assert (moe6["value"], moe6["evidence"]) == (0.0, "invariant:D-02 fail at 2026-10-20T13:01:00+00:00")  # fmt: skip
    again, _ = measure_all(lab, ctx, by="profile:example-checker")
    assert not any(again.values())  # the same data again: nothing new
    ctx.now = later = later + dt.timedelta(hours=1)
    again, _ = measure_all(lab, ctx, by="profile:example-checker")
    assert {k for k, e in again.items() if e} == {"MOP-001", "MOP-002"}  # counts are taken now
    grades = grade_all(load_tree(lab), load_doctrine(lab), later)
    assert grades["MOE-006"].state == "red" and grades["MOE-006"].trend == "down"
    assert grades["MOE-001"].state == "baseline"  # its first value (after a finding): cold start


def test_dry_run_writes_nothing(lab):
    before = sorted(p.name for p in lab.rglob("*.yml"))
    written, tree = measure_all(lab, Context(NOW, results=RESULTS), by="profile:x", write=False)
    assert written["MOE-002"] is not None
    assert sorted(p.name for p in lab.rglob("*.yml")) == before
    assert tree.of("measures")["MOE-002"]["values"][-1]["observed_at"] == "2026-10-20T13:00:00+00:00"  # fmt: skip


def test_a_value_event_carries_the_seven_fields(lab):
    from homelabnext.registers.events import check_event

    m = load_tree(lab).of("measures")["MOE-002"]
    r = read(m, Context(NOW, results=RESULTS))
    e = value_event({**m, "values": []}, r, "profile:example-checker", NOW)
    assert check_event(json.loads(json.dumps(e, default=str))) == []
    assert set(e) >= {"value", "observed_at", "sample", "definition_digest", "definition_version", "evidence"}  # fmt: skip


def test_rollup_is_the_worst_moe_and_child_with_mops_as_fallback(lab):
    tree = load_tree(lab)
    grades = grade_all(tree, load_doctrine(lab), NOW)
    states = rollup(tree, grades)
    assert states["TT-001"]["state"] == "amber"  # MOE-004, capped
    assert states["TO-001"] == {
        "state": "amber", "effect": "amber", "performance": "green",
        "children": ["TT-001"], "measures": ["MOE-003", "MOP-002"],
    }  # fmt: skip
    assert states["OO-002"]["state"] == "green"
    assert states["SO-002"]["state"] == "red"  # MOE-005 is not measurable: a finding rolls up red
    assert states["SO-001"]["children"] == ["OO-001"]


def test_rollup_falls_back_to_mops_when_no_effect_is_graded(lab):
    tree = load_tree(lab)
    grades = {
        "MOE-003": Grade("MOE-003", "baseline"),
        "MOP-002": Grade("MOP-002", "red"),
        "MOE-004": Grade("MOE-004", "pending"),
    }
    states = rollup(tree, grades)
    assert states["TT-001"]["state"] == "pending"
    assert (states["TO-001"]["effect"], states["TO-001"]["state"]) == ("baseline", "red")


def test_a_retired_measure_or_objective_is_skipped(lab):
    edit(lab, "measures/MOE-004.md", "kind: output", "kind: output")
    tree = load_tree(lab)
    tree.of("measures")["MOE-004"]["status"] = "retired"
    assert "MOE-004" not in grade_all(tree, load_doctrine(lab), NOW)
    tree.of("objectives")["TT-001"]["status"] = "retired"
    assert "TT-001" not in rollup(tree, grade_all(tree, load_doctrine(lab), NOW))


def test_grading_ages_readings_with_the_injected_clock(lab):
    tree = load_tree(lab)
    later = NOW + dt.timedelta(days=30)
    g = grade_all(tree, load_doctrine(lab), later)["MOE-002"]
    assert g.state == "green" and g.thin and g.confidence == "low"
