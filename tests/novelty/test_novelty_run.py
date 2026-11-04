# SPDX-License-Identifier: Apache-2.0
"""The analyzer end to end on the fake lake, through its declared reader ceiling."""

from __future__ import annotations

import copy
import math
from datetime import timedelta

import pytest
from novelty_support import AS_OF, SITE, SPEC, net, rows

from homelabnext.lake import FakeLake, LakeError, load_schemas
from homelabnext.lake.ceiling import CeilingError, reader_for
from homelabnext.novelty import READER, corroborate, parse_spec, run
from homelabnext.novelty.engine import WriteRefused, write_findings

SCHEMAS = load_schemas()


@pytest.fixture
def lake():
    lake = FakeLake(SCHEMAS)
    lake.write_batch("network_activity", rows(), idempotency_key="seed")
    return lake


def _run(lake, spec=SPEC, readers=SITE["tlp_readers"], *, write=True, as_of=AS_OF):
    reader = reader_for(lake, READER, readers, SCHEMAS)
    return run(reader, parse_spec(spec, SCHEMAS), as_of, writer=lake if write else None)


def _stored(lake):
    reader = reader_for(
        lake, "profile:t", [{"reader": "profile:t", "ceiling": "red", "why": "t"}], SCHEMAS
    )
    return reader.select("novelty_finding", ["uid", "entity", "value", "status", "score", "tlp"])


def test_the_analyzer_reads_as_its_declared_reader_and_finds_the_new_pair(lake):
    (result,) = _run(lake)
    s = result.summary()
    assert s["status"] == "ok" and s["history_days"] == 4 and s["oldest_day"] == "2026-03-05"
    got = {(r["entity"], r["value"]): r for r in result.rows}
    assert set(got) == {("192.0.2.10", "22"), ("192.0.2.11", "443")}
    new = got[("192.0.2.10", "22")]
    # the red 22 row is above the amber ceiling: support 0, so surprise 1;
    # T = 2 * (2**-2 + 2**-1.5 + 2**-1 + 2**-0.5), confidence T / 4
    total = 2 * (0.25 + 2**-1.5 + 0.5 + 2**-0.5)
    assert new["support"] == 0.0 and math.isclose(new["entity_total"], total, abs_tol=1e-9)
    assert math.isclose(new["score"], total / 4, abs_tol=1e-9)
    assert new["tlp"] == "green"
    assert got[("192.0.2.11", "443")]["status"] == "unlearned"
    assert got[("192.0.2.11", "443")]["tlp"] == "amber"
    assert {r["uid"] for r in _stored(lake)} == {r["uid"] for r in result.rows}


def test_a_red_reader_sees_the_red_row_and_labels_the_finding_red(lake):
    red = [{"reader": READER, "ceiling": "red", "why": "tests read everything"}]
    (result,) = _run(lake, readers=red, write=False)
    new = {(r["entity"], r["value"]): r for r in result.rows}[("192.0.2.10", "22")]
    assert new["support"] == 0.5  # one row two days old
    assert new["tlp"] == "red"


def test_a_rerun_of_the_same_window_writes_nothing_new(lake):
    (first,) = _run(lake)
    (again,) = _run(lake)
    assert first.written == 2 and first.replayed is False
    assert again.written == 0 and again.replayed is True
    assert again.rows == first.rows
    assert len(_stored(lake)) == 2


def test_a_dry_run_writes_nothing(lake):
    (result,) = _run(lake, write=False)
    assert result.rows and result.written is None and _stored(lake) == []


def test_an_undeclared_analyzer_reads_nothing(lake):
    with pytest.raises(CeilingError, match="no declared TLP ceiling"):
        _run(lake, readers=[])


def test_a_fresh_lake_warms_and_writes_nothing():
    lake = FakeLake(SCHEMAS)
    lake.write_batch(
        "network_activity", [r for r in rows() if r["time"].day >= 8], idempotency_key="seed"
    )
    (result,) = _run(lake)
    s = result.summary()
    assert s == {
        "profile": "host-dst-port",
        "status": "warming",
        "learn_window": ["2026-03-05T00:00:00Z", "2026-03-09T00:00:00Z"],
        "score_window": ["2026-03-09T00:00:00Z", "2026-03-10T00:00:00Z"],
        "oldest_day": "2026-03-08",
        "history_days": 1,
        "min_history_days": 4,
        "days_remaining": 3,
    }
    assert result.rows == [] and _stored(lake) == []
    # three days later the same lake (with the days in between) has its history
    (later,) = _run(lake, as_of=AS_OF + timedelta(days=3), write=False)
    assert later.summary()["history_days"] == 4 and later.status == "ok"


def test_a_profile_over_too_many_groups_fails_alone(lake):
    spec = copy.deepcopy(SPEC)
    spec["profiles"].append({**spec["profiles"][0], "id": "second"})
    reader = reader_for(lake, READER, SITE["tlp_readers"], SCHEMAS)
    a, b = run(reader, parse_spec(spec, SCHEMAS), AS_OF, limit=1)
    assert a.status == b.status == "failed" and "TooManyGroups" in a.error
    ok = run(reader, parse_spec(spec, SCHEMAS), AS_OF, limit=100)
    assert [r.status for r in ok] == ["ok", "ok"]
    assert ok[0].rows[0]["uid"] != ok[1].rows[0]["uid"]  # the profile is in the uid


def _lake_of(table_rows):
    lake = FakeLake(SCHEMAS)
    lake.write_batch("network_activity", table_rows, idempotency_key="seed")
    return lake


def test_a_sparse_table_is_not_warming_when_its_history_predates_the_window():
    # rows on 03-02 and 03-08 only: nothing on the learning window's first day (03-05)
    sparse = [net(0, day=2, src="192.0.2.10", port=443), net(1, day=8, src="192.0.2.10", port=443)]
    sparse.append(net(2, day=9, src="192.0.2.10", port=22))
    (result,) = _run(_lake_of(sparse), write=False)
    s = result.summary()
    assert (s["status"], s["oldest_day"], s["history_days"]) == ("ok", "2026-03-02", 4)


def test_a_non_midnight_as_of_reads_the_whole_first_day():
    # as_of 12:00: the learning window starts 03-05 12:00, the table's first row is 03-05 08:00
    first = [net(0, day=5, hour=8, src="192.0.2.10", port=443)]
    first += [net(1, day=9, hour=13, src="192.0.2.10", port=22)]
    (result,) = _run(_lake_of(first), write=False, as_of=AS_OF + timedelta(hours=12))
    s = result.summary()
    assert s["learn_window"][0] == "2026-03-05T12:00:00Z"
    assert (s["status"], s["oldest_day"], s["history_days"]) == ("ok", "2026-03-05", 4)
    later = [net(0, day=6, hour=8, src="192.0.2.10", port=443)]
    (warm,) = _run(_lake_of(later), write=False, as_of=AS_OF + timedelta(hours=12))
    assert (warm.status, warm.summary()["days_remaining"]) == ("warming", 1)


def test_a_table_entirely_above_the_ceiling_reads_as_fresh():
    red = [dict(r, tlp="red") for r in rows()]
    (result,) = _run(_lake_of(red), write=False)
    assert result.status == "warming" and result.summary()["history_days"] == 0


def test_one_port_scan_does_not_fail_the_profile():
    scan = rows() + [net(500 + p, day=7, src="192.0.2.66", port=1000 + p) for p in range(60)]
    scan.append(net(999, day=9, src="192.0.2.66", port=4444))
    lake = _lake_of(scan)
    reader = reader_for(lake, READER, SITE["tlp_readers"], SCHEMAS)
    # 60 values in the learning window: more groups than the limit, had they been read
    (result,) = run(reader, parse_spec(SPEC, SCHEMAS), AS_OF, limit=40)
    assert result.status == "ok", result.error
    got = {(r["entity"], r["status"]) for r in result.rows}
    assert ("192.0.2.66", "high_cardinality") in got and ("192.0.2.10", "finding") in got
    (scanner,) = [r for r in result.rows if r["entity"] == "192.0.2.66"]
    assert scanner["count"] == 1 and scanner["value"] is None


def test_the_analyzer_then_corroborate_over_its_window_finds_the_candidate(lake):
    (result,) = _run(lake)
    w = result.windows
    # a host sensor reports the same address, in the same window, as its own source
    host = {
        "uid": "host-1",
        "time": w.score_since + timedelta(hours=3),
        "as_of": w.score_since + timedelta(hours=3),
        "source": "host-kernel",
        "source_kind": "heuristic",
        "profile": "process-lineage",
        "entity_kind": "ip",
        "entity": "192.0.2.10",
        "status": "finding",
        "score": 0.9,
        "confidence": 1.0,
        "tlp": "green",
    }
    write_findings(lake, [host], source="host-kernel", mark="host-kernel/lineage", idempotency_key="h1")  # fmt: skip
    reader = reader_for(lake, READER, SITE["tlp_readers"], SCHEMAS)
    groups = reader.count_by(
        "novelty_finding", "entity", ["entity_kind", "source", "status"],
        since=w.score_since, until=w.score_until,
    )  # fmt: skip
    found = corroborate(
        {
            "entity": g.entity,
            "entity_kind": g.values[0],
            "source": g.values[1],
            "status": g.values[2],
            "tlp": g.label.value,
            "rows": g.count,
        }
        for g in groups
    )
    (c,) = found
    assert (c.entity_kind, c.entity, c.sources) == ("ip", "192.0.2.10", ("host-kernel", "lake-novelty"))  # fmt: skip


def test_a_writer_writes_only_its_own_source(lake):
    (result,) = _run(lake, write=False)
    with pytest.raises(WriteRefused, match="other sources"):
        write_findings(lake, result.rows, source="host-kernel", mark="host-kernel/x", idempotency_key="k")  # fmt: skip
    with pytest.raises(WriteRefused, match="mark"):
        write_findings(lake, result.rows, source="lake-novelty", mark="host-kernel/x", idempotency_key="k")  # fmt: skip
    assert _stored(lake) == []


def test_one_source_cannot_squat_anothers_uid(lake):
    (result,) = _run(lake)
    row = dict(result.rows[0], source="host-kernel", profile="process-lineage")
    write_findings(lake, [row], source="host-kernel", mark="host-kernel/x", idempotency_key="k")
    stored = _stored(lake)
    assert len(stored) == len(result.rows) + 1  # same uid, other source: a row of its own


def test_a_failed_write_fails_that_profile_only(lake):
    class Broken(FakeLake):
        def write_batch(self, table, rows, **kw):
            raise LakeError("catalog unavailable")

    spec = copy.deepcopy(SPEC)
    spec["profiles"].append({**spec["profiles"][0], "id": "second"})
    reader = reader_for(lake, READER, SITE["tlp_readers"], SCHEMAS)
    a, b = run(reader, parse_spec(spec, SCHEMAS), AS_OF, writer=Broken(SCHEMAS))
    assert a.status == b.status == "failed" and "catalog unavailable" in a.error
