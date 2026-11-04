# SPDX-License-Identifier: Apache-2.0
"""The analyzer end to end on the fake lake, through its declared reader ceiling."""

from __future__ import annotations

import copy
import math
from datetime import timedelta

import pytest
from novelty_support import AS_OF, SITE, SPEC, rows

from homelabnext.lake import FakeLake, load_schemas
from homelabnext.lake.ceiling import CeilingError, reader_for
from homelabnext.novelty import READER, parse_spec, run

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
