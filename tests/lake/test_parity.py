# SPDX-License-Identifier: Apache-2.0
"""Engine parity on 30 synthetic queries: DuckDB (reference) == recorded cassette == FakeLake.

The cassette (golden/parity.cassette.json) is recorded from DuckDB. A DuckDB upgrade that changes
an answer, or an adapter that disagrees with the reference, fails here naming the query.
Regenerate with HNX_UPDATE_GOLDEN=1 after reviewing the diff.
"""

from __future__ import annotations

import copy
import json
import os

import pytest
import queries
import synthetic
from golden_util import GOLDEN

from homelabnext.lake import (
    CassetteLake,
    CassetteMiss,
    FakeLake,
    LakeClient,
    WriteNotSupported,
    compare,
    load_schemas,
    normalize_result_rows,
    record,
)
from homelabnext.lake.cassette import dump

CASSETTE = GOLDEN / "parity.cassette.json"
SCHEMAS = load_schemas()


@pytest.fixture(scope="module")
def fake():
    f = FakeLake(SCHEMAS)
    for name, rows in synthetic.all_tables().items():
        f.write_batch(name, rows, idempotency_key="seed")
    return f


@pytest.fixture(scope="module")
def duck():
    pytest.importorskip("duckdb")
    pa = pytest.importorskip("pyarrow")
    from homelabnext.lake import DuckDBLake
    from homelabnext.lake.ddl import to_pyarrow
    from homelabnext.lake.validate import normalize_rows

    tabs = {
        n: pa.Table.from_pylist(normalize_rows(SCHEMAS[n], rows), schema=to_pyarrow(SCHEMAS[n]))
        for n, rows in synthetic.all_tables().items()
    }
    return DuckDBLake(tabs, SCHEMAS)


def test_there_are_thirty_queries_with_unique_names():
    assert len(queries.QUERIES) == 30
    assert len({q["name"] for q in queries.QUERIES}) == 30


def test_cassette_is_current_with_duckdb(duck):
    doc = record(duck, queries.QUERIES)
    if os.environ.get("HNX_UPDATE_GOLDEN") == "1":
        CASSETTE.write_text(dump(doc), encoding="utf-8")
    assert json.loads(CASSETTE.read_text(encoding="utf-8")) == doc


def test_duckdb_matches_cassette(duck):
    doc = json.loads(CASSETTE.read_text(encoding="utf-8"))
    assert compare(doc, duck) == []


def test_fakelake_matches_cassette_without_any_heavy_dependency(fake):
    doc = json.loads(CASSETTE.read_text(encoding="utf-8"))
    assert len(doc["recordings"]) == 30
    assert compare(doc, fake) == []


def test_cassette_lake_replays_every_recording_and_misses_loudly():
    c = CassetteLake.load(CASSETTE)
    assert isinstance(c, LakeClient)
    for q in queries.QUERIES:
        assert c.query(q["sql"], q.get("params")) == next(
            r["rows"]
            for r in json.loads(CASSETTE.read_text())["recordings"]
            if r["name"] == q["name"]
        )
    with pytest.raises(CassetteMiss):
        c.query("SELECT 1")
    with pytest.raises(WriteNotSupported):
        c.write_batch("authentication", [], idempotency_key="k")
    assert c.named("q01-count-auth") == [{"n": 60}]


def test_drift_is_detected_and_named(fake):
    doc = json.loads(CASSETTE.read_text(encoding="utf-8"))
    bad = copy.deepcopy(doc)
    bad["recordings"][2]["rows"] = [{"n": 999}]
    diffs = compare(bad, fake)
    assert len(diffs) == 1 and diffs[0].startswith("q03-failures")


def test_engine_error_is_reported_per_query(fake):
    doc = {
        "version": 1,
        "recordings": [
            {"name": "broken", "sql": "SELECT * FROM missing_table", "params": {}, "rows": []}
        ],
    }
    assert "broken: query failed" in compare(doc, fake)[0]


def test_aggregate_timestamps_normalise_to_the_same_utc_text(fake):
    # engines differ in the python type they return for computed timestamps; the comparison
    # form is ISO-8601 UTC text (see normalize_result_rows)
    got = normalize_result_rows(fake.query("SELECT min(time) AS a FROM authentication"))
    assert got == [{"a": "2026-03-01T00:00:00Z"}]
