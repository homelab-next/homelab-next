# SPDX-License-Identifier: Apache-2.0
"""Idempotent write against a real pyiceberg SQL (sqlite) catalog, and the same contract on
FakeLake. The crash tests encode the incident: a batch was committed, the process died before the
checkpoint was saved, and the restarted reader re-read a rotated log tail.

The invariant under test is always the same: after any sequence of crashes and replays,
``count(*) == count(DISTINCT uid)`` and every source row is present exactly once.
"""

from __future__ import annotations

import pytest
import synthetic

from homelabnext.lake import (
    Checkpoint,
    FakeLake,
    Ingestor,
    RowRejected,
    SchemaMismatch,
    UnknownTable,
    load_schemas,
)

SCHEMAS = load_schemas()
TABLE = "authentication"


class Crash(Exception):
    pass


def _boom():
    raise Crash


@pytest.fixture(params=["fake", "iceberg"])
def make_lake(request, tmp_path):
    """Factory that returns a NEW client over the SAME storage each call (= a process restart)."""
    if request.param == "fake":
        shared = FakeLake(SCHEMAS)
        return lambda: shared
    pytest.importorskip("pyiceberg")
    pytest.importorskip("pyarrow")
    pytest.importorskip("duckdb")
    pytest.importorskip("sqlalchemy")
    from homelabnext.lake.iceberg import IcebergLake, open_sql_catalog

    wh = tmp_path / "warehouse"
    wh.mkdir()
    uri = f"sqlite:///{tmp_path}/catalog.db"

    def factory():
        lake = IcebergLake(open_sql_catalog("test", uri=uri, warehouse=f"file://{wh}"), SCHEMAS)
        lake.ensure_tables()
        return lake

    return factory


def _count(lake):
    return lake.query("SELECT count(*) AS n, count(DISTINCT uid) AS d FROM authentication")[0]


def test_write_query_describe(make_lake):
    lake = make_lake()
    res = lake.write_batch(
        TABLE, synthetic.authentication(20), idempotency_key="b1", source="log-a", high_water="20"
    )
    assert res.rows_written == 20 and res.snapshot_id
    info = lake.describe(TABLE)
    assert info.row_count == 20
    assert info.committed["log-a"].batch_id == "b1" and info.committed["log-a"].high_water == "20"
    assert lake.list_tables().count(TABLE) == 1
    assert lake.query("SELECT count(*) AS n FROM authentication WHERE status_id = 2") == [{"n": 5}]


def test_retried_batch_id_is_a_noop(make_lake):
    lake = make_lake()
    rows = synthetic.authentication(10)
    lake.write_batch(TABLE, rows, idempotency_key="b1")
    again = make_lake().write_batch(TABLE, rows, idempotency_key="b1")  # even from a fresh process
    assert again.replayed and again.rows_written == 0
    assert _count(lake) == {"n": 10, "d": 10}


def test_content_key_dedupes_when_batch_id_differs_and_batching_changes(make_lake):
    lake = make_lake()
    lake.write_batch(TABLE, synthetic.authentication(10), idempotency_key="b1")
    res = lake.write_batch(TABLE, synthetic.authentication(15), idempotency_key="other-id")
    assert (res.rows_written, res.rows_skipped) == (5, 10)
    assert _count(lake) == {"n": 15, "d": 15}


def test_crash_between_commit_and_checkpoint_replay_yields_zero_duplicates(make_lake, tmp_path):
    """The incident. Committed batch 2, died before saving the checkpoint; the restarted reader did
    NOT recover and re-read the whole tail (rows 10..24) under a new batching."""
    cp = Checkpoint(tmp_path / "cp.json")
    ing = Ingestor(make_lake(), cp, table=TABLE, source="log-a")
    ing.start()
    src = synthetic.authentication(25)
    ing.ingest(src[:10], batch_id="log-a:0-10", position="10")
    assert cp.get("log-a").position == "10"

    crashing = Ingestor(make_lake(), cp, table=TABLE, source="log-a", before_checkpoint=_boom)
    with pytest.raises(Crash):
        crashing.ingest(src[10:20], batch_id="log-a:10-20", position="20")
    assert cp.get("log-a").position == "10"  # checkpoint is stale: it is behind the lake
    assert _count(make_lake())["n"] == 20  # but the data was committed

    # restart that ignores the lake mark and replays from the stale offset, re-chunked
    naive = Ingestor(make_lake(), cp, table=TABLE, source="log-a")
    res1 = naive.ingest(src[10:25], batch_id="log-a:10-25", position="25")
    assert res1.rows_written == 5 and res1.rows_skipped == 10
    assert _count(make_lake()) == {"n": 25, "d": 25}


def test_crash_then_same_batching_replay_is_caught_by_the_batch_ledger(make_lake, tmp_path):
    cp = Checkpoint(tmp_path / "cp.json")
    src = synthetic.authentication(20)
    with pytest.raises(Crash):
        Ingestor(make_lake(), cp, table=TABLE, source="s", before_checkpoint=_boom).ingest(
            src, batch_id="s:0-20", position="20"
        )
    res = Ingestor(make_lake(), cp, table=TABLE, source="s").ingest(
        src, batch_id="s:0-20", position="20"
    )
    assert res.replayed and res.rows_written == 0
    assert _count(make_lake()) == {"n": 20, "d": 20}
    assert cp.get("s").position == "20"


def test_start_fast_forwards_the_checkpoint_to_what_the_lake_committed(make_lake, tmp_path):
    cp = Checkpoint(tmp_path / "cp.json")
    src = synthetic.authentication(30)
    Ingestor(make_lake(), cp, table=TABLE, source="s").ingest(
        src[:10], batch_id="s:0", position="10"
    )
    with pytest.raises(Crash):
        Ingestor(make_lake(), cp, table=TABLE, source="s", before_checkpoint=_boom).ingest(
            src[10:20], batch_id="s:10", position="20"
        )
    assert cp.get("s").position == "10"
    resumed = Ingestor(make_lake(), cp, table=TABLE, source="s").start()
    assert resumed == "20"  # no tail re-read at all
    state = cp.get("s")
    assert state.batch_id == "s:10" and state.snapshot_id
    Ingestor(make_lake(), cp, table=TABLE, source="s").ingest(
        src[20:], batch_id="s:20", position="30"
    )
    assert _count(make_lake()) == {"n": 30, "d": 30}


def test_repeated_crashes_still_converge(make_lake, tmp_path):
    cp = Checkpoint(tmp_path / "cp.json")
    src = synthetic.authentication(40)
    for end in (10, 20, 30, 40):
        for _attempt in range(3):  # crash after commit, three times per batch, replaying each time
            ing = Ingestor(make_lake(), cp, table=TABLE, source="s", before_checkpoint=_boom)
            start = ing.start()
            first = int(start) if start else 0
            if first >= end:
                break
            with pytest.raises(Crash):
                ing.ingest(src[first:end], batch_id=f"s:{first}-{end}", position=str(end))
        Ingestor(make_lake(), cp, table=TABLE, source="s").start()
    assert _count(make_lake()) == {"n": 40, "d": 40}


def test_checkpoint_file_is_atomic_and_rejects_garbage(tmp_path):
    from homelabnext.lake import CheckpointError, SourceState

    p = tmp_path / "sub" / "cp.json"
    cp = Checkpoint(p)
    assert cp.get("x") is None
    cp.save("x", SourceState("5", "b", "snap"))
    assert cp.get("x") == SourceState("5", "b", "snap")
    assert [f.name for f in p.parent.iterdir()] == ["cp.json"]  # no temp file left behind
    p.write_text("{not json")
    with pytest.raises(CheckpointError):
        cp.get("x")


def test_batch_with_a_bad_row_writes_nothing(make_lake):
    lake = make_lake()
    rows = synthetic.authentication(5)
    rows[4]["time"] = "2026-03-01T00:00:00"  # naive
    with pytest.raises(RowRejected, match="no UTC offset"):
        lake.write_batch(TABLE, rows, idempotency_key="b")
    assert lake.describe(TABLE).row_count == 0


def test_unknown_table_refused(make_lake):
    with pytest.raises(UnknownTable):
        make_lake().write_batch("nope", [], idempotency_key="b")


# ------------------------------------------------------------ iceberg-only
@pytest.fixture
def ice(tmp_path):
    for m in ("pyiceberg", "pyarrow", "duckdb", "sqlalchemy"):
        pytest.importorskip(m)
    from homelabnext.lake.iceberg import IcebergLake, open_sql_catalog

    wh = tmp_path / "wh"
    wh.mkdir()
    cat = open_sql_catalog("t", uri=f"sqlite:///{tmp_path}/c.db", warehouse=f"file://{wh}")
    return IcebergLake, cat


def test_schema_mismatch_on_existing_table_is_refused(ice):
    IcebergLake, cat = ice
    from pyiceberg.schema import Schema
    from pyiceberg.types import NestedField, StringType

    cat.create_namespace_if_not_exists("ocsf")
    cat.create_table(
        ("ocsf", TABLE), schema=Schema(NestedField(1, "uid", StringType(), required=True))
    )
    lake = IcebergLake(cat, SCHEMAS)
    with pytest.raises(SchemaMismatch) as ei:
        lake.ensure_tables([TABLE])
    msg = str(ei.value)
    assert "missing column" in msg and "time" in msg
    with pytest.raises(SchemaMismatch):  # and a write straight at it is refused too
        lake.write_batch(TABLE, synthetic.authentication(1), idempotency_key="b")


def test_type_drift_is_refused(ice):
    IcebergLake, cat = ice
    from pyiceberg.schema import Schema
    from pyiceberg.types import NestedField, StringType

    from homelabnext.lake.ddl import to_iceberg

    good = to_iceberg(SCHEMAS[TABLE])
    fields = [
        NestedField(
            f.field_id,
            f.name,
            StringType() if f.name == "activity_id" else f.field_type,
            required=f.required,
        )
        for f in good.fields
    ]
    cat.create_namespace_if_not_exists("ocsf")
    cat.create_table(("ocsf", TABLE), schema=Schema(*fields))
    with pytest.raises(SchemaMismatch, match="activity_id"):
        IcebergLake(cat, SCHEMAS).ensure_tables([TABLE])


def test_ensure_tables_is_idempotent_and_partitioned(ice):
    IcebergLake, cat = ice
    lake = IcebergLake(cat, SCHEMAS)
    lake.ensure_tables()
    lake.ensure_tables()
    spec = cat.load_table(("ocsf", TABLE)).spec()
    assert [f.name for f in spec.fields] == ["time_day"]
    assert lake.list_tables() == sorted(SCHEMAS)


def test_snapshot_summary_carries_the_ledger(ice):
    IcebergLake, cat = ice
    lake = IcebergLake(cat, SCHEMAS)
    lake.ensure_tables()
    lake.write_batch(
        TABLE, synthetic.authentication(3), idempotency_key="b9", source="src", high_water="hw"
    )
    props = cat.load_table(("ocsf", TABLE)).current_snapshot().summary.additional_properties
    assert (props["hnx.batch-id"], props["hnx.source"], props["hnx.high-water"]) == (
        "b9",
        "src",
        "hw",
    )


def test_replay_is_safe_even_after_the_ledger_is_gone(ice):
    """Snapshot expiry removes the batch ledger; the content key still prevents duplicates."""
    IcebergLake, cat = ice
    lake = IcebergLake(cat, SCHEMAS)
    lake.ensure_tables()
    rows = synthetic.authentication(12)
    lake.write_batch(TABLE, rows, idempotency_key="b1")
    res = lake.write_batch(TABLE, rows, idempotency_key="b1-reissued-after-expiry")
    assert res.rows_written == 0 and lake.describe(TABLE).row_count == 12


def test_large_batch_dedupe_spans_key_chunks(ice):
    IcebergLake, cat = ice
    lake = IcebergLake(cat, SCHEMAS)
    lake.ensure_tables()
    rows = synthetic.authentication(1200)
    lake.write_batch(TABLE, rows, idempotency_key="big1")
    res = lake.write_batch(
        TABLE, rows + synthetic.authentication(1250)[1200:], idempotency_key="big2"
    )
    assert (res.rows_written, res.rows_skipped) == (50, 1200)
    assert lake.describe(TABLE).row_count == 1250


def test_iceberg_matches_cassette_too(ice):
    import json

    from golden_util import GOLDEN

    from homelabnext.lake import compare

    IcebergLake, cat = ice
    lake = IcebergLake(cat, SCHEMAS)
    lake.ensure_tables()
    for n, rows in synthetic.all_tables().items():
        lake.write_batch(n, rows, idempotency_key="seed")
    doc = json.loads((GOLDEN / "parity.cassette.json").read_text())
    assert compare(doc, lake) == []


def test_control_a_writer_without_content_keys_does_duplicate(tmp_path):
    """Negative control: proves the crash scenario really produces duplicates when the content-key
    layer is absent, so the zero-duplicate assertions above are not vacuous."""

    class NaiveLake(FakeLake):
        def _exists(self, s, key):
            return False

    lake = NaiveLake(SCHEMAS)
    src = synthetic.authentication(25)
    lake.write_batch(TABLE, src[:20], idempotency_key="a")  # committed, then "crash"
    lake.write_batch(TABLE, src[10:25], idempotency_key="b")  # stale-offset replay, new batching
    assert _count(lake) == {"n": 35, "d": 25}
