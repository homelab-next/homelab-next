# SPDX-License-Identifier: Apache-2.0
"""``lake-catalog``: table metadata and idempotent, atomic writes."""

from __future__ import annotations

from homelabnext.conform.core import Mutant, Suite
from homelabnext.lake import FakeLake

from ._lake import TABLE, auth_row
from ._util import raises, uniq

SUITE = Suite(
    "lake-catalog",
    "tables, schemas and commit-then-checkpoint idempotent writes",
    "conformance.protocols.lake:LakeClient",
)


def _count(lake, prefix):
    sql = f"SELECT count(*) AS n FROM {TABLE} WHERE uid LIKE :p"
    return lake.query(sql, {"p": prefix + "-%"})[0]["n"]


@SUITE.check("lists-pinned-tables", "list_tables is sorted and includes the OCSF tables")
def _(lake):
    tables = lake.list_tables()
    assert tables == sorted(tables), f"not sorted: {tables}"
    assert TABLE in tables, f"{TABLE!r} missing from {tables}"


@SUITE.check("describe-reports-key-and-columns", "describe gives the content key and typed columns")
def _(lake):
    info = lake.describe(TABLE)
    assert info.name == TABLE
    assert info.key, "table has no content key"
    names = [c.name for c in info.columns]
    assert all(k in names for k in info.key), f"key {info.key} not among columns {names}"
    assert "time" in names


@SUITE.check("describe-unknown-table-rejected", "describe of a missing table is an error")
def _(lake):
    raises(lambda: lake.describe("no_such_table_zz"), "describe unknown table")


@SUITE.check("write-counts-rows", "row_count grows by exactly rows_written")
def _(lake):
    pre = uniq("c")
    before = lake.describe(TABLE).row_count
    res = lake.write_batch(
        TABLE, [auth_row(f"{pre}-{i}") for i in range(4)], idempotency_key=uniq("k")
    )
    assert (res.rows_in, res.rows_written, res.rows_skipped) == (4, 4, 0), f"result {res}"
    assert not res.replayed
    after = lake.describe(TABLE).row_count
    if before is not None and after is not None:
        assert after - before == 4, f"row_count {before} -> {after}"
    assert _count(lake, pre) == 4


@SUITE.check("replay-writes-nothing", "a repeated idempotency key commits nothing")
def _(lake):
    pre, key = uniq("c"), uniq("k")
    rows = [auth_row(f"{pre}-{i}") for i in range(3)]
    lake.write_batch(TABLE, rows, idempotency_key=key)
    again = lake.write_batch(TABLE, rows, idempotency_key=key)
    assert again.replayed, f"second write was not flagged as a replay: {again}"
    assert again.rows_written == 0, f"replay wrote {again.rows_written} rows"
    assert _count(lake, pre) == 3, f"expected 3 rows, found {_count(lake, pre)}"


@SUITE.check("content-key-dedups-across-batches", "same rows under a new key are skipped")
def _(lake):
    pre = uniq("c")
    rows = [auth_row(f"{pre}-{i}") for i in range(3)]
    lake.write_batch(TABLE, rows, idempotency_key=uniq("k"))
    res = lake.write_batch(TABLE, rows, idempotency_key=uniq("k"))
    assert (res.rows_written, res.rows_skipped) == (0, 3), f"result {res}"
    assert _count(lake, pre) == 3


@SUITE.check("duplicates-inside-batch-written-once", "a repeated key within one batch counts once")
def _(lake):
    pre = uniq("c")
    row = auth_row(f"{pre}-0")
    res = lake.write_batch(TABLE, [row, dict(row)], idempotency_key=uniq("k"))
    assert res.rows_written == 1 and res.rows_skipped == 1, f"result {res}"
    assert _count(lake, pre) == 1


@SUITE.check("bad-row-rejects-whole-batch", "one invalid row writes nothing from the batch")
def _(lake):
    pre = uniq("c")
    rows = [auth_row(f"{pre}-0"), auth_row(f"{pre}-1", severity_id="high")]
    raises(lambda: lake.write_batch(TABLE, rows, idempotency_key=uniq("k")), "invalid row")
    assert _count(lake, pre) == 0, "a rejected batch left rows behind"


@SUITE.check("naive-timestamp-refused", "a timestamp without a UTC offset is rejected")
def _(lake):
    pre = uniq("c")
    row = auth_row(f"{pre}-0", time="2026-03-01T08:15:00")
    raises(lambda: lake.write_batch(TABLE, [row], idempotency_key=uniq("k")), "naive timestamp")
    assert _count(lake, pre) == 0


@SUITE.check("unknown-column-refused", "a column outside the pinned schema is rejected")
def _(lake):
    pre = uniq("c")
    row = auth_row(f"{pre}-0", surprise_field="x")
    raises(lambda: lake.write_batch(TABLE, [row], idempotency_key=uniq("k")), "unknown column")


@SUITE.check("source-mark-recorded", "source and high-water mark are committed with the batch")
def _(lake):
    pre, key, src = uniq("c"), uniq("k"), uniq("src")
    lake.write_batch(
        TABLE, [auth_row(f"{pre}-0")], idempotency_key=key, source=src, high_water="hw-42"
    )
    mark = lake.describe(TABLE).committed.get(src)
    assert mark is not None, f"no mark for source {src!r}"
    assert (mark.batch_id, mark.high_water) == (key, "hw-42"), f"mark {mark}"


def make_fake():
    return FakeLake()


class ReplayingLake(FakeLake):
    """Defect: the idempotency key is ignored; only the content key stops duplicates, and
    the 'replayed' flag is never raised, so a retry is indistinguishable from new data."""

    def write_batch(self, table, rows, *, idempotency_key, source=None, high_water=None):
        res = super().write_batch(
            table, rows, idempotency_key=uniq("ignored"), source=source, high_water=high_water
        )
        return res


MUTANTS = {
    "idempotency-key-ignored": Mutant(
        ReplayingLake, "replay-writes-nothing", "a retried batch key is treated as new"
    ),
}
