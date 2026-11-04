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


@SUITE.check(
    "batch-id-bound-to-its-source",
    "a batch id committed by one source is refused, never replayed, for another",
)
def _(lake):
    pre, key = uniq("c"), uniq("k")
    lake.write_batch(TABLE, [auth_row(f"{pre}-0")], idempotency_key=key, source=uniq("src-a"))
    other = [auth_row(f"{pre}-1")]
    raises(
        lambda: lake.write_batch(TABLE, other, idempotency_key=key, source=uniq("src-b")),
        "another source's batch id",
    )
    assert _count(lake, pre) == 1, f"expected 1 row, found {_count(lake, pre)}"
    # the other order: a batch id committed with no source does not replay for a sourced write
    key2 = uniq("k")
    lake.write_batch(TABLE, [auth_row(f"{pre}-2")], idempotency_key=key2)
    raises(
        lambda: lake.write_batch(
            TABLE, [auth_row(f"{pre}-3")], idempotency_key=key2, source=uniq("src-c")
        ),
        "a sourced write of a batch id committed without a source",
    )
    # a write that names no source is not judged: it replays
    assert lake.write_batch(
        TABLE, [auth_row(f"{pre}-4")], idempotency_key=key, source=None
    ).replayed
    assert _count(lake, pre) == 2, f"expected 2 rows, found {_count(lake, pre)}"


@SUITE.check(
    "replay-judged-by-expect-source",
    "a batch re-sent without its mark but with expect_source is judged as that source's",
)
def _(lake):
    pre, key = uniq("c"), uniq("k")
    src = uniq("src-a")
    lake.write_batch(TABLE, [auth_row(f"{pre}-0")], idempotency_key=key, source=src)
    again = lake.write_batch(
        TABLE, [auth_row(f"{pre}-0")], idempotency_key=key, source=None, expect_source=src
    )
    assert again.replayed, f"its own batch, re-sent without the mark, did not replay: {again}"
    raises(
        lambda: lake.write_batch(
            TABLE, [auth_row(f"{pre}-1")], idempotency_key=key, expect_source=uniq("src-b")
        ),
        "a re-send expecting another source",
    )
    # a batch committed with no source is not another's to replay, even when only expected
    bare = uniq("k")
    lake.write_batch(TABLE, [auth_row(f"{pre}-2")], idempotency_key=bare)
    raises(
        lambda: lake.write_batch(
            TABLE, [auth_row(f"{pre}-3")], idempotency_key=bare, expect_source=src
        ),
        "a re-send expecting a source, of a batch committed with none",
    )
    # a write naming two different sources is refused outright
    raises(
        lambda: lake.write_batch(
            TABLE, [auth_row(f"{pre}-4")], idempotency_key=uniq("k"), source=src,
            expect_source=uniq("src-c"),
        ),
        "a write naming two sources",
    )  # fmt: skip
    assert _count(lake, pre) == 2, f"expected 2 rows, found {_count(lake, pre)}"


def make_fake():
    return FakeLake()


class ReplayingLake(FakeLake):
    """Defect: the idempotency key is ignored; only the content key stops duplicates, and
    the 'replayed' flag is never raised, so a retry is indistinguishable from new data."""

    def write_batch(
        self, table, rows, *, idempotency_key, source=None, high_water=None, expect_source=None
    ):
        res = super().write_batch(
            table, rows, idempotency_key=uniq("ignored"), source=source, high_water=high_water
        )
        return res


class SourceBlindLake(FakeLake):
    """Defect: a batch id replays whichever source committed it, so one writer can suppress
    another's batch by using its id first."""

    def write_batch(
        self, table, rows, *, idempotency_key, source=None, high_water=None, expect_source=None
    ):
        seen = self._db.execute(
            "SELECT seq FROM _hnx_batches WHERE batch_id=?", (idempotency_key,)
        ).fetchone()
        if seen is not None:
            from homelabnext.lake.protocol import WriteResult

            return WriteResult(len(rows), 0, len(rows), True, str(seen[0]))
        return super().write_batch(
            table, rows, idempotency_key=idempotency_key, source=source, high_water=high_water
        )


class StoredNoneUnjudgedLake(FakeLake):
    """Defect: a batch committed with no source replays for any write, so a writer that takes a
    sourced writer's batch id without a source still suppresses it."""

    def write_batch(
        self, table, rows, *, idempotency_key, source=None, high_water=None, expect_source=None
    ):
        seen = self._db.execute(
            "SELECT seq, source FROM _hnx_batches WHERE batch_id=?", (idempotency_key,)
        ).fetchone()
        if seen is not None and seen[1] is None:
            from homelabnext.lake.protocol import WriteResult

            return WriteResult(len(rows), 0, len(rows), True, str(seen[0]))
        return super().write_batch(
            table,
            rows,
            idempotency_key=idempotency_key,
            source=source,
            high_water=high_water,
            expect_source=expect_source,
        )


class ExpectedNoneUnjudgedLake(FakeLake):
    """Defect: expect_source is judged only against a recorded source, so a batch committed
    with no source replays for a writer that only expects one."""

    def write_batch(
        self, table, rows, *, idempotency_key, source=None, high_water=None, expect_source=None
    ):
        seen = self._db.execute(
            "SELECT seq, source FROM _hnx_batches WHERE batch_id=?", (idempotency_key,)
        ).fetchone()
        if seen is not None and seen[1] is None and expect_source is not None:
            from homelabnext.lake.protocol import WriteResult

            return WriteResult(len(rows), 0, len(rows), True, str(seen[0]))
        return super().write_batch(
            table,
            rows,
            idempotency_key=idempotency_key,
            source=source,
            high_water=high_water,
            expect_source=expect_source,
        )


class ExpectSourceIgnoredLake(FakeLake):
    """Defect: expect_source is ignored, so a mark-less re-send is never judged."""

    def write_batch(
        self, table, rows, *, idempotency_key, source=None, high_water=None, expect_source=None
    ):
        return super().write_batch(
            table, rows, idempotency_key=idempotency_key, source=source, high_water=high_water
        )


MUTANTS = {
    "stored-none-not-judged": Mutant(
        StoredNoneUnjudgedLake,
        "batch-id-bound-to-its-source",
        "a batch committed with no source replays for a sourced write",
    ),
    "expected-none-not-judged": Mutant(
        ExpectedNoneUnjudgedLake,
        "replay-judged-by-expect-source",
        "a batch committed with no source replays for a write that only expects a source",
    ),
    "expect-source-ignored": Mutant(
        ExpectSourceIgnoredLake,
        "replay-judged-by-expect-source",
        "a re-send without its mark is never judged",
    ),
    "batch-source-ignored": Mutant(
        SourceBlindLake,
        "batch-id-bound-to-its-source",
        "a batch id replays whichever source committed it",
    ),
    "idempotency-key-ignored": Mutant(
        ReplayingLake, "replay-writes-nothing", "a retried batch key is treated as new"
    ),
}
