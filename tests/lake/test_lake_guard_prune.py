# SPDX-License-Identifier: Apache-2.0
"""The lake-query adapter (``TrinoRestLake``, reached through the slot's factory): the NOT
EXISTS guard is bounded to each statement's own time range (so the engine prunes to those day
partitions), with the same idempotency as the unbounded guard.

Measured on the lab's engine: the unbounded guard scanned the whole target table once per
statement, so a commit's cost grew with the table and the raw archive fell behind for good.
"""

from __future__ import annotations

import dataclasses
import json
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fake_lab import FakeLab, parse_using

from homelabnext.conform.adapters.lake import make_lake
from homelabnext.lake import LakeError, load_schemas
from homelabnext.lake.tables import schema_from_json
from homelabnext.lake.validate import normalize_rows

ROOT = Path(__file__).resolve().parents[2]
T0 = datetime(2026, 3, 1, 8, 15, tzinfo=UTC)
BOUND = ' AND "t"."time" >= ? AND "t"."time" <= ?)'
GUARD_MARGIN = timedelta(seconds=1)  # the adapter's documented slack either side
_ADAPTER: list[type] = []


@pytest.fixture
def lab(monkeypatch):
    with FakeLab() as fl:
        monkeypatch.setenv("HNX_ENDPOINT_LAKE_QUERY", fl.url)
        monkeypatch.setenv("HNX_ENDPOINT_LAKE_CATALOG", fl.url)
        monkeypatch.setenv("LAB_WAREHOUSE", "lab")
        yield fl


def _lake(lab, max_query_length=None):
    """The lake slot's adapter on ``lab`` (a fresh namespace, its tables created)."""
    lake = make_lake(domain="example.internal")
    if max_query_length is not None:
        lake.max_query_length = max_query_length
    _ADAPTER[:] = [type(lake)]
    return lake


@pytest.fixture
def adapter(lab):
    _lake(lab)
    return _ADAPTER[0]


def _execute_immediate(sql, args):
    """The statement as the adapter sends it."""
    return sys.modules[_ADAPTER[0].__module__].execute_immediate(sql, args)


def _bare(max_query_length=900_000):
    """An adapter for building statements only (nothing is sent)."""
    lake = object.__new__(_ADAPTER[0])
    lake._cat, lake._ns, lake.max_query_length = "lake", "t_ns", max_query_length
    return lake


def _schema():
    return load_schemas()["authentication"]


def _rows(n, *, step=timedelta(hours=1), start=T0, prefix="r"):
    s = _schema()
    doc = json.loads((ROOT / "schemas/ocsf/examples/authentication.v1.valid1.json").read_text())
    raw = [
        dict(
            {k: doc.get(k) for k in s.column_names}, uid=f"{prefix}-{i:05d}", time=start + i * step
        )
        for i in range(n)
    ]
    return normalize_rows(s, raw)


def _times_of(s, args):
    """The time values of a statement's rows (its args without the two trailing bounds)."""
    width, at = len(s.columns), s.column_names.index("time")
    return [args[i + at] for i in range(0, len(args) - 2, width)]


_SENT = iter(range(10**6))


def _post(lake, stmt):
    """``stmt`` sent again on its own, past the write's content-key lookup (a coordinator that
    ran it and lost the reply, a client that re-sent it): only the statement's guard decides.
    Returns how many rows the engine appended."""
    s = _schema()
    rows = [None] * ((len(stmt[1]) - (2 if stmt[0].endswith(BOUND) else 0)) // len(s.columns))
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(lake, "_existing_keys", lambda s, rows: set())
        mp.setattr(lake, "_inserts", lambda s, fresh: [stmt])
        res = lake.write_batch(
            "authentication", _rows(len(rows)), idempotency_key=f"re-{next(_SENT)}"
        )
    return res.rows_written


def _count(lake):
    return lake.query("SELECT count(*) AS n FROM authentication")[0]["n"]


# ---------------------------------------------------------------- the generated SQL
def test_the_guard_is_bounded_by_the_statements_own_time_range(adapter):
    s = _schema()
    rows = _rows(5, step=timedelta(days=1))  # five days, five partitions
    [(sql, args)] = _bare()._inserts(s, rows)
    assert sql.endswith(BOUND)
    assert args[-2:] == [T0 - GUARD_MARGIN, T0 + timedelta(days=4) + GUARD_MARGIN]
    assert len(args) == 5 * len(s.columns) + 2 and sql.count("?") == len(args)
    # the bounds travel as typed timestamp literals in the USING list, never in the SQL text
    back, got = parse_using(_execute_immediate(sql, args))
    assert back == sql and got[-2:] == args[-2:]
    assert "TIMESTAMP '2026-03-01 08:14:59.000000 UTC'" in _execute_immediate(sql, args)


def test_every_statement_of_a_split_batch_has_its_own_bounds(adapter):
    s = _schema()
    rows = _rows(300, step=timedelta(minutes=30))  # a little over six days
    stmts = _bare(max_query_length=60_000)._inserts(s, rows)
    assert len(stmts) > 2
    for sql, args in stmts:
        assert sql.endswith(BOUND) and len(_execute_immediate(sql, args)) <= 60_000
        times = _times_of(s, args)
        assert args[-2:] == [min(times) - GUARD_MARGIN, max(times) + GUARD_MARGIN]
    assert sum(len(_times_of(s, a)) for _, a in stmts) == 300
    # consecutive statements cover consecutive ranges: each prunes to its own days only
    assert stmts[0][1][-1] < stmts[-1][1][-2]


def test_a_statement_with_a_row_without_a_time_keeps_the_unbounded_guard(adapter):
    s = dataclasses.replace(
        _schema(),
        columns=tuple(
            dataclasses.replace(c, required=False) if c.name == "time" else c
            for c in _schema().columns
        ),
    )
    rows = [dict(r) for r in _rows(3)]
    rows[1]["time"] = None
    [(sql, args)] = _bare()._inserts(s, rows)
    assert not sql.endswith(BOUND) and sql.endswith(' = "v"."uid")')
    assert len(args) == 3 * len(s.columns)


def test_the_longest_bounds_are_reserved_so_a_full_statement_stays_under_the_limit(adapter):
    s = _schema()
    far = datetime(9999, 12, 30, tzinfo=UTC)
    rows = _rows(400, step=timedelta(seconds=1), start=far)
    stmts = _bare(max_query_length=20_000)._inserts(s, rows)
    assert len(stmts) > 1
    assert all(len(_execute_immediate(q, a)) <= 20_000 for q, a in stmts)


def test_a_range_past_the_representable_one_falls_back_to_the_unbounded_guard(adapter):
    s = _schema()
    rows = _rows(1, start=datetime.max.replace(tzinfo=UTC) - timedelta(microseconds=1))
    [(sql, _)] = _bare()._inserts(s, rows)
    assert not sql.endswith(BOUND)


# ---------------------------------------------------------------- the same idempotency, end to end
def test_a_replayed_bounded_statement_appends_nothing_and_a_new_row_in_range_is_written(lab):
    lake = _lake(lab)
    s = _schema()
    rows = _rows(4, step=timedelta(hours=6))
    [stmt] = lake._inserts(s, rows)
    assert stmt[0].endswith(BOUND)
    assert [_post(lake, stmt) for _ in range(3)] == [4, 0, 0]
    assert _count(lake) == 4
    # a new row inside the same range, sent in a statement with the old ones: only it lands
    mixed = [*rows, *_rows(1, start=T0 + timedelta(hours=7), prefix="new")]
    [stmt2] = lake._inserts(s, mixed)
    assert _post(lake, stmt2) == 1
    assert _count(lake) == 5


def test_a_replay_of_a_split_write_appends_nothing(lab, monkeypatch):
    with FakeLab(max_query_length=60_000) as small:
        monkeypatch.setenv("HNX_ENDPOINT_LAKE_QUERY", small.url)
        monkeypatch.setenv("HNX_ENDPOINT_LAKE_CATALOG", small.url)
        lake = _lake(small, max_query_length=50_000)
        s = _schema()
        rows = _rows(200, step=timedelta(minutes=45))
        stmts = lake._inserts(s, rows)
        assert len(stmts) > 1
        assert sum(_post(lake, st) for st in stmts) == 200
        assert sum(_post(lake, st) for st in stmts) == 0
        assert _count(lake) == 200


def test_a_uid_stored_at_another_time_is_still_skipped_by_a_write(lab):
    # the bounded guard does not look outside its range; the write's own content-key lookup
    # does (the whole table), so a re-emitted row with a new time is still a duplicate
    lake = _lake(lab)
    [row] = _rows(1)
    lake.write_batch("authentication", [row], idempotency_key="b1")
    later = dict(row, time=row["time"] + timedelta(days=3))
    res = lake.write_batch("authentication", [later], idempotency_key="b2")
    assert (res.rows_written, res.rows_skipped) == (0, 1)
    assert _count(lake) == 1
    lookups = [t for t in lab.statements if t.lstrip().startswith("EXECUTE IMMEDIATE 'SELECT")]
    assert lookups and all('"time" >=' not in t for t in lookups)


def test_the_stand_in_honours_the_bound(lab):
    # proof the fake is not vacuous: the bounded guard alone does not see a key stored outside
    # its range (which is why the write's lookup stays unbounded unless a schema opts in)
    lake = _lake(lab)
    s = _schema()
    [row] = _rows(1)
    lake.write_batch("authentication", [row], idempotency_key="b1")
    [stmt] = lake._inserts(s, [dict(row, time=row["time"] + timedelta(days=3))])
    assert _post(lake, stmt) == 1
    assert _count(lake) == 2


# ---------------------------------------------------------------- the opt-in lookup bound
def test_no_shipped_schema_opts_in_to_a_bounded_lookup():
    from homelabnext.lake.tables import load_schemas as load

    shipped = {**load(), **load(ROOT / "modules/lake-writer/roles/lake_writer/files/schemas")}
    assert shipped and all(s.dedupe_window_hours is None for s in shipped.values())


def test_the_lookup_is_bounded_only_for_a_time_key_or_an_opt_in(adapter):
    lake, s = _bare(), _schema()
    rows = _rows(3, step=timedelta(hours=2))
    [(q, a)] = lake._key_lookups(s, rows)
    assert '"time"' not in q and a == [r["uid"] for r in rows]
    timed = dataclasses.replace(s, key=("uid", "time"))
    [(q, a)] = lake._key_lookups(timed, rows)
    assert q.startswith(
        'SELECT "uid", "time" FROM "lake"."t_ns"."authentication" WHERE "time" >= ? AND "time" <= ? AND (('
    )
    assert a[:2] == [T0, T0 + timedelta(hours=4)]  # equal keys, equal times: no slack needed
    opted = dataclasses.replace(s, dedupe_window_hours=24)
    [(q, a)] = lake._key_lookups(opted, rows)
    assert q.endswith("))") and a[:2] == [T0 - timedelta(hours=24), T0 + timedelta(hours=28)]
    assert len(_execute_immediate(q, a)) <= lake.max_query_length


def test_an_opted_in_window_skips_a_key_inside_it_and_appends_one_outside(lab, monkeypatch):
    lake = _lake(lab)
    opted = dataclasses.replace(_schema(), dedupe_window_hours=24)
    monkeypatch.setattr(lake, "_schema", lambda table: opted)
    [row] = _rows(1)
    lake.write_batch("authentication", [row], idempotency_key="b1")
    near = lake.write_batch(
        "authentication", [dict(row, time=row["time"] + timedelta(hours=20))], idempotency_key="b2"
    )
    assert (near.rows_written, near.rows_skipped) == (0, 1)
    far = lake.write_batch(
        "authentication", [dict(row, time=row["time"] + timedelta(days=3))], idempotency_key="b3"
    )
    assert (far.rows_written, far.rows_skipped) == (1, 0)  # the documented cost of opting in
    assert _count(lake) == 2


@pytest.mark.parametrize("bad", [-1, 1.5, "24", True])
def test_a_bad_dedupe_window_is_refused(bad):
    doc = json.loads((ROOT / "schemas/ocsf/authentication.v1.json").read_text())
    assert schema_from_json(doc).dedupe_window_hours is None
    doc["x-lake"]["dedupe_window_hours"] = bad
    with pytest.raises(LakeError, match="dedupe_window_hours"):
        schema_from_json(doc)
    doc["x-lake"]["dedupe_window_hours"] = 48
    assert schema_from_json(doc).dedupe_window_hours == 48
