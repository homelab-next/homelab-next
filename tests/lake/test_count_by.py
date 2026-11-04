# SPDX-License-Identifier: Apache-2.0
"""``CeilingReader.count_by``: the bounded grouped aggregate (ADR-0035 decision 4)."""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta

import pytest
import synthetic

from homelabnext.lake import FakeLake, LakeError, load_schemas
from homelabnext.lake.ceiling import (
    MAX_GROUPS,
    CeilingError,
    CeilingReader,
    GroupCount,
    RedGrant,
    TooManyGroups,
)
from homelabnext.tlp import Label

SCHEMAS = load_schemas()
GRANT = RedGrant("tests", "the count_by tests read every row")
SINCE = datetime(2026, 3, 1, tzinfo=UTC)
UNTIL = datetime(2026, 3, 3, tzinfo=UTC)


def _reader(lake, ceiling):
    return CeilingReader(lake, ceiling, SCHEMAS, grant=GRANT if ceiling is Label.RED else None)


def _row(uid, *, t, user="alice", ip="198.51.100.10", port=22, label="green"):
    row = synthetic.authentication(1)[0]
    row.update(uid=uid, time=t, user_name=user, tlp=label)
    row["dst_endpoint"] = {"ip": ip, "port": port, "hostname": None}
    return row


def _lake(rows):
    lake = FakeLake(SCHEMAS)
    lake.write_batch("authentication", rows, idempotency_key="seed")
    return lake


@pytest.fixture
def lake():
    d1 = datetime(2026, 3, 1, 10, tzinfo=UTC)
    d2 = datetime(2026, 3, 2, 23, 59, 59, tzinfo=UTC)
    return _lake(
        [
            _row("a1", t=d1, port=22),
            _row("a2", t=d1 + timedelta(hours=1), port=22),
            _row("a3", t=d2, port=22),
            _row("a4", t=d2, port=443, label="amber"),
            _row("a5", t=d2, user="bob", port=22, label="red"),
            _row("a6", t=UNTIL, port=22),  # at until: outside the half-open range
            _row("a7", t=SINCE - timedelta(microseconds=1), port=22),  # before since
        ]
    )


def test_groups_by_entity_nested_value_day_and_label(lake):
    got = _reader(lake, Label.RED).count_by(
        "authentication", "user_name", ["dst_endpoint.port"], since=SINCE, until=UNTIL
    )
    assert got == [
        GroupCount("alice", (22,), date(2026, 3, 1), Label.GREEN, 2),
        GroupCount("alice", (22,), date(2026, 3, 2), Label.GREEN, 1),
        GroupCount("alice", (443,), date(2026, 3, 2), Label.AMBER, 1),
        GroupCount("bob", (22,), date(2026, 3, 2), Label.RED, 1),
    ]


@pytest.mark.parametrize(
    "ceiling, labels",
    [
        (Label.CLEAR, set()),
        (Label.GREEN, {Label.GREEN}),
        (Label.AMBER, {Label.GREEN, Label.AMBER}),
        (Label.RED, {Label.GREEN, Label.AMBER, Label.RED}),
    ],
)
def test_the_ceiling_filters_groups(lake, ceiling, labels):
    got = _reader(lake, ceiling).count_by(
        "authentication", "user_name", ["dst_endpoint.port"], since=SINCE, until=UNTIL
    )
    assert {g.label for g in got} == labels


def test_groups_are_rechecked_against_the_ceiling(lake):
    """A lake that ignored the predicate still returns nothing above the ceiling."""

    class Leaky(FakeLake):
        def query(self, sql, params=None):
            return super().query(sql.replace("coalesce(tlp, 'red') IN", "'x' NOT IN"), params)

    leaky = Leaky(SCHEMAS)
    leaky.write_batch("authentication", [_row("r", t=SINCE, label="red")], idempotency_key="k")
    reader = _reader(leaky, Label.GREEN)
    assert (
        reader.count_by(
            "authentication", "user_name", ["dst_endpoint.ip"], since=SINCE, until=UNTIL
        )
        == []
    )


def test_a_non_canonical_label_reads_red(lake):
    lake._db.execute("UPDATE authentication SET tlp = 'Green' WHERE uid = 'a1'")
    lake._db.execute("UPDATE authentication SET tlp = NULL WHERE uid = 'a2'")
    green = _reader(lake, Label.GREEN).count_by(
        "authentication", "user_name", ["dst_endpoint.port"], since=SINCE, until=UNTIL
    )
    assert date(2026, 3, 1) not in {g.day for g in green}
    red = _reader(lake, Label.RED).count_by(
        "authentication", "user_name", ["dst_endpoint.port"], since=SINCE, until=UNTIL
    )
    day1 = [g for g in red if g.day == date(2026, 3, 1)]
    assert {g.label for g in day1} == {Label.RED} and sum(g.count for g in day1) == 2


def test_where_is_bound_and_takes_nested_paths(lake):
    reader = _reader(lake, Label.RED)
    got = reader.count_by(
        "authentication",
        "user_name",
        ["dst_endpoint.port"],
        since=SINCE,
        until=UNTIL,
        where={"dst_endpoint.ip": "198.51.100.10", "user_name": "bob"},
    )
    assert [(g.entity, g.count) for g in got] == [("bob", 1)]
    hostile = {"user_name": "x' OR '1'='1"}
    assert (
        reader.count_by(
            "authentication",
            "user_name",
            ["dst_endpoint.port"],
            since=SINCE,
            until=UNTIL,
            where=hostile,
        )
        == []
    )


def test_multiple_values_and_nulls_are_not_counted(lake):
    lake._db.execute(
        "UPDATE authentication SET dst_endpoint = json_set(dst_endpoint, '$.port', NULL)"
        " WHERE uid = 'a5'"
    )
    got = _reader(lake, Label.RED).count_by(
        "authentication",
        "user_name",
        ["dst_endpoint.ip", "dst_endpoint.port"],
        since=SINCE,
        until=UNTIL,
    )
    assert {g.values for g in got} == {("198.51.100.10", 22), ("198.51.100.10", 443)}
    assert "bob" not in {g.entity for g in got}


@pytest.mark.parametrize(
    "kwargs, match",
    [
        ({"entity": "nope"}, "not its column"),
        ({"values": ["dst_endpoint.nope"]}, "not its column"),
        ({"values": ["dst_endpoint"]}, "is a struct"),
        ({"values": ["time"]}, "is a timestamp"),
        ({"values": []}, "at least one value"),
        ({"entity": None}, "or neither"),
        ({"time_column": "user_name"}, "time column"),
        ({"where": {"nope": 1}}, "not its column"),
        ({"where": {"user_name": None}}, "None"),
        ({"since": datetime(2026, 3, 1)}, "timezone-aware"),
        ({"until": SINCE}, "after since"),
        ({"limit": 0}, "limit"),
        ({"limit": MAX_GROUPS + 1}, "limit"),
        ({"table": "no_such_table"}, "unknown table"),
    ],
)
def test_bad_arguments_are_refused(lake, kwargs, match):
    args = {
        "table": "authentication",
        "entity": "user_name",
        "values": ["dst_endpoint.port"],
        "since": SINCE,
        "until": UNTIL,
    }
    args.update(kwargs)
    table, entity, values = args.pop("table"), args.pop("entity"), args.pop("values")
    with pytest.raises(CeilingError, match=match):
        _reader(lake, Label.RED).count_by(table, entity, values, **args)


def test_no_entity_and_no_values_counts_days(lake):
    got = _reader(lake, Label.AMBER).count_by("authentication", None, [], since=SINCE, until=UNTIL)
    assert got == [
        GroupCount(None, (), date(2026, 3, 1), Label.GREEN, 2),
        GroupCount(None, (), date(2026, 3, 2), Label.AMBER, 1),
        GroupCount(None, (), date(2026, 3, 2), Label.GREEN, 1),
    ]


def test_more_groups_than_the_limit_is_an_error_never_a_truncation(lake):
    reader = _reader(lake, Label.RED)
    args = ("authentication", "user_name", ["dst_endpoint.port"])
    assert len(reader.count_by(*args, since=SINCE, until=UNTIL, limit=4)) == 4
    with pytest.raises(TooManyGroups, match="more than 3 groups"):
        reader.count_by(*args, since=SINCE, until=UNTIL, limit=3)


def test_a_lake_without_a_dialect_is_refused(lake):
    class Bare:
        def query(self, sql, params=None):  # pragma: no cover - never reached
            raise AssertionError("ran")

    with pytest.raises(LakeError, match="declares no SQL dialect"):
        _reader(Bare(), Label.RED).count_by(
            "authentication", "user_name", ["dst_endpoint.port"], since=SINCE, until=UNTIL
        )


class _Recorder:
    def __init__(self, dialect):
        self.sql_dialect = dialect
        self.seen = []

    def query(self, sql, params=None):
        self.seen.append((sql, dict(params or {})))
        return []


@pytest.mark.parametrize(
    "dialect, field, day",
    [
        ("json-text", 'json_extract("dst_endpoint", \'$."port"\')', 'substr("time", 1, 10)'),
        ("struct", '"dst_endpoint"."port"', 'CAST("time" AS DATE)'),
    ],
)
def test_the_sql_follows_the_adapter_dialect(dialect, field, day):
    rec = _Recorder(dialect)
    _reader(rec, Label.GREEN).count_by(
        "authentication",
        "user_name",
        ["dst_endpoint.port"],
        since=SINCE,
        until=UNTIL,
        where={"auth_protocol": "ssh"},
    )
    ((sql, params),) = rec.seen
    assert sql == (
        f'SELECT "user_name" AS k_entity, {field} AS k_v0, {day} AS k_day, "tlp" AS k_tlp, '
        'count(*) AS k_n FROM "authentication" WHERE "time" >= :since AND "time" < :until '
        f'AND "user_name" IS NOT NULL AND {field} IS NOT NULL AND "auth_protocol" = :w0 '
        "AND coalesce(tlp, 'red') IN ('clear', 'green') "
        f'GROUP BY "user_name", {field}, {day}, "tlp" ORDER BY 1, 2, 3, 4 LIMIT 10001'
    )
    assert params == {"since": SINCE, "until": UNTIL, "w0": "ssh"}


def test_every_query_adapter_declares_a_dialect():
    """Every adapter in the lake package that runs SQL declares the dialect count_by renders;
    only the cassette, which replays recorded answers, declares none."""
    import importlib
    import pkgutil

    import homelabnext.lake as pkg
    from homelabnext.lake.base import AdapterBase
    from homelabnext.lake.dialect import DIALECTS

    for mod in pkgutil.iter_modules(pkg.__path__):
        importlib.import_module(f"homelabnext.lake.{mod.name}")
    adapters = {c.__name__: c for c in AdapterBase.__subclasses__()}
    assert len(adapters) >= 6 and FakeLake.sql_dialect == "json-text"
    for name, cls in adapters.items():
        want = None if name == "CassetteLake" else cls.__dict__.get("sql_dialect")
        assert getattr(cls, "sql_dialect", None) == want, name
        assert want is None or want in DIALECTS, name


def test_duckdb_agrees_with_the_fake(lake):
    pytest.importorskip("duckdb")
    pa = pytest.importorskip("pyarrow")
    from homelabnext.lake import DuckDBLake
    from homelabnext.lake.ddl import to_pyarrow
    from homelabnext.lake.validate import normalize_rows

    rows = [
        _row("a1", t=datetime(2026, 3, 1, 10, tzinfo=UTC), port=22),
        _row("a3", t=datetime(2026, 3, 2, 23, 59, 59, tzinfo=UTC), port=22),
        _row("a4", t=datetime(2026, 3, 2, 1, tzinfo=UTC), port=443, label="amber"),
        _row("a5", t=datetime(2026, 3, 2, 2, tzinfo=UTC), user="bob", label="red"),
    ]
    s = SCHEMAS["authentication"]
    tab = pa.Table.from_pylist(normalize_rows(s, rows), schema=to_pyarrow(s))
    duck = DuckDBLake({"authentication": tab}, SCHEMAS)
    args = ("authentication", "user_name", ["dst_endpoint.ip", "dst_endpoint.port"])
    for ceiling in (Label.GREEN, Label.AMBER, Label.RED):
        want = _reader(_lake(rows), ceiling).count_by(*args, since=SINCE, until=UNTIL)
        assert _reader(duck, ceiling).count_by(*args, since=SINCE, until=UNTIL) == want
        assert want
