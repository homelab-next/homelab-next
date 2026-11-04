# SPDX-License-Identifier: Apache-2.0
"""``lake-query``: the read side of the lake - parameter binding, ordering, types, errors."""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta

from homelabnext.conform.core import Mutant, Suite
from homelabnext.lake import FakeLake, load_schemas
from homelabnext.lake.ceiling import CeilingReader, GroupCount, RedGrant
from homelabnext.tlp import Label

from ._lake import TABLE, auth_row
from ._util import ip, raises, uniq

SUITE = Suite(
    "lake-query",
    "SQL (portable subset) over the OCSF tables with bound named parameters",
    "conformance.protocols.lake:LakeClient",
)

_BASE = f"SELECT uid, user_name, time FROM {TABLE} WHERE uid LIKE :p ORDER BY uid"


def _seed(lake, n=3, user="alice"):
    pre = uniq("q")
    rows = [auth_row(f"{pre}-{i:02d}", user=user) for i in range(n)]
    lake.write_batch(TABLE, rows, idempotency_key=uniq("seed"))
    return pre, [r["uid"] for r in rows]


@SUITE.check("returns-written-rows-in-order", "ORDER BY returns exactly the rows written")
def _(lake):
    pre, uids = _seed(lake)
    got = [r["uid"] for r in lake.query(_BASE, {"p": pre + "-%"})]
    assert got == uids, f"expected {uids}, got {got}"


@SUITE.check("rows-unique-by-key", "a query never returns the same key twice")
def _(lake):
    pre, uids = _seed(lake)
    got = [r["uid"] for r in lake.query(_BASE, {"p": pre + "-%"})]
    assert len(got) == len(set(got)), f"duplicate rows returned: {got}"
    assert len(got) == len(uids), f"expected {len(uids)} rows, got {len(got)}"


#: values that change the meaning of a query if they are spliced into the SQL text instead of
#: bound: quotes, comments, statement separators, backslash escapes and placeholder look-alikes
HOSTILE = (
    "x' OR '1'='1",
    "x'' OR ''1''=''1",
    "\\' OR 1=1 --",
    "x' --",
    "x'; DELETE FROM authentication; --",
    "x'); DROP TABLE authentication; SELECT ('",
    ":q",
    ":p OR 1=1",
    "%' OR uid LIKE '%",
    "x\nOR 1=1",
)


@SUITE.check("named-params-are-bound", "a parameter value is data, never SQL - in any position")
def _(lake):
    pre, uids = _seed(lake)
    two = f"SELECT uid FROM {TABLE} WHERE uid LIKE :p AND user_name = :q ORDER BY uid"
    for hostile in HOSTILE:
        assert lake.query(_BASE, {"p": hostile}) == [], f"hostile value {hostile!r} matched rows"
        # two placeholders, the hostile value in either, in either insertion order
        for params in (
            {"p": hostile, "q": "alice"},
            {"q": "alice", "p": hostile},
            {"p": pre + "-%", "q": hostile},
            {"q": hostile, "p": pre + "-%"},
        ):
            got = lake.query(two, params)
            assert got == [], f"hostile value {hostile!r} matched rows with {params}"
    # the table is intact afterwards
    assert len(lake.query(_BASE, {"p": pre + "-%"})) == len(uids)


@SUITE.check(
    "hostile-values-roundtrip-verbatim",
    "a bound value comes back exactly as given, whether selected or compared",
)
def _(lake):
    pre = uniq("v")
    rows = [auth_row(f"{pre}-{i:02d}", user=v) for i, v in enumerate(HOSTILE)]
    lake.write_batch(TABLE, rows, idempotency_key=uniq("seed"))
    # the placeholder names match the look-alikes in HOSTILE, so text substitution collides
    sel = f"SELECT uid, :p AS v, user_name FROM {TABLE} WHERE uid = :q AND user_name = :p"
    for i, v in enumerate(HOSTILE):
        uid = f"{pre}-{i:02d}"
        for params in ({"p": v, "q": uid}, {"q": uid, "p": v}):
            got = lake.query(sel, params)
            assert len(got) == 1, f"value {v!r}: expected its one row, got {len(got)}"
            assert got[0]["v"] == v and got[0]["user_name"] == v, (
                f"value {v!r} came back as {got[0]['v']!r} / {got[0]['user_name']!r}"
            )


@SUITE.check("missing-param-rejected", "a placeholder with no value is an error")
def _(lake):
    raises(lambda: lake.query(_BASE, {}), "missing parameter")


@SUITE.check("unused-param-rejected", "a value for a placeholder that does not exist is an error")
def _(lake):
    raises(lambda: lake.query(_BASE, {"p": "%", "extra": 1}), "unused parameter")


@SUITE.check("unknown-table-rejected", "querying a table that does not exist is an error")
def _(lake):
    raises(lambda: lake.query("SELECT uid FROM no_such_table_zz"), "unknown table")


@SUITE.check(
    "timestamps-roundtrip-as-utc",
    "a time column comes back as the UTC instant written (aware UTC, or naive wall time in UTC)",
)
def _(lake):
    pre, _ = _seed(lake, 1)
    (row,) = lake.query(_BASE, {"p": pre + "-%"})
    t = row["time"]
    assert isinstance(t, datetime), f"time is {type(t).__name__}, not a datetime"
    if t.tzinfo is not None:
        assert t.utcoffset() == timedelta(0), f"aware but not UTC: {t!r}"
        t = t.replace(tzinfo=None)
    assert t == datetime(2026, 3, 1, 8, 15, 0), f"wrong instant: {t!r}"


@SUITE.check("limit-and-order-respected", "ORDER BY ... DESC LIMIT n returns the top n")
def _(lake):
    pre, uids = _seed(lake, 4)
    sql = f"SELECT uid FROM {TABLE} WHERE uid LIKE :p ORDER BY uid DESC LIMIT 2"
    got = [r["uid"] for r in lake.query(sql, {"p": pre + "-%"})]
    assert got == uids[::-1][:2], f"expected {uids[::-1][:2]}, got {got}"


@SUITE.check("aggregates-count-rows", "count(*) agrees with the rows written")
def _(lake):
    pre, uids = _seed(lake, 5)
    sql = f"SELECT count(*) AS n FROM {TABLE} WHERE uid LIKE :p"
    (row,) = lake.query(sql, {"p": pre + "-%"})
    assert row["n"] == len(uids), f"count {row['n']} != {len(uids)}"


@SUITE.check("struct-columns-roundtrip", "nested columns come back as objects")
def _(lake):
    pre, _ = _seed(lake, 1)
    (row,) = lake.query(
        f"SELECT src_endpoint FROM {TABLE} WHERE uid LIKE :p",
        {"p": pre + "-%"},
    )
    ep = row["src_endpoint"]
    assert isinstance(ep, dict) and ep.get("ip") == ip(10, 1), f"got {ep!r}"


@SUITE.check(
    "count-by-groups-nested-fields-by-utc-day",
    "CeilingReader.count_by over the adapter's dialect groups a nested field by UTC day and label",
)
def _(lake):
    user = uniq("cb")
    rows = [
        auth_row(f"{user}-0", user=user, time="2026-03-01T23:59:59Z"),
        auth_row(f"{user}-1", user=user, time="2026-03-02T00:30:00+01:00"),  # 03-01 23:30 UTC
        auth_row(f"{user}-2", user=user, time="2026-03-02T00:00:00Z", tlp="green"),
        auth_row(
            f"{user}-3",
            user=user,
            time="2026-03-02T08:00:00Z",
            dst_endpoint={"ip": ip(21), "port": 22},
        ),
    ]
    lake.write_batch(TABLE, rows, idempotency_key=uniq("seed"))
    grant = RedGrant("conformance", "the lake-query suite counts the rows it wrote")
    reader = CeilingReader(lake, Label.RED, load_schemas(), grant=grant)
    got = reader.count_by(
        TABLE,
        "user_name",
        ["dst_endpoint.ip", "is_mfa"],
        since=datetime(2026, 3, 1, tzinfo=UTC),
        until=datetime(2026, 3, 3, tzinfo=UTC),
        where={"user_name": user},
    )
    want = [
        GroupCount(user, (ip(20), False), date(2026, 3, 1), Label.RED, 2),
        GroupCount(user, (ip(20), False), date(2026, 3, 2), Label.GREEN, 1),
        GroupCount(user, (ip(21), False), date(2026, 3, 2), Label.RED, 1),
    ]
    assert got == want, f"expected {want}, got {got}"
    types = {(type(g.entity), *map(type, g.values)) for g in got}
    assert types == {(str, str, bool)}, f"keys must come back as their column types: {types}"


@SUITE.check("unknown-named-query-rejected", "named() with an unregistered name is an error")
def _(lake):
    raises(lambda: lake.named("no_such_named_query_zz"), "unknown named query")


def make_fake():
    return FakeLake()


class DuplicatingLake(FakeLake):
    """Defect: every query result is returned twice (a join fan-out that nobody noticed)."""

    def query(self, sql, params=None):
        rows = super().query(sql, params)
        return [r for r in rows for _ in (0, 1)]


class InterpolatingLake(FakeLake):
    """Defect: parameters are spliced into the SQL text (quotes doubled, one name at a time)."""

    def query(self, sql, params=None):
        from homelabnext.lake.sqlparams import check_params

        check_params(sql, params)
        for k, v in (params or {}).items():
            lit = str(v) if isinstance(v, int) else "'" + str(v).replace("'", "''") + "'"
            sql = sql.replace(":" + k, lit)
        return super().query(sql, {})


class WrongDialectLake(FakeLake):
    """Defect: the adapter declares a dialect its engine does not speak."""

    sql_dialect = "struct"


MUTANTS = {
    "wrong-dialect": Mutant(
        WrongDialectLake,
        "count-by-groups-nested-fields-by-utc-day",
        "the adapter's sql_dialect does not match its engine",
    ),
    "duplicate-rows": Mutant(
        DuplicatingLake, "rows-unique-by-key", "query returns every row twice"
    ),
    "interpolated-params": Mutant(
        InterpolatingLake,
        "hostile-values-roundtrip-verbatim",
        "parameters are spliced into the SQL text with quote doubling",
    ),
}
