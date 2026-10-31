# SPDX-License-Identifier: Apache-2.0
"""``homelabnext.lake.ceiling``: reading the lake at a TLP ceiling (ADR-0033 decision 6)."""

import dataclasses

import pytest
import synthetic

from homelabnext import tlp
from homelabnext.lake import FakeLake, load_schemas
from homelabnext.lake.ceiling import MAX_LIMIT, CeilingError, CeilingReader
from homelabnext.tlp import Label

SCHEMAS = load_schemas()


@pytest.fixture
def lake():
    lake = FakeLake(SCHEMAS)
    lake.write_batch("authentication", synthetic.authentication(10), idempotency_key="k")
    return lake


def _labels(rows):
    return sorted({r["tlp"] for r in rows})


@pytest.mark.parametrize(
    "ceiling, want",
    [
        (Label.CLEAR, ["clear"]),
        (Label.GREEN, ["clear", "green"]),
        (Label.AMBER, ["amber", "clear", "green"]),
        (Label.AMBER_STRICT, ["amber", "amber+strict", "clear", "green"]),
        (Label.RED, ["amber", "amber+strict", "clear", "green", "red"]),
    ],
)
def test_select_returns_rows_at_or_below_the_ceiling(lake, ceiling, want):
    rows = CeilingReader(lake, ceiling, SCHEMAS).select("authentication", ["uid", "user_name"])
    assert _labels(rows) == want
    assert all(set(r) == {"uid", "user_name", "tlp"} for r in rows)  # tlp always comes back


def test_where_filters_by_equality_with_bound_values(lake):
    reader = CeilingReader(lake, Label.RED, SCHEMAS)
    rows = reader.select("authentication", ["uid"], {"user_name": "alice"})
    assert rows and all(r["uid"] for r in rows)
    # a value is a parameter, never SQL
    assert reader.select("authentication", ["uid"], {"user_name": "x' OR '1'='1"}) == []


def test_a_row_with_no_label_reads_red(lake):
    s = SCHEMAS["authentication"]
    lake._db.execute(f'UPDATE "{s.name}" SET tlp = NULL WHERE uid = ?', ("auth-000000",))
    lake._db.execute(f'UPDATE "{s.name}" SET tlp = ? WHERE uid = ?', ("Green", "auth-000001"))
    green = CeilingReader(lake, Label.GREEN, SCHEMAS).select("authentication", ["uid"])
    assert {"auth-000000", "auth-000001"}.isdisjoint(r["uid"] for r in green)
    red = CeilingReader(lake, Label.RED, SCHEMAS).select("authentication", ["uid"])
    assert {"auth-000000", "auth-000001"} <= {r["uid"] for r in red}


@pytest.mark.parametrize("ceiling", [Label.CLEAR, Label.AMBER])
def test_raw_sql_is_refused_below_red(lake, ceiling):
    reader = CeilingReader(lake, ceiling, SCHEMAS)
    with pytest.raises(CeilingError, match="refused below red"):
        reader.query("SELECT 'clear' AS tlp, user_name FROM authentication")
    with pytest.raises(CeilingError, match="refused below red"):
        reader.named("anything")


def test_raw_sql_is_allowed_at_red(lake):
    rows = CeilingReader(lake, Label.RED, SCHEMAS).query("SELECT count(*) AS n FROM authentication")
    assert rows == [{"n": 10}]


@pytest.mark.parametrize(
    "call, needle",
    [
        (lambda r: r.select("nope"), "unknown table"),
        (lambda r: r.select("authentication", ["uid", "nope"]), "not its columns"),
        (lambda r: r.select("authentication", ['uid" FROM x --']), "not its columns"),
        (lambda r: r.select("authentication", ["uid"], {"nope": 1}), "not its columns"),
        (lambda r: r.select("authentication", limit=0), "limit"),
        (lambda r: r.select("authentication", limit=MAX_LIMIT + 1), "limit"),
        (lambda r: r.select("authentication", limit=True), "limit"),
    ],
)
def test_select_refuses_what_it_cannot_check(lake, call, needle):
    with pytest.raises(CeilingError, match=needle):
        call(CeilingReader(lake, Label.CLEAR, SCHEMAS))


def test_a_table_without_a_label_column_is_red_only(lake):
    s = SCHEMAS["authentication"]
    unlabelled = dataclasses.replace(s, columns=tuple(c for c in s.columns if c.name != "tlp"))
    schemas = {**SCHEMAS, "authentication": unlabelled}
    with pytest.raises(CeilingError, match="only red reads it"):
        CeilingReader(lake, Label.AMBER, schemas).select("authentication", ["uid"])
    assert CeilingReader(lake, Label.RED, schemas).select("authentication", ["uid"])


@pytest.mark.parametrize("ceiling", ["green", None, 1])
def test_the_ceiling_must_be_parsed(lake, ceiling):
    with pytest.raises(TypeError, match="ceiling must be a Label"):
        CeilingReader(lake, ceiling, SCHEMAS)


def test_row_filter_sql():
    assert tlp.row_filter_sql(Label.RED) is None
    assert tlp.row_filter_sql(Label.CLEAR) == "coalesce(tlp, 'red') IN ('clear')"
    assert tlp.row_filter_sql(Label.AMBER_STRICT, "label") == (
        "coalesce(label, 'red') IN ('clear', 'green', 'amber', 'amber+strict')"
    )
    with pytest.raises(ValueError, match="plain column"):
        tlp.row_filter_sql(Label.GREEN, "tlp); DROP TABLE x; --")
    with pytest.raises(TypeError):
        tlp.at_or_below("green")


def test_the_ceiling_is_fixed_and_odd_arguments_are_refused(lake):
    reader = CeilingReader(lake, Label.CLEAR, SCHEMAS)
    with pytest.raises(AttributeError):
        reader.ceiling = Label.RED
    with pytest.raises(CeilingError, match="unknown table"):
        reader.select(["authentication"])
    with pytest.raises(CeilingError, match="at least one column"):
        reader.select("authentication", [])
