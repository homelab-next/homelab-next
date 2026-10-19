# SPDX-License-Identifier: Apache-2.0
import copy
from datetime import timedelta

import lakes
import pytest

from homelabnext.lake import FakeLake
from homelabnext.parity import (
    ParityQuery,
    RowRules,
    Sample,
    compare_queries,
    compare_tables,
    schema_drift,
)

Q_COUNT = ParityQuery(
    "auth-by-user",
    sql="SELECT user_name, count(*) AS n FROM authentication GROUP BY user_name",
    rules=RowRules(key=("user_name",)),
    min_rows=3,
)
Q_ALL = ParityQuery(
    "dns",
    sql="SELECT uid, time, message FROM dns_activity",
    rules=RowRules(key=("uid",)),
    min_rows=1,
)


def test_identical_lakes_pass():
    a, b = lakes.pair()
    rep = compare_queries(a, b, [Q_COUNT, Q_ALL])
    assert rep.ok, rep.summary()
    assert compare_tables(a, b, lakes.TABLES, min_rows=10).ok


def test_empty_both_sides_is_not_parity():
    a, b = FakeLake(), FakeLake()
    rep = compare_queries(a, b, [Q_COUNT])
    assert not rep.ok and "need >=" in rep.checks[0].summary


def test_drift_dropped_row_changed_value_and_timestamp_caught():
    base = lakes.rows_for("authentication")
    mutated = copy.deepcopy(base)
    mutated.pop(5)  # dropped row
    mutated[3]["message"] = "login tampered"  # changed value
    mutated[8]["time"] = mutated[8]["time"] + timedelta(seconds=30)  # timestamp skew
    a = lakes.seeded()
    b = lakes.seeded({"authentication": mutated})
    rep = compare_tables(a, b, ["authentication"])
    assert not rep.ok
    rows = next(c for c in rep.checks if c.name.endswith(":rows"))
    assert rows.detail["only_left_total"] == 1
    assert rows.detail["changed_total"] == 2
    assert not compare_queries(
        a,
        b,
        [
            ParityQuery(
                "auth",
                sql="SELECT uid, message, time FROM authentication",
                rules=RowRules(key=("uid",)),
            )
        ],
    ).ok


def test_aggregate_drift_caught():
    base = lakes.rows_for("authentication")
    mutated = copy.deepcopy(base)
    for r in mutated:
        if r["user_name"] == "alice":
            r["user_name"] = "bob"
    rep = compare_queries(lakes.seeded(), lakes.seeded({"authentication": mutated}), [Q_COUNT])
    assert not rep.ok


def test_schema_drift_report():
    a = lakes.seeded()
    b = lakes.seeded(schemas=lakes.schemas_without_column("authentication", "auth_protocol"))
    drift = schema_drift(a.describe("authentication"), b.describe("authentication"))
    assert [(d.kind, d.column) for d in drift] == [("missing_on_right", "auth_protocol")]
    rep = compare_tables(a, b, ["authentication"])
    assert not rep.ok
    sch = next(c for c in rep.checks if c.name.endswith(":schema"))
    assert sch.detail["drift"][0]["column"] == "auth_protocol"
    assert schema_drift(b.describe("authentication"), a.describe("authentication"))[0].kind == (
        "extra_on_right"
    )


def test_sampling_marks_report_and_still_catches_drift_in_sample():
    base = lakes.rows_for("authentication")
    mutated = copy.deepcopy(base)
    for r in mutated[::2]:
        r["message"] = "drift"
    a = lakes.seeded()
    b = lakes.seeded({"authentication": mutated})
    rep = compare_tables(a, b, ["authentication"], sample=Sample(0.5))
    assert rep.sampled and not rep.ok
    assert compare_tables(a, lakes.seeded(), ["authentication"], sample=Sample(0.5)).ok


def test_query_error_is_a_failed_check_not_an_exception():
    a, b = lakes.pair()
    rep = compare_queries(a, b, [ParityQuery("bad", sql="SELECT nope FROM authentication")])
    assert not rep.ok and "query failed" in rep.checks[0].summary


def test_named_queries_and_validation():
    named = {"n": "SELECT count(*) AS c FROM authentication"}
    a, b = FakeLake(named_queries=named), FakeLake(named_queries=named)
    a.write_batch("authentication", lakes.rows_for("authentication"), idempotency_key="k")
    b.write_batch("authentication", lakes.rows_for("authentication"), idempotency_key="k")
    assert compare_queries(a, b, [ParityQuery("n", named="n", min_rows=1)]).ok
    with pytest.raises(ValueError):
        ParityQuery("both", sql="SELECT 1", named="n")
    with pytest.raises(ValueError):
        compare_tables(a, b, ["authentication; DROP"])


def test_report_json_is_canonical_and_stable():
    a, b = lakes.pair()
    r1 = compare_tables(a, b, lakes.TABLES)
    r2 = compare_tables(a, b, lakes.TABLES)
    assert r1.to_json() == r2.to_json() and r1.digest() == r2.digest()


def test_table_names_are_validated_and_quoted():
    from homelabnext.lake.errors import LakeError
    from homelabnext.lake.sqlparams import quote_table

    assert quote_table("authentication") == '"authentication"'
    assert quote_table("iceberg.soc.auth") == '"iceberg"."soc"."auth"'
    for bad in ("auth\n", "auth; DROP TABLE x", 'a"b', "a..b", "", "1abc", "a.b.c.d"):
        with pytest.raises(LakeError):
            quote_table(bad)
    a, b = lakes.pair()
    with pytest.raises(ValueError):
        compare_tables(a, b, ["authentication\n"])  # re.match + $ used to accept this


def test_a_describe_name_from_the_adapter_is_not_trusted():
    a, b = lakes.pair()

    class Lying:
        def __init__(self, inner):
            self.inner = inner

        def describe(self, t):
            info = self.inner.describe(t)
            from dataclasses import replace

            return replace(info, name="authentication WHERE 1=0 UNION SELECT 1")

        def __getattr__(self, n):
            return getattr(self.inner, n)

    rep = compare_tables(Lying(a), b, ["authentication"])
    rows = next(c for c in rep.checks if c.name == "table:authentication:rows")
    assert not rows.ok and "not a table identifier" in rows.summary
