# SPDX-License-Identifier: Apache-2.0
"""``TrinoRestLake`` (Trino client protocol + Iceberg REST catalog) against a loopback fake."""

from __future__ import annotations

import math
from datetime import UTC, date, datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path

import pytest
from fake_lab import FakeLab, ParseError, parse_using

from homelabnext.conform.core import run_checks
from homelabnext.conform.registry import load_suite
from homelabnext.conform.target import load_target
from homelabnext.lake import LakeError, SchemaMismatch, UnknownTable
from homelabnext.lake.rest_catalog import RestCatalog
from homelabnext.lake.trino_http import Row, TrinoHTTP, decode_value, execute_immediate, literal
from homelabnext.lake.trino_rest import _ENSURED, TrinoRestLake

ROOT = Path(__file__).resolve().parents[2]
DOC_URL = "http://192.0.2.8:8080"  # no-raw-endpoint: allow RFC 5737 documentation address
NEVER = "http://localhost:1"  # no-raw-endpoint: allow never contacted
HOSTILE = (
    "x' OR '1'='1",
    "\\' OR 1=1 --",
    "x'; DELETE FROM authentication; --",
    ":q",
    "?",
    "x\nOR 1=1",
    "日本'語",
    "",
)


def _lake(lab, ns="t_ns", **kw):
    _ENSURED.clear()
    return TrinoRestLake(
        TrinoHTTP(lab.url, user="tester", sleep=lambda s: None),
        RestCatalog(lab.url, warehouse="lab"),
        namespace=ns,
        **kw,
    )


@pytest.fixture
def lab():
    with FakeLab() as fl:
        yield fl


# ---------------------------------------------------------------- the suites, end to end
@pytest.mark.parametrize("cap", ["lake-query", "lake-catalog"])
def test_the_lake_suites_pass_through_the_adapter(lab, cap):
    suite = load_suite(cap, ROOT)
    _lake(lab)  # creates the namespace and tables once, as the first subject of a run does
    res = run_checks(suite, lambda: _lake2(lab))
    bad = [(r.check, r.evidence) for r in res if r.status != "pass"]
    assert not bad, bad


def _lake2(lab):
    return TrinoRestLake(
        TrinoHTTP(lab.url, user="tester"), RestCatalog(lab.url, warehouse="lab"), namespace="t_ns"
    )


class _SplicingLake(TrinoRestLake):
    """Defect: values spliced into the text (quotes doubled) instead of bound."""

    def query(self, sql, params=None):
        from homelabnext.lake.sqlparams import check_params

        check_params(sql, params)
        for k, v in (params or {}).items():
            sql = sql.replace(":" + k, "'" + str(v).replace("'", "''") + "'")
        return self._trino.execute(sql).rows


def test_the_query_suite_fails_an_adapter_that_splices_values(lab):
    suite = load_suite("lake-query", ROOT)
    _lake(lab)
    res = run_checks(
        suite,
        lambda: _SplicingLake(
            TrinoHTTP(lab.url, user="t"), RestCatalog(lab.url, warehouse="lab"), namespace="t_ns"
        ),
    )
    failed = {r.check for r in res if not r.ok}
    assert "hostile-values-roundtrip-verbatim" in failed


# ---------------------------------------------------------------- binding
def test_every_hostile_value_is_one_literal_that_parses_back_verbatim():
    values = [*HOSTILE, None, True, False, 0, -(2**63), 2**63 - 1, 1.5, 1e-300, Decimal("1.10")]
    values += [datetime(2026, 3, 1, 8, 15, tzinfo=UTC), date(2026, 3, 1), b"\x00'\xff"]
    values += [["a'", None], Row(("ip'", 5, None))]
    stmt = execute_immediate("SELECT " + ", ".join("?" for _ in values), values)
    sql, got = parse_using(stmt)
    assert sql.count("?") == len(values)
    assert got == [tuple(v) if isinstance(v, Row) else v for v in values]
    _, (nan, inf, ninf) = parse_using(
        execute_immediate("SELECT ?, ?, ?", [math.nan, math.inf, -math.inf])
    )
    assert math.isnan(nan) and inf == math.inf and ninf == -math.inf


def test_the_statement_text_itself_is_quoted_too():
    sql = "SELECT 'it''s' AS a, ? AS b"
    back, args = parse_using(execute_immediate(sql, ["x"]))
    assert back == sql and args == ["x"]


def test_values_without_a_literal_are_refused():
    for bad in ({"a": 1}, object(), 2**64, Decimal("nan")):
        with pytest.raises(LakeError):
            literal(bad)
    assert literal(datetime(2026, 3, 1, 9, 15, tzinfo=timezone(timedelta(hours=1)))) == (
        "TIMESTAMP '2026-03-01 08:15:00.000000 UTC'"
    )


def test_the_fake_rejects_a_spliced_using_list():
    with pytest.raises(ParseError):
        parse_using("EXECUTE IMMEDIATE 'SELECT ?' USING 'a' OR 1=1")


# ---------------------------------------------------------------- decoding
def test_decode_by_type_signature():
    row_sig = {
        "rawType": "row",
        "arguments": [
            {
                "kind": "NAMED_TYPE",
                "value": {"fieldName": {"name": "ip"}, "typeSignature": {"rawType": "varchar"}},
            },
            {
                "kind": "NAMED_TYPE",
                "value": {"fieldName": {"name": "port"}, "typeSignature": {"rawType": "bigint"}},
            },
        ],
    }
    assert decode_value(["a", 22], row_sig) == {"ip": "a", "port": 22}
    assert decode_value({"port": 22, "ip": "x"}, row_sig) == {"ip": "x", "port": 22}
    tz = {"rawType": "timestamp with time zone"}
    want = datetime(2026, 3, 1, 8, 15, 0, 123456, tzinfo=UTC)
    assert decode_value("2026-03-01 08:15:00.123456789 UTC", tz) == want
    assert decode_value("2026-03-01 09:15:00.123456 +01:00", tz) == want
    assert decode_value("2026-03-01 09:15:00.123456 Europe/Paris", tz) == want
    assert decode_value("2026-03-01 08:15:00", {"rawType": "timestamp"}) == datetime(
        2026, 3, 1, 8, 15
    )
    arr = {"rawType": "array", "arguments": [{"kind": "TYPE", "value": {"rawType": "double"}}]}
    got = decode_value([1, "NaN", "Infinity"], arr)
    assert got[0] == 1.0 and math.isnan(got[1]) and got[2] == math.inf
    assert decode_value("1.10", {"rawType": "decimal"}) == Decimal("1.10")
    assert decode_value("AAE=", {"rawType": "varbinary"}) == b"\x00\x01"
    assert decode_value("2026-03-01", {"rawType": "date"}) == date(2026, 3, 1)
    with pytest.raises(LakeError):
        decode_value("yesterday", tz)


# ---------------------------------------------------------------- protocol behaviour
def test_results_are_paged_and_assembled(lab):
    lake = _lake(lab)
    from conformance.suites._lake import auth_row

    lake.write_batch("authentication", [auth_row(f"p-{i}") for i in range(5)], idempotency_key="k")
    rows = lake.query("SELECT uid FROM authentication ORDER BY uid")
    assert [r["uid"] for r in rows] == [f"p-{i}" for i in range(5)]  # 3 pages of 2


def test_unknown_table_and_schema_are_unknown_table_errors(lab):
    lake = _lake(lab)
    with pytest.raises(UnknownTable, match="TABLE_NOT_FOUND"):
        lake.query("SELECT uid FROM no_such_table_zz")
    with pytest.raises(UnknownTable):
        lake.describe("no_such_table_zz")
    t = TrinoHTTP(lab.url, user="u", schema="ghost")
    with pytest.raises(UnknownTable, match="SCHEMA_NOT_FOUND"):
        t.execute("SELECT 1 FROM authentication")


def test_a_next_uri_to_another_origin_is_not_followed(lab):
    t = TrinoHTTP(lab.url, user="u")
    t._request = _redirecting(t._request)  # type: ignore[method-assign]
    with pytest.raises(LakeError, match="another origin"):
        t.execute("SELECT 1")


def _redirecting(real):
    def call(url, body):
        doc = real(url, body)
        if body is not None:
            doc["nextUri"] = (
                "http://198.51.100.9:8080/v1/statement/x"  # no-raw-endpoint: allow RFC 5737 documentation address
            )
        return doc

    return call


def test_server_errors_and_unreachable_servers_are_lake_errors(lab):
    url = lab.url
    with pytest.raises(LakeError, match="HTTP 404"):
        TrinoHTTP(url + "/nope", user="u").execute("SELECT 1")
    lab.__exit__()
    with pytest.raises(LakeError, match="cannot reach"):
        TrinoHTTP(url, user="u", timeout=1).execute("SELECT 1")
    with pytest.raises(LakeError, match="cannot reach"):
        RestCatalog(url, warehouse="lab", timeout=1).list_tables("x")


# ---------------------------------------------------------------- catalog side
def test_list_tables_follows_page_tokens(lab):
    lake = _lake(lab)
    assert lake.list_tables() == sorted(lake._schemas)  # five tables, pages of two


def test_a_drifted_table_is_refused(lab):
    lab.schema_override["dns_activity"] = [
        {"id": 1, "name": "uid", "required": True, "type": "long"}
    ]
    with pytest.raises(SchemaMismatch, match="uid"):
        _lake(lab)


def test_marks_and_ledger_survive_a_commit_conflict(lab):
    from conformance.suites._lake import auth_row

    lake = _lake(lab)
    lab.conflicts = 2
    res = lake.write_batch(
        "authentication", [auth_row("c-1")], idempotency_key="b1", source="s1", high_water="hw"
    )
    mark = lake.describe("authentication").committed["s1"]
    assert (mark.batch_id, mark.high_water, mark.snapshot_id) == ("b1", "hw", res.snapshot_id)
    again = lake.write_batch("authentication", [auth_row("c-1")], idempotency_key="b1")
    assert again.replayed and again.snapshot_id == res.snapshot_id


def test_without_a_query_id_the_current_snapshot_is_recorded():
    from conformance.suites._lake import auth_row

    with FakeLab(trino_query_id=False) as lab:
        lake = _lake(lab)
        res = lake.write_batch("authentication", [auth_row("q-1")], idempotency_key="b")
        assert res.snapshot_id == lake.describe("authentication").snapshot_id


def test_bad_namespace_and_base_urls_are_refused():
    with pytest.raises(LakeError):
        TrinoHTTP("ftp://x", user="u")
    with pytest.raises(LakeError):
        RestCatalog("nope", warehouse="w")
    with pytest.raises(LakeError, match="namespace"):
        TrinoRestLake(
            TrinoHTTP(NEVER, user="u"),
            RestCatalog(NEVER, warehouse="w"),
            namespace="Bad-Name",
        )


# ---------------------------------------------------------------- the target factory
def test_factory_and_target_files(lab, monkeypatch):
    from homelabnext.conform.adapters.lake import make_lake

    _ENSURED.clear()
    monkeypatch.setenv("HNX_ENDPOINT_LAKE_QUERY", lab.url)
    monkeypatch.setenv("HNX_ENDPOINT_LAKE_CATALOG", lab.url)
    monkeypatch.setenv("LAB_WAREHOUSE", "lab")
    lake = make_lake(domain="example.internal")
    assert lake._ns.startswith("hnx_conform_") and "authentication" in lake.list_tables()
    monkeypatch.setenv("HNX_ENDPOINT_LAKE_QUERY", DOC_URL)
    with pytest.raises(LakeError, match="plaintext"):
        make_lake(domain="example.internal")
    monkeypatch.delenv("LAB_WAREHOUSE")
    with pytest.raises(LookupError, match="LAB_WAREHOUSE"):
        make_lake(domain="example.internal")
    for cap in ("lake-query", "lake-catalog"):
        t = load_target(str(ROOT / "compose" / "lab-in-a-box" / "targets" / f"{cap}.yml"))
        assert t.binding(cap).adapter == "homelabnext.conform.adapters.lake:make_lake"
