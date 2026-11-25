# SPDX-License-Identifier: Apache-2.0
"""The read-only lake MCP server (``hnx lake mcp``, ``homelabnext.lake.mcp_tools``, catalog id
``hnx-lake``): anything but one SELECT is refused before a byte reaches the engine, parameters are
bound by the engine, rows and time are bounded, the settings refuse an unsafe credential or
endpoint, and the catalog record holds read tools only."""

from __future__ import annotations

import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml
from fake_lab import FakeLab

from homelabnext.lake import cli as lake_cli
from homelabnext.lake.errors import LakeError
from homelabnext.lake.mcp_tools import (
    MAX_ROWS,
    SERVER_NAME,
    TOOLS,
    LakeReader,
    Settings,
    SettingsError,
    engine_for,
    load_settings,
)
from homelabnext.lake.readonly import WRITE_WORDS, QueryRefused, select_only

ROOT = Path(__file__).resolve().parents[2]
RECORD = ROOT / "examples" / "mcp" / f"{SERVER_NAME}.yml"

WRITES = (
    "INSERT INTO soc.raw_archive VALUES (1)",
    "insert into t select * from u",
    "CREATE TABLE soc.x AS SELECT 1",
    "CREATE SCHEMA lake.x",
    "CALL lake.system.rollback_to_snapshot('soc', 'raw_archive', 1)",
    "ALTER TABLE soc.raw_archive EXECUTE expire_snapshots(retention_threshold => '0d')",
    "ALTER TABLE soc.raw_archive ADD COLUMN x varchar",
    "DELETE FROM soc.raw_archive",
    "DROP TABLE soc.raw_archive",
    "UPDATE t SET a = 1",
    "MERGE INTO t USING u ON t.a = u.a WHEN MATCHED THEN DELETE",
    "TRUNCATE TABLE t",
    "GRANT SELECT ON t TO x",
    "EXPLAIN ANALYZE INSERT INTO t VALUES (1)",
    "EXPLAIN SELECT 1",
    "SHOW TABLES",
    "SET SESSION query_max_run_time = '1d'",
    "USE lake.soc",
    "EXECUTE IMMEDIATE 'DELETE FROM t'",
    "SELECT 1; DELETE FROM t",
    "WITH a AS (SELECT 1) INSERT INTO t SELECT * FROM a",
    "SELECT * FROM t WHERE a = 1; DROP TABLE t; --",
    "(SELECT 1); CALL x()",
    "1 SELECT",
    "SELECT 'unterminated",
    "SELECT 1 /* open comment",
    "",
    "   ",
)
READS = (
    ("SELECT 1", "SELECT 1"),
    ("select count(*) from soc.raw_archive;", "select count(*) from soc.raw_archive"),
    ("WITH a AS (SELECT 1 AS x) SELECT x FROM a", "WITH a AS (SELECT 1 AS x) SELECT x FROM a"),
    ("(SELECT 1) UNION ALL (SELECT 2)", "(SELECT 1) UNION ALL (SELECT 2)"),
    ("SELECT 'DELETE; DROP' AS s", "SELECT 'DELETE; DROP' AS s"),
    ('SELECT "update", "delete" FROM t', 'SELECT "update", "delete" FROM t'),
    ("/* why */ SELECT 1 -- note; done", "/* why */ SELECT 1 -- note; done"),
    ("SELECT 1; -- trailing; comment", "SELECT 1"),
    ("SELECT * FROM t WHERE a = :a", "SELECT * FROM t WHERE a = :a"),
)


class Engine:
    """An engine double: records every statement, answers from ``answer`` (a function of the
    statement) and honours ``max_rows`` like the real client."""

    def __init__(self, answer=None):
        self.sent: list[tuple[str, list]] = []
        self.answer = answer or (lambda sql, args: ([{"name": "x"}], [{"x": 1}]))

    def execute(self, sql, args=(), *, client_tags=(), max_rows=None, deadline=None):
        self.sent.append((sql, list(args)))
        self.deadline = deadline
        cols, rows = self.answer(sql, list(args))
        res = SimpleNamespace(query_id="q1", columns=list(cols), rows=list(rows), truncated=False)
        if max_rows is not None and len(res.rows) > max_rows:
            del res.rows[max_rows:]
            res.truncated = True
        return res


def _settings(tmp_path: Path, **kw) -> Settings:
    cred = tmp_path / "reader-password"
    cred.write_text("pw" * 4 + "\n")
    cred.chmod(0o600)
    v = {
        "endpoint": "https://lake-query.example.internal",
        "user": "lake-mcp",
        "catalog": "lake_ro",
        "schemas": ["soc", "cti"],
        "credential_file": str(cred),
        "max_rows": 50,
        "timeout_s": 30,
    }
    v.update(kw)
    return Settings(**{**v, "schemas": tuple(v["schemas"])})


# ---------------------------------------------------------------- the SELECT-only gate
@pytest.mark.parametrize("sql", WRITES)
def test_anything_but_one_select_is_refused_and_nothing_is_sent(tmp_path, sql):
    with pytest.raises(QueryRefused):
        select_only(sql)
    engine = Engine()
    with pytest.raises(QueryRefused):
        LakeReader(engine, _settings(tmp_path)).query(sql)
    assert engine.sent == [], "a refused statement reached the engine"


@pytest.mark.parametrize("sql,sent", READS)
def test_a_single_read_passes_the_gate_verbatim(sql, sent):
    assert select_only(sql) == sent


def test_every_write_verb_is_refused_as_a_bare_word_and_passes_quoted():
    for word in sorted(WRITE_WORDS):
        with pytest.raises(QueryRefused, match=word):
            select_only(f"SELECT {word.lower()} FROM t")
        assert select_only(f'SELECT "{word.lower()}" FROM t')


def test_the_gate_never_echoes_the_statement():
    secretish = "SELECT 1; DELETE FROM t WHERE x = 'do-not-echo-me'"
    with pytest.raises(QueryRefused) as exc:
        select_only(secretish)
    assert "do-not-echo-me" not in str(exc.value)


def test_an_oversized_statement_is_refused():
    with pytest.raises(QueryRefused, match="longer"):
        select_only("SELECT 1 " + " " * 20_001)


# ---------------------------------------------------------------- the reads
def test_parameters_are_bound_by_the_engine_never_spliced(tmp_path):
    engine = Engine()
    reader = LakeReader(engine, _settings(tmp_path))
    hostile = "x' OR '1'='1; DROP TABLE t; --"
    out = reader.query("SELECT a FROM soc.t WHERE a = :v AND b IN (:v, :w)", {"v": hostile, "w": 3})
    ((sql, args),) = engine.sent
    assert sql == "SELECT a FROM soc.t WHERE a = ? AND b IN (?, ?)"
    assert args == [hostile, hostile, 3] and hostile not in sql
    assert out["columns"] == ["x"] and out["rows"] == [[1]] and out["truncated"] is False


def test_a_missing_an_unused_or_an_unbindable_parameter_is_refused(tmp_path):
    reader = LakeReader(Engine(), _settings(tmp_path))
    with pytest.raises(LakeError, match="not supplied"):
        reader.query("SELECT 1 WHERE 1 = :a")
    with pytest.raises(LakeError, match="not used"):
        reader.query("SELECT 1", {"a": 1})
    with pytest.raises(QueryRefused):
        reader.query("SELECT 1 WHERE 1 = :a", {"a": {"nested": "object"}})
    with pytest.raises(QueryRefused):
        reader.query("SELECT 1 WHERE 1 = :a", ["not", "a", "mapping"])


def test_rows_are_capped_by_the_call_and_never_above_the_settings(tmp_path):
    many = lambda sql, args: ([{"name": "n"}], [{"n": i} for i in range(200)])  # noqa: E731
    engine = Engine(many)
    reader = LakeReader(engine, _settings(tmp_path, max_rows=50, timeout_s=30))
    out = reader.query("SELECT n FROM t", max_rows=10)
    assert out["row_count"] == 10 and out["truncated"] is True and engine.deadline == 30.0
    assert reader.query("SELECT n FROM t")["row_count"] == 50
    for bad in (0, 51, -1, True, "5"):
        with pytest.raises(QueryRefused, match="max_rows"):
            reader.query("SELECT n FROM t", max_rows=bad)


def test_values_come_back_as_json(tmp_path):
    from datetime import UTC, datetime
    from decimal import Decimal

    when = datetime(2026, 11, 24, 12, 0, tzinfo=UTC)
    row = {"t": when, "d": Decimal("1.50"), "b": b"\x00\x01", "s": {"ip": "x"}, "f": float("nan")}
    engine = Engine(lambda sql, args: ([{"name": k} for k in row], [row]))
    out = LakeReader(engine, _settings(tmp_path)).query("SELECT * FROM t")
    text = json.dumps(out, allow_nan=False)
    assert json.loads(text)["rows"][0] == [
        when.isoformat(),
        "1.50",
        {"base64": "AAE="},
        {"ip": "x"},
        "nan",
    ]


def test_list_and_describe_look_only_at_the_allowed_schemas(tmp_path):
    def answer(sql, args):
        if "information_schema.tables" in sql:
            return [], [{"table_schema": s, "table_name": "t"} for s in args]
        return [], [
            {
                "table_schema": "soc",
                "column_name": "uid",
                "data_type": "varchar",
                "is_nullable": "NO",
            }
        ]

    engine = Engine(answer)
    reader = LakeReader(engine, _settings(tmp_path))
    assert reader.list_tables()["tables"] == ["soc.t", "cti.t"]
    assert engine.sent[-1][0].startswith('SELECT table_schema, table_name FROM "lake_ro".')
    assert reader.list_tables("cti")["tables"] == ["cti.t"]
    with pytest.raises(QueryRefused):
        reader.list_tables("honeypot")
    got = reader.describe_table("soc.raw_archive")
    assert got == {
        "table": "soc.raw_archive",
        "columns": [{"name": "uid", "type": "varchar", "nullable": False}],
    }
    assert engine.sent[-1][1] == ["raw_archive", "soc"]
    for bad in ("honeypot.events", "soc.x; DROP", 'soc."x"', "a.b.c"):
        with pytest.raises(QueryRefused):
            reader.describe_table(bad)


# ---------------------------------------------------------------- the engine client's limits
@pytest.fixture(autouse=True)
def _no_secret_left(monkeypatch):
    """engine_for puts the reader's password in this process's secret variable: restore it."""
    monkeypatch.setenv("HNX_SECRET_LAKE_MCP_READER_PASSWORD", "x")  # records the old state
    monkeypatch.delenv("HNX_SECRET_LAKE_MCP_READER_PASSWORD")


@pytest.fixture
def lab():
    with FakeLab(page_size=2) as fl:
        yield fl


def _seeded(lab, tmp_path, **options):
    """Seven rows in the stand-in's namespace mcp_ns, and an engine of the server's own settings
    pointed at it (loopback http, the reader's password from its file)."""
    from conformance.suites._lake import auth_row
    from homelabnext.conform.adapters.lake import make_lake

    lake = make_lake(namespace="mcp_ns", resolver=_Here(lab.url), warehouse="lab")
    lake.write_batch("authentication", [auth_row(f"r-{i}") for i in range(7)], idempotency_key="k")
    s = _settings(tmp_path, endpoint=lab.url, catalog="lake_ro")
    engine = engine_for(s, schema="mcp_ns", **options)
    return engine


class _Here:
    def __init__(self, url):
        self.url = url

    def resolve(self, capability):
        from homelabnext.registry.resolver import parse_override

        return parse_override(capability, "test", self.url)


def test_the_client_stops_reading_and_cancels_past_max_rows(lab, tmp_path, monkeypatch):
    engine = _seeded(lab, tmp_path)
    cancelled = []
    monkeypatch.setattr(type(engine), "cancel", lambda self, uri: cancelled.append(uri))
    res = engine.execute("SELECT uid FROM authentication ORDER BY uid", max_rows=3)
    assert [r["uid"] for r in res.rows] == ["r-0", "r-1", "r-2"] and res.truncated
    assert len(cancelled) == 1 and cancelled[0].startswith(lab.url)
    full = engine.execute("SELECT uid FROM authentication ORDER BY uid", max_rows=7)
    assert len(full.rows) == 7 and not full.truncated
    # it signed in as the reader, with the engine's own time limit on the statement
    assert lab.auth[-1][2].startswith("Basic ")


def test_the_client_cancels_and_fails_past_its_deadline(lab, tmp_path, monkeypatch):
    ticks = iter(range(0, 1000, 50))
    engine = _seeded(lab, tmp_path, monotonic=lambda: next(ticks))
    cancelled = []
    monkeypatch.setattr(type(engine), "cancel", lambda self, uri: cancelled.append(uri))
    with pytest.raises(LakeError, match="limit"):
        engine.execute("SELECT uid FROM authentication ORDER BY uid", deadline=30)
    assert len(cancelled) == 1


def test_session_properties_are_checked(tmp_path):
    s = load_settings(_write(tmp_path))
    for bad in ({"x,y": "1"}, {"a": "1,b=2"}, {"a": "x y"}):
        with pytest.raises(LakeError):
            engine_for(s, session=bad)
    with pytest.raises(SettingsError, match="not an engine setting"):
        engine_for(s, auth=lambda: "Basic eA==")


# ---------------------------------------------------------------- the settings
def _write(tmp_path: Path, **kw) -> Path:
    s = _settings(tmp_path)
    doc = {k: getattr(s, k) for k in ("endpoint", "user", "catalog", "credential_file")}
    doc["schemas"] = list(s.schemas)
    doc.update(kw)
    p = tmp_path / "lake-mcp.yml"
    p.write_text(yaml.safe_dump({k: v for k, v in doc.items() if v is not None}))
    return p


def test_good_settings_load_and_the_engine_signs_in_as_the_reader(tmp_path):
    s = load_settings(_write(tmp_path, max_rows=100, timeout_s=20))
    assert s.user == "lake-mcp" and s.max_rows == 100 and s.schemas == ("soc", "cti")
    engine = engine_for(s)
    h = {k.rsplit("-", 1)[-1]: v for k, v in engine._headers().items()}  # the engine's header names
    assert h["User"] == "lake-mcp" and h["Catalog"] == "lake_ro"
    assert h["Authorization"].startswith("Basic ")
    assert h["Session"] == "query_max_execution_time=20s,query_max_run_time=20s"
    assert "pwpw" not in repr(engine)


@pytest.mark.parametrize(
    "change,why",
    [
        ({"endpoint": "http://lake.example.internal"}, "https"),
        ({"endpoint": "https://lake.example.internal/mcp"}, "no path"),
        ({"endpoint": "ftp://lake.example.internal"}, "http"),
        ({"user": "a b"}, "user"),
        ({"catalog": "Lake-RO"}, "plain"),
        ({"schemas": "soc"}, "list"),
        ({"schemas": ["soc", "x;y"]}, "plain"),
        ({"max_rows": MAX_ROWS + 1}, "max_rows"),
        ({"timeout_s": 0}, "timeout_s"),
        ({"credential_file": "reader-password"}, "absolute"),
        ({"password": "pw"}, "unknown"),
        ({"credential_file": None}, "required"),
    ],
)
def test_unsafe_or_malformed_settings_are_refused(tmp_path, change, why):
    with pytest.raises(SettingsError, match=why):
        load_settings(_write(tmp_path, **change))


def test_a_credential_others_may_read_is_refused_at_load_and_when_the_engine_is_built(tmp_path):
    p = _write(tmp_path)
    cred = tmp_path / "reader-password"
    cred.chmod(0o640)
    with pytest.raises(SettingsError, match="0600"):
        load_settings(p)
    cred.chmod(0o600)
    settings = load_settings(p)
    cred.chmod(0o644)
    with pytest.raises(SettingsError, match="0600"):
        engine_for(settings)
    cred.chmod(0o600)
    cred.write_text("\n")
    with pytest.raises(SettingsError, match="empty"):
        engine_for(settings)


def test_plain_http_is_accepted_to_loopback_only(tmp_path):
    assert (
        load_settings(_write(tmp_path, endpoint="http://localhost")).endpoint == "http://localhost"
    )


# ---------------------------------------------------------------- the command
def test_the_command_refuses_bad_settings_with_exit_2(tmp_path, capsys):
    p = _write(tmp_path, endpoint="http://lake.example.internal")
    assert lake_cli.main(["mcp", "--config", str(p)]) == 2
    assert "https" in capsys.readouterr().err


def test_check_signs_in_lists_and_reports_without_serving(tmp_path, monkeypatch, capsys):
    from homelabnext.lake import mcp_tools

    engine = Engine(lambda sql, args: ([], [{"table_schema": "soc", "table_name": "raw_archive"}]))
    monkeypatch.setattr(mcp_tools, "engine_for", lambda s: engine)
    monkeypatch.setattr("homelabnext.mcp.server.sdk_missing", lambda: False)
    assert lake_cli.main(["mcp", "--config", str(_write(tmp_path)), "--check"]) == 0
    out = capsys.readouterr().out
    assert "signed in as lake-mcp" in out and "1 table(s)" in out

    def down(sql, args):
        raise LakeError("cannot reach the engine")

    monkeypatch.setattr(mcp_tools, "engine_for", lambda s: Engine(down))
    assert lake_cli.main(["mcp", "--config", str(_write(tmp_path)), "--check"]) == 100


# ---------------------------------------------------------------- the catalog record
def test_the_catalog_record_is_the_first_party_entry_with_read_tools_only():
    from homelabnext.mcp import servers

    rec = yaml.safe_load(RECORD.read_text())
    assert rec["id"] == SERVER_NAME and rec["origin"] == {
        "kind": "first-party",
        "path": "homelabnext/lake/mcp_tools.py",
    }
    assert {t["name"] for t in rec["tools"]} == set(TOOLS)
    assert all(t["classes"] == ["read"] and t["approval"] is False for t in rec["tools"])
    assert "acts_via" not in rec, "the lake server acts on nothing"
    assert rec["transport"]["entry"] == "lake-mcp"
    assert servers.hnx_args_problems("lake-mcp", rec["transport"]["args"]) == []
    assert servers.hnx_args_problems("lake-mcp", ["--config", "relative.yml"])
    assert servers.hnx_args_problems("lake-mcp", ["--check"]), "--check is not a server flag"
    ns = lake_cli._parser().parse_args(["mcp", *rec["transport"]["args"]])
    assert ns.cmd == "mcp" and not ns.check


def test_tools_in_memory(tmp_path):
    pytest.importorskip("mcp")
    import anyio

    from homelabnext.lake.mcp_tools import build_server

    def client(server):
        import mcp

        if hasattr(mcp, "Client"):  # 2.x
            return mcp.Client(server)
        from mcp.shared.memory import create_connected_server_and_client_session

        return create_connected_server_and_client_session(server)

    engine = Engine(lambda sql, args: ([{"name": "n"}], [{"n": 7}]))
    reader = LakeReader(engine, _settings(tmp_path))

    async def run():
        async with client(build_server(reader)) as s:
            tools = {t.name: t for t in (await s.list_tools()).tools}
            assert set(tools) == set(TOOLS)
            for t in tools.values():
                hints = t.annotations.model_dump(by_alias=True)
                assert hints["readOnlyHint"] is True and hints["openWorldHint"] is False
                schema = getattr(t, "input_schema", None) or t.inputSchema
                props = set(schema.get("properties", {}))
                assert not {"user", "password", "endpoint", "catalog"} & props
            res = await s.call_tool(
                "query", {"sql": "SELECT n FROM t WHERE n = :n", "params": {"n": 7}}
            )
            assert json.loads(res.content[0].text)["rows"] == [[7]]
            bad = await s.call_tool("query", {"sql": "INSERT INTO t VALUES (1)"})
            assert getattr(bad, "is_error", getattr(bad, "isError", False))
            assert "refused" in bad.content[0].text

    anyio.run(run)
    assert [sql for sql, _ in engine.sent] == ["SELECT n FROM t WHERE n = ?"]
    assert os.environ.get("HNX_SECRET_LAKE_MCP_READER_PASSWORD") is None
