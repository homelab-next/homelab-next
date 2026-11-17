# SPDX-License-Identifier: Apache-2.0
"""tools/migrate/lake_verify.py: the per-table count at a fixed snapshot against a reference TSV.

Run against a stand-in for the query engine's statement protocol: it answers each
``FOR VERSION AS OF`` count from a table of (table, snapshot) -> rows, so a copy that differs, a
snapshot the copy does not hold and a reference the stand-in cannot answer are each told apart.
"""

from __future__ import annotations

import http.server
import importlib.util
import json
import re
import sys
import threading
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location(
    "lake_verify", ROOT / "tools" / "migrate" / "lake_verify.py"
)
lv = importlib.util.module_from_spec(spec)
sys.modules["lake_verify"] = lv
spec.loader.exec_module(lv)

# the old lake's archive shape: schema.table, rows, snapshot id (no header)
ARCHIVE = "cape.ioc\t116045\t4344198482287195337\ncti.nrd\t28680210\t8244950033341841439\n"


class _Engine(http.server.ThreadingHTTPServer):
    def __init__(self, counts, summaries=None, broken_history=(), catalog=None):
        super().__init__(("localhost", 0), _Handler)
        self.counts, self.summaries, self.statements, self.auth = counts, summaries or {}, [], []
        self.catalog = catalog  # the tables the catalog lists (information_schema), or None for the reference's
        self.broken_history = set(broken_history)  # tables whose $all_manifests cannot be read


class _Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_POST(self):
        sql = self.rfile.read(int(self.headers["Content-Length"])).decode()
        self.server.statements.append(sql)
        self.server.auth.append(self.headers.get("Authorization", ""))
        if "information_schema.tables" in sql:
            names = (
                self.server.catalog if self.server.catalog is not None else ["cape.ioc", "cti.nrd"]
            )
            raw = json.dumps(
                {"columns": [{"name": "table_schema"}, {"name": "table_name"}],
                 "data": [n.split(".") for n in names]}
            ).encode()  # fmt: skip
            self.send_response(200)
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
            return
        h = re.search(r'"(\w+)"\."(\w+)\$all_manifests"', sql)
        if h:
            name = f"{h.group(1)}.{h.group(2)}"
            if name in self.server.broken_history:
                body = {"error": {"message": f"Failed to open input stream for file: s3://b/{h.group(2)}/metadata/snap-1.avro",
                                  "errorName": "GENERIC_INTERNAL_ERROR"}}  # fmt: skip
            else:
                body = {"columns": [{"name": "n"}], "data": [[7]]}
            raw = json.dumps(body).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
            return
        m = re.search(
            r'"(\w+)"\."(\w+)(\$snapshots)?" (?:FOR VERSION AS OF CAST\((\d+) AS BIGINT\)|WHERE snapshot_id = (\d+))',
            sql,
        )
        schema, table, meta, v1, v2 = (
            m.groups()[0],
            m.groups()[1],
            m.groups()[2],
            m.groups()[3],
            m.groups()[4],
        )
        key = (f"{schema}.{table}", int(v1 or v2))
        if meta:
            body = {
                "columns": [{"name": "n"}],
                "data": [[self.server.summaries[key]]] if key in self.server.summaries else [],
            }
        elif key in self.server.counts:
            body = {
                "columns": [{"name": "n", "typeSignature": {"rawType": "bigint"}}],
                "data": [[self.server.counts[key]]],
            }
        else:
            body = {
                "error": {
                    "message": f"Iceberg snapshot ID does not exists: {key[1]}",
                    "errorName": "INVALID_ARGUMENTS",
                }
            }
        raw = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


@pytest.fixture
def engine():
    started = []

    def start(counts, summaries=None, broken_history=(), catalog=None):
        s = _Engine(counts, summaries, broken_history, catalog)
        threading.Thread(target=s.serve_forever, daemon=True).start()
        started.append(s)
        return s

    yield start
    for s in started:
        s.shutdown()


def _run(tmp_path, monkeypatch, engine, tsv=ARCHIVE, *extra):
    ref = tmp_path / "ref.tsv"
    ref.write_text(tsv)
    monkeypatch.setenv("HNX_LAKE_VERIFY_PASSWORD", "pw-not-printed")
    return lv.main(["--expected", str(ref), "--url", f"http://localhost:{engine.server_port}",
                    "--user", "verifier", *extra])  # fmt: skip


GOOD = {("cape.ioc", 4344198482287195337): 116045, ("cti.nrd", 8244950033341841439): 28680210}


def test_equal_counts_at_every_snapshot_pass(tmp_path, monkeypatch, engine, capsys):
    e = engine(GOOD)
    assert _run(tmp_path, monkeypatch, e, ARCHIVE, "--expect-tables", "2") == 0
    out = capsys.readouterr().out
    assert "2 of 2 table(s) equal the reference" in out and "pw-not-printed" not in out
    # the statement is the one the lake's source answered: a count at the snapshot, by id
    assert (
        e.statements[0]
        == 'SELECT count(*) AS n FROM iceberg."cape"."ioc" FOR VERSION AS OF CAST(4344198482287195337 AS BIGINT)'
    )
    assert all(a.startswith("Basic ") for a in e.auth)


def test_a_count_that_differs_fails_and_names_both_numbers(tmp_path, monkeypatch, engine, capsys):
    e = engine({**GOOD, ("cti.nrd", 8244950033341841439): 28680209})
    assert _run(tmp_path, monkeypatch, e) == 1
    out = capsys.readouterr().out
    assert "MISMATCH" in out and "cti.nrd" in out and "28680209" in out and "28680210" in out
    assert "NOT EQUAL" in out


def test_a_snapshot_the_copy_does_not_hold_is_an_error_never_a_pass(
    tmp_path, monkeypatch, engine, capsys
):
    e = engine({("cape.ioc", 4344198482287195337): 116045})
    assert _run(tmp_path, monkeypatch, e) == 1
    out = capsys.readouterr().out
    assert "ERROR" in out and "does not exists" in out and "1 of 2 table(s)" in out


def test_the_table_count_is_held_when_one_is_asked_for(tmp_path, monkeypatch, engine, capsys):
    e = engine(GOOD)
    assert _run(tmp_path, monkeypatch, e, ARCHIVE, "--expect-tables", "37") == 1
    assert "37 expected" in capsys.readouterr().out


def test_the_four_column_shape_and_a_header_are_read(tmp_path, monkeypatch, engine):
    e = engine(GOOD)
    tsv = "schema\ttable\tsnapshot_id\trows\ncape\tioc\t4344198482287195337\t116045\ncti\tnrd\t8244950033341841439\t28680210\n"
    assert _run(tmp_path, monkeypatch, e, tsv) == 0


def test_only_limits_the_run_and_an_unknown_name_is_a_usage_error(tmp_path, monkeypatch, engine):
    e = engine(GOOD)
    assert _run(tmp_path, monkeypatch, e, ARCHIVE, "--only", "cti.nrd") == 0
    assert len([x for x in e.statements if "$all_manifests" not in x]) == 1
    assert _run(tmp_path, monkeypatch, e, ARCHIVE, "--only", "cti.missing") == 2


def test_the_cross_check_notes_a_summary_that_disagrees_but_does_not_fail(
    tmp_path, monkeypatch, engine, capsys
):
    e = engine(
        GOOD, {("cape.ioc", 4344198482287195337): "7", ("cti.nrd", 8244950033341841439): "28680210"}
    )
    assert _run(tmp_path, monkeypatch, e, ARCHIVE, "--cross-check") == 0
    out = capsys.readouterr().out
    assert "note: cross-check: the snapshot summary says 7 records" in out and "cti.nrd" in out


@pytest.mark.parametrize(
    "tsv",
    [
        "cape.ioc\t1\n",  # two columns
        "x.y\t1\t2\ncape.ioc\tmany\t5\n",  # a count that is not a number, past the first line (the first is a header)
        'a"b.c\t1\t5\n',  # a name that could not be put in a statement
        "a.b\t1\t5\na.b\t1\t5\n",  # a table twice
        "a.b\t-1\t5\n",
    ],
)
def test_a_malformed_reference_is_a_usage_error_before_any_statement_runs(
    tmp_path, monkeypatch, engine, tsv
):
    e = engine(GOOD)
    assert _run(tmp_path, monkeypatch, e, tsv) == 2
    assert e.statements == []


def test_without_a_password_or_over_plain_http_to_another_host_nothing_is_sent(
    tmp_path, monkeypatch
):
    ref = tmp_path / "ref.tsv"
    ref.write_text(ARCHIVE)
    monkeypatch.delenv("HNX_LAKE_VERIFY_PASSWORD", raising=False)
    assert (
        lv.main(["--expected", str(ref), "--url", "https://engine.example.internal", "--user", "u"])
        == 2
    )
    monkeypatch.setenv("HNX_LAKE_VERIFY_PASSWORD", "x")
    assert (
        lv.main(["--expected", str(ref), "--url", "http://engine.example.internal", "--user", "u"])
        == 2
    )


def test_the_archive_reference_of_the_old_lake_parses_as_thirty_seven_unique_tables():
    # a stand-in of the archive's 37-row file in its real shape: the parser takes it whole
    rows = "".join(f"s{i // 10}.t{i}\t{i * 7}\t{4000000000000000000 + i}\n" for i in range(37))
    parsed = lv.parse_reference(rows)
    assert len(parsed) == 37 and len({p.name for p in parsed}) == 37
    assert parsed[0].snapshot_id == 4000000000000000000 and parsed[3].rows == 21


def test_every_tables_whole_history_is_read_through_all_manifests(
    tmp_path, monkeypatch, engine, capsys
):
    e = engine(GOOD)
    assert _run(tmp_path, monkeypatch, e) == 0
    reads = [x for x in e.statements if "$all_manifests" in x]
    assert reads == [
        'SELECT count(*) AS n FROM iceberg."cape"."ioc$all_manifests"',
        'SELECT count(*) AS n FROM iceberg."cti"."nrd$all_manifests"',
    ]


def test_a_table_with_dangling_history_fails_naming_the_table_though_its_current_snapshot_counts(
    tmp_path, monkeypatch, engine, capsys
):
    e = engine(GOOD, broken_history=["cti.nrd"])
    assert _run(tmp_path, monkeypatch, e) == 1
    out = capsys.readouterr().out
    assert "HISTORY" in out and "cti.nrd" in out and "snap-1.avro" in out
    assert "cape.ioc" in out and out.count("HISTORY") == 1  # the readable table is ok
    assert "1 of 2 table(s) equal the reference" in out and "NOT EQUAL" in out


def test_the_all_history_failure_is_in_the_json_and_an_error_count_keeps_its_status(
    tmp_path, monkeypatch, engine, capsys
):
    e = engine({("cape.ioc", 4344198482287195337): 116045}, broken_history=["cape.ioc", "cti.nrd"])
    assert _run(tmp_path, monkeypatch, e, ARCHIVE, "--json") == 1
    doc = json.loads(capsys.readouterr().out)
    by = {t["name"]: t for t in doc["tables"]}
    assert by["cape.ioc"]["status"] == "HISTORY" and "snap-1.avro" in by["cape.ioc"]["history"]
    assert (
        by["cti.nrd"]["status"] == "ERROR" and by["cti.nrd"]["history"]
    )  # the count error stays the status
    assert doc["ok"] is False


def test_no_all_history_skips_the_check(tmp_path, monkeypatch, engine):
    e = engine(GOOD, broken_history=["cti.nrd"])
    assert _run(tmp_path, monkeypatch, e, ARCHIVE, "--no-all-history") == 0
    assert not any("$all_manifests" in x for x in e.statements)


def test_without_all_catalog_tables_the_catalog_is_never_listed(tmp_path, monkeypatch, engine):
    e = engine(GOOD, catalog=["cape.ioc", "cti.nrd", "ocsf.dead"], broken_history=["ocsf.dead"])
    assert _run(tmp_path, monkeypatch, e) == 0
    assert not any("information_schema" in x for x in e.statements)


def test_all_catalog_tables_checks_the_history_of_tables_the_reference_does_not_list(
    tmp_path, monkeypatch, engine, capsys
):
    e = engine(
        GOOD,
        catalog=["cape.ioc", "cti.nrd", "ocsf.dead", "obs.gone", "rba.extra"],
        broken_history=["ocsf.dead", "obs.gone"],
    )
    assert _run(tmp_path, monkeypatch, e, ARCHIVE, "--all-catalog-tables") == 1
    out = capsys.readouterr().out
    section = out.split("catalog tables not in the reference:")[1]
    assert "ocsf.dead" in section and "obs.gone" in section and "rba.extra" not in section
    assert "1 readable, 2 failing" in section
    # the reference tables are reported above the section, unchanged
    assert "2 of 2 table(s) equal the reference" in out
    assert any('"rba"."extra$all_manifests"' in x for x in e.statements)


def test_all_catalog_tables_with_readable_extras_passes_and_json_reports_them_separately(
    tmp_path, monkeypatch, engine, capsys
):
    e = engine(GOOD, catalog=["cape.ioc", "cti.nrd", "rba.extra"])
    assert _run(tmp_path, monkeypatch, e, ARCHIVE, "--all-catalog-tables", "--json") == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["extras"] == {"failing": [], "readable": 1}
    assert [t["name"] for t in doc["tables"]] == ["cape.ioc", "cti.nrd"]


def test_all_catalog_tables_ignores_only_when_deciding_what_is_extra(
    tmp_path, monkeypatch, engine, capsys
):
    e = engine(GOOD, catalog=["cape.ioc", "cti.nrd"], broken_history=["cape.ioc"])
    # --only limits the reference run to cti.nrd; cape.ioc is still in the reference, so not an extra
    assert _run(tmp_path, monkeypatch, e, ARCHIVE, "--only", "cti.nrd", "--all-catalog-tables") == 0
    assert "0 readable, 0 failing" in capsys.readouterr().out
