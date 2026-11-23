# SPDX-License-Identifier: Apache-2.0
"""tools/migrate/catalog_register.py: registering a lake's tables into another catalog at their current
metadata files, and verifying the target against the source.

Run against a stand-in for the two catalog APIs (one with a management API and a warehouse prefix,
one without either, like the reference catalog), so a refusal, a register, a conflict and a verify
are each told apart. The rules that protect the lake each have a test: no live file, no vacuous run, no
location outside the warehouse, no destructive request, no repointing of an existing entry.
"""

from __future__ import annotations

import http.server
import importlib.util
import json
import socket
import sqlite3
import sys
import threading
import uuid
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location(
    "catalog_register", ROOT / "tools" / "migrate" / "catalog_register.py"
)
cr = importlib.util.module_from_spec(spec)
sys.modules["catalog_register"] = cr
spec.loader.exec_module(cr)

BUCKET = "lake-bucket"
LOOPBACK = socket.gethostbyname("localhost")  # by resolution, not a literal


def loc(ns, table, n=3):
    return f"s3://{BUCKET}/{ns}/{table}-abc/metadata/{n:05d}-uuid.metadata.json"


def make_db(path: Path, rows=(("cti", "a"), ("cti", "b"), ("rba", "c")), table="iceberg_tables"):
    c = sqlite3.connect(path)
    c.execute(f"CREATE TABLE {table} (catalog_name TEXT, table_namespace TEXT, table_name TEXT, "
              "metadata_location TEXT, previous_metadata_location TEXT, record_type TEXT)")  # fmt: skip
    for ns, t in rows:
        c.execute(
            f"INSERT INTO {table} VALUES ('rest_backend', ?, ?, ?, NULL, 'TABLE')",
            (ns, t, loc(ns, t)),
        )
    c.commit()
    c.close()
    return path


def meta(ns, table, snap=7, stats=(), history=1):
    return {
        "table-uuid": str(uuid.uuid5(uuid.NAMESPACE_DNS, f"{ns}.{table}")), "location": f"s3://{BUCKET}/{ns}/{table}-abc",
        "current-snapshot-id": snap, "current-schema-id": 0,
        "snapshots": [{"snapshot-id": snap, "manifest-list": f"s3://{BUCKET}/{ns}/{table}-abc/metadata/snap-{snap}.avro"},
                      *[{"snapshot-id": snap - i, "manifest-list": f"s3://{BUCKET}/{ns}/{table}-abc/metadata/snap-{snap - i}.avro"}
                        for i in range(1, history + 1)]],
        "metadata-log": [{"metadata-file": loc(ns, table, 1)}],
        "statistics": [{"snapshot-id": snap, "statistics-path": s} for s in stats],
    }  # fmt: skip


class Cat(http.server.ThreadingHTTPServer):
    """A catalog stand-in. managed=True: /catalog/v1/<prefix>/..., a management API with one warehouse;
    managed=False: /v1/... only, 400 on the management API (the reference catalog)."""

    def __init__(self, managed, tables=None, warehouse_bucket=BUCKET):
        super().__init__((LOOPBACK, 0), H)
        self.managed, self.wh_bucket = managed, warehouse_bucket
        self.tables = dict(tables or {})  # (ns, name) -> (metadata_location, metadata)
        self.namespaces, self.calls, self.protected = set(), [], []

    @property
    def url(self):
        return f"http://{LOOPBACK}:{self.server_address[1]}"


class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, doc=None):
        raw = json.dumps(doc).encode() if doc is not None else b""
        self.send_response(code)
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(raw)

    def _route(self):
        s = self.server
        p = self.path.split("?")[0]
        base = "/catalog/v1/pfx" if s.managed else "/v1"
        return p, base

    def do_GET(self):
        s = self.server
        p, base = self._route()
        s.calls.append(("GET", p, None))
        if p == "/management/v1/warehouse":
            if not s.managed:
                return self._send(400, {"error": {"message": "no"}})
            return self._send(200, {"warehouses": [{"name": "lake", "id": "11111111-1111-1111-1111-111111111111",
                                                    "storage-profile": {"bucket": s.wh_bucket, "key-prefix": None}}]})  # fmt: skip
        if p == "/catalog/v1/config" and s.managed:
            return self._send(200, {"defaults": {"prefix": "pfx"}})
        if p == "/v1/config" and not s.managed:
            return self._send(200, {"defaults": {}})
        if p.startswith(base + "/namespaces/") and "/tables/" in p:
            ns, name = p[len(base + "/namespaces/") :].split("/tables/")
            t = s.tables.get((ns, name))
            if not t:
                return self._send(404)
            return self._send(200, {"metadata-location": t[0], "metadata": t[1]})
        if p == base + "/namespaces":
            return self._send(200, {"namespaces": sorted([n] for n in {k[0] for k in s.tables})})
        if p.startswith(base + "/namespaces/") and p.endswith("/tables"):
            ns = p.split("/")[-2]
            return self._send(
                200, {"identifiers": [{"name": k[1]} for k in s.tables if k[0] == ns]}
            )
        self._send(404)

    def do_POST(self):
        s = self.server
        p, base = self._route()
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])) or b"null")
        s.calls.append(("POST", p, body))
        if p == base + "/namespaces":
            if tuple(body["namespace"]) in s.namespaces:
                return self._send(409)
            s.namespaces.add(tuple(body["namespace"]))
            return self._send(200, {"namespace": body["namespace"]})
        if p.endswith("/register"):
            ns = p.split("/")[-2]
            key = (ns, body["name"])
            if key in s.tables:
                return self._send(409)
            s.tables[key] = (body["metadata-location"], meta(ns, body["name"]))
            return self._send(
                200, {"metadata-location": body["metadata-location"], "metadata": s.tables[key][1]}
            )
        if p.endswith("/protection"):
            s.protected.append((p, body))
            return self._send(200, {"protected": True})
        self._send(404)

    def do_DELETE(self):  # the tool must never get here
        self.server.calls.append(("DELETE", self.path, None))
        self._send(204)


@pytest.fixture
def cat():
    servers = []

    def make(managed=True, **kw):
        s = Cat(managed, **kw)
        threading.Thread(target=s.serve_forever, daemon=True).start()
        servers.append(s)
        return s

    yield make
    for s in servers:
        s.shutdown()


def run(argv, capsys):
    code = cr.main(argv)
    out = capsys.readouterr()
    return code, out.out, out.err


# ----------------------------------------------------------------------------- the source file


def test_the_source_is_read_through_a_read_only_copy_and_sorted(tmp_path):
    db = make_db(tmp_path / "c.db", rows=(("rba", "z"), ("cti", "a")))
    before = db.read_bytes()
    entries = cr.read_source(str(db))
    assert [e.name for e in entries] == ["cti.a", "rba.z"]
    assert db.read_bytes() == before  # never written


@pytest.mark.parametrize("sidecar", ["-wal", "-shm", "-journal"])
def test_a_live_looking_database_is_refused(tmp_path, sidecar):
    db = make_db(tmp_path / "c.db")
    Path(str(db) + sidecar).write_text("x")
    with pytest.raises(cr.SourceError, match="live database"):
        cr.read_source(str(db))


def test_a_link_a_missing_file_and_a_non_database_are_refused(tmp_path):
    db = make_db(tmp_path / "c.db")
    link = tmp_path / "l.db"
    link.symlink_to(db)
    for bad in (link, tmp_path / "absent.db", tmp_path):
        with pytest.raises(cr.SourceError):
            cr.read_source(str(bad))
    junk = tmp_path / "junk.db"
    junk.write_text("not sqlite" * 50)
    with pytest.raises(cr.SourceError):
        cr.read_source(str(junk))


def test_an_unknown_schema_and_zero_tables_are_errors_never_an_ok(tmp_path):
    with pytest.raises(cr.SourceError, match="unknown schema"):
        cr.read_source(str(make_db(tmp_path / "a.db", table="other_tables")))
    with pytest.raises(cr.SourceError, match="vacuous"):
        cr.read_source(str(make_db(tmp_path / "b.db", rows=())))


def test_a_view_an_unsafe_name_and_a_bad_location_are_refused(tmp_path):
    db = make_db(tmp_path / "a.db")
    c = sqlite3.connect(db)
    c.execute("UPDATE iceberg_tables SET record_type='VIEW' WHERE table_name='a'")
    c.commit()
    c.close()
    with pytest.raises(cr.SourceError, match="VIEW"):
        cr.read_source(str(db))
    with pytest.raises(cr.SourceError, match="unsafe"):
        cr.read_source(str(make_db(tmp_path / "b.db", rows=(("cti", "a;drop"),))))
    db = make_db(tmp_path / "c.db")
    c = sqlite3.connect(db)
    c.execute("UPDATE iceberg_tables SET metadata_location='file:///etc/passwd'")
    c.commit()
    c.close()
    with pytest.raises(cr.SourceError, match="metadata location"):
        cr.read_source(str(db))


# ----------------------------------------------------------------------------- the requests it may make


@pytest.mark.parametrize("method, path", [
    ("DELETE", "/catalog/v1/pfx/namespaces/cti/tables/a"),
    ("DELETE", "/catalog/v1/pfx/namespaces/cti"),
    ("PUT", "/catalog/v1/pfx/namespaces/cti/tables/a"),
    ("POST", "/catalog/v1/pfx/namespaces/cti/tables/a"),
    ("POST", "/management/v1/warehouse"),
    ("POST", "/management/v1/warehouse/x/delete-profile"),
    ("GET", "/etc/passwd"),
])  # fmt: skip
def test_nothing_destructive_or_outside_the_catalog_api_can_be_requested(cat, method, path):
    c = cr.Catalog(cat().url)
    with pytest.raises(PermissionError, match="refused"):
        c._call(method, path)


def test_protection_can_only_be_set_to_true(cat):
    c = cr.Catalog(cat().url)
    path = "/management/v1/warehouse/11111111-1111-1111-1111-111111111111/table/22222222-2222-2222-2222-222222222222/protection"
    with pytest.raises(PermissionError, match="only be set to true"):
        c._call("POST", path, {"protected": False})
    assert c._call("POST", path, {"protected": True})[0] == 200


def test_a_redirect_is_not_followed_so_a_token_never_travels(cat):
    assert any(
        isinstance(h, cr._NoRedirect) for h in cr.Catalog(f"http://{LOOPBACK}:1").opener.handlers
    )
    assert cr._NoRedirect().redirect_request(None, None, 302, "", {}, "http://elsewhere") is None


# ----------------------------------------------------------------------------- plan and register


def args(db, s, *extra):
    return ["--source-db", str(db), "--url", s.url, "--warehouse", "lake", *extra]


def test_plan_lists_every_table_and_asks_nothing_destructive(tmp_path, cat, capsys):
    s = cat()
    code, out, _ = run(["plan", *args(make_db(tmp_path / "c.db"), s)], capsys)
    assert code == 0 and out.count("planned") == 4  # three rows and the summary line
    assert all(m == "GET" for m, _, _ in s.calls)


def test_register_without_apply_is_a_plan(tmp_path, cat, capsys):
    s = cat()
    code, _, _ = run(["register", *args(make_db(tmp_path / "c.db"), s)], capsys)
    assert code == 0 and not [c for c in s.calls if c[0] == "POST"]


def test_register_creates_the_namespaces_registers_each_table_and_protects_it(
    tmp_path, cat, capsys
):
    s = cat()
    code, out, _ = run(["register", *args(make_db(tmp_path / "c.db"), s, "--apply")], capsys)
    assert code == 0, out
    assert s.namespaces == {("cti",), ("rba",)}
    assert sorted(k for k in s.tables) == [("cti", "a"), ("cti", "b"), ("rba", "c")]
    for (ns, name), (location, _) in s.tables.items():
        assert location == loc(ns, name)  # at the metadata file it already had: nothing re-rooted
    assert len(s.protected) == 3 and all(b == {"protected": True} for _, b in s.protected)
    assert "DELETE" not in {m for m, _, _ in s.calls}
    assert not any("overwrite" in json.dumps(b) for _, _, b in s.calls if b)


def test_a_second_register_finds_each_table_there_and_changes_nothing(tmp_path, cat, capsys):
    s = cat()
    db = make_db(tmp_path / "c.db")
    run(["register", *args(db, s, "--apply")], capsys)
    s.calls.clear()
    code, out, _ = run(["register", *args(db, s, "--apply")], capsys)
    assert code == 0 and out.count("exists    ") == 3
    assert len(s.tables) == 3  # the 409 answers changed nothing


def test_a_table_registered_at_another_location_is_an_error_and_left_alone(tmp_path, cat, capsys):
    other = loc("cti", "a", 99)
    s = cat(tables={("cti", "a"): (other, meta("cti", "a"))})
    code, out, _ = run(["register", *args(make_db(tmp_path / "c.db"), s, "--apply")], capsys)
    assert code == 1 and "already registered at another location" in out
    assert s.tables[("cti", "a")][0] == other  # never repointed
    assert "DELETE" not in {m for m, _, _ in s.calls}


def test_a_location_outside_the_warehouse_stops_everything_before_any_write(tmp_path, cat, capsys):
    s = cat(warehouse_bucket="another-bucket")
    code, out, _ = run(["register", *args(make_db(tmp_path / "c.db"), s, "--apply")], capsys)
    assert code == 1 and "outside the warehouse" in out
    assert not [c for c in s.calls if c[0] == "POST"]  # not even a namespace


def test_a_target_without_a_management_api_takes_the_register_with_nothing_to_protect(
    tmp_path, cat, capsys
):
    s = cat(managed=False)
    code, out, _ = run(["register", *args(make_db(tmp_path / "c.db"), s, "--apply")], capsys)
    assert code == 0, out
    assert s.protected == [] and len(s.tables) == 3


def test_only_narrows_and_an_unknown_name_is_a_usage_error(tmp_path, cat, capsys):
    s = cat()
    db = make_db(tmp_path / "c.db")
    code, out, _ = run(["plan", *args(db, s, "--only", "cti.a")], capsys)
    assert code == 0 and "cti.b" not in out
    assert run(["plan", *args(db, s, "--only", "cti.nope")], capsys)[0] == 2


def test_a_wrong_table_count_fails_the_run(tmp_path, cat, capsys):
    s = cat()
    code, out, _ = run(
        ["plan", *args(make_db(tmp_path / "c.db"), s, "--expect-tables", "5")], capsys
    )
    assert code == 1 and "expected 5" in out


def test_giving_both_or_neither_source_is_a_usage_error(tmp_path, cat, capsys):
    s = cat()
    assert run(["plan", "--url", s.url, "--warehouse", "lake"], capsys)[0] == 2
    assert (
        run(
            ["plan", "--source-db", "x", "--source-url", s.url, "--url", s.url, "--warehouse", "l"],
            capsys,
        )[0]
        == 2
    )


# ----------------------------------------------------------------------------- rollback source


def test_the_pointers_of_a_running_catalog_are_the_source_of_a_rollback(tmp_path, cat, capsys):
    new = cat(tables={("cti", "a"): (loc("cti", "a", 12), meta("cti", "a"))})
    old = cat(managed=False)
    code, out, _ = run(["register", "--source-url", new.url, "--source-warehouse", "lake",
                        "--url", old.url, "--warehouse", "x", "--apply"], capsys)  # fmt: skip
    assert code == 0, out
    assert old.tables[("cti", "a")][0] == loc(
        "cti", "a", 12
    )  # the CURRENT pointer, not the first one


# ----------------------------------------------------------------------------- verify


def listing(tmp_path, keys):
    p = tmp_path / "keys.txt"
    p.write_text("".join(f"2026-11-22 10:00:00 100 {k}\n" for k in keys))
    return p


def keys_of(ns, table, snap=7, extra=()):
    base = f"{ns}/{table}-abc/metadata/"
    return [f"{ns}/{table}-abc/metadata/{n:05d}-uuid.metadata.json" for n in (3,)] + [
        base + f"snap-{snap}.avro",
        *extra,
    ]


def pair(
    cat,
    tmp_path,
    *,
    stats=("s3://lake-bucket/cti/a-abc/metadata/x.stats",),
    target_snap=7,
    ref_snap=7,
):
    db = make_db(tmp_path / "c.db", rows=(("cti", "a"),))
    tgt = cat(tables={("cti", "a"): (loc("cti", "a"), meta("cti", "a", target_snap, stats))})
    ref = cat(
        managed=False, tables={("cti", "a"): (loc("cti", "a"), meta("cti", "a", ref_snap, stats))}
    )
    return db, tgt, ref


def vargs(db, tgt, ref, keys):
    return ["verify", "--source-db", str(db), "--url", tgt.url, "--warehouse", "lake",
            "--reference-url", ref.url, "--listing", str(keys)]  # fmt: skip


def test_verify_passes_when_the_target_equals_the_source_and_every_named_object_exists(
    tmp_path, cat, capsys
):
    db, tgt, ref = pair(cat, tmp_path)
    keys = listing(tmp_path, keys_of("cti", "a", extra=["cti/a-abc/metadata/x.stats"]))
    code, out, _ = run([*vargs(db, tgt, ref, keys), "--expect-tables", "1"], capsys)
    assert code == 0, out
    assert "history: 2 of 2 older objects absent" in out  # reported, not a failure


def test_verify_fails_on_a_missing_statistics_file_the_ll586_class(tmp_path, cat, capsys):
    db, tgt, ref = pair(cat, tmp_path)
    keys = listing(tmp_path, keys_of("cti", "a"))  # the .stats object is not there
    code, out, _ = run(vargs(db, tgt, ref, keys), capsys)
    assert code == 1 and "MISSING" in out and "x.stats" in out


def test_verify_fails_on_a_different_snapshot_a_different_location_and_a_missing_table(
    tmp_path, cat, capsys
):
    db, tgt, ref = pair(cat, tmp_path, target_snap=8, ref_snap=7)
    keys = listing(tmp_path, keys_of("cti", "a", 8, ["cti/a-abc/metadata/x.stats"]))
    code, out, _ = run(vargs(db, tgt, ref, keys), capsys)
    assert code == 1 and "MISMATCH" in out and "current-snapshot-id" in out
    db2 = make_db(tmp_path / "d.db", rows=(("cti", "gone"),))
    code, out, _ = run(vargs(db2, tgt, ref, keys), capsys)
    assert code == 1 and "ERROR" in out


def test_verify_refuses_an_empty_listing_and_a_missing_reference(tmp_path, cat, capsys):
    db, tgt, ref = pair(cat, tmp_path)
    empty = tmp_path / "empty.txt"
    empty.write_text("\n")
    assert run(vargs(db, tgt, ref, empty), capsys)[0] == 2  # a vacuous check is an error
    assert (
        run(["verify", "--source-db", str(db), "--url", tgt.url, "--warehouse", "lake"], capsys)[0]
        == 2
    )


def test_a_json_listing_is_read_too(tmp_path):
    p = tmp_path / "k.jsonl"
    p.write_text(json.dumps({"key": "a/b"}) + "\n")
    assert cr.read_listing(str(p)) == {"a/b"}


def test_the_token_is_read_from_the_environment_and_never_argv(tmp_path, cat, capsys, monkeypatch):
    s = cat()
    db = make_db(tmp_path / "c.db")
    assert run(["plan", *args(db, s, "--token-env", "NO_SUCH_VAR")], capsys)[0] == 2
    monkeypatch.setenv("TOK_VAR", "t" * 20)
    assert run(["plan", *args(db, s, "--token-env", "TOK_VAR")], capsys)[0] == 0
