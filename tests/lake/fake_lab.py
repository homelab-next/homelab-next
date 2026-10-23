# SPDX-License-Identifier: Apache-2.0
"""A loopback stand-in for the lab's query engine and catalog, for the adapter tests.

One server answers both APIs the adapter speaks:

* Trino's client protocol: ``POST /v1/statement`` -> a queued reply with a ``nextUri``, then
  pages of ``data`` (``page_size`` rows each) with ``columns`` carrying ``typeSignature``s, wire
  values as Trino sends them (``timestamp with time zone`` as ``'... UTC'`` text, rows as
  positional arrays), errors with ``errorName``.  Statements arrive as ``EXECUTE IMMEDIATE
  '<sql>' USING <literals>``; the literals are *parsed* (:func:`parse_using`), never spliced, so a
  value the adapter failed to encode as one literal breaks the parse instead of slipping through.
  SQL runs on a per-namespace SQLite database (``FakeLake``); INSERTs add an Iceberg-style
  snapshot whose summary carries ``trino_query_id`` and ``total-records``.
* the Iceberg REST catalog under ``/catalog/v1``: config (prefix), table listing with paging,
  table metadata (schema in Iceberg JSON with Trino's nullability: nested fields optional) and
  ``set-properties``/``remove-properties`` commits guarded by ``assert-table-uuid``.

A statement longer than ``max_query_length`` (Trino's ``query.max-length``, 1,000,000 by default)
fails with ``QUERY_TEXT_TOO_LARGE``, as Trino does.
"""

from __future__ import annotations

import itertools
import json
import re
import sqlite3
import threading
import urllib.parse
import uuid
from datetime import UTC, date, datetime
from decimal import Decimal
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from homelabnext.lake import FakeLake
from homelabnext.lake.fake import _ts_text
from homelabnext.lake.tables import Column, load_schemas

LOOPBACK = "127.0.0.1"  # no-raw-endpoint: allow fake server binds loopback only


# ---------------------------------------------------------------- the literal parser
class ParseError(ValueError):
    pass


_TOK = re.compile(
    r"\s*(?:(?P<str>'(?:[^']|'')*')|(?P<num>-?\d+(?:\.\d+)?(?:[eE][-+]?\d+)?)"
    r"|(?P<word>[A-Za-z_][A-Za-z0-9_]*)|(?P<p>[()\[\],-]))"
)


def _tokens(text: str) -> list[tuple[str, str]]:
    out, i = [], 0
    while i < len(text):
        if text[i:].strip() == "":
            break
        m = _TOK.match(text, i)
        if not m or m.end() == i:
            raise ParseError(f"cannot tokenise at {text[i : i + 20]!r}")
        kind = m.lastgroup
        out.append((kind, m.group(kind)))
        i = m.end()
    return out


def _unq(s: str) -> str:
    return s[1:-1].replace("''", "'")


class _P:
    def __init__(self, toks):
        self.t, self.i = toks, 0

    def peek(self):
        return self.t[self.i] if self.i < len(self.t) else (None, None)

    def take(self, want=None):
        tok = self.peek()
        if tok[0] is None or (want is not None and tok[1].upper() != want):
            raise ParseError(f"expected {want}, got {tok}")
        self.i += 1
        return tok

    def expr(self):
        kind, val = self.take()
        if kind == "str":
            return _unq(val)
        if kind == "p" and val == "-":
            self.take("INFINITY"), self.take("("), self.take(")")
            return float("-inf")
        if kind != "word":
            raise ParseError(f"unexpected {val!r}")
        w = val.upper()
        if w == "NULL":
            return None
        if w in ("TRUE", "FALSE"):
            return w == "TRUE"
        if w in ("NAN", "INFINITY"):
            self.take("("), self.take(")")
            return float("nan") if w == "NAN" else float("inf")
        if w in ("ARRAY", "ROW"):
            close = "]" if w == "ARRAY" else ")"
            self.take("[" if w == "ARRAY" else "(")
            items = []
            while self.peek()[1] != close:
                items.append(self.expr())
                if self.peek()[1] == ",":
                    self.take(",")
            self.take(close)
            return items if w == "ARRAY" else tuple(items)
        kind2, text = self.take()
        if kind2 != "str":
            raise ParseError(f"{w} needs a string literal")
        s = _unq(text)
        if w == "BIGINT":
            return int(s)
        if w == "DOUBLE":
            return float(s)
        if w == "DECIMAL":
            return Decimal(s)
        if w == "DATE":
            return date.fromisoformat(s)
        if w == "X":
            return bytes.fromhex(s)
        if w == "TIMESTAMP":
            if not s.endswith(" UTC"):
                raise ParseError("timestamp literal without UTC")
            return datetime.fromisoformat(s[:-4]).replace(tzinfo=UTC)
        raise ParseError(f"unknown literal type {w}")


def parse_using(statement: str) -> tuple[str, list[Any]]:
    """``EXECUTE IMMEDIATE '<sql>' USING a, b`` -> (sql, [a, b]); other statements unchanged."""
    if not statement.lstrip().upper().startswith("EXECUTE IMMEDIATE"):
        return statement, []
    p = _P(_tokens(statement))
    p.take("EXECUTE"), p.take("IMMEDIATE")
    kind, text = p.take()
    if kind != "str":
        raise ParseError("EXECUTE IMMEDIATE needs a string")
    p.take("USING")
    args = [p.expr()]
    while p.peek()[1] == ",":
        p.take(",")
        args.append(p.expr())
    if p.peek()[0] is not None:
        raise ParseError(f"trailing text after the USING list: {p.peek()}")
    return _unq(text), args


# ---------------------------------------------------------------- types on the wire
def _sig(t: str, fields=()) -> dict[str, Any]:
    if t == "struct":
        return {
            "rawType": "row",
            "arguments": [
                {
                    "kind": "NAMED_TYPE",
                    "value": {
                        "fieldName": {"name": f.name},
                        "typeSignature": _sig(f.type, f.fields),
                    },
                }
                for f in fields
            ],
        }
    if t.startswith("list<"):
        return {"rawType": "array", "arguments": [{"kind": "TYPE", "value": _sig(t[5:-1])}]}
    raw = {
        "string": "varchar",
        "long": "bigint",
        "double": "double",
        "boolean": "boolean",
        "timestamp": "timestamp with time zone",
    }[t]
    return {"rawType": raw, "arguments": []}


def _wire(v: Any, t: str, fields=()) -> Any:
    if v is None:
        return None
    if t == "timestamp":
        return _ts_text(v if isinstance(v, datetime) else datetime.fromisoformat(v)) + " UTC"
    if t == "struct":
        return [_wire(v.get(f.name), f.type, f.fields) for f in fields]
    return v


def _ice(c: Column, ids, top: bool) -> dict[str, Any]:
    fid = next(ids)
    if c.type == "struct":
        typ: Any = {"type": "struct", "fields": [_ice(f, ids, False) for f in c.fields]}
    elif c.type.startswith("list<"):
        inner = {"timestamp": "timestamptz"}.get(c.type[5:-1], c.type[5:-1])
        typ = {"type": "list", "element-id": next(ids), "element": inner, "element-required": False}
    else:
        typ = {"timestamp": "timestamptz"}.get(c.type, c.type)
    return {"id": fid, "name": c.name, "required": bool(c.required and top), "type": typ}


# ---------------------------------------------------------------- state and server
class FakeLab:
    def __init__(
        self,
        *,
        page_size: int = 2,
        list_page: int = 2,
        trino_query_id: bool = True,
        max_query_length: int = 1_000_000,  # Trino's default query.max-length
    ):
        self.schemas = load_schemas()
        self.max_query_length = max_query_length
        self.page_size, self.list_page = page_size, list_page
        self.trino_query_id = trino_query_id
        self.lakes: dict[str, FakeLake] = {}
        self.tables: dict[tuple[str, str], dict[str, Any]] = {}
        self.statements: list[str] = []
        self.conflicts = 0  # answer the next N commits with 409
        self.schema_override: dict[str, list[dict[str, Any]]] = {}
        self._ids = itertools.count(1)
        self._pending: dict[str, list[dict[str, Any]]] = {}
        self._lock = threading.Lock()
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                outer._dispatch(self, None)

            def do_POST(self):
                n = int(self.headers.get("Content-Length") or 0)
                outer._dispatch(self, self.rfile.read(n))

        self._srv = ThreadingHTTPServer((LOOPBACK, 0), H)
        self._t = threading.Thread(target=self._srv.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        host, port = self._srv.server_address[:2]
        return f"http://{host}:{port}"

    def __enter__(self):
        self._t.start()
        return self

    def __exit__(self, *exc):
        self._srv.shutdown()
        self._srv.server_close()

    def _json(self, h, status, doc):
        body = json.dumps(doc).encode()
        h.send_response(status)
        h.send_header("Content-Type", "application/json")
        h.send_header("Content-Length", str(len(body)))
        h.end_headers()
        h.wfile.write(body)

    def _dispatch(self, h, body):
        with self._lock:
            path = urllib.parse.urlsplit(h.path)
            if path.path == "/v1/statement" and body is not None:
                return self._statement(h, body.decode("utf-8"))
            if path.path.startswith("/v1/statement/"):
                return self._page(h, path.path.rsplit("/", 1)[-1])
            if path.path.startswith("/catalog/v1/"):
                return self._rest(h, path, body)
            return self._json(h, 404, {"error": {"message": "no route", "code": 404}})

    # ---------------------------------------------------------------- Trino
    def _statement(self, h, text):
        qid = f"20260301_000000_{next(self._ids):05d}_fake"
        self.statements.append(text)
        ns = h.headers.get("X-Trino-Schema", "")
        assert h.headers.get("X-Trino-Time-Zone") == "UTC"
        try:
            if len(text) > self.max_query_length:
                raise _TrinoFail(
                    f"Query text length ({len(text)}) exceeds the maximum length"
                    f" ({self.max_query_length})",
                    "QUERY_TEXT_TOO_LARGE",
                )
            columns, rows, update = self._run(ns, text, qid)
            pages = [
                {"columns": columns, "data": rows[i : i + self.page_size]}
                for i in range(0, len(rows), self.page_size)
            ] or [{"columns": columns}]
            if update:
                pages[-1].update(update)
        except _TrinoFail as exc:
            pages = [{"error": {"message": exc.args[0], "errorName": exc.args[1]}}]
        chain = []
        for i, pg in enumerate(pages):
            pg = {"id": qid, **pg}
            if i + 1 < len(pages):
                pg["nextUri"] = f"{self.url}/v1/statement/executing/{qid}.{i + 1}"
            chain.append(pg)
        self._pending[qid] = chain
        return self._json(
            h, 200, {"id": qid, "nextUri": f"{self.url}/v1/statement/queued/{qid}.0", "stats": {}}
        )

    def _page(self, h, token):
        qid, _, i = token.partition(".")
        return self._json(h, 200, self._pending[qid][int(i)])

    def _lake(self, ns: str) -> FakeLake:
        if ns not in self.lakes:
            raise _TrinoFail(f"Schema '{ns}' does not exist", "SCHEMA_NOT_FOUND")
        return self.lakes[ns]

    def _run(self, ns, text, qid):
        try:
            sql, args = parse_using(text)
        except ParseError as exc:
            raise _TrinoFail(f"line 1:1: mismatched input: {exc}", "SYNTAX_ERROR") from None
        m = re.match(r'CREATE SCHEMA IF NOT EXISTS "\w+"\."(\w+)"$', sql)
        if m:
            self.lakes.setdefault(m.group(1), FakeLake(self.schemas))
            return [], [], {"updateType": "CREATE SCHEMA"}
        m = re.match(r'CREATE TABLE IF NOT EXISTS "\w+"\."(\w+)"\."(\w+)" \(', sql)
        if m:
            tns, t = m.groups()
            self._lake(tns)
            if (tns, t) not in self.tables:
                ids = itertools.count(1)
                fields = self.schema_override.get(t) or [
                    _ice(c, ids, True) for c in self.schemas[t].columns
                ]
                self.tables[(tns, t)] = {
                    "format-version": 2,
                    "table-uuid": str(uuid.UUID(int=next(self._ids))),
                    "current-schema-id": 0,
                    "schemas": [{"schema-id": 0, "type": "struct", "fields": fields}],
                    "properties": {},
                    "current-snapshot-id": None,
                    "snapshots": [],
                }
            return [], [], {"updateType": "CREATE TABLE"}
        if sql.count("?") != len(args):
            raise _TrinoFail("Incorrect number of parameters", "INVALID_PARAMETER_USAGE")
        ins = _parse_insert(sql)
        if ins:
            return self._insert(*ins, args, qid)
        return self._select(ns, sql, args)

    def _insert(self, ns, t, cols, args, qid):
        schema = self.schemas[t]
        names = [c.strip().strip('"') for c in cols.split(",")]
        assert names == list(schema.column_names)

        def unrow(c, v):
            if v is None:
                return None
            if c.type == "struct":
                return {f.name: unrow(f, x) for f, x in zip(c.fields, v, strict=True)}
            return v

        rows = []
        for i in range(0, len(args), len(names)):
            rows.append(
                {c.name: unrow(c, v) for c, v in zip(schema.columns, args[i:], strict=False)}
            )
        res = self._lake(ns).write_batch(t, rows, idempotency_key=qid)
        meta = self.tables[(ns, t)]
        total = self._lake(ns).describe(t).row_count
        summary = {
            "operation": "append",
            "added-records": str(res.rows_written),
            "total-records": str(total),
        }
        if self.trino_query_id:
            summary["trino_query_id"] = qid
        sid = 7000 + next(self._ids)
        meta["snapshots"].append({"snapshot-id": sid, "summary": summary})
        meta["current-snapshot-id"] = sid
        return (
            [{"name": "rows", "type": "bigint", "typeSignature": _sig("long")}],
            [[len(rows)]],
            {
                "updateType": "INSERT",
                "updateCount": len(rows),
            },
        )

    def _select(self, ns, sql, args):
        lake = self._lake(ns)
        for t in re.findall(r'FROM\s+(?:"\w+"\."\w+"\.)?"?(\w+)"?', sql):
            if (ns, t) not in self.tables:
                raise _TrinoFail(f"Table 'iceberg.{ns}.{t}' does not exist", "TABLE_NOT_FOUND")
        sql = re.sub(r'"\w+"\."\w+"\.("\w+")', r"\1", sql)
        vals = [_ts_text(a) if isinstance(a, datetime) else a for a in args]
        try:
            lake._db.execute("PRAGMA case_sensitive_like = ON")
            cur = lake._db.execute(sql, vals)
        except sqlite3.Error as exc:
            raise _TrinoFail(str(exc), "GENERIC_USER_ERROR") from None
        names = [d[0] for d in cur.description or []]
        raw = cur.fetchall()
        cols, out = [], []
        for i, n in enumerate(names):
            col = next((s.column(n) for s in self.schemas.values() if n in s.column_names), None)
            if col is None:
                sample = next((r[i] for r in raw if r[i] is not None), "")
                col = Column(n, "long" if isinstance(sample, int) else "string")
            cols.append(col)
        columns = [
            {"name": c.name, "type": c.type, "typeSignature": _sig(c.type, c.fields)} for c in cols
        ]
        for r in raw:
            out.append(
                [_wire(lake._decode(c.name, r[i]), c.type, c.fields) for i, c in enumerate(cols)]
            )
        return columns, out, None

    # ---------------------------------------------------------------- REST catalog
    def _rest(self, h, path, body):
        parts = [urllib.parse.unquote(p) for p in path.path.split("/")[3:]]
        q = dict(urllib.parse.parse_qsl(path.query))
        if parts == ["config"]:
            return self._json(
                h, 200, {"defaults": {}, "overrides": {"prefix": f"wh-{q['warehouse']}"}}
            )
        if len(parts) >= 4 and parts[1] == "namespaces" and parts[3] == "tables":
            ns = parts[2]
            if ns not in self.lakes:
                return self._json(
                    h,
                    404,
                    {
                        "error": {
                            "message": "no namespace",
                            "type": "NoSuchNamespaceException",
                            "code": 404,
                        }
                    },
                )
            if len(parts) == 4:
                names = sorted(t for (n, t) in self.tables if n == ns)
                start = int(q.get("pageToken", "0"))
                page = names[start : start + self.list_page]
                doc: dict[str, Any] = {
                    "identifiers": [{"namespace": [ns], "name": t} for t in page]
                }
                if start + self.list_page < len(names):
                    doc["next-page-token"] = str(start + self.list_page)
                return self._json(h, 200, doc)
            meta = self.tables.get((ns, parts[4]))
            if meta is None:
                return self._json(
                    h,
                    404,
                    {
                        "error": {
                            "message": "Table does not exist",
                            "type": "NoSuchTableException",
                            "code": 404,
                        }
                    },
                )
            if body is not None:
                req = json.loads(body)
                if self.conflicts:
                    self.conflicts -= 1
                    return self._json(
                        h,
                        409,
                        {
                            "error": {
                                "message": "commit conflict",
                                "type": "CommitFailedException",
                                "code": 409,
                            }
                        },
                    )
                for r in req["requirements"]:
                    assert r["type"] == "assert-table-uuid"
                    if r["uuid"] != meta["table-uuid"]:
                        return self._json(
                            h,
                            409,
                            {
                                "error": {
                                    "message": "uuid",
                                    "type": "CommitFailedException",
                                    "code": 409,
                                }
                            },
                        )
                for u in req["updates"]:
                    if u["action"] == "set-properties":
                        meta["properties"].update(u["updates"])
            return self._json(
                h, 200, {"metadata-location": "s3://lab-lake/x.json", "metadata": meta}
            )
        return self._json(h, 404, {"error": {"message": "no route", "code": 404}})


class _TrinoFail(Exception):
    pass


def _parse_insert(sql):
    """(namespace, table, column list) of `INSERT INTO "c"."ns"."t" (cols) VALUES ...`, else None.

    Plain string splitting rather than a regex, so the stand-in's parse is linear on any input.
    """
    head, sep, _ = sql.partition(") VALUES ")
    if not sep or not head.startswith('INSERT INTO "'):
        return None
    target, sep, cols = head[len("INSERT INTO ") :].partition(" (")
    parts = target.split(".")
    if not sep or len(parts) != 3 or "(" in cols:
        return None
    names = [x[1:-1] for x in parts if len(x) > 2 and x[0] == x[-1] == '"']
    if len(names) != 3 or not all(n.replace("_", "").isalnum() for n in names):
        return None
    return names[1], names[2], cols
