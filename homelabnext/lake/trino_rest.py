# SPDX-License-Identifier: Apache-2.0
"""``TrinoRestLake``: the full ``LakeClient`` over a Trino query engine and an Iceberg REST
catalog, standard library only (:mod:`.trino_http`, :mod:`.rest_catalog`).

Who does what:

* **reads** (``query``, ``named``) go to Trino with server-side parameter binding;
* **metadata** (``list_tables``, ``describe``: schema check, row count, committed marks) comes
  from the REST catalog (Lakekeeper), the system of record for the Iceberg tables;
* **writes** (``write_batch``) validate the whole batch first (the same rules as every adapter),
  skip rows whose content key is already present, append the rest with ``INSERT`` statements
  (an Iceberg commit each, done by Trino through the same catalog), as few as fit under
  ``max_query_length`` characters (Trino refuses a longer query text: ``query.max-length``,
  1,000,000 by default), then record the batch id and the source's high-water mark as table
  properties through the REST catalog;
* **setup** (``ensure_tables``) creates the namespace and the pinned tables with the generated
  Trino DDL and refuses an existing table whose schema differs (``SchemaMismatch``).

A limit worth knowing (a real finding, not a fake): Trino cannot attach properties to the
snapshot it commits, so the rows and the ledger entry are **two** commits, not one as in
``IcebergLake`` (snapshot summary) or ``FakeLake`` (one transaction).  A crash between them leaves
the rows without their ledger entry; a retry of the same batch then writes nothing (every row is
skipped by its content key) but is reported as ``replayed=False`` and the source mark stays at the
previous batch.  No duplicate is ever written; only the replay flag and the mark lag.  The same
holds for a crash between the INSERTs of a batch split in several: the retry writes only the rows
not yet present.  The snapshot recorded is the one whose summary carries the last INSERT's
``trino_query_id``.

The batch ledger is bounded: each table keeps the newest ``ledger_size`` batch entries (each
numbered by a ``seq``), and the commit that records a batch removes older ones in the same
catalog update.  Iceberg rewrites every property in each metadata file, so an unbounded ledger
would make every commit, and every ``describe``, larger for good.  The per-source marks are one
property each and are kept.  A batch replayed after its entry was dropped is written as nothing
(every row is skipped by its content key) and reported as ``replayed=False``, exactly as in
``IcebergLake`` once its snapshots have expired.
One writer per ``(table, source)`` is assumed, as everywhere in the lake library.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from .base import AdapterBase
from .ddl import _trino_type, trino_ddl
from .errors import LakeError, SchemaMismatch, UnknownTable
from .protocol import Mark, TableInfo, WriteResult
from .rest_catalog import CommitConflict, RestCatalog, current_schema_fields, current_snapshot
from .sqlparams import check_params, to_qmark
from .tables import Column, TableSchema, column_diffs, load_schemas, table_name
from .trino_http import Row, TrinoHTTP, execute_immediate, literal
from .validate import content_key, normalize_rows

__all__ = ["TrinoRestLake", "rest_schema_diffs"]

PROP_BATCH = "hnx.batch."
PROP_MARK = "hnx.mark."
KEY_CHUNK = 500
#: the longest query text sent (key lookups and INSERTs): safely below Trino's default
#: ``query.max-length`` (1,000,000)
MAX_QUERY_LENGTH = 900_000
#: batch ledger entries kept per table (older ones are removed when a batch is recorded)
LEDGER_SIZE = 1000
_NS = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")
#: setups already done in this process: (catalog root, Trino catalog, namespace, schemas digest).
#: Only the constructor's ``ensure=True`` consults it; an explicit ``ensure_tables()`` always runs.
_ENSURED: set[tuple[str, str, str, str]] = set()


def _qi(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def _digest(text: str, n: int) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:n]


# ---------------------------------------------------------------- schema comparison
def _ice_type(t: Any) -> str:
    if isinstance(t, str):
        return {"timestamptz": "timestamp"}.get(t, t)
    kind = t.get("type")
    if kind == "list":
        return f"list<{_ice_type(t.get('element'))}>"
    if kind == "struct":
        return "struct<" + ", ".join(_ice_field(f) for f in t.get("fields") or []) + ">"
    return json.dumps(t, sort_keys=True)


def _ice_field(f: Mapping[str, Any]) -> str:
    return f"{f['name']}: {_ice_type(f['type'])}" + (" not null" if f.get("required") else "")


def _col_text(c: Column, nested_required: bool, top: bool = True) -> str:
    req = c.required and (top or nested_required)
    if c.type == "struct":
        inner = ", ".join(_col_text(f, nested_required, False) for f in c.fields)
        return f"{c.name}: struct<{inner}>" + (" not null" if req else "")
    return f"{c.name}: {c.type}" + (" not null" if req else "")


def rest_schema_diffs(
    expected: TableSchema, fields: Sequence[Mapping[str, Any]], *, nested_required: bool = False
) -> list[str]:
    """Differences between the pinned schema and a REST catalog schema's ``fields``.

    Trino's DDL cannot declare ``NOT NULL`` inside a ``ROW``, so a table it created has every
    struct field optional.  With ``nested_required=False`` (the default) a pinned *required*
    struct field may be optional in the table (the batch validation still refuses a null there);
    a table that is *stricter* than the pinned schema, or differs in any type, is still a diff.
    """
    want = {c.name: _col_text(c, nested_required) for c in expected.columns}
    have = {f["name"]: _ice_field(f) for f in fields}
    return column_diffs(want, have)


# ---------------------------------------------------------------- the lake
class TrinoRestLake(AdapterBase):
    features: tuple[str, ...] = ()

    def __init__(
        self,
        trino: TrinoHTTP,
        catalog: RestCatalog,
        *,
        namespace: str,
        trino_catalog: str = "iceberg",
        schemas: Iterable[TableSchema] | Mapping[str, TableSchema] | None = None,
        named_queries: Mapping[str, str] | None = None,
        ensure: bool = True,
        max_query_length: int = MAX_QUERY_LENGTH,
        ledger_size: int = LEDGER_SIZE,
    ):
        if not _NS.fullmatch(namespace):
            raise LakeError(f"namespace must be a lower-case identifier, got {namespace!r}")
        if not isinstance(max_query_length, int) or max_query_length < 1024:
            raise LakeError(
                f"max_query_length must be an integer >= 1024, got {max_query_length!r}"
            )
        self.max_query_length = max_query_length
        if not isinstance(ledger_size, int) or ledger_size < 1:
            raise LakeError(f"ledger_size must be a positive integer, got {ledger_size!r}")
        self.ledger_size = ledger_size
        if schemas is None:
            schemas = load_schemas()
        pool = schemas.values() if isinstance(schemas, Mapping) else schemas
        self._schemas = {s.name: s for s in pool}
        self._trino = trino
        self._rest = catalog
        self._ns = namespace
        self._cat = trino_catalog
        self._named = dict(named_queries or {})
        trino.catalog, trino.schema = trino_catalog, namespace
        if ensure and self._setup_key() not in _ENSURED:
            self.ensure_tables()

    def __repr__(self) -> str:
        return f"TrinoRestLake(namespace={self._ns!r})"

    def close(self) -> None:
        pass

    # ---------------------------------------------------------------- setup
    def _fq(self, table: str) -> str:
        return f"{_qi(self._cat)}.{_qi(self._ns)}.{_qi(table)}"

    def _setup_key(self) -> tuple[str, str, str, str]:
        """What one setup covers: the catalog, the Trino catalog, the namespace and the exact
        table definitions (a digest of their DDL), so a lake with other tables is set up again."""
        ddl = "\n".join(
            trino_ddl(self._schemas[n], catalog=self._cat, schema_name=self._ns)
            for n in sorted(self._schemas)
        )
        return (self._rest.root, self._cat, self._ns, _digest(ddl, 64))

    def ensure_tables(self, names: Iterable[str] | None = None) -> None:
        """Create the namespace and missing tables; refuse a table whose schema differs.

        Always runs (a table dropped since an earlier setup is created again); the constructor
        skips it when this process already set up the same catalog, namespace and tables."""
        self._trino.execute(f"CREATE SCHEMA IF NOT EXISTS {_qi(self._cat)}.{_qi(self._ns)}")
        for n in names if names is not None else sorted(self._schemas):
            s = self._schema(n)
            ddl = trino_ddl(s, catalog=self._cat, schema_name=self._ns).strip().rstrip(";")
            self._trino.execute(ddl)
            self._check_schema(s, self._rest.load_table(self._ns, s.name))
        if names is None:
            _ENSURED.add(self._setup_key())

    def _schema(self, table: str) -> TableSchema:
        n = table_name(table)
        try:
            return self._schemas[n]
        except KeyError:
            raise UnknownTable(f"unknown table {n!r}; known: {sorted(self._schemas)}") from None

    @staticmethod
    def _check_schema(s: TableSchema, meta: Mapping[str, Any]) -> None:
        diffs = rest_schema_diffs(s, current_schema_fields(meta))
        if diffs:
            raise SchemaMismatch(s.name, diffs)

    def _meta(self, s: TableSchema) -> dict[str, Any]:
        try:
            meta = self._rest.load_table(self._ns, s.name)
        except UnknownTable:
            raise UnknownTable(f"table {s.name!r} does not exist; call ensure_tables()") from None
        self._check_schema(s, meta)
        return meta

    # ---------------------------------------------------------------- LakeClient
    def query(self, sql: str, params: Mapping[str, Any] | None = None) -> list[dict[str, Any]]:
        bound = check_params(sql, params)
        text, args = to_qmark(sql, bound)
        return self._trino.execute(text, args).rows

    def list_tables(self) -> list[str]:
        have = set(self._rest.list_tables(self._ns))
        return sorted(n for n in self._schemas if n in have)

    def describe(self, table: str) -> TableInfo:
        s = self._schema(table)
        meta = self._meta(s)
        snap = current_snapshot(meta)
        count: int | None = 0
        if snap is not None:
            total = (snap.get("summary") or {}).get("total-records")
            if total is not None:
                count = int(total)
            else:
                (row,) = self._trino.execute(f"SELECT count(*) AS n FROM {self._fq(s.name)}").rows
                count = int(row["n"])
        committed: dict[str, Mark] = {}
        for k, v in sorted((meta.get("properties") or {}).items()):
            if not k.startswith(PROP_MARK):
                continue
            try:
                doc = json.loads(v)
                committed[str(doc["source"])] = Mark(
                    str(doc["batch_id"]), doc.get("high_water"), doc.get("snapshot_id")
                )
            except (ValueError, KeyError, TypeError):
                raise LakeError(f"table {s.name!r}: unreadable mark property {k!r}") from None
        return TableInfo(
            s.name,
            s.schema_id,
            s.columns,
            s.key,
            count,
            None if snap is None else str(snap["snapshot-id"]),
            committed,
        )

    def _existing_keys(self, s: TableSchema, rows: list[dict[str, Any]]) -> set[tuple]:
        found: set[tuple] = set()
        for sql, args in self._key_lookups(s, rows):
            for r in self._trino.execute(sql, args).rows:
                found.add(tuple(r[k] for k in s.key))
        return found

    def _key_lookups(self, s: TableSchema, rows: list[dict[str, Any]]) -> list[tuple[str, list]]:
        """The content-key lookups for ``rows``: at most ``KEY_CHUNK`` keys each, and each
        query text (as sent) within ``max_query_length``, like the INSERTs."""
        keys = sorted({content_key(s, r) for r in rows}, key=repr)
        cols = ", ".join(_qi(k) for k in s.key)
        head = f"SELECT {cols} FROM {self._fq(s.name)} WHERE "
        if len(s.key) == 1:
            one, sep = "?", ", "
            head += f"{_qi(s.key[0])} IN ("

            def text(n: int) -> str:
                return head + ", ".join("?" for _ in range(n)) + ")"
        else:
            one, sep = "(" + " AND ".join(f"{_qi(k)} = ?" for k in s.key) + ")", " OR "

            def text(n: int) -> str:
                return head + sep.join(one for _ in range(n))

        base = len(execute_immediate(text(0), [None]))  # the frame and one spare separator
        per = len(one) + len(sep)
        out: list[tuple[str, list]] = []
        n, args, size = 0, [], base
        for k in keys:
            cost = per + sum(len(literal(v)) + 2 for v in k)
            if base + cost > self.max_query_length:
                raise LakeError(
                    f"a content key of {s.name!r} needs {base + cost} characters of query text,"
                    f" more than max_query_length ({self.max_query_length})"
                )
            if n and (n >= KEY_CHUNK or size + cost > self.max_query_length):
                out.append((text(n), args))
                n, args, size = 0, [], base
            n, size = n + 1, size + cost
            args.extend(k)
        if n:
            out.append((text(n), args))
        return out

    @staticmethod
    def _value(c: Column, v: Any) -> Any:
        if v is None:
            return None
        if c.type == "struct":
            return Row(TrinoRestLake._value(f, v.get(f.name)) for f in c.fields)
        if c.type.startswith("list<"):
            return list(v)
        return v

    def write_batch(
        self,
        table: str,
        rows: Sequence[Mapping[str, Any]],
        *,
        idempotency_key: str,
        source: str | None = None,
        high_water: str | None = None,
    ) -> WriteResult:
        if not idempotency_key:
            raise LakeError("idempotency_key must be a non-empty string")
        s = self._schema(table)
        norm = normalize_rows(s, rows)  # the whole batch is validated before anything is sent
        meta = self._meta(s)
        prior = (meta.get("properties") or {}).get(PROP_BATCH + _digest(idempotency_key, 32))
        if prior is not None:
            snap = json.loads(prior).get("snapshot_id")
            return WriteResult(len(norm), 0, len(norm), True, snap)
        fresh: list[dict[str, Any]] = []
        if norm:
            have = self._existing_keys(s, norm)
            seen: set[tuple] = set()
            for r in norm:
                k = content_key(s, r)
                if k in have or k in seen:
                    continue
                seen.add(k)
                fresh.append(r)
        if not fresh:  # nothing new: no commit (same as the other adapters)
            return WriteResult(len(norm), 0, len(norm), False, None)
        query_id = ""
        for sql, args in self._inserts(s, fresh):  # the ledger is written once, after the last
            query_id = self._trino.execute(sql, args).query_id
        snap_id = self._record(s, query_id, idempotency_key, source, high_water)
        return WriteResult(len(norm), len(fresh), len(norm) - len(fresh), False, snap_id)

    def _inserts(self, s: TableSchema, rows: list[dict[str, Any]]) -> list[tuple[str, list[Any]]]:
        """``rows`` as INSERT statements whose query text (as sent: ``EXECUTE IMMEDIATE '<sql>'
        USING <literals>``) stays within ``max_query_length``; refuses a row that alone exceeds it
        before anything is sent."""
        cols = ", ".join(_qi(c.name) for c in s.columns)
        one = "(" + ", ".join(f"CAST(? AS {_trino_type(c)})" for c in s.columns) + ")"
        head = f"INSERT INTO {self._fq(s.name)} ({cols}) VALUES "
        base = len(execute_immediate(head, [None]))  # the frame, the head and one ", " spare
        out: list[tuple[str, list[Any]]] = []
        n, args, size = 0, [], base
        for r in rows:
            vals = [self._value(c, r[c.name]) for c in s.columns]
            # one more "(CAST(...), ...)" (with its ", ") in the quoted SQL, and its literals
            cost = len(literal(one)) + sum(len(literal(v)) + 2 for v in vals)
            if base + cost > self.max_query_length:
                raise LakeError(
                    f"a row of {s.name!r} needs {base + cost} characters of query text, more"
                    f" than max_query_length ({self.max_query_length})"
                )
            if n and size + cost > self.max_query_length:
                out.append((head + ", ".join(one for _ in range(n)), args))
                n, args, size = 0, [], base
            n, size = n + 1, size + cost
            args.extend(vals)
        if n:
            out.append((head + ", ".join(one for _ in range(n)), args))
        return out

    def _record(
        self,
        s: TableSchema,
        query_id: str,
        batch_id: str,
        source: str | None,
        high_water: str | None,
    ) -> str | None:
        for attempt in range(4):
            meta = self._rest.load_table(self._ns, s.name)
            snap = next(
                (
                    x
                    for x in meta.get("snapshots") or []
                    if (x.get("summary") or {}).get("trino_query_id") == query_id
                ),
                None,
            ) or current_snapshot(meta)
            snap_id = None if snap is None else str(snap["snapshot-id"])
            key = PROP_BATCH + _digest(batch_id, 32)
            ledger = _ledger(meta.get("properties") or {}, exclude=key)
            seq = max((n for n, _ in ledger), default=0) + 1
            props = {
                key: json.dumps(
                    {"batch_id": batch_id, "snapshot_id": snap_id, "seq": seq}, sort_keys=True
                )
            }
            keep = self.ledger_size - 1  # the entry recorded now is the newest
            removals = [k for _, k in ledger[: max(0, len(ledger) - keep)]]
            if source is not None:
                props[PROP_MARK + _digest(source, 24)] = json.dumps(
                    {
                        "source": source,
                        "batch_id": batch_id,
                        "high_water": high_water,
                        "snapshot_id": snap_id,
                    },
                    sort_keys=True,
                )
            try:
                self._rest.set_properties(
                    self._ns,
                    s.name,
                    props,
                    table_uuid=str(meta.get("table-uuid")),
                    removals=removals,
                )
                return snap_id
            except CommitConflict:
                if attempt == 3:
                    raise
        return None  # pragma: no cover - the loop returns or raises


def _ledger(props: Mapping[str, Any], *, exclude: str) -> list[tuple[int, str]]:
    """The batch ledger entries of ``props`` (but ``exclude``) as ``(seq, key)``, oldest first;
    an entry written before entries were numbered (or unreadable) counts as the oldest."""
    out = []
    for k, v in props.items():
        if not k.startswith(PROP_BATCH) or k == exclude:
            continue
        try:
            seq = int(json.loads(v).get("seq") or 0)
        except (ValueError, TypeError, AttributeError):
            seq = 0
        out.append((seq, k))
    return sorted(out)
