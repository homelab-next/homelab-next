# SPDX-License-Identifier: Apache-2.0
"""``FakeLake``: an in-memory implementation of :class:`LakeClient` using only the standard
library (``sqlite3``). It is the second implementation the swap kit and the conformance tests
use, and the one every unit test of a lake consumer should use.

It applies the same validation, the same idempotency rules and the same portable SQL subset as
the real adapters. Rows and the idempotency ledger are committed in one SQLite transaction,
so a "crash" can never leave one without the other.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable, Mapping, Sequence
from datetime import UTC, datetime
from typing import Any

from .base import AdapterBase
from .ddl import sqlite_ddl
from .errors import LakeError, UnknownTable
from .protocol import Mark, TableInfo, WriteResult
from .sqlparams import check_params
from .tables import TableSchema, load_schemas, table_name
from .validate import content_key, normalize_rows


def _ts_text(dt: datetime) -> str:
    dt = dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt.astimezone(UTC)  # naive = UTC
    t = dt.strftime("%Y-%m-%d %H:%M:%S")
    return t + (f".{dt.microsecond:06d}" if dt.microsecond else "")


class FakeLake(AdapterBase):
    def __init__(
        self,
        schemas: Iterable[TableSchema] | Mapping[str, TableSchema] | None = None,
        *,
        named_queries: Mapping[str, str] | None = None,
    ):
        if schemas is None:
            schemas = load_schemas()
        pool = schemas.values() if isinstance(schemas, Mapping) else schemas
        self._schemas: dict[str, TableSchema] = {s.name: s for s in pool}
        self._named = dict(named_queries or {})
        self._db = sqlite3.connect(":memory:", check_same_thread=False, isolation_level=None)
        self._db.row_factory = sqlite3.Row
        self._db.execute(
            'CREATE TABLE "_hnx_batches" (seq INTEGER PRIMARY KEY AUTOINCREMENT, tbl TEXT NOT NULL, '
            "batch_id TEXT NOT NULL, source TEXT, high_water TEXT, rows_written INTEGER NOT NULL, "
            "UNIQUE (tbl, batch_id))"
        )
        for s in self._schemas.values():
            self._db.executescript(sqlite_ddl(s))
        self._types: dict[str, str] = {}
        clash: set[str] = set()
        for s in self._schemas.values():
            for c in s.columns:
                if self._types.get(c.name, c.type) != c.type:
                    clash.add(c.name)
                self._types[c.name] = c.type
        for n in clash:
            self._types.pop(n, None)

    # ------------------------------------------------------------ helpers
    def _schema(self, table: str) -> TableSchema:
        n = table_name(table)
        try:
            return self._schemas[n]
        except KeyError:
            raise UnknownTable(f"unknown table {n!r}; known: {sorted(self._schemas)}") from None

    def _encode(self, schema: TableSchema, row: Mapping[str, Any]) -> list[Any]:
        out: list[Any] = []
        for c in schema.columns:
            v = row[c.name]
            if v is None:
                out.append(None)
            elif c.type == "timestamp":
                out.append(_ts_text(v))
            elif c.type == "boolean":
                out.append(1 if v else 0)
            elif c.type == "struct" or c.type.startswith("list<"):
                out.append(json.dumps(self._jsonable(v), sort_keys=True))
            else:
                out.append(v)
        return out

    def _jsonable(self, v: Any) -> Any:
        if isinstance(v, datetime):
            return _ts_text(v)
        if isinstance(v, Mapping):
            return {k: self._jsonable(x) for k, x in v.items()}
        if isinstance(v, list | tuple):
            return [self._jsonable(x) for x in v]
        return v

    def _decode(self, name: str, v: Any) -> Any:
        if v is None:
            return None
        t = self._types.get(name)
        if t == "boolean":
            return bool(v)
        if t == "timestamp" and isinstance(v, str):
            return datetime.fromisoformat(v).replace(tzinfo=UTC)
        if (t == "struct" or (t or "").startswith("list<")) and isinstance(v, str):
            return json.loads(v)
        return v

    # ------------------------------------------------------------ LakeClient
    def list_tables(self) -> list[str]:
        return sorted(self._schemas)

    def describe(self, table: str) -> TableInfo:
        s = self._schema(table)
        count = self._db.execute(f'SELECT count(*) FROM "{s.name}"').fetchone()[0]
        committed: dict[str, Mark] = {}
        for r in self._db.execute(
            "SELECT seq, batch_id, source, high_water FROM _hnx_batches WHERE tbl=? "
            "AND source IS NOT NULL ORDER BY seq",
            (s.name,),
        ):
            committed[r["source"]] = Mark(r["batch_id"], r["high_water"], str(r["seq"]))
        last = self._db.execute(
            "SELECT max(seq) FROM _hnx_batches WHERE tbl=?", (s.name,)
        ).fetchone()[0]
        return TableInfo(
            s.name,
            s.schema_id,
            s.columns,
            s.key,
            count,
            None if last is None else str(last),
            committed,
        )

    def query(self, sql: str, params: Mapping[str, Any] | None = None) -> list[dict[str, Any]]:
        bound = check_params(sql, params)
        bound = {k: (_ts_text(v) if isinstance(v, datetime) else v) for k, v in bound.items()}
        try:
            cur = self._db.execute(sql, bound)
        except sqlite3.Error as e:
            raise LakeError(f"query failed: {e}") from e
        names = [d[0] for d in cur.description or []]
        return [{n: self._decode(n, r[i]) for i, n in enumerate(names)} for r in cur.fetchall()]

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
        norm = normalize_rows(s, rows)  # raises before anything is written
        db = self._db
        db.execute("BEGIN IMMEDIATE")
        try:
            seen = db.execute(
                "SELECT seq FROM _hnx_batches WHERE tbl=? AND batch_id=?", (s.name, idempotency_key)
            ).fetchone()
            if seen is not None:
                db.execute("COMMIT")
                return WriteResult(len(norm), 0, len(norm), True, str(seen[0]))
            fresh: list[dict[str, Any]] = []
            keys: set[tuple[Any, ...]] = set()
            for r in norm:
                k = content_key(s, r)
                if k in keys or self._exists(s, k):
                    continue
                keys.add(k)
                fresh.append(r)
            if not fresh:  # nothing new: no commit (same as the Iceberg adapter)
                db.execute("COMMIT")
                return WriteResult(len(norm), 0, len(norm), False, None)
            cols = ", ".join(f'"{c}"' for c in s.column_names)
            marks = ", ".join("?" for _ in s.column_names)
            for r in fresh:
                db.execute(f'INSERT INTO "{s.name}" ({cols}) VALUES ({marks})', self._encode(s, r))
            cur = db.execute(
                "INSERT INTO _hnx_batches (tbl, batch_id, source, high_water, rows_written) "
                "VALUES (?,?,?,?,?)",
                (s.name, idempotency_key, source, high_water, len(fresh)),
            )
            seq = cur.lastrowid
            db.execute("COMMIT")
        except BaseException:
            db.execute("ROLLBACK")
            raise
        return WriteResult(len(norm), len(fresh), len(norm) - len(fresh), False, str(seq))

    def _exists(self, s: TableSchema, key: tuple[Any, ...]) -> bool:
        where = " AND ".join(f'"{k}" = ?' for k in s.key)
        vals = [_ts_text(v) if isinstance(v, datetime) else v for v in key]
        return (
            self._db.execute(f'SELECT 1 FROM "{s.name}" WHERE {where} LIMIT 1', vals).fetchone()
            is not None
        )
