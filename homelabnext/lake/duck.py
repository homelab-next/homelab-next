# SPDX-License-Identifier: Apache-2.0
"""DuckDB query engine over Arrow tables (extra ``lake``: duckdb + pyarrow).

DuckDB is the reference engine for the portable SQL subset. Timestamps are exposed as naive UTC
``TIMESTAMP`` (the lake is UTC; DuckDB's ``TIMESTAMPTZ`` fetch would need ``pytz``).
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from datetime import UTC, datetime
from typing import Any

from .base import AdapterBase
from .ddl import _need
from .errors import LakeError, UnknownTable, WriteNotSupported
from .protocol import TableInfo, WriteResult
from .sqlparams import check_params, to_dollar
from .tables import TableSchema, load_schemas, table_name


def to_naive_utc(table: Any) -> Any:
    """Drop the zone from tz-aware timestamp columns, keeping the UTC wall time."""
    pa = _need("pyarrow")
    cols, fields = [], []
    for i, f in enumerate(table.schema):
        col = table.column(i)
        if pa.types.is_timestamp(f.type) and f.type.tz:
            col = col.cast(pa.timestamp(f.type.unit))
            f = pa.field(f.name, col.type, nullable=f.nullable)
        cols.append(col)
        fields.append(f)
    return pa.Table.from_arrays(cols, schema=pa.schema(fields))


def run_duckdb(sql: str, params: Mapping[str, Any] | None, tables: Mapping[str, Any]) -> list[dict]:
    duckdb = _need("duckdb")
    bound = {
        k: (v.astimezone(UTC).replace(tzinfo=None) if isinstance(v, datetime) and v.tzinfo else v)
        for k, v in check_params(sql, params).items()
    }
    con = duckdb.connect(":memory:")
    try:
        con.execute("SET TimeZone='UTC'")
        for name, tbl in tables.items():
            con.register(name, to_naive_utc(tbl))
        try:
            cur = con.execute(to_dollar(sql), bound)
        except duckdb.Error as e:
            raise LakeError(f"query failed: {e}") from e
        names = [d[0] for d in cur.description]
        return [dict(zip(names, r, strict=True)) for r in cur.fetchall()]
    finally:
        con.close()


class DuckDBLake(AdapterBase):
    """Read-only :class:`LakeClient` over in-memory Arrow tables (parity reference, tests)."""

    def __init__(
        self,
        tables: Mapping[str, Any],
        schemas: Iterable[TableSchema] | Mapping[str, TableSchema] | None = None,
        *,
        named_queries: Mapping[str, str] | None = None,
    ):
        if schemas is None:
            schemas = load_schemas()
        pool = schemas.values() if isinstance(schemas, Mapping) else schemas
        self._schemas = {s.name: s for s in pool}
        self._tables = dict(tables)
        self._named = dict(named_queries or {})

    def list_tables(self) -> list[str]:
        return sorted(self._tables)

    def describe(self, table: str) -> TableInfo:
        n = table_name(table)
        if n not in self._tables or n not in self._schemas:
            raise UnknownTable(f"unknown table {n!r}")
        s = self._schemas[n]
        return TableInfo(n, s.schema_id, s.columns, s.key, self._tables[n].num_rows)

    def query(self, sql: str, params: Mapping[str, Any] | None = None) -> list[dict[str, Any]]:
        return run_duckdb(sql, params, self._tables)

    def write_batch(
        self,
        table: str,
        rows: Sequence[Mapping[str, Any]],
        *,
        idempotency_key: str,
        source: str | None = None,
        high_water: str | None = None,
    ) -> WriteResult:
        raise WriteNotSupported("DuckDBLake is read-only; write through IcebergLake or FakeLake")


_WORD = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def referenced_tables(sql: str, names: Iterable[str]) -> list[str]:
    words = set(_WORD.findall(sql))
    return [n for n in names if n in words]
