# SPDX-License-Identifier: Apache-2.0
"""Iceberg-backed lake: pyiceberg catalog for writes, DuckDB over scans for queries.

Extra ``lake`` (``pyiceberg[sql-sqlite]``, ``pyarrow``, ``duckdb``). The catalog can be a local
SQLite catalog (tests, laptops) or a REST catalog whose URL comes from the registry.

Idempotent writes
-----------------
Two independent layers, because each covers a failure the other cannot:

1. **Batch ledger in the snapshot.** Every commit stores ``hnx.batch-id`` (and optionally
   ``hnx.source`` / ``hnx.high-water``) in the Iceberg snapshot summary. The append and the
   record that it happened are one atomic catalog commit, so there is no window in which one
   exists without the other. A retried ``idempotency_key`` is found in the history and skipped.
2. **Content key.** Rows whose key columns (``uid``) already exist in the table are filtered out
   before the append. That makes replay safe when the batching changes, when the same log tail is
   re-read under new batch ids, or when old snapshots were expired (the ledger is gone, the data
   is not). The lookup is over the whole table, as in the other adapters: a ``uid`` stored with
   another ``time`` (a re-emitted finding, a re-normalised event) is still found. Only a schema
   whose key includes its time column has the lookup bounded to the batch's time range.

``hnx.high-water`` lets a restarted reader fast-forward its checkpoint to what the lake already
holds (see :mod:`homelabnext.lake.checkpoint`).
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from .base import AdapterBase
from .ddl import _need, iceberg_partition_spec, to_iceberg, to_pyarrow
from .duck import referenced_tables, run_duckdb
from .endpoints import endpoint_for
from .errors import LakeError, SchemaMismatch, UnknownTable
from .protocol import Mark, TableInfo, WriteResult
from .tables import CORE_NAMESPACE, Column, TableSchema, column_diffs, load_schemas, table_name
from .validate import content_key, normalize_rows

PROP_BATCH = "hnx.batch-id"
PROP_SOURCE = "hnx.source"
PROP_HIGH_WATER = "hnx.high-water"
KEY_CHUNK = 500


# ---------------------------------------------------------------- catalogs
def open_sql_catalog(name: str, *, uri: str, warehouse: str) -> Any:
    """Local SQL catalog (``sqlite:///...``) with file warehouse. For tests and laptops."""
    _need("pyiceberg")
    from pyiceberg.catalog.sql import SqlCatalog

    return SqlCatalog(name, uri=uri, warehouse=warehouse)


def open_rest_catalog(
    name: str = "lake",
    *,
    resolver: Any = None,
    registry: Any = None,
    environ: Mapping[str, str] | None = None,
    **properties: str,
) -> Any:
    """REST catalog at the ``lake-catalog`` capability endpoint. Raises if it is not configured."""
    ep = endpoint_for("lake-catalog", resolver=resolver, registry=registry, environ=environ)
    _need("pyiceberg")
    from pyiceberg.catalog import load_catalog

    return load_catalog(name, type="rest", uri=ep.url, **properties)


# ---------------------------------------------------------------- schema comparison
def _ice_text(t: Any) -> str:
    from pyiceberg import types as T

    if isinstance(t, T.StringType):
        return "string"
    if isinstance(t, T.LongType):
        return "long"
    if isinstance(t, T.DoubleType):
        return "double"
    if isinstance(t, T.BooleanType):
        return "boolean"
    if isinstance(t, T.TimestamptzType):
        return "timestamp"
    if isinstance(t, T.ListType):
        return f"list<{_ice_text(t.element_type)}>"
    if isinstance(t, T.StructType):
        return "struct<" + ", ".join(_ice_field(f) for f in t.fields) + ">"
    return str(t)


def _ice_field(f: Any) -> str:
    return f"{f.name}: {_ice_text(f.field_type)}" + ("" if not f.required else " not null")


def _col_text(c: Column) -> str:
    if c.type == "struct":
        inner = ", ".join(_col_text(f) for f in c.fields)
        return f"{c.name}: struct<{inner}>" + (" not null" if c.required else "")
    return f"{c.name}: {c.type}" + (" not null" if c.required else "")


def schema_diffs(expected: TableSchema, ice_schema: Any) -> list[str]:
    want = {c.name: _col_text(c) for c in expected.columns}
    have = {f.name: _ice_field(f) for f in ice_schema.fields}
    return column_diffs(want, have)


# ---------------------------------------------------------------- the lake
class IcebergLake(AdapterBase):
    def __init__(
        self,
        catalog: Any,
        schemas: Iterable[TableSchema] | Mapping[str, TableSchema] | None = None,
        *,
        namespace: str = CORE_NAMESPACE,
        named_queries: Mapping[str, str] | None = None,
    ):
        _need("pyiceberg")
        if schemas is None:
            schemas = load_schemas()
        pool = schemas.values() if isinstance(schemas, Mapping) else schemas
        self._schemas = {s.name: s for s in pool}
        self._catalog = catalog
        self._ns = namespace
        self._named = dict(named_queries or {})

    # -- setup
    def ensure_tables(self, names: Iterable[str] | None = None) -> None:
        """Create missing tables; verify existing ones match; refuse (SchemaMismatch) otherwise."""
        from pyiceberg.exceptions import NoSuchTableError

        self._catalog.create_namespace_if_not_exists(self._ns)
        for n in names if names is not None else sorted(self._schemas):
            s = self._schema(n)
            ident = (self._ns, s.name)
            try:
                tbl = self._catalog.load_table(ident)
            except NoSuchTableError:
                ice = to_iceberg(s)
                self._catalog.create_table(
                    ident,
                    schema=ice,
                    partition_spec=iceberg_partition_spec(s, ice),
                    properties={"hnx.schema-id": s.schema_id},
                )
                continue
            diffs = schema_diffs(s, tbl.schema())
            if diffs:
                raise SchemaMismatch(s.name, diffs)

    def _schema(self, table: str) -> TableSchema:
        n = table_name(table)
        try:
            return self._schemas[n]
        except KeyError:
            raise UnknownTable(f"unknown table {n!r}; known: {sorted(self._schemas)}") from None

    def _load(self, s: TableSchema) -> Any:
        from pyiceberg.exceptions import NoSuchTableError

        try:
            tbl = self._catalog.load_table((self._ns, s.name))
        except NoSuchTableError:
            raise UnknownTable(f"table {s.name!r} does not exist; call ensure_tables()") from None
        diffs = schema_diffs(s, tbl.schema())
        if diffs:
            raise SchemaMismatch(s.name, diffs)
        return tbl

    # -- LakeClient
    def list_tables(self) -> list[str]:
        have = {i[-1] for i in self._catalog.list_tables(self._ns)}
        return sorted(n for n in self._schemas if n in have)

    @staticmethod
    def _props(snap: Any) -> Mapping[str, str]:
        return snap.summary.additional_properties if snap.summary is not None else {}

    def _snapshots_newest_first(self, tbl: Any) -> list[Any]:
        return sorted(tbl.snapshots(), key=lambda s: (s.timestamp_ms, s.snapshot_id), reverse=True)

    def describe(self, table: str) -> TableInfo:
        s = self._schema(table)
        tbl = self._load(s)
        committed: dict[str, Mark] = {}
        for snap in self._snapshots_newest_first(tbl):
            p = self._props(snap)
            src = p.get(PROP_SOURCE)
            if src is not None and src not in committed:
                committed[src] = Mark(
                    p.get(PROP_BATCH, ""), p.get(PROP_HIGH_WATER), str(snap.snapshot_id)
                )
        cur = tbl.current_snapshot()
        return TableInfo(
            s.name,
            s.schema_id,
            s.columns,
            s.key,
            tbl.scan().count(),
            None if cur is None else str(cur.snapshot_id),
            committed,
        )

    def query(self, sql: str, params: Mapping[str, Any] | None = None) -> list[dict[str, Any]]:
        arrow = {}
        for n in referenced_tables(sql, self._schemas):
            arrow[n] = self._load(self._schema(n)).scan().to_arrow()
        return run_duckdb(sql, params, arrow)

    def _batch_committed(self, tbl: Any, batch_id: str) -> Any | None:
        for snap in self._snapshots_newest_first(tbl):
            if self._props(snap).get(PROP_BATCH) == batch_id:
                return snap
        return None

    def _existing_keys(self, tbl: Any, s: TableSchema, rows: list[dict[str, Any]]) -> set[tuple]:
        from pyiceberg.expressions import And, GreaterThanOrEqual, In, LessThanOrEqual

        bound = None
        if s.time_column in s.key:  # a key that holds the time: the batch's range prunes safely
            times = [r[s.time_column] for r in rows]
            bound = And(
                GreaterThanOrEqual(s.time_column, min(times).isoformat()),
                LessThanOrEqual(s.time_column, max(times).isoformat()),
            )
        k0 = s.key[0]
        found: set[tuple] = set()
        values = sorted({r[k0] for r in rows}, key=str)
        for i in range(0, len(values), KEY_CHUNK):
            flt = In(k0, values[i : i + KEY_CHUNK])
            if bound is not None:
                flt = And(bound, flt)
            got = tbl.scan(row_filter=flt, selected_fields=tuple(s.key)).to_arrow()
            for rec in got.to_pylist():
                found.add(tuple(rec[k] for k in s.key))
        return found

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
        pa = _need("pyarrow")
        s = self._schema(table)
        norm = normalize_rows(s, rows)  # validate the whole batch first
        tbl = self._load(s)  # also refuses a table whose schema drifted
        prior = self._batch_committed(tbl, idempotency_key)
        if prior is not None:
            return WriteResult(len(norm), 0, len(norm), True, str(prior.snapshot_id))
        fresh: list[dict[str, Any]] = []
        if norm:
            have = self._existing_keys(tbl, s, norm)
            seen: set[tuple] = set()
            for r in norm:
                k = content_key(s, r)
                if k in have or k in seen:
                    continue
                seen.add(k)
                fresh.append(r)
        props = {PROP_BATCH: idempotency_key}
        if source is not None:
            props[PROP_SOURCE] = source
        if high_water is not None:
            props[PROP_HIGH_WATER] = high_water
        if not fresh:  # nothing new: no commit, no empty snapshot
            return WriteResult(len(norm), 0, len(norm), False, None)
        pa_tbl = pa.Table.from_pylist(fresh, schema=to_pyarrow(s))
        tbl.append(pa_tbl, snapshot_properties=props)  # one atomic catalog commit
        snap = tbl.current_snapshot()
        return WriteResult(
            len(norm), len(fresh), len(norm) - len(fresh), False, str(snap.snapshot_id)
        )
