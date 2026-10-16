# SPDX-License-Identifier: Apache-2.0
"""Generate Arrow / Iceberg schemas and per-engine DDL from a :class:`TableSchema`.

``pyarrow`` and ``pyiceberg`` are imported lazily; the DDL text renderers need only the
standard library. The text produced here is pinned by golden files in ``tests/lake/golden``.
"""

from __future__ import annotations

from typing import Any

from .errors import MissingExtra
from .tables import Column, TableSchema


def _q(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


# ---------------------------------------------------------------- Arrow
def _need(module: str, extra: str = "lake") -> Any:
    import importlib

    try:
        return importlib.import_module(module)
    except ImportError as e:
        raise MissingExtra(module.split(".")[0], extra) from e


def arrow_type(col: Column) -> Any:
    pa = _need("pyarrow")
    t = col.type
    simple = {
        "string": pa.string(),
        "long": pa.int64(),
        "double": pa.float64(),
        "boolean": pa.bool_(),
        "timestamp": pa.timestamp("us", tz="UTC"),
    }
    if t in simple:
        return simple[t]
    if t.startswith("list<"):
        return pa.list_(pa.field("element", simple[t[5:-1]]))
    if t == "struct":
        return pa.struct([arrow_field(f) for f in col.fields])
    raise ValueError(t)


def arrow_field(col: Column) -> Any:
    pa = _need("pyarrow")
    return pa.field(col.name, arrow_type(col), nullable=not col.required)


def to_pyarrow(schema: TableSchema) -> Any:
    pa = _need("pyarrow")
    return pa.schema([arrow_field(c) for c in schema.columns])


def arrow_type_text(t: Any) -> str:
    pa = _need("pyarrow")
    if pa.types.is_string(t):
        return "string"
    if pa.types.is_int64(t):
        return "int64"
    if pa.types.is_float64(t):
        return "float64"
    if pa.types.is_boolean(t):
        return "bool"
    if pa.types.is_timestamp(t):
        return f"timestamp[{t.unit}, tz={t.tz}]" if t.tz else f"timestamp[{t.unit}]"
    if pa.types.is_list(t):
        return f"list<{t.value_field.name}: {arrow_type_text(t.value_type)}>"
    if pa.types.is_struct(t):
        inner = ", ".join(arrow_field_text(t.field(i)) for i in range(t.num_fields))
        return f"struct<{inner}>"
    return str(t)


def arrow_field_text(f: Any) -> str:
    return f"{f.name}: {arrow_type_text(f.type)}" + ("" if f.nullable else " not null")


def arrow_schema_text(pa_schema: Any) -> str:
    """Canonical, pyarrow-version-independent text of an Arrow schema (one field per line)."""
    return "\n".join(arrow_field_text(pa_schema.field(i)) for i in range(len(pa_schema))) + "\n"


# ---------------------------------------------------------------- Iceberg
def to_iceberg(schema: TableSchema) -> Any:
    """pyiceberg ``Schema`` with deterministic sequential field ids (depth first)."""
    _need("pyiceberg")
    from pyiceberg.schema import Schema
    from pyiceberg.types import (
        BooleanType,
        DoubleType,
        ListType,
        LongType,
        NestedField,
        StringType,
        StructType,
        TimestamptzType,
    )

    counter = iter(range(1, 10_000))
    scalar = {
        "string": StringType,
        "long": LongType,
        "double": DoubleType,
        "boolean": BooleanType,
        "timestamp": TimestamptzType,
    }

    def build(col: Column) -> NestedField:
        fid = next(counter)
        if col.type == "struct":
            return NestedField(
                fid, col.name, StructType(*[build(f) for f in col.fields]), required=col.required
            )
        if col.type.startswith("list<"):
            eid = next(counter)
            return NestedField(
                fid,
                col.name,
                ListType(eid, scalar[col.type[5:-1]](), element_required=False),
                required=col.required,
            )
        return NestedField(fid, col.name, scalar[col.type](), required=col.required)

    return Schema(*[build(c) for c in schema.columns])


def iceberg_partition_spec(schema: TableSchema, iceberg_schema: Any) -> Any:
    from pyiceberg.partitioning import PartitionField, PartitionSpec
    from pyiceberg.transforms import DayTransform

    if schema.partition != f"day({schema.time_column})":
        raise ValueError(f"unsupported partition {schema.partition!r}")
    src = iceberg_schema.find_field(schema.time_column)
    return PartitionSpec(
        PartitionField(
            source_id=src.field_id,
            field_id=1000,
            transform=DayTransform(),
            name=f"{schema.time_column}_day",
        )
    )


# ---------------------------------------------------------------- DDL text
def _trino_type(col: Column) -> str:
    t = col.type
    simple = {
        "string": "VARCHAR",
        "long": "BIGINT",
        "double": "DOUBLE",
        "boolean": "BOOLEAN",
        "timestamp": "TIMESTAMP(6) WITH TIME ZONE",
    }
    if t in simple:
        return simple[t]
    if t.startswith("list<"):
        return f"ARRAY({simple[t[5:-1]]})"
    return "ROW(" + ", ".join(f"{_q(f.name)} {_trino_type(f)}" for f in col.fields) + ")"


def trino_ddl(schema: TableSchema, *, catalog: str, schema_name: str) -> str:
    """``CREATE TABLE IF NOT EXISTS`` for the Trino Iceberg connector."""
    cols = ",\n".join(
        f"    {_q(c.name)} {_trino_type(c)}" + (" NOT NULL" if c.required else "")
        for c in schema.columns
    )
    return (
        f"CREATE TABLE IF NOT EXISTS {_q(catalog)}.{_q(schema_name)}.{_q(schema.name)} (\n{cols}\n)\n"
        f"WITH (\n    format = 'PARQUET',\n    partitioning = ARRAY['{schema.partition}']\n);\n"
    )


def _duck_type(col: Column) -> str:
    t = col.type
    simple = {
        "string": "VARCHAR",
        "long": "BIGINT",
        "double": "DOUBLE",
        "boolean": "BOOLEAN",
        "timestamp": "TIMESTAMP",
    }
    if t in simple:
        return simple[t]
    if t.startswith("list<"):
        return f"{simple[t[5:-1]]}[]"
    return "STRUCT(" + ", ".join(f"{_q(f.name)} {_duck_type(f)}" for f in col.fields) + ")"


def duckdb_ddl(schema: TableSchema) -> str:
    """DuckDB DDL. Timestamps are naive UTC (the lake is UTC; DuckDB's TIMESTAMPTZ fetch needs pytz)."""
    cols = ",\n".join(
        f"    {_q(c.name)} {_duck_type(c)}" + (" NOT NULL" if c.required else "")
        for c in schema.columns
    )
    return f"CREATE TABLE IF NOT EXISTS {_q(schema.name)} (\n{cols}\n);\n"


def sqlite_ddl(schema: TableSchema) -> str:
    """DDL for the in-memory fake; lists and structs are stored as JSON text."""
    kinds = {"long": "INTEGER", "double": "REAL", "boolean": "INTEGER"}
    cols = ",\n".join(
        f"    {_q(c.name)} {kinds.get(c.type, 'TEXT')}" + (" NOT NULL" if c.required else "")
        for c in schema.columns
    )
    return f"CREATE TABLE IF NOT EXISTS {_q(schema.name)} (\n{cols}\n);\n"
