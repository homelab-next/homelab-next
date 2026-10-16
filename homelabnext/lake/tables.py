# SPDX-License-Identifier: Apache-2.0
"""Table schemas generated from the pinned OCSF subsets in ``schemas/ocsf``.

The JSON Schema file is the single source. Everything else (the Arrow schema, the Iceberg
schema, the DDL for each engine, row validation) is derived from the :class:`TableSchema` built
here, so a column can never exist in one place and not in another.

Only the standard library is needed here. Logical column types:

``string``  ``long``  ``double``  ``boolean``  ``timestamp`` (UTC, microseconds)
``list<string>``  ``list<long>``  ``list<double>``  ``struct`` (one or more nested columns)
"""

from __future__ import annotations

import json
import os
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .errors import LakeError, UnknownTable

SCALARS = ("string", "long", "double", "boolean", "timestamp")
LISTS = ("list<string>", "list<long>", "list<double>")
SCHEMAS_ENV = "HNX_SCHEMAS_DIR"


@dataclass(frozen=True)
class Column:
    name: str
    type: str
    required: bool = False
    fields: tuple[Column, ...] = ()  # only for type == "struct"

    def render(self) -> str:
        """Canonical type text, e.g. ``struct<ip: string, port: long>``."""
        if self.type == "struct":
            return "struct<" + ", ".join(f"{f.name}: {f.render()}" for f in self.fields) + ">"
        return self.type


@dataclass(frozen=True)
class TableSchema:
    name: str
    schema_id: str
    ocsf_class_uid: int
    ocsf_version: str
    columns: tuple[Column, ...]
    key: tuple[str, ...]
    time_column: str
    partition: str  # e.g. "day(time)"

    def column(self, name: str) -> Column:
        for c in self.columns:
            if c.name == name:
                return c
        raise KeyError(name)

    @property
    def column_names(self) -> tuple[str, ...]:
        return tuple(c.name for c in self.columns)


def _column(name: str, spec: Mapping[str, Any], required: bool) -> Column:
    t = spec.get("type")
    if t == "string":
        return Column(
            name, "timestamp" if spec.get("format") == "date-time" else "string", required
        )
    if t == "integer":
        return Column(name, "long", required)
    if t == "number":
        return Column(name, "double", required)
    if t == "boolean":
        return Column(name, "boolean", required)
    if t == "array":
        inner = _column("item", spec.get("items", {}), False).type
        if f"list<{inner}>" not in LISTS:
            raise LakeError(f"column {name!r}: arrays of {inner!r} are not supported")
        return Column(name, f"list<{inner}>", required)
    if t == "object":
        req = set(spec.get("required", []))
        subs = tuple(_column(k, v, k in req) for k, v in spec.get("properties", {}).items())
        if not subs:
            raise LakeError(f"column {name!r}: an object needs declared properties")
        return Column(name, "struct", required, subs)
    raise LakeError(f"column {name!r}: unsupported JSON Schema type {t!r}")


def schema_from_json(doc: Mapping[str, Any]) -> TableSchema:
    meta = doc.get("x-lake")
    if not isinstance(meta, Mapping):
        raise LakeError(f"{doc.get('$id')}: missing the 'x-lake' block")
    req = set(doc.get("required", []))
    cols = tuple(_column(k, v, k in req) for k, v in doc["properties"].items())
    names = {c.name for c in cols}
    key = tuple(meta["key"])
    if not key or not set(key) <= names:
        raise LakeError(f"{doc['$id']}: x-lake.key must name existing columns")
    tcol = meta["time_column"]
    if tcol not in names:
        raise LakeError(f"{doc['$id']}: x-lake.time_column is not a column")
    return TableSchema(
        name=meta["table"],
        schema_id=doc["$id"],
        ocsf_class_uid=int(meta["ocsf_class_uid"]),
        ocsf_version=meta["ocsf_version"],
        columns=cols,
        key=key,
        time_column=tcol,
        partition=meta["partition"],
    )


def default_schema_dir() -> Path:
    env = os.environ.get(SCHEMAS_ENV)
    if env:
        return Path(env)
    return Path(__file__).resolve().parents[2] / "schemas" / "ocsf"


def load_schemas(directory: str | os.PathLike | None = None) -> dict[str, TableSchema]:
    """Load every ``*.v1.json`` OCSF subset in ``directory`` (default: the repository's)."""
    base = Path(directory) if directory is not None else default_schema_dir()
    if not base.is_dir():
        raise LakeError(
            f"OCSF schema directory {base} not found; run from a source checkout or set {SCHEMAS_ENV}"
        )
    out: dict[str, TableSchema] = {}
    for p in sorted(base.glob("*.v*.json")):
        s = schema_from_json(json.loads(p.read_text(encoding="utf-8")))
        out[s.name] = s
    if not out:
        raise LakeError(f"no OCSF schema subsets found in {base}")
    return out


def get_schema(name: str, schemas: Mapping[str, TableSchema] | None = None) -> TableSchema:
    table = table_name(name)
    pool = schemas if schemas is not None else load_schemas()
    try:
        return pool[table]
    except KeyError:
        raise UnknownTable(f"unknown table {table!r}; known: {sorted(pool)}") from None


def table_name(name: str) -> str:
    """Accept ``authentication`` or the logical id ``table:authentication``."""
    n = name[len("table:") :] if name.startswith("table:") else name
    if not n or not (n[0].isalpha() and n.replace("_", "").isalnum() and n == n.lower()):
        raise LakeError(f"invalid table name {name!r}")
    return n


def iter_columns(columns: tuple[Column, ...], prefix: str = "") -> Iterator[tuple[str, Column]]:
    for c in columns:
        yield prefix + c.name, c
        if c.type == "struct":
            yield from iter_columns(c.fields, prefix + c.name + ".")
