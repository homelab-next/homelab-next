# SPDX-License-Identifier: Apache-2.0
"""Row validation and normalisation against a :class:`TableSchema`.

A batch is validated as a whole before anything is written. Timestamps must carry an explicit
offset (naive values are refused: the lake is UTC and a guessed zone is a silent skew) and are
returned as aware UTC datetimes.
"""

from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from typing import Any

from .errors import RowRejected
from .tables import Column, TableSchema


def parse_timestamp(value: Any) -> datetime:
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value)
        except ValueError as e:
            raise ValueError(f"not an RFC 3339 timestamp: {value!r}") from e
    if not isinstance(value, datetime):
        raise ValueError(f"expected a timestamp, got {type(value).__name__}")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp has no UTC offset (naive timestamps are refused)")
    return value.astimezone(UTC)


INT64_MIN, INT64_MAX = -(2**63), 2**63 - 1


def _check(col: Column, value: Any, path: str, problems: list[str]) -> Any:
    if value is None:
        if col.required:
            problems.append(f"{path}: required but null/missing")
        return None
    t = col.type
    if t == "string":
        if not isinstance(value, str):
            problems.append(f"{path}: expected string, got {type(value).__name__}")
        return value
    if t == "long":
        if isinstance(value, bool) or not isinstance(value, int):
            problems.append(f"{path}: expected integer, got {type(value).__name__}")
        elif not INT64_MIN <= value <= INT64_MAX:  # every engine stores a long in 64 bits
            problems.append(f"{path}: integer {value} is outside the 64-bit range of a long")
        return value
    if t == "double":
        if (
            isinstance(value, bool)
            or not isinstance(value, int | float)
            or not math.isfinite(value)
        ):
            problems.append(f"{path}: expected finite number, got {value!r}")
            return value
        return float(value)
    if t == "boolean":
        if not isinstance(value, bool):
            problems.append(f"{path}: expected boolean, got {type(value).__name__}")
        return value
    if t == "timestamp":
        try:
            return parse_timestamp(value)
        except ValueError as e:
            problems.append(f"{path}: {e}")
            return value
    if t.startswith("list<"):
        if isinstance(value, str | bytes) or not isinstance(value, Sequence):
            problems.append(f"{path}: expected list, got {type(value).__name__}")
            return value
        elem = Column("item", t[5:-1])
        return [_check(elem, v, f"{path}[{i}]", problems) for i, v in enumerate(value)]
    if t == "struct":
        if not isinstance(value, Mapping):
            problems.append(f"{path}: expected object, got {type(value).__name__}")
            return value
        known = {f.name for f in col.fields}
        for k in value:
            if k not in known:
                problems.append(f"{path}.{k}: unknown field")
        return {
            f.name: _check(f, value.get(f.name), f"{path}.{f.name}", problems) for f in col.fields
        }
    problems.append(f"{path}: unsupported type {t}")
    return value


def normalize_rows(schema: TableSchema, rows: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Return rows with every column present and values canonicalised, or raise RowRejected."""
    problems: list[str] = []
    out: list[dict[str, Any]] = []
    known = set(schema.column_names)
    for i, row in enumerate(rows):
        if not isinstance(row, Mapping):
            problems.append(f"row {i}: expected an object")
            continue
        sub: list[str] = []
        for k in row:
            if k not in known:
                sub.append(f"{k}: unknown column")
        norm = {c.name: _check(c, row.get(c.name), c.name, sub) for c in schema.columns}
        problems.extend(f"row {i} {p}" for p in sub)
        out.append(norm)
    if problems:
        raise RowRejected(schema.name, problems)
    return out


def content_key(schema: TableSchema, row: Mapping[str, Any]) -> tuple[Any, ...]:
    return tuple(row[k] for k in schema.key)
