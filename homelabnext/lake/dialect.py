# SPDX-License-Identifier: Apache-2.0
"""The SQL an adapter's query path speaks for the few expressions the portable subset lacks.

The portable subset (``README.md``) has no struct field access and no portable way to take the
UTC date of a timestamp.  :meth:`~homelabnext.lake.ceiling.CeilingReader.count_by` needs both,
so every adapter that runs SQL declares its dialect in a ``sql_dialect`` class attribute and
this module turns a validated column path into that dialect's expression.  There are two:

=============== ============================================ ==============================
dialect         field ``src_endpoint.ip``                    UTC day of ``time``
=============== ============================================ ==============================
``json-text``   ``json_extract("src_endpoint", '$."ip"')``   ``substr("time", 1, 10)``
``struct``      ``"src_endpoint"."ip"``                      ``CAST("time" AS DATE)``
=============== ============================================ ==============================

``json-text`` is ``FakeLake``'s SQLite, which stores a struct as JSON text and a timestamp as UTC
text (``YYYY-MM-DD HH:MM:SS``).  ``struct`` is every engine with native struct columns: the
DuckDB adapters and the query-engine adapters, each run with the session time zone pinned to UTC
(``duck.run_duckdb``, the query-engine clients), so the cast is the UTC date.  Only names
checked against a table schema reach these functions; a part that is not a plain identifier is
refused here too.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from typing import Any

from .errors import LakeError

__all__ = ["DIALECTS", "JSON_TEXT", "STRUCT", "day_expr", "dialect_of", "field_expr"]

#: structs as JSON text, timestamps as UTC text (the SQLite fake)
JSON_TEXT = "json-text"
#: native struct columns and timestamps
STRUCT = "struct"
DIALECTS = (JSON_TEXT, STRUCT)
_PART = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def _ident(name: str) -> str:
    if not _PART.fullmatch(name):
        raise LakeError(f"not a plain column name: {name!r}")
    return f'"{name}"'


def dialect_of(lake: Any) -> str:
    """The dialect ``lake`` declares (``sql_dialect``); one that declares none is refused."""
    name = getattr(lake, "sql_dialect", None)
    if name not in DIALECTS:
        raise LakeError(
            f"{type(lake).__name__} declares no SQL dialect (sql_dialect: one of {DIALECTS}),"
            " so it cannot run a grouped read"
        )
    return name


def field_expr(dialect: str, path: Sequence[str]) -> str:
    """The expression for the column ``path`` (top-level column, then nested struct fields)."""
    if not path:
        raise LakeError("an empty column path")
    head = _ident(path[0])
    rest = [_ident(p) for p in path[1:]]
    if not rest:
        return head
    if dialect == JSON_TEXT:
        return f"json_extract({head}, '$.{'.'.join(rest)}')"
    if dialect == STRUCT:
        return ".".join([head, *rest])
    raise LakeError(f"unknown SQL dialect {dialect!r}")


def day_expr(dialect: str, expr: str) -> str:
    """The UTC date of the timestamp expression ``expr``."""
    if dialect == JSON_TEXT:
        return f"substr({expr}, 1, 10)"
    if dialect == STRUCT:
        return f"CAST({expr} AS DATE)"
    raise LakeError(f"unknown SQL dialect {dialect!r}")
