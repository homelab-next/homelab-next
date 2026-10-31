# SPDX-License-Identifier: Apache-2.0
"""Reading the lake at a TLP ceiling (ADR-0033 decision 6): the shared read path for library code.

A reader below ``red`` never runs SQL it was handed: :class:`CeilingReader` builds the SELECT
itself, from a table, columns and equality filters checked against the table's schema, adds the
ceiling's predicate (:func:`homelabnext.tlp.row_filter_sql`) and checks every returned row's
label again (:func:`tables.row_label`) before returning it.  SQL written elsewhere could alias a
constant as ``tlp`` and launder a row, so ``query`` and ``named`` are refused below ``red``.  The
query engine's own row filter (``hnx modules render``: ``lake-access.json``) is the control for a
reader that composes its own SQL; this one is for code in this repository.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from homelabnext import tlp

from .errors import LakeError
from .tables import LABEL_COLUMN, TableSchema, row_label

__all__ = ["CeilingError", "CeilingReader"]

#: the most rows one select returns
MAX_LIMIT = 10_000


class CeilingError(LakeError):
    """A read the reader's ceiling does not allow (raw SQL below red, an unlabelled table)."""


def _ident(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


class CeilingReader:
    """``lake`` read as a reader with ``ceiling`` (a parsed :class:`~homelabnext.tlp.Label`).

    ``schemas`` maps a table name to its :class:`TableSchema` (``load_schemas()``).
    """

    def __init__(self, lake: Any, ceiling: tlp.Label, schemas: Mapping[str, TableSchema]):
        if type(ceiling) is not tlp.Label:
            raise TypeError(f"ceiling must be a Label, not {type(ceiling).__name__}")
        self._lake = lake
        self.ceiling = ceiling
        self._schemas = dict(schemas)

    def select(
        self,
        table: str,
        columns: Sequence[str] | None = None,
        where: Mapping[str, Any] | None = None,
        *,
        limit: int = 1000,
    ) -> list[dict[str, Any]]:
        """Rows of ``table`` at or below the ceiling: ``columns`` (default all) where each
        ``where`` column equals its value.  ``tlp`` is always selected, so every row says its
        label."""
        schema = self._schemas.get(table)
        if schema is None:
            raise CeilingError(f"unknown table {table!r}")
        if not schema.labelled and self.ceiling is not tlp.Label.RED:
            raise CeilingError(f"{table}: has no {LABEL_COLUMN} column; only red reads it")
        known = set(schema.column_names)
        cols = list(columns) if columns is not None else list(schema.column_names)
        bad = [c for c in [*cols, *(where or {})] if type(c) is not str or c not in known]
        if bad:
            raise CeilingError(f"{table}: not its columns: {bad!r}")
        if schema.labelled and LABEL_COLUMN not in cols:
            cols.append(LABEL_COLUMN)
        if type(limit) is not int or not 1 <= limit <= MAX_LIMIT:
            raise CeilingError(f"limit must be 1..{MAX_LIMIT}")
        conds, params = [], {}
        for i, (col, value) in enumerate((where or {}).items()):
            conds.append(f"{_ident(col)} = :w{i}")
            params[f"w{i}"] = value
        predicate = tlp.row_filter_sql(self.ceiling, LABEL_COLUMN) if schema.labelled else None
        if predicate:
            conds.append(predicate)
        sql = f"SELECT {', '.join(_ident(c) for c in cols)} FROM {_ident(table)}"
        if conds:
            sql += " WHERE " + " AND ".join(conds)
        sql += f" LIMIT {limit}"
        rows = self._lake.query(sql, params)
        if not schema.labelled:
            return rows
        return [r for r in rows if tlp.allows(self.ceiling, row_label(r))]

    def query(self, sql: str, params: Mapping[str, Any] | None = None) -> list[dict[str, Any]]:
        """Raw SQL: ``red`` only (it could alias a constant as the label)."""
        self._red_only("query")
        return self._lake.query(sql, params)

    def named(self, name: str, params: Mapping[str, Any] | None = None) -> list[dict[str, Any]]:
        """A named query: ``red`` only, as for :meth:`query`."""
        self._red_only("named")
        return self._lake.named(name, params)

    def _red_only(self, what: str) -> None:
        if self.ceiling is not tlp.Label.RED:
            raise CeilingError(
                f"{what}: raw SQL is refused below red (ceiling {self.ceiling}); use select()"
            )
