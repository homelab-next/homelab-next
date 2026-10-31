# SPDX-License-Identifier: Apache-2.0
"""The one-off TLP backfill of rows stored before the ``tlp`` column (ADR-0033 decision 5).

A plan, never an execution: :func:`plan` returns the statements an operator reviews and runs on
the lab's engine, in order.  The rule:

* the column is added where the table lacks it;
* a row whose source is recorded (``source_column`` names it, a top-level column or one struct
  field, ``metadata.log_source`` say) takes that source's declared label, mapped from the source
  value to its ``<module>/<dataset>`` route; a source whose items carried labels of their own that
  were never stored (it honours item labels) is backfilled ``red``, as the lost labels may have
  been stricter;
* a row whose source is not recorded, or is a value the mapping does not know, takes the
  strictest label of any source that feeds the table;
* only rows whose ``tlp`` is still null are touched, so running the plan twice changes nothing,
  and a row the writer already labelled keeps its label.

Values are written into the statements as SQL literals (single quotes doubled): the plan is
printed for review, not bound by a client.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from homelabnext import tlp

from .tables import LABEL_COLUMN, Column, TableSchema

__all__ = ["BackfillError", "Source", "plan"]


class BackfillError(ValueError):
    """The inputs cannot be turned into a backfill plan."""


@dataclass(frozen=True)
class Source:
    """One source that feeds the table: its declared label and whether it honours item labels."""

    label: tlp.Label
    honour_item_labels: bool = False

    @property
    def backfill(self) -> tlp.Label:
        """The label its old rows get: red when its items' own labels were never stored."""
        return tlp.Label.RED if self.honour_item_labels else self.label


def _ident(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def _literal(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _source_expr(schema: TableSchema, path: str) -> str:
    parts = path.split(".")
    if not 1 <= len(parts) <= 2:
        raise BackfillError(f"source column {path!r}: a column or one struct field")
    try:
        col: Column = schema.column(parts[0])
    except KeyError:
        raise BackfillError(f"{schema.name}: no column {parts[0]!r}") from None
    if len(parts) == 2:
        fields = {f.name: f for f in col.fields}
        if col.type != "struct" or parts[1] not in fields:
            raise BackfillError(f"{schema.name}: no field {path!r}")
        col = fields[parts[1]]
    if col.type != "string":
        raise BackfillError(f"{schema.name}: source column {path!r} is not a string")
    return ".".join(_ident(p) for p in parts)


def plan(
    schema: TableSchema,
    *,
    table: str,
    sources: Mapping[str, Source],
    source_map: Mapping[str, str],
    source_column: str | None = None,
    add_column: bool = True,
) -> list[str]:
    """The backfill statements for ``table`` (the engine's qualified name).

    ``sources`` maps each route feeding the table to its :class:`Source`; ``source_map`` maps a
    recorded source value (what ``source_column`` holds) to its route.  Without a
    ``source_column`` every row takes the strictest source's label.
    """
    if not schema.labelled:
        raise BackfillError(f"{schema.name}: the schema has no {LABEL_COLUMN} column to fill")
    if not sources:
        raise BackfillError(f"{schema.name}: no source feeds it, so its rows stay red")
    for value, route in source_map.items():
        if route not in sources:
            raise BackfillError(f"source value {value!r} maps to {route!r}, which is no source")
    col = _ident(LABEL_COLUMN)
    out = []
    if add_column:
        out.append(f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS {col} VARCHAR")
    if source_column is not None:
        expr = _source_expr(schema, source_column)
        for value in sorted(source_map):
            label = sources[source_map[value]].backfill
            out.append(
                f"UPDATE {table} SET {col} = {_literal(str(label))} "
                f"WHERE {col} IS NULL AND {expr} = {_literal(value)}"
            )
    strictest = max(s.backfill for s in sources.values())
    out.append(f"UPDATE {table} SET {col} = {_literal(str(strictest))} WHERE {col} IS NULL")
    return out
