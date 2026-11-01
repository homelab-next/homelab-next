# SPDX-License-Identifier: Apache-2.0
"""The one-off TLP backfill of rows stored before the ``tlp`` column (ADR-0033 decision 5).

A plan, never an execution: :func:`plan` returns the statements an operator reviews and runs on
the lab's engine, in order.  The rule:

* the column is added where the table lacks it;
* a row whose source is recorded (``source_column`` names it, a top-level column or one struct
  field, ``metadata.log_source`` say) takes that source's declared label, mapped from the source
  value to its ``<module>/<dataset>`` route, but only where a human has recorded that the source's
  items carried no labels of their own (:attr:`Source.items_carried_no_labels`).  Every other
  source is backfilled ``red``: the rows predate the column, so no item label was ever stored, and
  a lost one may have been stricter than the declaration (decision 3 lets it be, whether or not the
  source honours item labels);
* a row whose source is not recorded, or is a value the mapping does not know, takes the
  strictest label of any source that feeds the table;
* only rows whose ``tlp`` is still null are touched, so running the plan twice changes nothing,
  and a row the writer already labelled keeps its label.

Values are written into the statements as SQL literals (single quotes doubled, the ANSI rule;
the target is the lake's query engine, whose field access is ``"struct"."field"`` and whose
``ADD COLUMN IF NOT EXISTS`` makes a second run harmless): the plan is printed for review, not
bound by a client.  The table name is checked to be a plain or dotted identifier and a source
value may hold no control character, so nothing in the plan can hide a second statement.  The
plan ends with two checks for the operator: no row is left unlabelled, and the rows holding a
non-canonical label (``white``, ``Green``, a damaged value) are listed for a human decision; they
read as ``red`` until then and are never relabelled by a guess.  Nothing here lowers a row below
``red`` on an assumption: the declared label is used only on the human record above.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass

from homelabnext import tlp

from .tables import LABEL_COLUMN, Column, TableSchema

__all__ = ["BackfillError", "Source", "plan"]


class BackfillError(ValueError):
    """The inputs cannot be turned into a backfill plan."""


@dataclass(frozen=True)
class Source:
    """One source that feeds the table.

    ``label`` and ``honour_item_labels`` are its declaration.  ``items_carried_no_labels`` is the
    human record decision 5 asks for: that the source's items never carried a label of their own,
    so none was lost when its old rows were stored without one.  It defaults to ``False``.
    """

    label: tlp.Label
    honour_item_labels: bool = False
    items_carried_no_labels: bool = False

    @property
    def backfill(self) -> tlp.Label:
        """The label its old rows get: the declaration on the human record, otherwise red."""
        return self.label if self.items_carried_no_labels else tlp.Label.RED


_TABLE = re.compile(
    r'(?:[A-Za-z_][A-Za-z0-9_$]*|"[^"\x00-\x1f]+")(?:\.(?:[A-Za-z_][A-Za-z0-9_$]*|"[^"\x00-\x1f]+")){0,2}'
)


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
    if type(table) is not str or _TABLE.fullmatch(table) is None:
        raise BackfillError(f"{table!r} is not a table name (catalog.schema.table at most)")
    bad = [v for v in source_map if type(v) is not str or any(ord(c) < 0x20 for c in v)]
    if bad:
        raise BackfillError(f"source values with a control character: {bad!r}")
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
    canonical = ", ".join(_literal(v) for v in tlp.LABELS)
    out.append(f"SELECT count(*) AS unlabelled FROM {table} WHERE {col} IS NULL")
    out.append(
        f"SELECT {col}, count(*) AS n FROM {table} WHERE {col} NOT IN ({canonical}) GROUP BY {col}"
    )
    return out
