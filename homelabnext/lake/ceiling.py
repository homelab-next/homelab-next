# SPDX-License-Identifier: Apache-2.0
"""Reading the lake at a TLP ceiling (ADR-0033 decision 6): the shared read path for library code.

A reader below ``red`` never runs SQL it was handed: :class:`CeilingReader` builds the SELECT
itself, from a table, columns and equality filters checked against the table's schema, adds the
ceiling's predicate (:func:`homelabnext.tlp.row_filter_sql`) and checks every returned row's
label again (:func:`tables.row_label`) before returning it.  SQL written elsewhere could alias a
constant as ``tlp`` and launder a row, so ``query`` and ``named`` are refused below ``red``.  The
query engine's own row filter (``hnx modules render``: ``lake-access.json``) is the control for a
reader that composes its own SQL; this one is for code in this repository.

A reader with no declared ceiling is refused (decision 6), and reading at ``red`` is never a
default:

* :func:`reader_for` is the factory for a consumer: it takes the reader's ceiling from its
  declaration (the site's ``tlp_readers``) and refuses a reader that has none;
* every read at ``red`` names a :class:`RedGrant` (who reads everything and why): a red
  :class:`CeilingReader` needs one, and :func:`raw_query` / :func:`raw_named`, the only way code
  outside this package runs SQL against a lake client, take one.  :func:`reader_for` makes the
  grant of a reader declared ``red`` from its declaration's ``why``; the swap and parity tools,
  which copy and compare every row, hold their own.

``tests/lake/test_lake_read_boundary.py`` refuses a ``.query(`` or ``.named(`` call in any module
outside ``homelabnext/lake/`` (and the conformance harness, whose subject is that method) that
imports the lake library.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import date, datetime, timedelta
from typing import Any

from homelabnext import tlp

from .dialect import day_expr, dialect_of, field_expr
from .errors import LakeError
from .tables import LABEL_COLUMN, SCALARS, Column, TableSchema, iter_columns, row_label

__all__ = [
    "CeilingError",
    "CeilingReader",
    "GroupCount",
    "RedGrant",
    "TooManyGroups",
    "raw_named",
    "raw_query",
    "reader_for",
]

#: the most rows one select returns
MAX_LIMIT = 10_000
#: the most groups one count_by may be asked for (its ``limit``)
MAX_GROUPS = 100_000
#: the column types a count_by key may have (a struct or list is not a key; nor is a timestamp,
#: which the day already buckets)
KEY_TYPES = tuple(t for t in SCALARS if t != "timestamp")


class CeilingError(LakeError):
    """A read the reader's ceiling does not allow (raw SQL below red, an unlabelled table)."""


class TooManyGroups(LakeError):
    """A :meth:`CeilingReader.count_by` whose groups exceed its ``limit``: the read is refused
    whole rather than truncated, so a caller never scores a partial count as the full one."""


@dataclass(frozen=True)
class GroupCount:
    """One group of :meth:`CeilingReader.count_by`: rows of ``entity`` with ``values`` on the
    UTC ``day``, at the stored ``label``, ``count`` of them."""

    entity: Any
    values: tuple[Any, ...]
    day: date
    label: tlp.Label
    count: int


@dataclass(frozen=True)
class RedGrant:
    """Leave to read the lake at ``red`` (every row, raw SQL): ``holder`` is who reads, ``why``
    the reviewed reason.  It is passed explicitly wherever a red read happens, so a red read is
    always visible at its call site."""

    holder: str
    why: str

    def __post_init__(self) -> None:
        for name in ("holder", "why"):
            value = getattr(self, name)
            if type(value) is not str or not value.strip():
                raise CeilingError(f"a red grant needs a non-empty {name}")


def _grant(grant: object, what: str) -> RedGrant:
    if type(grant) is not RedGrant:
        raise CeilingError(f"{what}: reading at red needs a RedGrant, not {type(grant).__name__}")
    return grant


def raw_query(
    lake: Any, grant: RedGrant, sql: str, params: Mapping[str, Any] | None = None
) -> list[dict[str, Any]]:
    """``lake.query(sql, params)`` at ``red``, under ``grant``: the one raw read path for code
    outside this package."""
    _grant(grant, "raw_query")
    return lake.query(sql, params)


def raw_named(
    lake: Any, grant: RedGrant, name: str, params: Mapping[str, Any] | None = None
) -> list[dict[str, Any]]:
    """``lake.named(name, params)`` at ``red``, under ``grant`` (as :func:`raw_query`)."""
    _grant(grant, "raw_named")
    return lake.named(name, params)


def _ident(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


class CeilingReader:
    """``lake`` read as a reader with ``ceiling`` (a parsed :class:`~homelabnext.tlp.Label`).

    ``schemas`` maps a table name to its :class:`TableSchema` (``load_schemas()``).  A ``red``
    reader needs ``grant``, a :class:`RedGrant`; below ``red`` it is not taken.  A consumer gets
    its reader from :func:`reader_for`, which reads the ceiling from its declaration.
    """

    def __init__(
        self,
        lake: Any,
        ceiling: tlp.Label,
        schemas: Mapping[str, TableSchema],
        *,
        grant: RedGrant | None = None,
    ):
        if type(ceiling) is not tlp.Label:
            raise TypeError(f"ceiling must be a Label, not {type(ceiling).__name__}")
        if ceiling is tlp.Label.RED:
            _grant(grant, "a red reader")
        elif grant is not None:
            raise CeilingError(f"a {ceiling} reader takes no red grant")
        self._lake = lake
        self._ceiling = ceiling
        self._schemas = dict(schemas)

    @property
    def ceiling(self) -> tlp.Label:
        """The ceiling this reader reads at (fixed when it is made)."""
        return self._ceiling

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
        schema = self._table(table)
        known = set(schema.column_names)
        cols = list(columns) if columns is not None else list(schema.column_names)
        if not cols:
            raise CeilingError(f"{table}: select at least one column")
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

    def count_by(
        self,
        table: str,
        entity: str | None,
        values: Sequence[str],
        *,
        since: datetime,
        until: datetime,
        time_column: str = "time",
        where: Mapping[str, Any] | None = None,
        limit: int = MAX_LIMIT,
    ) -> list[GroupCount]:
        """Rows of ``table`` with ``since <= time_column < until`` at or below the ceiling,
        counted per (``entity``, ``values``, UTC day of ``time_column``, stored label).

        ``entity``, each of ``values``, ``time_column`` and each ``where`` key is a column path:
        a top-level column or a dotted path into a struct (``src_endpoint.ip``), checked against
        the table's schema.  A key is a scalar column that is not a timestamp; ``time_column`` is
        a timestamp.  A row whose entity or any value is null is not counted.  ``where`` values
        are bound parameters (equality only; ``None`` is refused, as ``= NULL`` matches nothing).
        The ceiling's row filter is applied in the query and every group's label is checked
        again, as :meth:`select` does.  More than ``limit`` groups raise :class:`TooManyGroups`:
        nothing is truncated.  Groups come back sorted by entity, values, day and label.

        ``entity=None`` with no ``values`` counts per day and label only (the table's history in
        the range, as this reader sees it); its groups have ``entity`` None and ``values`` ()."""
        schema = self._table(table)
        if type(values) not in (list, tuple):
            raise CeilingError(f"{table}: count_by values must be a list of column paths")
        if (entity is None) != (not values):
            raise CeilingError(
                f"{table}: count_by needs an entity and at least one value column (or neither)"
            )
        dialect = dialect_of(self._lake)
        paths = dict(iter_columns(schema.columns))

        def expr(path: object, types: tuple[str, ...], what: str) -> str:
            col: Column | None = paths.get(path) if type(path) is str else None
            if col is None:
                raise CeilingError(f"{table}: not its column: {path!r}")
            if col.type not in types:
                raise CeilingError(
                    f"{table}: {what} {path!r} is a {col.type}, not {'/'.join(types)}"
                )
            return field_expr(dialect, path.split("."))

        keys = [expr(k, KEY_TYPES, "key") for k in ([entity, *values] if values else [])]
        tcol = expr(time_column, ("timestamp",), "time column")
        for name, when in (("since", since), ("until", until)):
            if not isinstance(when, datetime) or when.utcoffset() is None:
                raise CeilingError(f"count_by: {name} must be a timezone-aware datetime")
        if until - since <= timedelta(0):
            raise CeilingError("count_by: until must be after since")
        if type(limit) is not int or not 1 <= limit <= MAX_GROUPS:
            raise CeilingError(f"count_by: limit must be 1..{MAX_GROUPS}")
        conds = [f"{tcol} >= :since", f"{tcol} < :until", *(f"{k} IS NOT NULL" for k in keys)]
        params: dict[str, Any] = {"since": since, "until": until}
        for i, (col, value) in enumerate((where or {}).items()):
            if value is None:
                raise CeilingError(f"{table}: where {col!r} is None (equality never matches null)")
            conds.append(f"{expr(col, SCALARS, 'where column')} = :w{i}")
            params[f"w{i}"] = value
        predicate = tlp.row_filter_sql(self.ceiling, LABEL_COLUMN) if schema.labelled else None
        if predicate:
            conds.append(predicate)
        group = [*keys, day_expr(dialect, tcol)]
        if schema.labelled:
            group.append(f'"{LABEL_COLUMN}"')
        names = (["k_entity"] if values else []) + [f"k_v{i}" for i in range(len(values))]
        names.append("k_day")
        names += ["k_tlp"] if schema.labelled else []
        sql = (
            "SELECT "
            + ", ".join(f"{e} AS {n}" for e, n in zip(group, names, strict=True))
            + f", count(*) AS k_n FROM {_ident(schema.name)} WHERE "
            + " AND ".join(conds)
            + " GROUP BY "
            + ", ".join(group)
            + " ORDER BY "
            + ", ".join(str(i) for i in range(1, len(group) + 1))
            + f" LIMIT {limit + 1}"
        )
        rows = self._lake.query(sql, params)
        if len(rows) > limit:
            raise TooManyGroups(
                f"{table}: more than {limit} groups for count_by({entity!r}, {list(values)!r});"
                " narrow the window, the filters or the values, or raise the limit"
            )
        out = []
        for r in rows:
            label = row_label({LABEL_COLUMN: r.get("k_tlp")}) if schema.labelled else tlp.Label.RED
            if not tlp.allows(self.ceiling, label):
                continue
            out.append(
                GroupCount(
                    r.get("k_entity"),
                    tuple(r[f"k_v{i}"] for i in range(len(values))),
                    _as_day(r["k_day"]),
                    label,
                    int(r["k_n"]),
                )
            )
        return sorted(out, key=_group_order)

    def _table(self, table: str) -> TableSchema:
        schema = self._schemas.get(table) if type(table) is str else None
        if schema is None:
            raise CeilingError(f"unknown table {table!r}")
        if not schema.labelled and self.ceiling is not tlp.Label.RED:
            raise CeilingError(f"{table}: has no {LABEL_COLUMN} column; only red reads it")
        return schema

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


def _as_day(value: Any) -> date:
    """A grouped day as a date: engines return a date (DuckDB, Trino) or its text (SQLite)."""
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    if isinstance(value, str):
        return date.fromisoformat(value[:10])
    raise LakeError(f"count_by: a day that is not a date: {value!r}")


def _group_order(g: GroupCount) -> tuple:
    """A total order over groups whatever the key types (``str`` sorts after numbers)."""

    def k(v: Any) -> tuple:
        return (isinstance(v, str), v if not isinstance(v, bool) else int(v))

    return (k(g.entity), tuple(k(v) for v in g.values), g.day, g.label.value)


def reader_for(
    lake: Any,
    reader: str,
    readers: Iterable[Mapping[str, Any]],
    schemas: Mapping[str, TableSchema],
) -> CeilingReader:
    """``lake`` read as ``reader`` (``profile:<id>``, ``module:<id>``, ...) at the ceiling its
    declaration in ``readers`` (the site's ``tlp_readers``) states.

    A reader with no declaration, one declared twice, or a ceiling that is not a canonical label
    is refused (:class:`CeilingError`): there is no default ceiling.  A reader declared ``red``
    reads under a :class:`RedGrant` made from its declaration (``why``, required)."""
    if type(reader) is not str or not reader:
        raise CeilingError(f"not a reader id: {reader!r}")
    found = [e for e in readers if isinstance(e, Mapping) and e.get("reader") == reader]
    if not found:
        raise CeilingError(f"{reader}: no declared TLP ceiling (tlp_readers), so it reads nothing")
    if len(found) > 1:
        raise CeilingError(f"{reader}: declared {len(found)} times in tlp_readers")
    (entry,) = found
    try:
        ceiling = tlp.parse_stored(entry.get("ceiling"))
    except ValueError:
        raise CeilingError(
            f"{reader}: ceiling {entry.get('ceiling')!r} is not a canonical TLP label"
        ) from None
    grant = None
    if ceiling is tlp.Label.RED:
        why = entry.get("why")
        if type(why) is not str or not why.strip():
            raise CeilingError(f"{reader}: a red reader's declaration needs a why")
        grant = RedGrant(reader, why)
    return CeilingReader(lake, ceiling, schemas, grant=grant)
