# SPDX-License-Identifier: Apache-2.0
"""``lake-access.json``: the query engine's row filters from the selection's TLP readers.

ADR-0033 decision 6: a reader receives only rows at or below its ceiling, and the filter is the
engine's, not each reader's.  ``hnx modules render`` writes this file from the selection's
``tlp_readers`` and ``lake_catalog`` in the query engine's file-based access control form, where
the first matching rule wins and a principal no rule matches is denied:

* ``catalogs``: each reader reaches the lake catalog only (read-only, a writer all), and every
  other catalog, the engine's own system catalog included, is ``none`` for everyone;
* ``schemas``: nobody owns a schema through these rules, so no reader creates, drops or renames
  one (schema changes run under the lake's own administrator, outside this file);
* ``tables``: per reader, its catalog's ``information_schema`` (metadata, which the engine
  already narrows to what the reader may see), then every table with the row filter
  :func:`homelabnext.tlp.row_filter_sql` below ``red`` (a table without a ``tlp`` column fails
  the query, so it is not readable below ``red``) and no filter at ``red``.  A writer may insert
  and delete, never update: an update could rewrite a stored label.  An ``analyzer:`` reader
  with ``writes`` (ADR-0036, amending ADR-0033 decision 6) gets, before its ``.*`` rule, a rule
  per named table with ``SELECT`` and ``INSERT`` only and its own row filter: it appends its
  derived rows at any ceiling, only to a declared analyzer-output table
  (:data:`ANALYZER_TABLES`) in the core's namespace.  The engine applies the row filter to an
  insert, so it refuses a row labelled above the analyzer's ceiling; it cannot see a label set
  lower than the row's inputs, so the analyzer's code labels each row with the strictest input it
  read;
* ``procedures``: no ``CALL`` procedure for anyone.  A table procedure (``ALTER TABLE ...
  EXECUTE``) is not a procedure rule's business: file-based access control's own check allows
  one, and it is the query engine that refuses it on a table with a row filter.  Every rule
  below ``red`` carries one, so a reader below ``red`` cannot run one; that is why an analyzer
  with ``writes`` must be below ``red``.  A ``red`` reader's rule has no filter (an open point of
  ADR-0033, not of this file);
* ``queries``: everyone may run queries; seeing or stopping another's is not granted.

A principal can match several rules (a user in a group), and the first match wins.  Rules are
ordered user rules (``profile:``, ``module:``, ``analyzer:``, ``user:``) before group rules, each
tier by ascending ceiling, then by reader id, whatever order the list was written in: among groups the
most restrictive applies, but a principal with an entry of its own is judged by that entry, even
when it is also in a group with a stricter ceiling (group membership is the engine's, not known
here), so its own entry must carry the ceiling it should have (docs/modules.md says the same).
A ``profile:``, ``module:``, ``analyzer:`` or ``user:`` reader is the engine user whose name is
the whole reader id (``user:alice`` signs in as ``user:alice``); a ``group:`` reader is the engine
group of the part after the colon.  The set of analyzers is open (any ``analyzer:<name>``), like
the other kinds: what an id may do is only what its entry here grants.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from homelabnext import tlp
from homelabnext.lake.tables import CORE_NAMESPACE

__all__ = ["FILE", "KINDS", "LakeAccessError", "render", "write"]

FILE = "lake-access.json"
#: reader kinds whose rule names an engine user, and the one that names an engine group
USER_KINDS = ("profile", "module", "analyzer", "user")
KINDS = (*USER_KINDS, "group")
READER_RE = re.compile(r"(profile|module|analyzer|user|group):[a-z0-9][a-z0-9._-]{0,62}")
CATALOG_RE = re.compile(r"[a-z][a-z0-9_]{0,62}")
TABLE_RE = re.compile(r"[a-z][a-z0-9_]{0,62}")
READ = ["SELECT"]
WRITE = ["SELECT", "INSERT", "DELETE"]
#: an analyzer's table-scoped grant (ADR-0036): it appends its own rows, never deletes or updates
APPEND = ["SELECT", "INSERT"]
#: the tables an analyzer may append to: the declared analyzer-output tables, all in the core's
#: namespace (a new analyzer table joins this list, the schema's enum and its ADR together)
ANALYZER_TABLES = ("novelty_finding",)


class LakeAccessError(ValueError):
    """The selection's TLP readers cannot be turned into access rules."""


def _reader(entry: Any) -> tuple[str, str, tlp.Label, bool, tuple[str, ...]]:
    if not isinstance(entry, dict):
        raise LakeAccessError("tlp_readers: an entry is not a mapping")
    reader = entry.get("reader")
    if type(reader) is not str or READER_RE.fullmatch(reader) is None:
        raise LakeAccessError(f"tlp_readers: {reader!r} is not a reader id")
    ceiling = entry.get("ceiling")
    if type(ceiling) is not str or ceiling not in tlp.LABELS:
        raise LakeAccessError(f"tlp_readers: {reader}: ceiling {ceiling!r} is not a TLP label")
    label = tlp.parse(ceiling)
    write = entry.get("write") is True
    if write and label is not tlp.Label.RED:
        raise LakeAccessError(f"tlp_readers: {reader} writes rows, so its ceiling is red")
    kind = reader.split(":", 1)[0]
    if "writes" not in entry:  # present but null is refused below, as the schema refuses it
        return reader, kind, label, write, ()
    writes = entry["writes"]
    if kind != "analyzer":
        raise LakeAccessError(f"tlp_readers: {reader}: only an analyzer: reader has writes")
    if write:
        raise LakeAccessError(f"tlp_readers: {reader}: writes and write: true together")
    if label is tlp.Label.RED:
        raise LakeAccessError(
            f"tlp_readers: {reader}: writes at a red ceiling (its table rule would carry no row "
            "filter, so nothing would refuse a table procedure on it)"
        )
    if (
        not isinstance(writes, list)
        or not writes
        or len(set(writes)) != len(writes)
        or not all(type(t) is str and TABLE_RE.fullmatch(t) for t in writes)
    ):
        raise LakeAccessError(f"tlp_readers: {reader}: writes is a list of distinct table names")
    other = sorted(set(writes) - set(ANALYZER_TABLES))
    if other:
        raise LakeAccessError(
            f"tlp_readers: {reader}: writes {other}: not an analyzer-output table "
            f"({', '.join(ANALYZER_TABLES)})"
        )
    return reader, kind, label, write, tuple(sorted(writes))


def _who(reader: str, kind: str) -> dict[str, str]:
    if kind == "group":
        return {"group": f"^{re.escape(reader.split(':', 1)[1])}$"}
    return {"user": f"^{re.escape(reader)}$"}


def render(site: dict[str, Any]) -> dict[str, Any] | None:
    """The access rules for ``site``'s ``tlp_readers``, or None when it declares none."""
    if "tlp_readers" not in site:
        return None
    readers = site.get("tlp_readers")
    if not isinstance(readers, list):
        raise LakeAccessError("tlp_readers is not a list")
    catalog = site.get("lake_catalog")
    if type(catalog) is not str or CATALOG_RE.fullmatch(catalog) is None:
        raise LakeAccessError(
            "tlp_readers needs lake_catalog, the query engine's name for the lake catalog"
        )
    parsed = [_reader(e) for e in readers]
    seen: set[str] = set()
    for reader, *_ in parsed:
        if reader in seen:
            raise LakeAccessError(f"tlp_readers: {reader} is listed twice")
        seen.add(reader)
    # a principal's own entry first, then groups, each from the lowest ceiling up
    parsed.sort(key=lambda p: (p[1] == "group", p[2].rank, p[0]))
    cat = f"^{re.escape(catalog)}$"
    catalogs, tables = [], []
    for reader, kind, label, write, writes in parsed:
        who = _who(reader, kind)
        allow = "all" if write or writes else "read-only"
        catalogs.append({**who, "catalog": cat, "allow": allow})
        tables.append(
            {**who, "catalog": cat, "schema": "^information_schema$", "privileges": ["SELECT"]}
        )
        predicate = tlp.row_filter_sql(label)
        # an analyzer's own tables first (first match wins): append, read at its ceiling
        for table in writes:
            own: dict[str, Any] = {**who, "catalog": cat, "schema": f"^{CORE_NAMESPACE}$"}
            own.update(table=f"^{re.escape(table)}$", privileges=APPEND)
            if predicate is not None:
                own["filter"] = predicate
            tables.append(own)
        rule: dict[str, Any] = {**who, "catalog": cat, "schema": ".*", "table": ".*"}
        rule["privileges"] = WRITE if write else READ
        if predicate is not None:
            rule["filter"] = predicate
        tables.append(rule)
    catalogs.append({"catalog": ".*", "allow": "none"})
    return {
        "catalogs": catalogs,
        "schemas": [{"owner": False}],
        "tables": tables,
        # no CALL procedure for anyone (table procedures: refused by the row filters above)
        "procedures": [{"procedure": ".*", "privileges": []}],
        "queries": [{"allow": ["execute"]}],
    }


def write(doc: dict[str, Any], out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    (out / FILE).write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
