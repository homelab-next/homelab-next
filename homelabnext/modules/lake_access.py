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
  and delete, never update: an update could rewrite a stored label;
* ``queries``: everyone may run queries; seeing or stopping another's is not granted.

A principal can match several rules (a user in a group), and the first match wins, so rules are
ordered so the most restrictive applies: user rules (``profile:``, ``module:``, ``user:``) before
group rules, each tier by ascending ceiling, then by reader id.  A ``profile:``, ``module:`` or
``user:`` reader is the engine user whose name is the whole reader id (``user:alice`` signs in as
``user:alice``); a ``group:`` reader is the engine group of the part after the colon.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from homelabnext import tlp

__all__ = ["FILE", "KINDS", "LakeAccessError", "render", "write"]

FILE = "lake-access.json"
#: reader kinds whose rule names an engine user, and the one that names an engine group
USER_KINDS = ("profile", "module", "user")
KINDS = (*USER_KINDS, "group")
READER_RE = re.compile(r"(profile|module|user|group):[a-z0-9][a-z0-9._-]{0,62}")
CATALOG_RE = re.compile(r"[a-z][a-z0-9_]{0,62}")
READ = ["SELECT"]
WRITE = ["SELECT", "INSERT", "DELETE"]


class LakeAccessError(ValueError):
    """The selection's TLP readers cannot be turned into access rules."""


def _reader(entry: Any) -> tuple[str, str, tlp.Label, bool]:
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
    return reader, reader.split(":", 1)[0], label, write


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
    # the most restrictive rule a principal matches comes first
    parsed.sort(key=lambda p: (p[1] == "group", p[2].rank, p[0]))
    cat = f"^{re.escape(catalog)}$"
    catalogs, tables = [], []
    for reader, kind, label, write in parsed:
        who = _who(reader, kind)
        catalogs.append({**who, "catalog": cat, "allow": "all" if write else "read-only"})
        tables.append(
            {**who, "catalog": cat, "schema": "^information_schema$", "privileges": ["SELECT"]}
        )
        rule: dict[str, Any] = {**who, "catalog": cat, "schema": ".*", "table": ".*"}
        rule["privileges"] = WRITE if write else READ
        predicate = tlp.row_filter_sql(label)
        if predicate is not None:
            rule["filter"] = predicate
        tables.append(rule)
    catalogs.append({"catalog": ".*", "allow": "none"})
    return {
        "catalogs": catalogs,
        "schemas": [{"owner": False}],
        "tables": tables,
        "queries": [{"allow": ["execute"]}],
    }


def write(doc: dict[str, Any], out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    (out / FILE).write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
