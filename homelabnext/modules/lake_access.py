# SPDX-License-Identifier: Apache-2.0
"""``lake-access.json``: the query engine's row filters from the selection's TLP readers.

ADR-0033 decision 6: a reader receives only rows at or below its ceiling, and the filter is the
engine's, not each reader's.  ``hnx modules render`` writes this file from the selection's
``tlp_readers`` in the query engine's file-based access control form (a ``tables`` list, first
match wins): every reader below ``red`` reads every table with the row filter
:func:`homelabnext.tlp.row_filter_sql` (a table without a ``tlp`` column fails the query, so it is
not readable below ``red``); a ``red`` reader reads every row; a writer also inserts and deletes.
A principal no rule names matches nothing and reads nothing.  ``profile:``, ``module:`` and
``user:`` readers are the engine user of that exact name; ``group:`` readers are its group.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from homelabnext import tlp

__all__ = ["FILE", "LakeAccessError", "render", "write"]

FILE = "lake-access.json"
READ = ["SELECT"]
WRITE = ["SELECT", "INSERT", "DELETE", "UPDATE"]


class LakeAccessError(ValueError):
    """The selection's TLP readers cannot be turned into access rules."""


def _rule(entry: dict[str, Any]) -> dict[str, Any]:
    reader = entry.get("reader")
    if type(reader) is not str or ":" not in reader:
        raise LakeAccessError(f"tlp_readers: {reader!r} is not a reader id")
    kind, name = reader.split(":", 1)
    ceiling = tlp.parse(entry.get("ceiling"))
    if entry.get("write") is True and ceiling is not tlp.Label.RED:
        raise LakeAccessError(f"tlp_readers: {reader} writes rows, so its ceiling is red")
    rule: dict[str, Any] = {
        "group"
        if kind == "group"
        else "user": f"^{re.escape(name if kind == 'group' else reader)}$"
    }
    rule.update({"catalog": ".*", "schema": ".*", "table": ".*"})
    rule["privileges"] = WRITE if entry.get("write") is True else READ
    predicate = tlp.row_filter_sql(ceiling)
    if predicate is not None:
        rule["filter"] = predicate
    return rule


def render(site: dict[str, Any]) -> dict[str, Any] | None:
    """The access rules for ``site``'s ``tlp_readers``, or None when it declares none."""
    if "tlp_readers" not in site:
        return None
    readers = site.get("tlp_readers") or []
    if not isinstance(readers, list):
        raise LakeAccessError("tlp_readers is not a list")
    try:
        tables = [_rule(e) for e in readers]
    except (ValueError, TypeError, AttributeError) as exc:
        raise LakeAccessError(str(exc)) from None
    # anything else, the information schema included, is denied: no rule matches it
    return {"tables": tables}


def write(doc: dict[str, Any], out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    (out / FILE).write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
