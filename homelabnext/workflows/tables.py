# SPDX-License-Identifier: Apache-2.0
"""Lookup tables a workflow engine reads from a file: what a ``lookup`` step of a bound pack sees.

A binding declares each table it lets a ``lookup`` step read (``tables``: ``path``, ``format``, an
optional ``max_age_s`` and, for ``invariants-results``, ``keys``); the renderer pins the
declaration with the pack, and the run reads the file with :func:`read_table`.  Formats
(:data:`TABLE_FORMATS`):

* ``json-map``: a JSON object of rows (objects) by key;
* ``invariants-results``: the invariants runner's results document
  (:data:`INVARIANTS_RESULTS_SCHEMA`, ``hnx invariants run --out``); the row of each key of ``keys``
  is the verdict over its criteria (:func:`invariants_rows`).

It fails closed: anything but a readable, fresh, well-formed file of the declared format raises
:class:`TableError`, so a lookup that cannot read its table fails the run instead of reading as
"no row" (``found: false`` means only that a table that was read lacks the key).
"""

from __future__ import annotations

import json
import os
import stat
import time
from collections.abc import Callable, Mapping
from typing import Any

__all__ = [
    "INVARIANTS_RESULTS_SCHEMA",
    "INVARIANT_STATUSES",
    "TABLE_FORMATS",
    "TABLE_MAX_BYTES",
    "TABLE_OPS",
    "TableError",
    "invariants_rows",
    "read_table",
]

#: the enrich ops that read a declared table
TABLE_OPS = ("lookup",)
TABLE_FORMATS = ("json-map", "invariants-results")
#: a table file larger than this is refused unread (a watcher's table is a few KiB)
TABLE_MAX_BYTES = 1 << 20
INVARIANTS_RESULTS_SCHEMA = "homelabnext.invariants.results/1"


class TableError(ValueError):
    """A declared table could not be read as what it was declared to be: the run fails."""


#: what the invariants runner records per criterion; anything else reads as not ok
INVARIANT_STATUSES = ("pass", "fail", "error", "skip")
_SUMMARY_MAX = 300


def read_table(
    decl: Mapping[str, Any], *, clock: Callable[[], float] = time.time
) -> dict[str, dict[str, Any]]:
    """The rows of a table the binding declares, ``{key: row}``.  ``decl`` is its declaration:
    ``path`` (absolute, inside the action runner), ``format`` (:data:`TABLE_FORMATS`), optional
    ``max_age_s`` (the file's age bound) and, for ``invariants-results``, ``keys``.

    Fails closed: a table that cannot be opened, is not a regular file, is larger than
    :data:`TABLE_MAX_BYTES`, older than ``max_age_s``, not JSON or not of its declared format
    raises :class:`TableError`, so the run fails visibly instead of reading "no row"."""
    if not isinstance(decl, Mapping):
        raise TableError("the table declaration is not a mapping")
    fmt = decl.get("format")
    if fmt not in TABLE_FORMATS:
        raise TableError(f"unknown table format {fmt!r}")
    raw = decl.get("path")
    if (
        not isinstance(raw, str)
        or not raw.startswith("/")
        or any(part in ("", ".", "..") for part in raw.split("/")[1:])
    ):
        raise TableError(f"table path {raw!r} is not absolute and canonical")
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(raw, flags)
    except OSError as exc:
        raise TableError(f"{raw}: cannot be opened ({exc.__class__.__name__})") from None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise TableError(f"{raw}: not a regular file")
        with os.fdopen(fd, "rb") as fh:
            fd = -1  # the file object closes it now
            data = fh.read(TABLE_MAX_BYTES + 1)
    except OSError as exc:
        raise TableError(f"{raw}: cannot be read ({exc.__class__.__name__})") from None
    finally:
        if fd >= 0:
            os.close(fd)
    if len(data) > TABLE_MAX_BYTES:
        raise TableError(f"{raw}: larger than {TABLE_MAX_BYTES} bytes")
    max_age = decl.get("max_age_s")
    if max_age is not None and clock() - st.st_mtime > int(max_age):
        raise TableError(f"{raw}: older than {int(max_age)} s (its writer is not running)")
    try:
        doc = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise TableError(f"{raw}: not JSON") from None
    if fmt == "json-map":
        if not isinstance(doc, dict) or not all(isinstance(r, dict) for r in doc.values()):
            raise TableError(f"{raw}: not a JSON object of rows (objects) by key")
        return doc
    return invariants_rows(doc, decl.get("keys"), where=raw)


def invariants_rows(
    doc: Any, keys: Any, *, where: str = "the results document"
) -> dict[str, dict[str, Any]]:
    """The ``invariants-results`` rows: for each key the binding declares, the verdict over its
    criteria in the invariants runner's results document.  A row is ``ok`` only when every one of
    its criteria is ``pass``: a criterion that failed, could not be measured, was skipped or is
    missing from the document makes it not ok, and its ``summary`` names each one."""
    if (
        not isinstance(doc, dict)
        or doc.get("schema") != INVARIANTS_RESULTS_SCHEMA
        or not isinstance(doc.get("results"), dict)
    ):
        raise TableError(
            f"{where}: not an invariants results document ({INVARIANTS_RESULTS_SCHEMA})"
        )
    results = doc["results"]
    if not results:
        raise TableError(f"{where}: the results document holds no results")
    if not isinstance(keys, Mapping) or not keys:
        raise TableError(f"{where}: an invariants-results table needs its keys (key -> criteria)")
    rows: dict[str, dict[str, Any]] = {}
    for key, ids in keys.items():
        if not isinstance(ids, list) or not ids or not all(isinstance(i, str) for i in ids):
            raise TableError(f"{where}: key {key!r} names no criteria")
        criteria: dict[str, str] = {}
        for cid in ids:
            res = results.get(cid)
            got = res.get("status") if isinstance(res, dict) else None
            if res is None:
                criteria[cid] = "missing"
            else:
                criteria[cid] = got if got in INVARIANT_STATUSES else "unrecognised"
        red = [c for c, s in criteria.items() if s != "pass"]
        text = (
            ", ".join(f"{c} {criteria[c]}" for c in red) if red else f"{', '.join(criteria)} pass"
        )
        rows[str(key)] = {
            "ok": not red,
            "criteria": criteria,
            "red": red,
            "summary": f"{key}: {text}"[:_SUMMARY_MAX],
        }
    return rows
