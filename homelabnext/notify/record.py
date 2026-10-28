# SPDX-License-Identifier: Apache-2.0
"""The record of the pairs a running notifier holds, for the module census.

A process that owns a :class:`~homelabnext.notify.core.Notifier` (``hnx broker serve`` and ``hnx
status collect``) can be given a :class:`PairsRecord`: the notifier then writes every pair it
holds, at construction and after each registration, to one file named for its owner
(``<dir>/<owner>.json``, :data:`OWNERS`), replacing the whole file each time, so the file is what
this process registered and never a leftover of an earlier one.  The ``module_census`` role reads
the files at the fixed directory :data:`RECORD_DIR` and ``hnx modules gather`` turns them into the
inventory's ``notify_pairs`` (docs/modules.md, "What the census measures").

The document is ``{"schema_version": 1, "owner": <owner>, "pairs": [{"problem", "recovery",
"module"?}, ...]}``, the pairs sorted by problem title.  ``module`` is present only when the
registrant named the module the pair came from (``register_pair(..., module=...)``); the
notifier never guesses one, and a pair without it is the core's.

The file is written with :func:`homelabnext.state.store.atomic_write_text` under the store's
:func:`~homelabnext.state.store.file_lock`, mode ``0644``: titles are not secrets, and the census
reads it as the deploy's unprivileged user.  **Trust:** the file is the owning service's word
about its own pairs, as a host's ``systemctl`` output is about its units; a service (or a root)
that lies about them is believed, and nothing read from the host can rule that out.
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from homelabnext.schemas.module_manifest import TITLE_PATTERN
from homelabnext.state.store import atomic_write_text, file_lock

#: where the census looks: one file per owner, never a glob
RECORD_DIR = "/var/lib/homelabnext/notify-pairs"
#: the processes that own a notifier, each its own file (``<owner>.json``)
OWNERS = ("broker", "status")
SCHEMA_VERSION = 1
RECORD_MODE = 0o644
MAX_PAIRS = 256
MAX_BYTES = 256 * 1024
_TITLE = re.compile(TITLE_PATTERN.removeprefix("^").removesuffix("$(?!\\n)"))
#: a module id (``platform/module_inventory`` ``$defs.name``)
_MODULE = re.compile(r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*")


class RecordError(ValueError):
    """A pairs record that cannot be read."""


def _title(value: Any) -> bool:
    return isinstance(value, str) and 0 < len(value) <= 160 and bool(_TITLE.fullmatch(value))


class PairsRecord:
    """Where one notifier owner writes the pairs it holds (see the module)."""

    def __init__(self, directory: str | os.PathLike, owner: str) -> None:
        if owner not in OWNERS:
            raise ValueError(f"notify pairs record: owner is one of {', '.join(OWNERS)}")
        d = Path(directory)
        if d.is_symlink() or not d.is_dir():
            raise ValueError(f"notify pairs record: {d} is not a directory")
        self.owner = owner
        self.path = d / f"{owner}.json"

    def write(self, pairs: Mapping[str, tuple[str, str | None]]) -> None:
        """Replace the record with ``pairs`` (problem title -> (recovery title, module or None))."""
        rows = []
        for problem in sorted(pairs):
            recovery, module = pairs[problem]
            row = {"problem": problem, "recovery": recovery}
            if module is not None:
                row["module"] = module
            rows.append(row)
        doc = {"schema_version": SCHEMA_VERSION, "owner": self.owner, "pairs": rows}
        with file_lock(self.path.with_name(f"{self.path.name}.lock")):
            atomic_write_text(self.path, json.dumps(doc, indent=1) + "\n", mode=RECORD_MODE)


def record_in(directory: str | os.PathLike | None, owner: str) -> PairsRecord | None:
    """The record of ``owner`` in ``directory`` (``--notify-pairs-dir``), or None without one."""
    return PairsRecord(directory, owner) if directory else None


def parse_record(text: str, owner: str) -> list[dict[str, str]]:
    """The pairs of one record, read strictly: anything off the shape is :class:`RecordError`."""
    if len(text.encode("utf-8")) > MAX_BYTES:
        raise RecordError(f"{owner}: over {MAX_BYTES} bytes")
    try:
        doc = json.loads(text)
    except ValueError:
        raise RecordError(f"{owner}: not JSON") from None
    if not isinstance(doc, dict) or set(doc) != {"schema_version", "owner", "pairs"}:
        raise RecordError(f"{owner}: not {{schema_version, owner, pairs}}")
    if doc["schema_version"] != SCHEMA_VERSION or isinstance(doc["schema_version"], bool):
        raise RecordError(f"{owner}: schema_version is not {SCHEMA_VERSION}")
    if doc["owner"] != owner:
        raise RecordError(f"{owner}: written for another owner")
    pairs = doc["pairs"]
    if not isinstance(pairs, list) or len(pairs) > MAX_PAIRS:
        raise RecordError(f"{owner}: pairs is not a list of at most {MAX_PAIRS}")
    out: list[dict[str, str]] = []
    seen: set[str] = set()
    for i, p in enumerate(pairs, 1):
        if not isinstance(p, dict) or not (
            set(p) == {"problem", "recovery"} or set(p) == {"problem", "recovery", "module"}
        ):
            raise RecordError(f"{owner}: pair {i} is not {{problem, recovery, module?}}")
        if not _title(p["problem"]) or not _title(p["recovery"]):
            raise RecordError(f"{owner}: pair {i} has a title that is not one line of text")
        if "module" in p and not (
            isinstance(p["module"], str)
            and len(p["module"]) <= 64
            and _MODULE.fullmatch(p["module"])
        ):
            raise RecordError(f"{owner}: pair {i} names a module that is not a module id")
        if p["problem"] in seen:
            raise RecordError(f"{owner}: pair {i} repeats a problem title")
        seen.add(p["problem"])
        out.append(dict(p))
    return out
