# SPDX-License-Identifier: Apache-2.0
"""Contract for ``migration`` (extended suite): a stateful slot's export and validated import.

Every stateful slot in the slot registry (``examples/modules/slots.yml``, ``stateful: true``)
moves its data across a swap as a directory tree in one of its ``export_formats`` plus an export
manifest (draft schema ``platform/export_manifest`` 1.0).  ``export`` writes both; ``import_``
reads a tree somebody else wrote, so it is held to the import MUST (ADR-0027 follow-up 7,
docs/modules.md, "Import validation"):

* it refuses, by raising :class:`ImportRefused`, a manifest path that traverses (``..``, absolute,
  backslash, control character, a repeat), a symbolic link or special file anywhere in the tree, a
  file with more than one link, a file missing from the tree or the manifest, a size or sha256 that
  differs from the manifest, and a tree over the limits (its own, or the stricter ``limits`` the
  caller passes);
* it refuses **before it changes anything**: after a refusal an export is what it was before;
* it never follows a link while reading, even one that appears after its check.

:mod:`homelabnext.modules.importcheck` implements the checks.  An adapter meets the MUST when
it reads through it **and stages before it applies**: ``copy_tree`` (a verified copy that appears
whole or not at all) or ``read_tree`` (in memory), then parses the staged files in its own format;
``iter_tree`` streams, so applying its files as they come leaves a partial import on a late
refusal.  Callers' ``limits`` are combined with the adapter's own by ``Limits.tighten``.  The
format-specific parse (a zone file, parquet) is the slot's own suite.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from homelabnext.modules.importcheck import ImportRefused, Limits

__all__ = ["ImportRefused", "Limits", "Migratable"]


@runtime_checkable
class Migratable(Protocol):
    slot: str
    export_formats: tuple[str, ...]

    def export(self, dest: Path, fmt: str) -> dict[str, Any]:
        """Write the slot's data into the empty directory ``dest`` in ``fmt`` (one of
        ``export_formats``) and return its manifest."""

    def import_(self, src: Path, manifest: Mapping[str, Any], limits: Limits | None = None) -> int:
        """Import the tree at ``src`` against ``manifest`` and return the number of files read.
        ``limits``, when given, tightens the importer's own.  Raises ImportRefused, having changed
        nothing."""
