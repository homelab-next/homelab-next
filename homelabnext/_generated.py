# SPDX-License-Identifier: Apache-2.0
"""Which output directories a generator may prune.

A generator that removes the files it no longer renders (orphans) must only ever do that in a
directory it owns, or ``--out docs`` would delete every tracked page it did not write.  A
directory is the generator's own when it is the generator's default path, when it holds a
:data:`MARKER` file naming that generator, or when it did not exist or was empty before this
run (the generator then writes the marker, so the next run may prune it too).  Any other
``--out`` is written to and never pruned.
"""

from __future__ import annotations

from pathlib import Path

__all__ = ["MARKER", "claim"]

#: the file a generator writes in a directory it owns, holding the generator's name
MARKER = ".hnx-generated"


def claim(out: Path, generator: str, default: Path) -> bool:
    """Create ``out`` and say whether ``generator`` may prune it (see the module doc)."""
    if out.resolve() == default.resolve():
        out.mkdir(parents=True, exist_ok=True)
        return True
    marker = out / MARKER
    if marker.is_file():
        return marker.read_text(encoding="utf-8").strip() == generator
    fresh = not out.exists() or (out.is_dir() and not any(out.iterdir()))
    out.mkdir(parents=True, exist_ok=True)
    if fresh:
        marker.write_text(f"{generator}\n", encoding="utf-8")
    return fresh
