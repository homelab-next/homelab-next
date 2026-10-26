# SPDX-License-Identifier: Apache-2.0
"""In-memory stateful slot (``migration`` fake) and its import defects.

The fake holds ``{path: bytes}``, exports it as a plain tree and imports through
:func:`homelabnext.modules.importcheck.iter_tree`.  Each defective subclass replaces that read with
a hand-rolled one that skips exactly one part of the MUST.
"""

from __future__ import annotations

import os
from collections.abc import Iterator, Mapping
from pathlib import Path
from typing import Any

from homelabnext.modules.importcheck import (
    ImportRefused,
    Limits,
    build_manifest,
    check_tree,
    iter_tree,
)

SEED = {"records/one.md": b"# one\n", "records/two.md": b"# two\n", "index.json": b"{}\n"}


def tighter(own: Limits, asked: Limits | None) -> Limits:
    if asked is None:
        return own
    return Limits(**{k: min(getattr(own, k), getattr(asked, k)) for k in own.__dataclass_fields__})


class FakeMigratable:
    features = frozenset()

    def __init__(
        self, slot: str = "records", export_formats: tuple[str, ...] = ("markdown-tree",)
    ) -> None:
        self.slot = slot
        self.export_formats = tuple(export_formats)
        self.limits = Limits(max_files=1000, max_bytes=1 << 20, max_file_bytes=1 << 16)
        self._data: dict[str, bytes] = dict(SEED)

    def export(self, dest: Path, fmt: str) -> dict[str, Any]:
        if fmt not in self.export_formats:
            raise ValueError(f"{self.slot} does not export {fmt!r}")
        dest = Path(dest)
        if any(dest.iterdir()):
            raise ValueError("export needs an empty directory")
        for rel, body in sorted(self._data.items()):
            p = dest / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(body)
        return build_manifest(dest, self.slot, fmt, self.limits)

    def _read(
        self, src: Path, manifest: Mapping[str, Any], limits: Limits
    ) -> Iterator[tuple[str, bytes]]:
        return iter_tree(src, manifest, limits, slot=self.slot, formats=self.export_formats)

    def import_(self, src: Path, manifest: Mapping[str, Any], limits: Limits | None = None) -> int:
        staged = dict(self._read(Path(src), manifest, tighter(self.limits, limits)))
        self._data = staged  # only after every file was read and verified
        return len(staged)


def _naive(src: Path, manifest: Mapping[str, Any]) -> Iterator[tuple[str, bytes]]:
    for f in manifest["files"]:
        with open(os.path.join(src, f["path"]), "rb") as fh:
            yield f["path"], fh.read()


class FollowsLinks(FakeMigratable):
    """Checks everything except the kind of each entry, then reads with ``open``."""

    def _read(self, src, manifest, limits):
        problems = [
            p
            for p in check_tree(src, manifest, limits, slot=self.slot, formats=self.export_formats)
            if "symbolic link" not in p
        ]
        if problems:
            raise ImportRefused(problems)
        return _naive(src, manifest)


class TrustsPaths(FakeMigratable):
    """Reads the manifest's paths as given: no tree check at all."""

    def _read(self, src, manifest, limits):
        return _naive(src, manifest)


class IgnoresCallerLimits(FakeMigratable):
    """Applies only its own limits, never the caller's tighter ones."""

    def _read(self, src, manifest, limits):
        return super()._read(src, manifest, self.limits)


class ImportsUnlisted(FakeMigratable):
    """Checks the listed files, but imports every regular file it finds."""

    def _read(self, src, manifest, limits):
        problems = [
            p
            for p in check_tree(src, manifest, limits, slot=self.slot, formats=self.export_formats)
            if "not in the manifest" not in p
        ]
        if problems:
            raise ImportRefused(problems)
        for top, _dirs, names in os.walk(src):
            for n in sorted(names):
                full = os.path.join(top, n)
                with open(full, "rb") as fh:
                    yield os.path.relpath(full, src).replace(os.sep, "/"), fh.read()


class WritesAsItReads(FakeMigratable):
    """Writes each verified file straight into its live data, so a later refusal leaves half."""

    def import_(self, src, manifest, limits=None):
        n = 0
        for rel, body in self._read(Path(src), manifest, tighter(self.limits, limits)):
            self._data[rel] = body
            n += 1
        return n
