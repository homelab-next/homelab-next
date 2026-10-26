# SPDX-License-Identifier: Apache-2.0
"""In-memory stateful slot (``migration`` fake) and its import defects.

The fake holds ``{path: bytes}``, exports it as a plain tree and imports through
:func:`homelabnext.modules.importcheck.read_tree` (all or nothing).  Each defective subclass
replaces that read with a hand-rolled one that skips exactly one part of the MUST and keeps the
rest (every file it reads is still held to its manifest digest), so the suite catches it with the
one check that names the defect.
"""

from __future__ import annotations

import hashlib
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
        staged = dict(self._read(Path(src), manifest, self.limits.tighten(limits)))
        self._data = staged  # only after every file was read and verified
        return len(staged)


def _checked(problems: list[str], skip) -> None:
    kept = [p for p in problems if not skip(p)]
    if kept:
        raise ImportRefused(kept)


def _naive(src: Path, manifest: Mapping[str, Any]) -> Iterator[tuple[str, bytes]]:
    """Plain ``open`` (follows links, takes any path), but each file still held to its digest."""
    for f in manifest["files"]:
        with open(os.path.join(src, f["path"]), "rb") as fh:
            body = fh.read()
        if hashlib.sha256(body).hexdigest() != f["sha256"]:
            raise ImportRefused([f"{f['path']!r} does not match its sha256"])
        yield f["path"], body


class FollowsLinks(FakeMigratable):
    """Checks everything except whether an entry inside the tree is a link, then uses ``open``."""

    def _read(self, src, manifest, limits):
        problems = check_tree(src, manifest, limits, slot=self.slot, formats=self.export_formats)
        _checked(problems, lambda p: p.endswith(" is a symbolic link"))
        return _naive(src, manifest)


class TrustsPaths(FakeMigratable):
    """Checks everything except the manifest's paths, then opens them as written."""

    def _read(self, src, manifest, limits):
        problems = check_tree(src, manifest, limits, slot=self.slot, formats=self.export_formats)
        _checked(problems, lambda p: "'..'" in p)
        return _naive(src, manifest)


class IgnoresCallerLimits(FakeMigratable):
    """Applies only its own limits, never the caller's tighter ones."""

    def _read(self, src, manifest, limits):
        return super()._read(src, manifest, self.limits)


class ImportsUnlisted(FakeMigratable):
    """Checks the listed files, but imports every regular file it finds."""

    def _read(self, src, manifest, limits):
        problems = check_tree(src, manifest, limits, slot=self.slot, formats=self.export_formats)
        _checked(problems, lambda p: p.endswith(" is not in the manifest"))
        listed = {f["path"]: f["sha256"] for f in manifest["files"]}
        out = []
        for top, _dirs, names in os.walk(src):
            for n in sorted(names):
                full = os.path.join(top, n)
                rel = os.path.relpath(full, src).replace(os.sep, "/")
                with open(full, "rb") as fh:
                    body = fh.read()
                if rel in listed and hashlib.sha256(body).hexdigest() != listed[rel]:
                    raise ImportRefused([f"{rel!r} does not match its sha256"])
                out.append((rel, body))
        return iter(out)


class WritesAsItReads(FakeMigratable):
    """Writes each verified file straight into its live data, so a later refusal leaves half."""

    def import_(self, src, manifest, limits=None):
        n = 0
        for rel, body in self._read(Path(src), manifest, self.limits.tighten(limits)):
            self._data[rel] = body
            n += 1
        return n
