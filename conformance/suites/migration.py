# SPDX-License-Identifier: Apache-2.0
"""``migration`` (extended): a stateful slot exports a verifiable tree and its ``import_`` refuses
traversal, links, special files, strays and oversize trees, before changing anything."""

from __future__ import annotations

import contextlib
import hashlib
import os
import socket
import tempfile
from collections.abc import Callable, Iterator, Mapping
from pathlib import Path
from typing import Any

from conformance.fakes.migration_store import (
    FakeMigratable,
    FollowsLinks,
    IgnoresCallerLimits,
    ImportsUnlisted,
    TrustsPaths,
    WritesAsItReads,
)
from conformance.protocols.migration import ImportRefused, Limits
from homelabnext.conform.core import Mutant, Suite
from homelabnext.modules.importcheck import check_tree

from ._util import raises

SUITE = Suite(
    "migration",
    "a stateful slot's export is verifiable and its import refuses unsafe trees, atomically",
    "conformance.protocols.migration:Migratable",
    tier="extended",
)

BODY = {"a.txt": b"alpha\n", "b/c.txt": b"charlie\n"}


@contextlib.contextmanager
def _tmp() -> Iterator[Path]:
    # a short base: an AF_UNIX socket path must fit in 108 bytes
    base = "/tmp" if os.access("/tmp", os.W_OK | os.X_OK) else None
    with tempfile.TemporaryDirectory(prefix="hnx-mig-", dir=base) as d:
        yield Path(d)


def _entry(path: str, body: bytes) -> dict[str, Any]:
    return {"path": path, "size": len(body), "sha256": hashlib.sha256(body).hexdigest()}


def _manifest(m, entries: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "slot": m.slot,
        "format": m.export_formats[0],
        "files": entries,
        "totals": {"files": len(entries), "bytes": sum(e["size"] for e in entries)},
    }


def _tree(root: Path, files: Mapping[str, bytes]) -> None:
    for rel, body in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(body)


def _snapshot(m) -> list[dict[str, Any]]:
    with _tmp() as d:
        return m.export(d, m.export_formats[0])["files"]


def _refuses(
    m, what: str, plant: Callable[[Path], tuple[Path, dict[str, Any]]], limits=None
) -> None:
    before = _snapshot(m)
    with _tmp() as base:
        src, manifest = plant(base)
        raises(lambda: m.import_(src, manifest, limits), what, ImportRefused)
    assert _snapshot(m) == before, f"{what}: the refused import changed the data"


@SUITE.check("export-is-verifiable", "an export's tree matches its own manifest exactly")
def _(m):
    for fmt in m.export_formats:
        with _tmp() as d:
            manifest = m.export(d, fmt)
            assert manifest["slot"] == m.slot and manifest["format"] == fmt, manifest
            problems = check_tree(d, manifest, slot=m.slot, formats=m.export_formats)
            assert problems == [], problems


@SUITE.check("round-trip", "importing an export and exporting again gives the same files")
def _(m):
    with _tmp() as d:
        manifest = m.export(d, m.export_formats[0])
        assert m.import_(d, manifest) == len(manifest["files"])
    assert _snapshot(m) == manifest["files"]


@SUITE.check("refuses-traversal", "a manifest path with '..' is refused, even when the file exists")
def _(m):
    def plant(base):
        _tree(base / "tree", BODY)
        (base / "outside.txt").write_bytes(b"not yours\n")
        entries = [_entry(k, v) for k, v in BODY.items()] + [
            _entry("../outside.txt", b"not yours\n")
        ]
        return base / "tree", _manifest(m, entries)

    _refuses(m, "a '../' path", plant)


@SUITE.check("refuses-symlink", "a file that is a symbolic link is refused, never followed")
def _(m):
    def plant(base):
        _tree(base / "tree", BODY)
        (base / "secret").write_bytes(b"secret\n")
        os.symlink(base / "secret", base / "tree" / "s.txt")
        entries = [_entry(k, v) for k, v in BODY.items()] + [_entry("s.txt", b"secret\n")]
        return base / "tree", _manifest(m, entries)

    _refuses(m, "a symlinked file", plant)


@SUITE.check("refuses-symlinked-directory", "a directory that is a symbolic link is refused")
def _(m):
    def plant(base):
        _tree(base / "tree", BODY)
        _tree(base / "elsewhere", {"f.txt": b"elsewhere\n"})
        os.symlink(base / "elsewhere", base / "tree" / "d", target_is_directory=True)
        entries = [_entry(k, v) for k, v in BODY.items()] + [_entry("d/f.txt", b"elsewhere\n")]
        return base / "tree", _manifest(m, entries)

    _refuses(m, "a symlinked directory", plant)


@SUITE.check("refuses-symlinked-root", "a root that is a symbolic link is refused")
def _(m):
    def plant(base):
        _tree(base / "real", BODY)
        os.symlink(base / "real", base / "tree", target_is_directory=True)
        return base / "tree", _manifest(m, [_entry(k, v) for k, v in BODY.items()])

    _refuses(m, "a symlinked root", plant)


@SUITE.check("refuses-hard-link", "a file with a second hard link is refused")
def _(m):
    def plant(base):
        _tree(base / "tree", BODY)
        (base / "secret").write_bytes(b"secret\n")
        os.link(base / "secret", base / "tree" / "h.txt")
        entries = [_entry(k, v) for k, v in BODY.items()] + [_entry("h.txt", b"secret\n")]
        return base / "tree", _manifest(m, entries)

    _refuses(m, "a hard link", plant)


@SUITE.check("refuses-special-file", "a socket (or any non-regular file) in the tree is refused")
def _(m):
    holder: list[socket.socket] = []

    def plant(base):
        _tree(base / "tree", BODY)
        s = socket.socket(socket.AF_UNIX)
        s.bind(str(base / "tree" / "sock"))
        holder.append(s)
        entries = [_entry(k, v) for k, v in BODY.items()] + [_entry("sock", b"")]
        return base / "tree", _manifest(m, entries)

    try:
        _refuses(m, "a socket", plant)
    finally:
        for s in holder:
            s.close()


@SUITE.check("refuses-unlisted-file", "a file the manifest does not list is refused")
def _(m):
    def plant(base):
        _tree(base / "tree", {**BODY, "stray.txt": b"stray\n"})
        return base / "tree", _manifest(m, [_entry(k, v) for k, v in BODY.items()])

    _refuses(m, "an unlisted file", plant)


@SUITE.check("refuses-missing-file", "a listed file absent from the tree is refused")
def _(m):
    def plant(base):
        _tree(base / "tree", BODY)
        entries = [_entry(k, v) for k, v in BODY.items()] + [_entry("gone.txt", b"gone\n")]
        return base / "tree", _manifest(m, entries)

    _refuses(m, "a missing file", plant)


@SUITE.check("refuses-digest-mismatch", "a file whose sha256 differs from the manifest is refused")
def _(m):
    def plant(base):
        _tree(base / "tree", BODY)
        entries = [_entry(k, v) for k, v in BODY.items()]
        entries[0]["sha256"] = hashlib.sha256(b"something else").hexdigest()
        return base / "tree", _manifest(m, entries)

    _refuses(m, "a wrong sha256", plant)


@SUITE.check("refuses-over-caller-limits", "a tree over the caller's tighter limits is refused")
def _(m):
    def plant(base):
        files = {f"f{i}.txt": b"x\n" for i in range(4)}
        _tree(base / "tree", files)
        return base / "tree", _manifest(m, [_entry(k, v) for k, v in files.items()])

    _refuses(m, "four files with a limit of three", plant, Limits(max_files=3))


@SUITE.check(
    "refusal-changes-nothing",
    "a refusal found on the last file leaves the data exactly as it was (no partial import)",
)
def _(m):
    def plant(base):
        files = {"a.txt": b"alpha\n", "z.txt": b"zulu\n"}
        _tree(base / "tree", files)
        entries = [_entry(k, v) for k, v in files.items()]
        entries[-1]["sha256"] = hashlib.sha256(b"zuLU\n").hexdigest()  # same size, other bytes
        return base / "tree", _manifest(m, entries)

    _refuses(m, "a wrong sha256 on the last file", plant)


def make_fake():
    return FakeMigratable()


MUTANTS = {
    "follows-links": Mutant(FollowsLinks, "refuses-symlink", "reads a symlinked file's target"),
    "trusts-paths": Mutant(TrustsPaths, "refuses-traversal", "opens '../' paths as written"),
    "ignores-caller-limits": Mutant(
        IgnoresCallerLimits, "refuses-over-caller-limits", "applies only its own limits"
    ),
    "imports-unlisted": Mutant(
        ImportsUnlisted, "refuses-unlisted-file", "imports every file it finds"
    ),
    "writes-as-it-reads": Mutant(
        WritesAsItReads, "refusal-changes-nothing", "a late refusal leaves a partial import"
    ),
}
