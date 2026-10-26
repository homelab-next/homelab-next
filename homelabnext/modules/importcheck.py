# SPDX-License-Identifier: Apache-2.0
"""Import validation for a stateful slot's ``import_`` (ADR-0027 follow-up 7; docs/modules.md,
"Import validation").

An export is a directory tree plus an **export manifest** (draft schema
``platform/export_manifest`` 1.0): every file's relative path, size and sha256, and the totals.
An importer reads a tree somebody else wrote (the outgoing provider, possibly compromised, or an
operator's copy of it), so it trusts nothing in it.  The MUST every ``import_`` meets:

* **no traversal**: a manifest path is relative, POSIX, normalised and never names ``..``, an
  absolute path, a backslash, a control character or the same file twice (case-insensitively);
* **no links, special files or other filesystems**: the tree holds directories and regular files
  only, each file with one link, all on the root's filesystem and with no mount point inside it; a
  symbolic link anywhere (the root included) refuses the whole import;
* **exactly the manifest**: no file is missing, none is extra, and each one's size and sha256 are
  the manifest's;
* **within limits**: the manifest's totals are its files' sums, and the file count, the total and
  per-file bytes, the path length and the depth are within the importer's :class:`Limits`.

Everything goes through one descriptor of the root opened with ``O_NOFOLLOW``: the walk opens each
directory from its parent's descriptor and checks it is the entry it just examined, and each file
is opened the same way and re-checked on its open descriptor (type, link count, filesystem, size,
digest), so a tree changed between the check and the read (a file or directory swapped for a link)
is refused, not followed.  :func:`check_tree` names the problems (at most :data:`MAX_PROBLEMS`)
without reading content; :func:`copy_tree` streams a verified tree into a new directory and is
the one to use for large trees; :func:`iter_tree` and :func:`read_tree` hand the bytes over in
memory.  :func:`build_manifest` is the export side.  The manifest is the outgoing provider's own
claim: this proves the tree is safe to read and is what the manifest says, not where it came from.
Linux only (the lab's hosts are Linux; the mount-point check reads ``/proc/self/mountinfo``).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import tempfile
import unicodedata
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

__all__ = [
    "DEFAULT_LIMITS",
    "MANIFEST_VERSION",
    "MAX_DEPTH",
    "MAX_PROBLEMS",
    "ImportRefused",
    "Limits",
    "build_manifest",
    "check_manifest",
    "check_tree",
    "copy_tree",
    "iter_tree",
    "manifest_sha256",
    "read_tree",
]

MANIFEST_VERSION = "1.0"
#: a refusal names at most this many problems, then how many more there were
MAX_PROBLEMS = 100
#: the deepest tree any Limits may allow (the walk recurses once per level)
MAX_DEPTH = 256
_HEX = frozenset("0123456789abcdef")
_CHUNK = 1 << 20
#: where the mount table is read (a module attribute so tests can point it at a fixture)
MOUNTINFO = "/proc/self/mountinfo"
_DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_FILE = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC


class ImportRefused(Exception):
    """The tree or its manifest breaks the import MUST.  ``problems`` lists the reasons (at most
    :data:`MAX_PROBLEMS`, then a count of the rest); the message never carries file content."""

    def __init__(self, problems: list[str]) -> None:
        self.problems = _capped(list(problems))
        super().__init__("import refused: " + "; ".join(self.problems))


@dataclass(frozen=True)
class Limits:
    """The importer's ceilings.  The defaults are a backstop: a provider sets its own for its
    slot, and a caller may only tighten them (:meth:`tighten`).  ``read_tree`` and ``iter_tree``
    hold a file (``read_tree``: the tree) in memory, so callers of those pass limits that fit;
    ``copy_tree`` streams and needs only the disk."""

    max_files: int = 100_000
    max_bytes: int = 64 << 30
    max_file_bytes: int = 8 << 30
    max_depth: int = 32
    #: bytes of the UTF-8 path (the schema's maxLength counts characters: this is stricter)
    max_path_len: int = 1024

    def __post_init__(self) -> None:
        for name in self.__dataclass_fields__:
            v = getattr(self, name)
            if isinstance(v, bool) or not isinstance(v, int) or v < 0:
                raise ValueError(f"Limits.{name} must be a non-negative integer, got {v!r}")
        if self.max_depth > MAX_DEPTH:
            raise ValueError(f"Limits.max_depth must be at most {MAX_DEPTH}")

    def tighten(self, other: Limits | None) -> Limits:
        """The stricter of the two, field by field (``None``: these limits)."""
        if other is None:
            return self
        if not isinstance(other, Limits):
            raise TypeError("tighten() takes Limits")
        return Limits(
            **{k: min(getattr(self, k), getattr(other, k)) for k in self.__dataclass_fields__}
        )


DEFAULT_LIMITS = Limits()


def _capped(problems: list[str]) -> list[str]:
    if len(problems) <= MAX_PROBLEMS:
        return problems
    return [*problems[:MAX_PROBLEMS], f"... and {len(problems) - MAX_PROBLEMS} more"]


def _show(v: Any) -> str:
    """A bounded, printable rendering of an untrusted value."""
    try:
        s = repr(v) if not isinstance(v, int) or abs(v) < 10**30 else "a huge number"
    except Exception:  # a value whose repr fails is shown by its type
        s = f"<{type(v).__name__}>"
    return s if len(s) <= 80 else s[:77] + "..."


def _int(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and v >= 0


def _path_problems(p: Any, limits: Limits) -> list[str]:
    if not isinstance(p, str) or not p:
        return [f"path {_show(p)} is not a non-empty string"]
    shown = _show(p)
    if len(p) > limits.max_path_len:  # first: nothing else runs over an oversize path
        return [f"path {shown} is longer than {limits.max_path_len} bytes"]
    try:
        raw = p.encode("utf-8")
    except UnicodeEncodeError:
        return [f"path {shown} is not valid UTF-8 text"]
    out = []
    if len(raw) > limits.max_path_len:
        out.append(f"path {shown} is longer than {limits.max_path_len} bytes")
    if p.startswith("/"):
        out.append(f"path {shown} is absolute")
    if "\\" in p:
        out.append(f"path {shown} has a backslash")
    if any(ord(c) < 32 or ord(c) == 127 for c in p):
        out.append(f"path {shown} has a control character")
    if unicodedata.normalize("NFC", p) != p:
        out.append(f"path {shown} is not NFC-normalised")
    parts = p.split("/")
    if any(part in ("", ".", "..") for part in parts):
        out.append(f"path {shown} has an empty, '.' or '..' segment")
    if len(parts) > limits.max_depth:
        out.append(f"path {shown} is deeper than {limits.max_depth}")
    return out


def check_manifest(
    manifest: Mapping[str, Any],
    limits: Limits = DEFAULT_LIMITS,
    *,
    slot: str | None = None,
    formats: tuple[str, ...] | list[str] | None = None,
) -> list[str]:
    """Every problem with the manifest alone; ``slot`` and ``formats`` (the slot's
    ``export_formats``), when given, must be the manifest's."""
    try:
        return _capped(_manifest_problems(manifest, limits, slot, formats))
    except Exception as exc:  # a hostile manifest is refused, never a crash in the caller
        return [f"the manifest cannot be checked ({type(exc).__name__})"]


def _manifest_problems(manifest, limits, slot, formats) -> list[str]:
    if not isinstance(manifest, Mapping):
        return ["the manifest is not a mapping"]
    out: list[str] = []
    if manifest.get("schema_version") != MANIFEST_VERSION:
        out.append(f"schema_version must be {MANIFEST_VERSION!r}")
    if slot is not None and manifest.get("slot") != slot:
        out.append(f"the manifest is for slot {_show(manifest.get('slot'))}, not {slot!r}")
    if formats is not None and manifest.get("format") not in formats:
        out.append(f"format {_show(manifest.get('format'))} is not one of {sorted(formats)}")
    files = manifest.get("files")
    if not isinstance(files, list):
        return [*out, "files must be a list"]
    if len(files) > limits.max_files:
        return [*out, f"{len(files)} files is more than the limit of {limits.max_files}"]
    seen: dict[str, str] = {}
    total = 0
    sizes_ok = True
    paths: set[str] = set()
    for i, f in enumerate(files):
        if not isinstance(f, Mapping) or set(f) != {"path", "size", "sha256"}:
            out.append(f"files[{i}] must have exactly path, size and sha256")
            sizes_ok = False
            continue
        p, size, digest = f["path"], f["size"], f["sha256"]
        bad = _path_problems(p, limits)
        out += bad
        if not _int(size):
            out.append(f"files[{i}].size is not a non-negative integer")
            sizes_ok = False
        else:
            total += size
            if size > limits.max_file_bytes:
                out.append(
                    f"files[{i}] is {_show(size)} bytes, over the limit of {limits.max_file_bytes}"
                )
        if not (isinstance(digest, str) and len(digest) == 64 and set(digest) <= _HEX):
            out.append(f"files[{i}].sha256 is not 64 lower-case hex digits")
        if bad:
            continue
        key = p.casefold()
        if key in seen:
            out.append(
                f"path {_show(p)} repeats {_show(seen[key])} (paths compare case-insensitively)"
            )
        else:
            seen[key] = p
            paths.add(p)
    folded = {p.casefold(): p for p in paths}
    for p in sorted(paths):
        parts = p.split("/")
        for n in range(1, len(parts)):
            above = folded.get("/".join(parts[:n]).casefold())
            if above is not None:
                out.append(f"path {_show(p)} is under {_show(above)}, which is a file")
                break
    totals = manifest.get("totals")
    if not isinstance(totals, Mapping) or set(totals) != {"files", "bytes"}:
        out.append("totals must have exactly files and bytes")
    elif not (_int(totals["files"]) and _int(totals["bytes"])):
        out.append("totals.files and totals.bytes must be non-negative integers")
    else:
        if totals["files"] != len(files):
            out.append(
                f"totals.files is {_show(totals['files'])} but {len(files)} files are listed"
            )
        if sizes_ok and totals["bytes"] != total:
            out.append(f"totals.bytes is {_show(totals['bytes'])} but the files add up to {total}")
    if total > limits.max_bytes:
        out.append(f"{_show(total)} bytes is more than the limit of {limits.max_bytes}")
    return out


def _entry_kind(mode: int) -> str:
    if stat.S_ISLNK(mode):
        return "a symbolic link"
    if stat.S_ISDIR(mode):
        return "dir"
    if stat.S_ISREG(mode):
        return "file"
    return "a special file"


def _open_root(root: str | Path) -> int:
    """The root's descriptor, never through a link (a trailing ``/`` would make Linux ignore
    ``O_NOFOLLOW``, so it is stripped)."""
    path = os.fsdecode(root)
    stripped = path.rstrip("/") or "/"
    return os.open(stripped, _DIR)


_OCTAL = re.compile(rb"\\([0-7]{3})")


def _mounts_under(root_fd: int) -> list[str] | None:
    """Mount points strictly inside the root (bind mounts included), from mountinfo; ``None``
    when the mount table cannot be read (the caller refuses: this check fails closed)."""
    try:
        here = os.fsencode(os.readlink(f"/proc/self/fd/{root_fd}"))
        with open(MOUNTINFO, "rb") as fh:
            lines = fh.read().splitlines()
    except OSError:
        return None
    prefix = here.rstrip(b"/") + b"/"
    out = []
    for line in lines:
        fields = line.split(b" ")
        if len(fields) < 5:
            continue
        # mountinfo escapes space, tab, newline and backslash as \ooo; nothing else
        point = _OCTAL.sub(lambda m: bytes([int(m.group(1), 8)]), fields[4])
        if point.startswith(prefix):
            out.append(os.fsdecode(point[len(prefix) :]))
    return sorted(out)


@dataclass
class _Walk:
    limits: Limits
    wanted: dict[str, Any]
    dev: int
    found: set[str]
    out: list[str]
    seen: int = 0


def _scan(walk: _Walk, dir_fd: int, prefix: str, depth: int) -> bool:
    """Examine one directory; False stops the walk (too many entries)."""
    budget = walk.limits.max_files * 2 + 1024
    names = []
    with os.scandir(dir_fd) as it:
        for entry in it:
            walk.seen += 1
            if walk.seen > budget:
                walk.out.append(f"the tree has more than {budget} entries")
                return False
            names.append(entry.name)
    for name in sorted(names):
        rel = prefix + name
        st = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
        kind = _entry_kind(st.st_mode)
        shown = _show(rel)
        if st.st_dev != walk.dev:
            walk.out.append(f"{shown} is on another filesystem")
            walk.found.add(rel)
            continue
        if kind == "dir":
            if depth + 1 > walk.limits.max_depth:
                walk.out.append(f"directory {shown} is deeper than {walk.limits.max_depth}")
                continue
            fd = os.open(name, _DIR, dir_fd=dir_fd)
            try:
                now = os.fstat(fd)
                if (now.st_dev, now.st_ino) != (st.st_dev, st.st_ino):
                    walk.out.append(f"directory {shown} changed while it was being checked")
                    continue
                if not _scan(walk, fd, rel + "/", depth + 1):
                    return False
            finally:
                os.close(fd)
            continue
        if kind != "file":
            walk.out.append(f"{shown} is {kind}")
            walk.found.add(rel)
            continue
        if st.st_nlink != 1:
            walk.out.append(f"{shown} has {st.st_nlink} hard links")
        if rel not in walk.wanted:
            walk.out.append(f"{shown} is not in the manifest")
            continue
        walk.found.add(rel)
        if st.st_size != walk.wanted[rel]:
            walk.out.append(
                f"{shown} is {st.st_size} bytes, the manifest says {_show(walk.wanted[rel])}"
            )
    return True


def _check_fd(root_fd: int, manifest: Any, limits: Limits, slot, formats) -> list[str]:
    out = check_manifest(manifest, limits, slot=slot, formats=formats)
    if not isinstance(manifest, Mapping):
        return out
    listed = manifest.get("files")
    wanted = {
        f["path"]: f.get("size")
        for f in (listed if isinstance(listed, list) else [])
        if isinstance(f, Mapping)
        and isinstance(f.get("path"), str)
        and not _path_problems(f["path"], limits)  # an invalid path is already refused
    }
    root_st = os.fstat(root_fd)
    walk = _Walk(limits, wanted, root_st.st_dev, set(), [])
    points = _mounts_under(root_fd)
    if points is None:
        walk.out.append(
            f"the mount table ({MOUNTINFO}) cannot be read, so mounts inside the tree cannot be ruled out"
        )
    for point in points or []:
        walk.out.append(f"{_show(point)} is a mount point inside the tree")
    try:
        complete = _scan(walk, root_fd, "", 0)
    except OSError as exc:
        return _capped([*out, *walk.out, f"the tree cannot be read ({exc.strerror})"])
    out += walk.out
    if complete:
        for missing in sorted(set(wanted) - walk.found):
            out.append(f"{_show(missing)} is in the manifest but not in the tree")
    return _capped(out)


def check_tree(
    root: str | Path,
    manifest: Mapping[str, Any],
    limits: Limits = DEFAULT_LIMITS,
    *,
    slot: str | None = None,
    formats: tuple[str, ...] | list[str] | None = None,
) -> list[str]:
    """Every reason ``root`` may not be imported against ``manifest``, without reading content."""
    try:
        st = os.lstat(os.fsdecode(root).rstrip("/") or "/")
    except OSError as exc:
        return [
            *check_manifest(manifest, limits, slot=slot, formats=formats),
            f"the root cannot be read ({exc.strerror})",
        ]
    kind = _entry_kind(st.st_mode)
    if kind != "dir":
        what = "a file" if kind == "file" else kind
        return [
            *check_manifest(manifest, limits, slot=slot, formats=formats),
            f"the root is {what}, not a directory",
        ]
    try:
        root_fd = _open_root(root)
    except OSError as exc:
        return [
            *check_manifest(manifest, limits, slot=slot, formats=formats),
            f"the root cannot be opened without following a link ({exc.strerror})",
        ]
    try:
        return _check_fd(root_fd, manifest, limits, slot, formats)
    finally:
        os.close(root_fd)


def _open_verified(root_fd: int, dev: int, rel: str, size: int) -> int:
    """The file's descriptor, opened through directory descriptors without following a link and
    checked on the descriptor: a regular file with one link, on the root's filesystem, of ``size``."""
    parts = rel.split("/")
    dirs: list[int] = []
    try:
        at = root_fd
        for part in parts[:-1]:
            at = os.open(part, _DIR, dir_fd=at)
            dirs.append(at)
            if os.fstat(at).st_dev != dev:
                raise ImportRefused([f"{_show(rel)} is on another filesystem"])
        fd = os.open(parts[-1], _FILE, dir_fd=at)
    except OSError as exc:
        raise ImportRefused(
            [f"{_show(rel)} cannot be opened without following a link ({exc.strerror})"]
        ) from None
    finally:
        for d in reversed(dirs):
            os.close(d)
    st = os.fstat(fd)
    problem = None
    if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
        problem = f"{_show(rel)} changed into {_entry_kind(st.st_mode)} after the check"
    elif st.st_dev != dev:
        problem = f"{_show(rel)} is on another filesystem"
    elif st.st_size != size:
        problem = f"{_show(rel)} changed size after the check"
    if problem:
        os.close(fd)
        raise ImportRefused([problem])
    os.set_blocking(fd, True)
    return fd


def _stream(fd: int, rel: str, size: int, digest: str, sink) -> None:
    """Read exactly ``size`` bytes into ``sink`` and check the sha256; a file that grew or
    differs is refused."""
    h = hashlib.sha256()
    got = 0
    while got <= size:
        chunk = os.read(fd, min(_CHUNK, size + 1 - got))
        if not chunk:
            break
        got += len(chunk)
        if got > size:
            break
        h.update(chunk)
        sink(chunk)
    if got != size or h.hexdigest() != digest:
        raise ImportRefused([f"{_show(rel)} does not match its size and sha256 in the manifest"])


def _checked_root(root, manifest, limits, slot, formats) -> tuple[int, int]:
    try:
        root_fd = _open_root(root)
    except OSError as exc:
        raise ImportRefused(
            [
                *check_manifest(manifest, limits, slot=slot, formats=formats),
                f"the root cannot be opened without following a link ({exc.strerror})",
            ]
        ) from None
    try:
        problems = _check_fd(root_fd, manifest, limits, slot, formats)
        if problems:
            raise ImportRefused(problems)
        return root_fd, os.fstat(root_fd).st_dev
    except BaseException:
        os.close(root_fd)
        raise


def iter_tree(
    root: str | Path,
    manifest: Mapping[str, Any],
    limits: Limits = DEFAULT_LIMITS,
    *,
    slot: str | None = None,
    formats: tuple[str, ...] | list[str] | None = None,
) -> Iterator[tuple[str, bytes]]:
    """Check the tree, then yield ``(path, content)`` in manifest order, each file verified on its
    open descriptor.  A generator: the first ``next()`` raises :class:`ImportRefused` when the
    check fails, and a later one on the file that fails its read.  **Streaming**: a caller that
    applies files as they come leaves a partial import on a late refusal, so it must stage them
    (``read_tree`` and ``copy_tree`` do)."""
    root_fd, dev = _checked_root(root, manifest, limits, slot, formats)
    try:
        for f in manifest["files"]:
            fd = _open_verified(root_fd, dev, f["path"], f["size"])
            try:
                buf = bytearray()
                _stream(fd, f["path"], f["size"], f["sha256"], buf.extend)
            finally:
                os.close(fd)
            yield f["path"], bytes(buf)
    finally:
        os.close(root_fd)


def read_tree(
    root: str | Path,
    manifest: Mapping[str, Any],
    limits: Limits = DEFAULT_LIMITS,
    *,
    slot: str | None = None,
    formats: tuple[str, ...] | list[str] | None = None,
) -> dict[str, bytes]:
    """:func:`iter_tree` collected into a mapping: all or nothing, held in memory."""
    return dict(iter_tree(root, manifest, limits, slot=slot, formats=formats))


def _write_all(fd: int, data: bytes) -> None:
    """``os.write`` until every byte is written (a short write is not a success)."""
    view = memoryview(data)
    while view:
        n = os.write(fd, view)
        if n <= 0:
            raise OSError("short write")
        view = view[n:]


def _fsync_dir(path: str | Path) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def copy_tree(
    root: str | Path,
    manifest: Mapping[str, Any],
    dest: str | Path,
    limits: Limits = DEFAULT_LIMITS,
    *,
    slot: str | None = None,
    formats: tuple[str, ...] | list[str] | None = None,
) -> int:
    """Check the tree, then stream every file into a new directory ``dest`` (which must not
    exist; its parent is the importer's own and must exist), verifying each on the way.  The copy
    is built beside ``dest``, every file and directory flushed to disk, and renamed into place only
    when every file verified, so no partially built ``dest`` ever appears, a crash included.  The
    rename does not refuse a ``dest`` someone creates empty in between (a race only the importer's
    own directory admits).  Returns the number of files copied."""
    dest = Path(dest)
    if os.path.lexists(dest):
        raise ImportRefused([f"the destination {_show(str(dest))} already exists"])
    if not dest.parent.is_dir():
        raise ImportRefused(
            [f"the destination's parent {_show(str(dest.parent))} is not a directory"]
        )
    root_fd, dev = _checked_root(root, manifest, limits, slot, formats)
    staging = Path(tempfile.mkdtemp(prefix=f".{dest.name}.", dir=dest.parent))
    try:
        for f in manifest["files"]:
            target = staging.joinpath(*f["path"].split("/"))
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            fd = _open_verified(root_fd, dev, f["path"], f["size"])
            try:
                out_fd = os.open(
                    target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
                )
                try:
                    _stream(
                        fd, f["path"], f["size"], f["sha256"], lambda b, o=out_fd: _write_all(o, b)
                    )
                    os.fsync(out_fd)
                finally:
                    os.close(out_fd)
            finally:
                os.close(fd)
        for top, _dirs, _names in os.walk(staging, topdown=False):
            _fsync_dir(top)
        os.rename(staging, dest)
        _fsync_dir(dest.parent)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    finally:
        os.close(root_fd)
    return len(manifest["files"])


def build_manifest(
    root: str | Path, slot: str, fmt: str, limits: Limits = DEFAULT_LIMITS
) -> dict[str, Any]:
    """The export side: the manifest of ``root`` as it is, files sorted by path.  Refuses
    (:class:`ImportRefused`) a tree it could not import itself, so an exporter never writes what
    its peer must refuse (a file with a second hard link included: export fresh files, not a
    ``cp -al`` or ``rsync --link-dest`` tree)."""
    root = Path(root)
    files = []
    for top, dirs, names in os.walk(root, followlinks=False):
        dirs.sort()
        for name in sorted(names):
            full = os.path.join(top, name)
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            try:
                fd = os.open(full, _FILE)
            except OSError:
                continue  # a link or special file: check_tree below names it
            try:
                st = os.fstat(fd)
                if not stat.S_ISREG(st.st_mode):
                    continue
                os.set_blocking(fd, True)
                h = hashlib.sha256()
                size = 0
                while chunk := os.read(fd, _CHUNK):
                    h.update(chunk)
                    size += len(chunk)
            finally:
                os.close(fd)
            files.append({"path": rel, "size": size, "sha256": h.hexdigest()})
    files.sort(key=lambda f: f["path"])
    manifest = {
        "schema_version": MANIFEST_VERSION,
        "slot": slot,
        "format": fmt,
        "files": files,
        "totals": {"files": len(files), "bytes": sum(f["size"] for f in files)},
    }
    problems = check_tree(root, manifest, limits)
    if problems:
        raise ImportRefused(problems)
    return manifest


def manifest_sha256(manifest: Mapping[str, Any]) -> str:
    """The manifest's digest over canonical JSON (sorted keys, no spaces, files sorted by path):
    what a swap record's ``export_manifest_sha256`` names."""
    doc = dict(manifest)
    doc["files"] = sorted(doc.get("files", []), key=lambda f: f["path"])
    canon = json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canon.encode("utf-8")).hexdigest()
