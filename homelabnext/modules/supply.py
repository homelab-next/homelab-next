# SPDX-License-Identifier: Apache-2.0
"""The supply chain of fetched modules (ADR-0027 follow-up 5; docs/modules.md, "Supply chain").

A module's ``origin`` is ``in-tree`` (shipped in this repository's public ``modules/`` tree and
reviewed by its pull requests) or fetched (``{kind: git, url, commit}`` or ``{kind: archive, url,
sha256}``).  A fetched module is loadable only when the overlay **pins** it and **reviews** it:

* the **tree digest** (:func:`tree_digest`) is ``sha256:`` over every file of the module
  directory, code and roles included: each regular file's path, executable bit and content
  digest, sorted by path.  ``.git`` is left out (the commit is pinned in the origin); a symbolic
  link or special file anywhere refuses the digest, so a module cannot point outside itself;
* the **lock** (``lab/modules.lock``, draft schema ``platform/module_lock`` 1.0) holds, per
  fetched module id, its ``origin`` (exactly the manifest's) and ``tree`` (the digest), and the
  ``reviews`` of that tree.  Reviews never live in a module (its author could ship pre-stamped
  approvals): they are the overlay's, in the lock, in the shape of :mod:`homelabnext.reviews`,
  each one counting only while its ``digest`` is a prefix of the pinned tree;
* the review policy says what a module needs, by kind (``module-provider``, ``module-feature``,
  ``module-core``) in state ``locked``; the manifest's ``author`` never reviews their own module.

:func:`lock_problems` is the loader's check: every selected fetched module is pinned, its origin
is the lock's, its directory still has the pinned digest, and its reviews meet the policy, so an
unpinned, changed or unreviewed module is not loadable.  An in-tree module is never in the lock.
:func:`lock_entry` makes the entry for a module directory as it is (the reviews start empty).
"""

from __future__ import annotations

import hashlib
import os
import stat
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from homelabnext.reviews import Policy, evaluate, missing_message

__all__ = [
    "LOCK_VERSION",
    "SupplyError",
    "lock_entry",
    "lock_problems",
    "tree_digest",
]

LOCK_VERSION = "1.0"
#: version-control metadata a fetched checkout carries: not part of the module
SKIP = frozenset({".git"})
_CHUNK = 1 << 20
_FILE = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
Doc = dict[str, Any]


class SupplyError(Exception):
    """A module directory cannot be digested: it holds a link or a special file, or a file
    cannot be read."""


def _file_digest(path: str) -> str:
    fd = os.open(path, _FILE)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise SupplyError(f"{path} changed into something other than a file")
        os.set_blocking(fd, True)
        h = hashlib.sha256()
        while chunk := os.read(fd, _CHUNK):
            h.update(chunk)
        return h.hexdigest()
    finally:
        os.close(fd)


def tree_digest(module_dir: str | Path) -> str:
    """``sha256:<hex>`` over every file of ``module_dir``: one line per regular file,
    ``<path>\\0<x|->\\0<sha256 of content>\\n``, sorted by path (``/`` separated, relative)."""
    root = Path(module_dir)
    st = os.lstat(root)
    if not stat.S_ISDIR(st.st_mode):
        raise SupplyError(f"{root} is not a directory (a link to one is refused too)")
    lines: list[bytes] = []
    for top, dirs, names in os.walk(root, followlinks=False, onerror=_raise):
        if Path(top) == root:
            dirs[:] = [d for d in dirs if d not in SKIP]
        for name in sorted(dirs + names):
            full = os.path.join(top, name)
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            st = os.lstat(full)
            if stat.S_ISDIR(st.st_mode):
                continue
            if stat.S_ISLNK(st.st_mode):
                raise SupplyError(f"{rel}: a symbolic link in a module is refused")
            if not stat.S_ISREG(st.st_mode):
                raise SupplyError(f"{rel}: a special file in a module is refused")
            x = "x" if st.st_mode & 0o111 else "-"
            lines.append(f"{rel}\0{x}\0{_file_digest(full)}\n".encode("utf-8", "surrogateescape"))
    lines.sort()
    return "sha256:" + hashlib.sha256(b"".join(lines)).hexdigest()


def _raise(exc: OSError) -> None:
    raise SupplyError(f"{exc.filename}: cannot be read ({exc.strerror})")


def lock_entry(module_dir: str | Path, manifest: Mapping[str, Any]) -> Doc:
    """The lock entry for a fetched module as its directory is now: its origin and tree digest,
    with no reviews yet."""
    origin = manifest.get("origin", {})
    if not isinstance(origin, Mapping) or origin.get("kind") not in ("git", "archive"):
        raise SupplyError(f"{manifest.get('id')}: only a fetched module (git or archive) is locked")
    return {"origin": dict(origin), "tree": tree_digest(module_dir), "reviews": []}


def _kind_problems(lock: Any) -> list[str]:
    if not isinstance(lock, Mapping):
        return ["the lock is not a mapping"]
    out = []
    if lock.get("schema_version") != LOCK_VERSION:
        out.append(f"the lock's schema_version must be {LOCK_VERSION!r}")
    if not isinstance(lock.get("modules"), Mapping):
        out.append("the lock's modules must be a mapping of module id to entry")
    return out


def lock_problems(
    mods: Mapping[str, Doc],
    dirs: Mapping[str, Path],
    lock: Any,
    policy: Policy | None,
) -> list[str]:
    """Every reason a selected module is not loadable for its supply chain.  ``mods`` are the
    selected modules' manifests by id, ``dirs`` their directories, ``lock`` the parsed
    ``lab/modules.lock`` and ``policy`` the review policy (``None``: only the rules that need no
    policy run, and no module is ever reviewed enough: a fetched module then never loads)."""
    out = _kind_problems(lock)
    if out:
        return out
    entries = lock["modules"]
    for mid in sorted(set(entries) - set(mods)):
        out.append(f"lock: {mid} is locked but not selected (delete its entry with its selection)")
    for mid, m in sorted(mods.items()):
        origin = m.get("origin", {})
        kind = origin.get("kind") if isinstance(origin, Mapping) else None
        entry = entries.get(mid)
        if kind == "in-tree":
            if entry is not None:
                out.append(
                    f"{mid}: an in-tree module is reviewed by this repository; it is never locked"
                )
            continue
        if kind not in ("git", "archive"):
            out.append(f"{mid}: origin {kind!r} is not in-tree, git or archive")
            continue
        if not isinstance(entry, Mapping):
            out.append(f"{mid}: fetched ({kind}) but not pinned in the lock: not loadable")
            continue
        extra = set(entry) - {"origin", "tree", "reviews"}
        if extra:
            out.append(f"{mid}: unknown lock field(s) {sorted(extra)}")
        if entry.get("origin") != dict(origin):
            out.append(f"{mid}: the manifest's origin is not the one the lock pins")
        pinned = entry.get("tree")
        if not isinstance(pinned, str) or not pinned.startswith("sha256:") or len(pinned) != 71:
            out.append(f"{mid}: the lock's tree is not sha256:<64 hex>")
            continue
        try:
            now = tree_digest(dirs[mid])
        except (SupplyError, OSError, KeyError) as exc:
            out.append(f"{mid}: its directory cannot be digested ({exc})")
            continue
        if now != pinned:
            out.append(
                f"{mid}: the module changed since it was pinned ({now[:19]} is not {pinned[:19]}): not loadable"
            )
            continue
        ev = evaluate(
            entry.get("reviews", []),
            author=m.get("author"),
            digest=pinned,
            artefact=f"module-{m.get('kind')}",
            state="locked",
            policy=policy,
            who=mid,
        )
        out += ev.problems
        if policy is None:
            out.append(f"{mid}: no review policy, so no fetched module is reviewed enough to load")
        elif ev.missing:
            out.append(missing_message(mid, "locked", ev, pinned) + ": not loadable")
    return out
