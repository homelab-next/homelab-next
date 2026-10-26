# SPDX-License-Identifier: Apache-2.0
"""The supply chain of fetched modules (ADR-0027 follow-up 5; docs/modules.md, "Supply chain").

A module's ``origin`` is ``in-tree`` (shipped in this repository's public ``modules/`` tree and
reviewed by its pull requests) or fetched (``{kind: git, url, commit}`` or ``{kind: archive, url,
sha256}``).  A fetched module is loadable only when the overlay **pins** it and **reviews** it:

* the **tree digest** (:func:`tree_digest`) is ``sha256:`` over a ``hnx-tree-v1`` header and one
  line per regular file of the module directory, code and roles included: its path, whether any
  executable bit is set, and its content digest, sorted by path.  What it does not cover:
  empty directories, directory modes, ownership, times, and mode bits other than "executable".
  A symbolic link, special file, hard-linked file or ``.git`` entry anywhere refuses the digest
  (a module cannot point outside itself, and version-control metadata, which no review reads, is
  never part of a loaded module: fetch with ``git archive`` or strip ``.git`` first), and so does
  a tree over :class:`TreeLimits`;
* the **lock** (``lab/modules.lock``, draft schema ``platform/module_lock`` 1.0) holds, per
  fetched module id, its ``origin`` (exactly the manifest's) and ``tree`` (the digest), and the
  ``reviews`` of that tree, inline, in the shape of :mod:`homelabnext.reviews`.  Reviews never live
  in a module (its author could ship pre-stamped approvals).  A review counts only while its
  ``digest`` is the full pinned tree (a prefix, which a module author could grind for, is not
  enough here); reviews of an earlier tree stay in the list as history and are ignored;
* the review policy says what each module kind (``module-provider``, ``module-feature``,
  ``module-core``) needs in state ``locked``.  A kind the policy does not list, or lists with no
  requirement, is never reviewed enough: it fails closed.  The manifest's ``author`` never reviews
  their own module, and ``unknown`` is refused as a module's author.  Any review with a verdict
  other than ``pass`` on the pinned tree vetoes it.

:func:`lock_problems` is the loader's check: every selected fetched module is pinned, its origin is
the lock's, its directory still has the pinned digest, and its reviews meet the policy, so an
unpinned, changed or unreviewed module is not loadable.  Whether a module is in-tree is decided by
where its directory is (under a public ``modules/`` root), never by its own manifest; an in-tree
module is never in the lock.  :func:`lock_entry` makes the entry for a module directory as it is
(no reviews yet).  Like every review in this repository this is a consistency check over what the
files claim, not authentication: anyone who can edit the lock can edit both the pin and the
reviews, so the lock is reviewed by the overlay's own pull requests.  The digest is a string, not
a snapshot: the loader loads from a copy only it can write, so the tree it loads is the tree it
digested.
"""

from __future__ import annotations

import hashlib
import os
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from homelabnext.reviews import Policy, evaluate, identity, missing_message

__all__ = [
    "KINDS",
    "LOCK_VERSION",
    "SupplyError",
    "TreeLimits",
    "lock_entry",
    "lock_problems",
    "tree_digest",
]

LOCK_VERSION = "1.0"
KINDS = ("provider", "feature", "core")
HEADER = b"hnx-tree-v1\n"
_CHUNK = 1 << 20
_FILE = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
_FULL = len("sha256:") + 64
Doc = dict[str, Any]


class SupplyError(Exception):
    """A module directory cannot be digested: it holds a link, a special or hard-linked file, a
    ``.git`` entry, or more than its limits, or a file cannot be read."""


@dataclass(frozen=True)
class TreeLimits:
    max_files: int = 20_000
    max_bytes: int = 2 << 30


DEFAULT_LIMITS = TreeLimits()


def _file_digest(path: str) -> tuple[str, bool]:
    """(sha256, executable), read from one open descriptor (no link followed)."""
    fd = os.open(path, _FILE)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise SupplyError(f"{path} changed into something other than a file")
        if st.st_nlink != 1:
            raise SupplyError(f"{path} has {st.st_nlink} hard links: a module file has one")
        os.set_blocking(fd, True)
        h = hashlib.sha256()
        while chunk := os.read(fd, _CHUNK):
            h.update(chunk)
        return h.hexdigest(), bool(st.st_mode & 0o111)
    finally:
        os.close(fd)


def _raise(exc: OSError) -> None:
    raise SupplyError(f"{exc.filename}: cannot be read ({exc.strerror})")


def tree_digest(module_dir: str | Path, limits: TreeLimits = DEFAULT_LIMITS) -> str:
    """``sha256:<hex>`` over ``hnx-tree-v1\\n`` and one line per regular file,
    ``<path>\\0<x|->\\0<sha256 of content>\\n``, sorted by path (``/`` separated, relative)."""
    root = Path(module_dir)
    try:
        st = os.lstat(root)
    except OSError as exc:
        raise SupplyError(f"{root}: cannot be read ({exc.strerror})") from None
    if not stat.S_ISDIR(st.st_mode):
        raise SupplyError(f"{root} is not a directory (a link to one is refused too)")
    lines: list[bytes] = []
    total = 0
    for top, dirs, names in os.walk(root, followlinks=False, onerror=_raise):
        for name in dirs + names:
            full = os.path.join(top, name)
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            if name == ".git":
                raise SupplyError(
                    f"{rel}: version-control metadata in a module is refused (no review reads it):"
                    " fetch with git archive, or strip .git before pinning"
                )
            st = os.lstat(full)
            if stat.S_ISDIR(st.st_mode):
                continue
            if stat.S_ISLNK(st.st_mode):
                raise SupplyError(f"{rel}: a symbolic link in a module is refused")
            if not stat.S_ISREG(st.st_mode):
                raise SupplyError(f"{rel}: a special file in a module is refused")
            if len(lines) >= limits.max_files:
                raise SupplyError(f"more than {limits.max_files} files: over the module tree limit")
            total += st.st_size
            if total > limits.max_bytes:
                raise SupplyError(f"more than {limits.max_bytes} bytes: over the module tree limit")
            digest, x = _file_digest(full)
            line = f"{rel}\0{'x' if x else '-'}\0{digest}\n"
            lines.append(line.encode("utf-8", "surrogateescape"))
    lines.sort()
    return "sha256:" + hashlib.sha256(HEADER + b"".join(lines)).hexdigest()


def lock_entry(module_dir: str | Path, manifest: Mapping[str, Any]) -> Doc:
    """The lock entry for a fetched module as its directory is now: its origin and tree digest,
    with no reviews yet."""
    origin = manifest.get("origin", {}) if isinstance(manifest, Mapping) else {}
    if not isinstance(origin, Mapping) or origin.get("kind") not in ("git", "archive"):
        raise SupplyError("only a fetched module (origin git or archive) is locked")
    return {"origin": dict(origin), "tree": tree_digest(module_dir), "reviews": []}


def _under(path: Path, roots: tuple[Path, ...]) -> bool:
    real = os.path.realpath(path)
    for r in roots:
        base = os.path.realpath(r).rstrip("/")
        if real == base or real.startswith(base + "/"):
            return True
    return False


def _review_problems(mid: str, reviews: Any, pinned: str) -> list[str]:
    """Vetoes (a non-pass verdict on the pinned tree) and prefix-only reviews."""
    out = []
    for n, r in enumerate(reviews if isinstance(reviews, list) else [], 1):
        if not isinstance(r, Mapping):
            continue
        d = r.get("digest")
        if (
            r.get("verdict") in ("changes", "reject")
            and isinstance(d, str)
            and pinned.startswith(d)
        ):
            out.append(
                f"{mid}: review #{n} ({r.get('by')}) says {r['verdict']} to this tree: not loadable"
            )
        elif isinstance(d, str) and d != pinned and pinned.startswith(d):
            out.append(
                f"{mid}: review #{n} names a prefix of the tree; a module review names the full sha256"
            )
    return out


def lock_problems(
    mods: Mapping[str, Any],
    dirs: Mapping[str, Path],
    lock: Any,
    policy: Policy | None,
    in_tree_roots: tuple[Path, ...],
) -> list[str]:
    """Every reason a selected module is not loadable for its supply chain.  ``mods`` are the
    selected modules' manifests by id, ``dirs`` their directories, ``lock`` the parsed
    ``lab/modules.lock``, ``policy`` the review policy (``None``: no fetched module loads) and
    ``in_tree_roots`` the public ``modules/`` trees (:func:`homelabnext.modules.rules.
    public_module_roots`): a module is in-tree only when its directory is under one."""
    if not isinstance(lock, Mapping):
        return ["the lock is not a mapping"]
    out = []
    if lock.get("schema_version") != LOCK_VERSION:
        out.append(f"the lock's schema_version must be {LOCK_VERSION!r}")
    entries = lock.get("modules")
    if not isinstance(entries, Mapping):
        return [*out, "the lock's modules must be a mapping of module id to entry"]
    for mid in sorted(map(str, set(entries) - set(mods))):
        out.append(f"lock: {mid} is locked but not selected (delete its entry with its selection)")
    for mid in sorted(mods, key=str):
        out += _module_problems(
            str(mid), mods[mid], dirs.get(mid), entries.get(mid), policy, in_tree_roots
        )
    return out


def _module_problems(mid, m, directory, entry, policy, in_tree_roots) -> list[str]:
    if not isinstance(m, Mapping):
        return [f"{mid}: the manifest is not a mapping"]
    origin = m.get("origin")
    okind = origin.get("kind") if isinstance(origin, Mapping) else None
    in_tree = directory is not None and _under(Path(directory), in_tree_roots)
    if okind == "in-tree" or in_tree:
        if okind != "in-tree" or not in_tree:
            return [f"{mid}: in-tree means shipped under the public modules/ tree, and only that"]
        if entry is not None:
            return [f"{mid}: an in-tree module is reviewed by this repository; it is never locked"]
        return []
    if okind not in ("git", "archive"):
        return [f"{mid}: origin {okind!r:.40} is not in-tree, git or archive"]
    kind = m.get("kind")
    if kind not in KINDS:
        return [f"{mid}: kind {kind!r:.40} is not one of {list(KINDS)}: not loadable"]
    author = m.get("author")
    if author in (None, "unknown") or identity(author) is None:
        return [f"{mid}: a fetched module names its author as issuer:subject: not loadable"]
    if not isinstance(entry, Mapping):
        return [f"{mid}: fetched ({okind}) but not pinned in the lock: not loadable"]
    out = []
    extra = set(map(str, entry)) - {"origin", "tree", "reviews"}
    if extra:
        out.append(f"{mid}: unknown lock field(s) {sorted(extra)}")
    if entry.get("origin") != dict(origin):
        out.append(f"{mid}: the manifest's origin is not the one the lock pins")
    pinned = entry.get("tree")
    if not isinstance(pinned, str) or not pinned.startswith("sha256:") or len(pinned) != _FULL:
        return [*out, f"{mid}: the lock's tree is not sha256:<64 hex>"]
    if directory is None:
        return [*out, f"{mid}: no directory to digest"]
    try:
        now = tree_digest(directory)
    except (SupplyError, OSError) as exc:
        return [*out, f"{mid}: its directory cannot be digested ({exc})"]
    if now != pinned:
        return [
            *out,
            f"{mid}: the module changed since it was pinned ({now[:19]} is not {pinned[:19]}): not loadable",
        ]
    reviews = entry.get("reviews", [])
    out += _review_problems(mid, reviews, pinned)
    # only reviews of the full pinned tree count toward the policy
    full = (
        [r for r in reviews if isinstance(r, Mapping) and r.get("digest") == pinned]
        if isinstance(reviews, list)
        else reviews
    )
    artefact = f"module-{kind}"
    ev = evaluate(
        full,
        author=author,
        digest=pinned,
        artefact=artefact,
        state="locked",
        policy=policy,
        who=mid,
    )
    out += ev.problems
    if policy is None:
        out.append(f"{mid}: no review policy, so no fetched module is reviewed enough to load")
    elif not policy.required(artefact, "locked"):
        out.append(
            f"{mid}: the review policy asks nothing of {artefact} in state locked: not loadable"
        )
    elif ev.missing:
        out.append(missing_message(mid, "locked", ev, pinned) + ": not loadable")
    return out
