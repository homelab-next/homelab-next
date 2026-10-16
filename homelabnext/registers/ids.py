# SPDX-License-Identifier: Apache-2.0
"""Id allocation and loss detection for YAML registers.

Two authors who both read "the next free id" out of a file and append an entry collide. This
module removes the read-then-write race and detects the one corruption a duplicate-id check
cannot see (an entry that silently vanished in a merge).

    alloc       claim ids under a host-wide flock; two racers get N and N+1
    resolve     rewrite ``XX-NEW`` placeholders (``LL-NEW``, ``RB-NEW`` ...) into allocated ids
    check_lost  fail if an id a parent commit had is absent from the file being committed

Nothing here parses YAML: entries are split as text so comments survive byte for byte, and an
existing id is never renumbered.
"""

from __future__ import annotations

import contextlib
import fcntl
import os
import pathlib
import re
import subprocess
from dataclasses import dataclass

__all__ = [
    "SPECS",
    "IdError",
    "RegisterSpec",
    "allocate",
    "check_lost",
    "ids_in",
    "resolve_file",
    "spec_for",
    "split_entries",
]


class IdError(Exception):
    pass


@dataclass(frozen=True)
class RegisterSpec:
    """How one register kind lays out its entries.

    indent     exact whitespace before an entry's ``- id:`` line (anchoring on it keeps nested
               ``- id:`` keys from splitting a block)
    prefixes   allocatable prefixes
    width      zero padding of the number
    protected  append-only register: a vanished id is corruption (lessons, runbooks,
               invariants). Work-queue registers delete entries legitimately and are unprotected.
    """

    kind: str
    indent: str
    prefixes: tuple[str, ...]
    width: int
    protected: bool
    id_re: str


SPECS: dict[str, RegisterSpec] = {
    "lessons": RegisterSpec("lessons", "", ("LL",), 3, True, r"LL-(?:\d{3,}|NEW)"),
    "runbooks": RegisterSpec("runbooks", "", ("RB",), 3, True, r"RB-(?:\d{3,}|NEW)"),
    "invariants": RegisterSpec(
        "invariants", "", tuple("ABCDEFGHIJKLMNOPQRSTUVWXYZ"), 2, True, r"[A-Z]-(?:\d{2,}|NEW)"
    ),
    "queue": RegisterSpec("queue", "", ("PRJ",), 3, False, r"PRJ-(?:\d{3,}(?:\.\d+)?|NEW)"),
}


def spec_for(path: str | os.PathLike) -> RegisterSpec | None:
    """Register kind is taken from the file stem: lessons.yml, runbooks.yml, ..."""
    return SPECS.get(pathlib.Path(path).stem.split(".")[0])


def state_dir() -> pathlib.Path:
    return pathlib.Path(
        os.environ.get(
            "HOMELABNEXT_IDS_STATE", os.path.expanduser("~/.cache/homelabnext/register_ids")
        )
    )


def _anchor(spec: RegisterSpec) -> re.Pattern:
    return re.compile(rf"(?m)^{re.escape(spec.indent)}- id: ({spec.id_re})\s*$")


def split_entries(text: str, spec: RegisterSpec):
    """(header, [(id, block_text)]) - a pure, byte-reversible text split."""
    marks = [(m.start(), m.group(1)) for m in _anchor(spec).finditer(text)]
    if not marks:
        return text, []
    blocks = []
    for i, (pos, ident) in enumerate(marks):
        end = marks[i + 1][0] if i + 1 < len(marks) else len(text)
        blocks.append((ident, text[pos:end]))
    return text[: marks[0][0]], blocks


def ids_in(text: str, spec: RegisterSpec) -> list[str]:
    return [i for i, _ in split_entries(text, spec)[1]]


def _num(ident: str, prefix: str):
    m = re.fullmatch(rf"{re.escape(prefix)}-(\d+)", ident)
    return int(m.group(1)) if m else None


def _git(root, *args):
    return subprocess.run(["git", *args], cwd=root, capture_output=True, text=True)


def git_show(root, rev: str, relpath: str):
    out = _git(root, "show", f"{rev}:{relpath}")
    return out.stdout if out.returncode == 0 else None


def repo_root(start=None) -> pathlib.Path:
    out = _git(start or os.getcwd(), "rev-parse", "--show-toplevel")
    if out.returncode:
        raise IdError("not inside a git work tree")
    return pathlib.Path(out.stdout.strip())


def allocate(root, relpath: str, prefix: str, count: int = 1) -> list[str]:
    """Claim ``count`` ids atomically across every process on this host.

    The floor is the max of: the working file, HEAD, the remote default branch refs, and a
    host-wide high-water mark that records ids a concurrent worktree claimed but has not yet
    committed. A stale cache can only skip numbers (harmless), never reuse one.
    """
    root = pathlib.Path(root)
    spec = spec_for(relpath)
    if spec is None:
        raise IdError(f"{relpath}: unknown register kind ({', '.join(SPECS)})")
    if prefix not in spec.prefixes:
        raise IdError(f"prefix {prefix!r} is not allocatable in {relpath}")
    sd = state_dir()
    sd.mkdir(parents=True, exist_ok=True)
    key = relpath.replace("/", "_") + "." + prefix
    lock_path, hwm_path = sd / f"{key}.lock", sd / f"{key}.hwm"
    fd = os.open(str(lock_path), os.O_CREAT | os.O_RDWR, 0o644)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        disk = root / relpath
        texts = [disk.read_text() if disk.exists() else ""]
        for rev in ("HEAD", "origin/main", "origin/master"):
            t = git_show(root, rev, relpath)
            if t:
                texts.append(t)
        floor = 0
        for t in texts:
            for ident in ids_in(t, spec):
                n = _num(ident, prefix)
                if n is not None:
                    floor = max(floor, n)
        with contextlib.suppress(OSError, ValueError):
            floor = max(floor, int(hwm_path.read_text().strip()))
        hwm_path.write_text(str(floor + count) + "\n")
        return [f"{prefix}-{n:0{spec.width}d}" for n in range(floor + 1, floor + 1 + count)]
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)


def resolve_file(root, relpath: str, dry_run: bool = False) -> list[tuple[str, str]]:
    """Replace every ``XX-NEW`` entry id with an allocated one, including self-citations."""
    root = pathlib.Path(root)
    spec = spec_for(relpath)
    if spec is None:
        return []
    path = root / relpath
    header, blocks = split_entries(path.read_text(), spec)
    assigned, out = [], []
    for ident, block in blocks:
        if not ident.endswith("-NEW"):
            out.append(block)
            continue
        new_id = allocate(root, relpath, ident[:-4], 1)[0]
        out.append(re.sub(rf"\b{re.escape(ident)}\b", new_id, block))
        assigned.append((ident, new_id))
    if assigned and not dry_run:
        path.write_text(header + "".join(out))
    return assigned


def _rev_exists(root, rev: str) -> bool:
    return _git(root, "rev-parse", "--verify", "--quiet", rev + "^{commit}").returncode == 0


def check_lost(root, relpath: str, allow: set[str] | None = None) -> list[str]:
    """Ids present in a parent commit but absent from the working file.

    Parents: HEAD, plus MERGE_HEAD / CHERRY_PICK_HEAD / REBASE_HEAD during conflict resolution
    (when the id that vanished came from the OTHER side). ``allow`` or the environment variable
    ``REGISTER_IDS_ALLOW_DROP=ID,ID`` waives a deliberate consolidation.
    """
    root = pathlib.Path(root)
    spec = spec_for(relpath)
    if spec is None or not spec.protected:
        return []
    path = root / relpath
    if not path.exists():
        return []
    now = set(ids_in(path.read_text(), spec))
    parents: set[str] = set()
    for rev in ("HEAD", "MERGE_HEAD", "CHERRY_PICK_HEAD", "REBASE_HEAD"):
        if _rev_exists(root, rev):
            t = git_show(root, rev, relpath)
            if t:
                parents |= set(ids_in(t, spec))
    waived = set(allow or ()) | {
        s.strip() for s in os.environ.get("REGISTER_IDS_ALLOW_DROP", "").split(",") if s.strip()
    }
    return sorted(parents - now - waived)
