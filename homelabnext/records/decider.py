# SPDX-License-Identifier: Apache-2.0
"""Operator-side movers: approve, deny, complete.

This module is the decision maker's tool.  It is **not** imported by ``homelabnext.records`` or
by the agent API, and a test pins that: an agent process that imports the agent API cannot reach
these functions without importing this module by name, which is exactly the review signal wanted.
Notes are never edited; each move leaves a ``<name>.decision.json`` audit sidecar beside it.

Keeping this module out of the agent's imports is a review signal, not an access control: any
code in the agent's process could import it.  What actually stops an agent from deciding is
filesystem ownership: run the decider as a different OS user that owns ``decided/``, and give the
agent's user write access to ``inbox/`` only.

What a decided note is.  A move never renames the inbox file into a decided lane: that would keep
the agent's inode (its owner, its mode, any hard link or open descriptor it kept), so the agent
could rewrite a note after it was approved and :meth:`Decider.complete` would act on the rewrite.
Instead the decider reads the note once, through a descriptor opened without following a symlink,
refuses anything that is not a regular file with exactly one link, validates those bytes, writes
the same bytes to a **new file** in the destination lane (created by the decider's user, so owned
by it) and only then unlinks the source.  What lands in ``decided/`` is exactly what was
validated, and nothing the agent holds refers to it.  The guarantee holds only when the decider
runs as its own OS user: run as the agent's user it owns the copy too.  The command is
``hnx records decide approve|deny|complete`` (:func:`main`).
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import stat
import sys
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from homelabnext._tempfile import write_temp

from .agent import LaneViolation
from .notes import (
    AGENT_LANE,
    DECIDED_LANES,
    Note,
    NoteError,
    check_filename,
    parse_note,
    validate_note,
)

APPROVED, DENIED, COMPLETED = DECIDED_LANES


def init_tree(root: str | os.PathLike) -> None:
    """Create the lane directories (the operator owns the tree layout)."""
    for lane in (AGENT_LANE, *DECIDED_LANES):
        (Path(root) / lane).mkdir(parents=True, exist_ok=True)


class Decider:
    def __init__(
        self,
        root: str | os.PathLike,
        *,
        decided_by: str,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ):
        if not decided_by:
            raise ValueError("decided_by is required (the audit sidecar names the decider)")
        self.root = Path(root)
        self.decided_by = decided_by
        self.clock = clock
        # (lane, name) -> the validated bytes and the (st_dev, st_ino) they were read from;
        # _move writes exactly these bytes, never re-reading the source
        self._loaded: dict[tuple[str, str], tuple[bytes, tuple[int, int]]] = {}

    # ---------------------------------------------------------------- public movers
    def approve(self, name: str) -> Path:
        note = self._load(AGENT_LANE, name)
        if note.type == "completion-request":
            raise NoteError("a completion-request is closed with complete(), not approve()")
        return self._move(note, APPROVED, "approved", None)

    def deny(self, name: str, reason: str | None = None) -> Path:
        note = self._load(AGENT_LANE, name)
        return self._move(note, DENIED, "denied", reason)

    def complete(self, name: str, reason: str | None = None) -> list[Path]:
        """Close a completion-request: move every ``related:`` item approved -> completed.

        All-or-nothing preflight: if any related item is missing, does not load and validate,
        is named twice, or would collide with a name already in ``decided/completed/`` (as would
        the request itself), the call raises before the first move and changes nothing.
        The request itself is filed under ``decided/completed/`` as well.
        """
        req = self._load(AGENT_LANE, name)
        if req.type != "completion-request":
            raise NoteError(f"{name} is type {req.type!r}, not a completion-request")
        related = list(req.frontmatter.get("related", []))
        missing = [r for r in related if not (self.root / r).is_file()]
        if missing:
            raise NoteError(f"related: not in the approved lane: {', '.join(missing)}")
        notes = [self._load(APPROVED, Path(rel).name, validate_filename=False) for rel in related]
        names = [n.name for n in notes] + [req.name]
        twice = sorted({n for n in names if names.count(n) > 1})
        if twice:
            raise NoteError(f"related: named more than once: {', '.join(twice)}")
        taken = [n for n in names if (self.root / COMPLETED / n).exists()]
        if taken:
            raise FileExistsError(f"{COMPLETED}/ already holds: {', '.join(taken)}")
        moved = []
        for note in notes:
            moved.append(self._move(note, COMPLETED, "completed", reason, via=name))
        moved.append(self._move(req, COMPLETED, "completed", reason))
        return moved

    def fulfil(self, name: str, reason: str | None = None) -> Path:
        """Approve an inbox note and close it at once, for a request the decision maker carried
        out itself (the register decider applying a ``register-transition``).  Both moves leave
        their audit sidecar, exactly as :meth:`approve` then :meth:`complete` would.

        Idempotent across a crash between the two moves: a note already in the approved lane
        (and no longer in the inbox) is only completed."""
        inbox = self.root / AGENT_LANE / name
        if os.path.lexists(inbox) or not os.path.lexists(self.root / APPROVED / name):
            self.approve(name)
        note = self._load(APPROVED, name, validate_filename=False)
        return self._move(note, COMPLETED, "completed", reason)

    # ---------------------------------------------------------------- internals
    def _load(self, lane: str, name: str, *, validate_filename: bool = True) -> Note:
        if "/" in name or "\\" in name or not name.endswith(".md"):
            raise LaneViolation(f"not a bare note filename: {name!r}")
        path = self.root / lane / name
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except FileNotFoundError:
            raise FileNotFoundError(f"{lane}/{name} does not exist") from None
        except OSError as ex:  # ELOOP: the name is a symlink
            raise LaneViolation(f"{lane}/{name} is not a regular file (a symlink?)") from ex
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                raise LaneViolation(f"{lane}/{name} is not a regular file")
            if st.st_nlink != 1:
                raise LaneViolation(
                    f"{lane}/{name} has {st.st_nlink} hard links; a note must have exactly one"
                )
            chunks = []
            while chunk := os.read(fd, 1 << 16):
                chunks.append(chunk)
        finally:
            os.close(fd)
        data = b"".join(chunks)
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError as ex:
            raise NoteError(f"{lane}/{name} is not UTF-8 text") from ex
        fm, body = parse_note(text)
        note = Note(lane=lane, name=name, frontmatter=fm, body=body.lstrip("\n"))
        validate_note(note.frontmatter)
        if validate_filename:
            problems = check_filename(name, note.frontmatter)
            if problems:
                raise NoteError("; ".join(problems))
        self._loaded[(lane, name)] = (data, (st.st_dev, st.st_ino))
        return note

    def _move(
        self, note: Note, dest_lane: str, decision: str, reason: str | None, via: str | None = None
    ) -> Path:
        try:
            data, ident = self._loaded[(note.lane, note.name)]
        except KeyError:
            raise NoteError(f"{note.lane}/{note.name} was not loaded by this decider") from None
        src = self.root / note.lane / note.name
        dest_dir = self.root / dest_lane
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest = dest_dir / note.name
        if dest.exists():
            raise FileExistsError(f"{dest_lane}/{note.name} already exists")
        side: dict[str, Any] = {
            "decision": decision,
            "decided_by": self.decided_by,
            "decided_at": self.clock().astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "from_lane": note.lane,
        }
        if reason:
            side["reason"] = reason
        if via:
            side["via"] = via
        sidecar = dest_dir / f"{note.name}.decision.json"
        tmp = dest_dir / f".{note.name}.{os.getpid()}.decision.tmp"
        tmp.write_text(json.dumps(side, indent=1, sort_keys=True) + "\n", encoding="utf-8")
        os.replace(tmp, sidecar)
        _create(dest_dir, note.name, data)
        try:
            cur = os.lstat(src)
        except FileNotFoundError:
            cur = None
        if cur is not None and (cur.st_dev, cur.st_ino) == ident:
            os.unlink(src)
        elif cur is not None:
            # swapped after it was read: the decision is on the bytes that were read (now in
            # dest_lane); the replacement is left where it is, for the operator to look at
            print(
                f"[records] WARNING: {note.lane}/{note.name} changed after it was read; "
                f"left in place, {dest_lane}/{note.name} holds the note that was decided",
                file=sys.stderr,
            )
        del self._loaded[(note.lane, note.name)]
        return dest


def _create(dest_dir: Path, name: str, data: bytes) -> None:
    """Create ``dest_dir/name`` holding ``data``, exclusively and atomically: a new inode written
    by this process (so owned by the decider's user), linked into place without following a
    symlink, never replacing an existing name."""
    dfd = os.open(dest_dir, os.O_RDONLY | os.O_DIRECTORY)
    try:
        tmp = write_temp(name, data, dir_fd=dfd, mode=0o644)
        try:
            os.link(tmp, name, src_dir_fd=dfd, dst_dir_fd=dfd, follow_symlinks=False)
        finally:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(tmp, dir_fd=dfd)
        os.fsync(dfd)
    finally:
        os.close(dfd)


def main(argv: list[str] | None = None) -> int:
    """``hnx records decide approve|deny|complete NAME``: the operator's movers for generic notes.

    Run it as the decider's OS user (the one that owns ``decided/``); the guarantee in the module
    docstring rests on that.  Exit 0 moved, 1 refused (the reason is printed), 2 usage error."""
    ap = argparse.ArgumentParser(
        prog="hnx records decide",
        description="approve, deny or complete an inbox note (run as the decider's OS user)",
    )
    ap.add_argument("action", choices=("approve", "deny", "complete"))
    ap.add_argument("name", help="the note's bare filename in inbox/")
    ap.add_argument("--root", required=True, help="the records directory (holds inbox/, decided/)")
    ap.add_argument("--by", required=True, help="who decides (recorded in the audit sidecar)")
    ap.add_argument("--reason", default=None, help="why (deny, complete)")
    try:
        ns = ap.parse_args(argv)
    except SystemExit as exc:
        return 2 if exc.code else 0
    if ns.action == "approve" and ns.reason:
        print("[records] --reason is for deny and complete", file=sys.stderr)
        return 2
    d = Decider(ns.root, decided_by=ns.by)
    try:
        if ns.action == "approve":
            moved = [d.approve(ns.name)]
        elif ns.action == "deny":
            moved = [d.deny(ns.name, ns.reason)]
        else:
            moved = d.complete(ns.name, ns.reason)
    except (NoteError, LaneViolation, FileNotFoundError, FileExistsError) as ex:
        print(f"[records] refused: {ex}", file=sys.stderr)
        return 1
    root = Path(ns.root)
    for p in moved:
        print(p.relative_to(root).as_posix())
    return 0
