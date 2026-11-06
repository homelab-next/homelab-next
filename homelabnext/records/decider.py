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
by it) and only then removes the source (claimed first, see below).  What lands in ``decided/``
is exactly what was validated, and nothing the agent holds refers to it.  The guarantee holds
only when the decider runs as its own OS user: run as the agent's user it owns the copy too.  The
command is ``hnx records decide approve|deny|complete`` (:func:`main`).

A caller that decides on a note's content (the register and strategy deciders) reads it with
:meth:`Decider.read`, the same safe load, and the movers then file exactly the bytes that call
read: a note an agent could rewrite, or one that is a symlink or hard-linked, is refused before
anything is applied, and the bytes applied are the bytes filed.  The descriptor of that read is
held open until the move ends (:meth:`Decider.close`, or ``with Decider(...)``, releases those of
notes read and never moved, and a re-read of a name releases the earlier read's).  A move of a
note whose load was released, or taken by another move, fails with :class:`FileNotFoundError`.

A decided note (and its sidecar) is created mode ``0640`` less the decider's umask (``mode=``):
agents read ``decided/`` through the group of the decider's directories, so give ``decided/`` the
agents' group (setgid on the lane directories keeps it on new files).  A decider umask of ``077``
leaves the copies unreadable to :class:`~homelabnext.records.RecordsReader`.

Exactly one decision wins.  A move claims the note before it files anything, in two steps, both
in ``decided/.claims/`` (the decider's own directory):

1. the name: ``<name>.lock`` created ``O_CREAT|O_EXCL``, so one move per note name runs at a time
   and any other move of that name fails with :class:`FileNotFoundError`, having touched nothing.
   The lock records the pid, host and UTC time of its move, and the refusal says whether that pid
   still runs on this host (a lock whose process is gone was left by a crash);
2. the entry: an atomic rename of the source into the claims directory.  ``inbox/`` and
   ``decided/`` must therefore be on **one mount**; across mounts the rename fails ``EXDEV`` and
   the move is refused, saying so.

Then the copy is written and its sidecar after it, each a new file that never replaces a name;
the claimed entry is unlinked, and the lock last.  A move that fails after its claim removes only
the files it created and renames the claimed entry back.  A crash mid-move leaves the lock (and
perhaps the claimed entry) in ``decided/.claims/``: that name is refused until the operator looks
at it and removes them, and the note is no longer in the inbox, so it cannot be decided twice.

The claimed entry is compared with the descriptor held since the read (``fstat`` against
``lstat``): the held descriptor keeps that inode alive, so its number cannot be reused by a new
file.  An entry swapped in after the read is put back at the inbox name, and the decision is on
the bytes that were read, unless a decided lane already holds the name: the lock rules out a
move in flight, so another decider filed the inode that was read and this move fails having
filed nothing.  Putting an entry back never replaces a name that has reappeared meanwhile
(``renameat2(RENAME_NOREPLACE)`` on Linux; elsewhere a check then a rename, best effort): such an
entry is left in ``decided/.claims/`` and reported.
"""

from __future__ import annotations

import argparse
import contextlib
import ctypes
import errno
import functools
import json
import os
import secrets
import socket
import stat
import sys
import weakref
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
#: where a move claims a note: an O_EXCL lock on its name, then a rename of the entry
CLAIMS = "decided/.claims"

#: what open(O_NOFOLLOW) fails with on a symlink: ELOOP (Linux, POSIX), EMLINK (FreeBSD),
#: EFTYPE (NetBSD, macOS); any other error is reported as itself
_SYMLINK_ERRNOS = frozenset(
    e for e in (errno.ELOOP, errno.EMLINK, getattr(errno, "EFTYPE", None)) if e is not None
)


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
        mode: int = 0o640,
    ):
        if not decided_by:
            raise ValueError("decided_by is required (the audit sidecar names the decider)")
        self.root = Path(root)
        self.decided_by = decided_by
        self.clock = clock
        self.mode = mode
        # (lane, name) -> the note last loaded there, for a move that follows read()
        self._loaded: dict[tuple[str, str], Note] = {}
        # id(note) -> the validated bytes, the O_NOFOLLOW descriptor they were read through and
        # the note.  One record per load, owned by that load: a move takes its record out (an
        # atomic dict pop) and closes its descriptor when it ends, so a second load or move of
        # the same name on this Decider (another thread) never closes or files another's.  The
        # descriptor is held so the inode is not freed and its number cannot be reused.
        self._held: dict[int, tuple[bytes, int, Note]] = {}
        # notes whose record a move took, or a later load of the same name released: a move of
        # one of these is told so (FileNotFoundError), not that it was never loaded
        self._spent: weakref.WeakValueDictionary[int, Note] = weakref.WeakValueDictionary()

    def close(self) -> None:
        """Release the descriptors of notes loaded (:meth:`read`) but never moved.  The
        register and strategy deciders call it after each intent; a caller of :meth:`read` that
        may not move what it read should too (or use ``with Decider(...)``)."""
        self._loaded.clear()
        while self._held:
            try:
                _, (_, fd, _) = self._held.popitem()
            except KeyError:  # emptied meanwhile by a move on another thread
                break
            with contextlib.suppress(OSError):
                os.close(fd)

    def __enter__(self) -> Decider:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def __del__(self) -> None:
        with contextlib.suppress(Exception):
            self.close()

    # ---------------------------------------------------------------- public movers
    def read(self, lane: str, name: str) -> Note:
        """Load ``lane/name`` the way a move does (no symlink, one link, validated) and keep its
        bytes: a following :meth:`approve`, :meth:`deny` or :meth:`fulfil` of that note files
        exactly these bytes, so a caller that decides on what this returns files what it decided
        on.  Raises :class:`LaneViolation` (a :class:`PermissionError`) for a symlink or a
        hard-linked note and :class:`NoteError` for one that does not validate.  The file name
        is not checked against the front-matter here (:meth:`approve` does)."""
        return self._load(lane, name, validate_filename=False)

    def approve(self, name: str) -> Path:
        note = self._note(AGENT_LANE, name)
        if note.type == "completion-request":
            raise NoteError("a completion-request is closed with complete(), not approve()")
        return self._move(note, APPROVED, "approved", None)

    def deny(self, name: str, reason: str | None = None) -> Path:
        note = self._note(AGENT_LANE, name)
        return self._move(note, DENIED, "denied", reason)

    def complete(self, name: str, reason: str | None = None) -> list[Path]:
        """Close a completion-request: move every ``related:`` item approved -> completed.

        All-or-nothing preflight: if any related item is missing, does not load and validate,
        is named twice, or would collide with a name already in ``decided/completed/`` (as would
        the request itself), the call raises before the first move and changes nothing.
        The request itself is filed under ``decided/completed/`` as well.
        """
        req = self._note(AGENT_LANE, name)
        if req.type != "completion-request":
            raise NoteError(f"{name} is type {req.type!r}, not a completion-request")
        related = [str(r) for r in req.frontmatter.get("related", [])]
        # exactly decided/approved/<file>.md: the note completed is the one named, never a path
        # elsewhere that is only stat'ed (the schema says so too; this does not rely on it)
        bad = [r for r in related if r != f"{APPROVED}/{Path(r).name}"]
        if bad:
            raise NoteError(f"related: not a {APPROVED}/<file>.md entry: {', '.join(bad)}")
        missing = [r for r in related if not os.path.lexists(self.root / r)]
        if missing:
            raise NoteError(f"related: not in the approved lane: {', '.join(missing)}")
        notes: list[Note] = []
        try:
            for rel in related:
                notes.append(self._load(APPROVED, Path(rel).name, validate_filename=False))
            names = [n.name for n in notes] + [req.name]
            twice = sorted({n for n in names if names.count(n) > 1})
            if twice:
                raise NoteError(f"related: named more than once: {', '.join(twice)}")
            taken = [n for n in names if (self.root / COMPLETED / n).exists()]
            if taken:
                raise FileExistsError(f"{COMPLETED}/ already holds: {', '.join(taken)}")
        except BaseException:
            # the preflight refused: nothing moves, so release what it loaded
            for n in (*notes, req):
                self._release(n)
            raise
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
    def _note(self, lane: str, name: str) -> Note:
        """The note :meth:`read` kept for ``lane/name``, its file name checked; else a fresh
        load."""
        note = self._loaded.get((lane, name))
        if note is None:
            return self._load(lane, name)
        problems = check_filename(name, note.frontmatter)
        if problems:
            raise NoteError("; ".join(problems))
        return note

    def _load(self, lane: str, name: str, *, validate_filename: bool = True) -> Note:
        if "/" in name or "\\" in name or not name.endswith(".md"):
            raise LaneViolation(f"not a bare note filename: {name!r}")
        path = self.root / lane / name
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except FileNotFoundError:
            raise FileNotFoundError(f"{lane}/{name} does not exist") from None
        except OSError as ex:
            if ex.errno in _SYMLINK_ERRNOS:
                raise LaneViolation(f"{lane}/{name} is not a regular file (a symlink)") from ex
            raise
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
            return self._keep(lane, name, b"".join(chunks), fd, validate_filename)
        except BaseException:
            os.close(fd)
            raise

    def _keep(self, lane: str, name: str, data: bytes, fd: int, validate_filename: bool) -> Note:
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError as ex:
            raise NoteError(f"{lane}/{name} is not UTF-8 text") from ex
        # parse with universal newlines, as read_note's read_text does (a CRLF note validates);
        # the bytes filed are still the ones read
        text = text.replace("\r\n", "\n").replace("\r", "\n")
        fm, body = parse_note(text)
        note = Note(lane=lane, name=name, frontmatter=fm, body=body.lstrip("\n"))
        validate_note(note.frontmatter)
        if validate_filename:
            problems = check_filename(name, note.frontmatter)
            if problems:
                raise NoteError("; ".join(problems))
        self._held[id(note)] = (data, fd, note)
        prev = self._loaded.get((lane, name))
        self._loaded[(lane, name)] = note
        if prev is not None and prev is not note:
            # a re-read supersedes the earlier load of this name: release its descriptor unless
            # a move already took it (the pop in _release is atomic, so exactly one of the two
            # gets the record)
            self._release(prev)
        return note

    def _release(self, note: Note) -> None:
        """Close the descriptor of ``note``'s load if no move has taken it."""
        rec = self._held.pop(id(note), None)
        if rec is None:
            return
        if rec[2] is not note:  # not this note's record: put it back
            self._held[id(rec[2])] = rec
            return
        self._spent[id(note)] = note
        key = (note.lane, note.name)
        if self._loaded.get(key) is note:
            self._loaded.pop(key, None)
        with contextlib.suppress(OSError):
            os.close(rec[1])

    def _move(
        self, note: Note, dest_lane: str, decision: str, reason: str | None, via: str | None = None
    ) -> Path:
        rec = self._held.pop(id(note), None)
        if rec is None or rec[2] is not note:
            if rec is not None:
                self._held[id(rec[2])] = rec
            if self._spent.get(id(note)) is note:
                raise FileNotFoundError(
                    f"{note.lane}/{note.name} is being (or was) decided by another move, or was "
                    "read again since: decide the note the later read returned"
                )
            raise NoteError(f"{note.lane}/{note.name} was not loaded by this decider")
        self._spent[id(note)] = note
        key = (note.lane, note.name)
        if self._loaded.get(key) is note:
            self._loaded.pop(key, None)
        data, held, _ = rec
        try:
            return self._move_held(note, dest_lane, decision, reason, via, data, held)
        finally:
            os.close(held)

    def _move_held(
        self,
        note: Note,
        dest_lane: str,
        decision: str,
        reason: str | None,
        via: str | None,
        data: bytes,
        held: int,
    ) -> Path:
        dest_dir = self.root / dest_lane
        dest_dir.mkdir(parents=True, exist_ok=True)
        if (dest_dir / note.name).exists():
            raise FileExistsError(f"{dest_lane}/{note.name} already exists")
        claim_dir = self.root / CLAIMS
        claim_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        # 1. the name: one move per note name at a time, whatever its lanes.  Every other move of
        #    this name fails here, before it has touched anything.
        lock = claim_dir / f"{note.name}.lock"
        try:
            lfd = os.open(lock, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        except FileExistsError:
            raise FileNotFoundError(
                f"{note.lane}/{note.name} is being decided by another move: {_lock_holder(lock)}"
            ) from None
        try:
            os.write(lfd, _lock_record().encode("utf-8"))
        except OSError:
            pass  # the lock is the name; its content only helps an operator with a stale one
        finally:
            os.close(lfd)
        try:
            return self._move_locked(note, dest_lane, decision, reason, via, data, held)
        finally:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(lock)

    def _move_locked(
        self,
        note: Note,
        dest_lane: str,
        decision: str,
        reason: str | None,
        via: str | None,
        data: bytes,
        held: int,
    ) -> Path:
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
        src = self.root / note.lane / note.name
        dest_dir = self.root / dest_lane
        claim: Path | None = self.root / CLAIMS / f"{note.name}.{secrets.token_hex(8)}"
        # 2. the entry: an atomic rename into the decider's own directory.  A source the decider
        #    may not move (EACCES, EPERM: a sticky inbox it does not own) is refused here, before
        #    anything is filed.
        try:
            os.rename(src, claim)
        except FileNotFoundError:
            raise FileNotFoundError(
                f"{note.lane}/{note.name} does not exist (already decided?)"
            ) from None
        except OSError as ex:
            if ex.errno == errno.EXDEV:
                raise OSError(
                    errno.EXDEV, f"{note.lane}/ and decided/ must be on one mount", str(src)
                ) from ex
            raise
        sidecar = f"{note.name}.decision.json"
        made: list[str] = []  # only what this move created is ever removed again
        try:  # from here on, any failure puts the claimed entry back
            # the descriptor held since the read keeps that inode alive, so no new file can reuse
            # its number: another (st_dev, st_ino) is another file
            was, cur = os.fstat(held), os.lstat(claim)
            if (cur.st_dev, cur.st_ino) != (was.st_dev, was.st_ino):
                # swapped after the read: put the replacement back where the agent left it.
                # The name lock is held, so no other move is filing this name now: a decided
                # lane holding it means another decider filed the inode that was read, and this
                # move lost.
                _unclaim(claim, src)
                claim = None
                taken = [
                    lane for lane in DECIDED_LANES if os.path.lexists(self.root / lane / note.name)
                ]
                if taken:
                    raise FileNotFoundError(
                        f"{note.lane}/{note.name} was decided meanwhile (in {', '.join(taken)})"
                    )
            # 3. the copy, then the sidecar: each a new file that never replaces a name
            _create(dest_dir, note.name, data, self.mode)
            made.append(note.name)
            body = json.dumps(side, indent=1, sort_keys=True) + "\n"
            _create(dest_dir, sidecar, body.encode("utf-8"), self.mode)
            made.append(sidecar)
        except BaseException:
            for name in reversed(made):
                with contextlib.suppress(FileNotFoundError):
                    os.unlink(dest_dir / name)
            if claim is not None:
                _unclaim(claim, src)
            raise
        if claim is not None:
            # 4. the claimed entry goes last (then the name lock, in _move_held)
            try:
                os.unlink(claim)
            except OSError as ex:
                print(
                    f"[records] WARNING: {dest_lane}/{note.name} is filed but its claimed source "
                    f"{claim.relative_to(self.root)} could not be removed: {ex}",
                    file=sys.stderr,
                )
        else:
            # the decision is on the bytes that were read (now in dest_lane); the replacement is
            # left where it is, for the operator to look at
            print(
                f"[records] WARNING: {note.lane}/{note.name} changed after it was read; "
                f"left in place, {dest_lane}/{note.name} holds the note that was decided",
                file=sys.stderr,
            )
        return dest_dir / note.name


def _lock_record() -> str:
    now = datetime.now(UTC)  # hermetic: allow a lock record names when it was taken
    return f"pid={os.getpid()} host={socket.gethostname()} since={now:%Y-%m-%dT%H:%M:%SZ}\n"


def _lock_holder(lock: Path) -> str:
    """Who holds ``lock``, as its record says, and whether that pid still runs on this host."""
    where = f"{CLAIMS}/{lock.name}"
    try:
        fd = os.open(lock, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            text = os.read(fd, 512).decode("utf-8", "replace")
        finally:
            os.close(fd)
    except OSError:
        return f"{where} (released meanwhile)"
    fields = dict(f.split("=", 1) for f in text.split() if "=" in f)
    pid, host, since = fields.get("pid", ""), fields.get("host", ""), fields.get("since", "?")
    if not pid.isdigit():
        return f"{where} (being written, or not a lock this decider wrote)"
    held = f"{where} held by pid {pid} on {host or '?'} since {since}"
    if host != socket.gethostname():
        return f"{held} (another host: its liveness is not checked from here)"
    if _pid_alive(int(pid)):
        return f"{held} (that process is running)"
    return (
        f"{held} (no such process: a move that crashed; check {CLAIMS}/ for its claimed entry, "
        f"put it back or file it, then remove {where})"
    )


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True  # it exists, under another user
    return True


def leftover_claims(root: str | os.PathLike) -> list[str]:
    """The entries in ``decided/.claims/`` (locks and claimed notes); empty when no move is
    running, so any listed then were left by a move that crashed."""
    d = Path(root) / CLAIMS
    return sorted(os.listdir(d)) if d.is_dir() else []


def _unclaim(claim: Path, src: Path) -> None:
    """Put a claimed entry back at ``src``, never over a name that has reappeared meanwhile
    (``renameat2(RENAME_NOREPLACE)`` on Linux; elsewhere a check then a rename, best effort).
    An entry that cannot go back stays in the claims directory, and that is reported."""
    try:
        _rename_noreplace(claim, src)
    except OSError as ex:
        print(
            f"[records] WARNING: could not put {claim.name} back at {src} ({ex}); "
            f"it is left in {claim.parent}",
            file=sys.stderr,
        )


_RENAME_NOREPLACE = 1
_AT_FDCWD = -100


@functools.cache
def _renameat2() -> Any:
    """libc's ``renameat2`` on Linux, else None."""
    if not sys.platform.startswith("linux"):
        return None
    try:
        fn = ctypes.CDLL(None, use_errno=True).renameat2
    except (OSError, AttributeError):
        return None
    fn.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    fn.restype = ctypes.c_int
    return fn


def _rename_noreplace(src: Path, dst: Path) -> None:
    """Rename ``src`` to ``dst``; :class:`FileExistsError` if ``dst`` exists."""
    fn = _renameat2()
    if fn is not None:
        if fn(_AT_FDCWD, os.fsencode(src), _AT_FDCWD, os.fsencode(dst), _RENAME_NOREPLACE) == 0:
            return
        err = ctypes.get_errno()
        if err not in (errno.ENOSYS, errno.EINVAL):  # EINVAL: the filesystem lacks the flag
            raise OSError(err, os.strerror(err), str(dst))
    if os.path.lexists(dst):  # the fallback: a check, then a rename (best effort)
        raise FileExistsError(errno.EEXIST, os.strerror(errno.EEXIST), str(dst))
    os.rename(src, dst)


def _create(dest_dir: Path, name: str, data: bytes, mode: int) -> None:
    """Create ``dest_dir/name`` holding ``data``, exclusively and atomically: a new inode written
    by this process (so owned by the decider's user), linked into place without following a
    symlink, never replacing an existing name."""
    dfd = os.open(dest_dir, os.O_RDONLY | os.O_DIRECTORY)
    try:
        tmp = write_temp(name, data, dir_fd=dfd, mode=mode)
        try:
            os.link(tmp, name, src_dir_fd=dfd, dst_dir_fd=dfd, follow_symlinks=False)
        finally:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(tmp, dir_fd=dfd)
        os.fsync(dfd)
    finally:
        os.close(dfd)


def _report_leftovers(root: str) -> None:
    left = leftover_claims(root)
    if left:
        print(
            f"[records] {CLAIMS}/ holds {', '.join(left)}: a move that is running or crashed",
            file=sys.stderr,
        )


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
    try:
        d = Decider(ns.root, decided_by=ns.by)
    except ValueError as ex:
        print(f"[records] {ex}", file=sys.stderr)
        return 2
    try:
        if ns.action == "approve":
            moved = [d.approve(ns.name)]
        elif ns.action == "deny":
            moved = [d.deny(ns.name, ns.reason)]
        else:
            moved = d.complete(ns.name, ns.reason)
    except (NoteError, OSError) as ex:  # LaneViolation, FileNotFoundError: OSErrors too
        print(f"[records] refused: {ex}", file=sys.stderr)
        _report_leftovers(ns.root)
        return 1
    finally:
        d.close()
    root = Path(ns.root)
    for p in moved:
        print(p.relative_to(root).as_posix())
    return 0
