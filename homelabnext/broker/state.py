# SPDX-License-Identifier: Apache-2.0
"""Durable, conflict-free broker state under one directory (ADR-0014, ADR-0017).

Every write is a whole new file created exclusively (written to a temp name, fsynced, then
hard-linked to its final name, which fails when the name exists), so two processes never write
the same file and nothing is ever rewritten in place.  State is *derived* from which files exist:

``requests/<rid>.json``          the request as admitted (immutable)
``open/<rid>.json``              an index of the requests with no claim yet (``pending``), so a
                                 listing of what is pending reads only those; written after the
                                 request, removed after its claim, rebuilt for an older state
                                 directory, and checked against ``claims/`` on every read
``claims/<rid>.json``            the one terminal-or-running transition: ``run``, ``cancel`` or
                                 ``deny``.  Exclusive create: of a racing run and cancel, or two
                                 runs, exactly one wins
``results/<rid>.json``           how a claimed run ended (``done`` / ``error``)
``approvals/<rid>/<aid>.json``   approval and denial documents (``schemas/broker/approval``)
``consumed/<aid>.json``          consumed-approval markers: :class:`FileApprovalStore`, so an
                                 approval is single use across processes and restarts
``audit/<stamp>-<pid>-<n>-<rand>.json``  one audit record per file (``schemas/broker/audit``)
``decisions/<same name>``        an index of the audit trail's filed decisions (``ok`` approve and
                                 deny records), so the hub's recent-decisions and "already
                                 decided" reads cost O(decisions), however many refusals the trail
                                 holds; written after the audit record, rebuilt in full until the
                                 rebuild has once completed (``decisions.complete``), and on every
                                 start the newest :data:`RECONCILE_AUDIT` audit records are
                                 re-indexed, so a crash between the two writes loses no decision
``outbox/<event id>.json``       events emitted when no bus is configured, each with its place in
                                 emit order (``queued``: the next value of ``outbox.seq``, taken
                                 and linked under one ``flock``); ``hnx broker relay`` publishes
                                 them
``outbox.seq``                   the outbox's persisted counter (``flock``-guarded), so emit order
                                 survives restarts, other processes and a clock that goes back
``relay/``                       ``hnx broker relay``'s own directory (its user's, when it runs
                                 as one): ``delivered/`` (the bus acknowledged the event, or it
                                 was ``superseded`` on the first start), ``undeliverable/`` and
                                 ``quarantine/`` (malformed files), each a copy of the event with
                                 a receipt; the broker removes an outbox file once it has one
                                 (:meth:`StateDir.prune_outbox`).  Lock, first-start marker.
``digest.key``                   the broker-held key (hex) for the keyed hash of secret arguments in a
                                 request digest (created once, exclusively)
``runs/<rid>/``                  a run's private directory (handler copy, stdout, stderr)

A request's state: no claim -> ``pending``; claim ``cancel`` -> ``cancelled``; claim ``deny`` ->
``denied``; claim ``run`` -> the result's ``done`` / ``error``, or ``running`` while there is none.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import secrets
import threading
import time
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

__all__ = [
    "FileApprovalStore",
    "StateDir",
    "StateError",
    "is_id",
    "new_id",
    "write_exclusive",
    "write_temp",
]

#: the id shape of requests, approvals and audit records (``schemas/ids/common`` slug)
_ID_RE = re.compile(r"^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$")
_SUBDIRS = (
    "requests",
    "open",
    "claims",
    "results",
    "approvals",
    "consumed",
    "audit",
    "decisions",
    "outbox",
    "runs",
)
_KEY_BYTES = 32
#: how many of the newest audit records every start re-indexes into ``decisions/``
RECONCILE_AUDIT = 256
#: written once a full rebuild of ``decisions/`` has finished (an interrupted one runs again)
DECISIONS_COMPLETE = "decisions.complete"
#: the audit records the ``decisions/`` index holds: (operation, outcome)
DECISION_KINDS = frozenset({("approve", "ok"), ("deny", "ok")})
#: the outbox's persisted emit-order counter (:meth:`StateDir.put_outbox`)
OUTBOX_SEQ = "outbox.seq"
#: the relay's directory under the state directory, and its kinds of "done with this event"
RELAY_DIR = "relay"
RELAY_DONE = ("delivered", "undeliverable", "quarantine")
#: how often (at most) the broker removes outbox files the relay is done with
PRUNE_INTERVAL_S = 60.0


class StateError(RuntimeError):
    """The state directory is unusable (not a directory, a symlinked subdirectory, ...)."""


def is_id(value: Any) -> bool:
    """True for a slug id of at most 64 characters: the only names used as state file names."""
    return isinstance(value, str) and len(value) <= 64 and bool(_ID_RE.match(value))


def new_id(prefix: str) -> str:
    return f"{prefix}-{secrets.token_hex(8)}"


def write_temp(name: str, data: bytes, *, dir_fd: int, mode: int = 0o600) -> str:
    """Write ``data`` to a new temporary file beside ``name`` in the directory ``dir_fd`` and
    fsync it; returns the temporary name.  The one place the broker writes file bytes: callers
    then link (exclusive) or rename (replace) it into place and unlink the temp name."""
    tmp = f".{name}.{os.getpid()}.{secrets.token_hex(4)}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode, dir_fd=dir_fd)
    try:
        view = memoryview(data)
        while view:
            view = view[os.write(fd, view) :]
        os.fsync(fd)
    finally:
        os.close(fd)
    return tmp


def write_exclusive(path: Path, data: bytes, *, mode: int = 0o600) -> bool:
    """Create ``path`` with ``data`` atomically and exclusively; False when it already exists.

    The bytes are written and fsynced under a temporary name first, so a reader never sees a
    partial file, and the final name is taken with a hard link, which fails if it exists.
    """
    dir_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        tmp = write_temp(path.name, data, dir_fd=dir_fd, mode=mode)
        try:
            os.link(tmp, path.name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd, follow_symlinks=False)
        except FileExistsError:
            return False
        finally:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(tmp, dir_fd=dir_fd)
        with contextlib.suppress(OSError):
            os.fsync(dir_fd)
        return True
    finally:
        os.close(dir_fd)


def _dumps(doc: Any) -> bytes:
    return (json.dumps(doc, sort_keys=True, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def _order(doc: dict[str, Any]) -> int:
    """A request record's position in time: ``submitted_ns``, else its ``created`` stamp."""
    if isinstance(doc.get("submitted_ns"), int):
        return doc["submitted_ns"]
    from datetime import datetime

    created = str((doc.get("request") or {}).get("created", ""))
    try:
        return int(datetime.fromisoformat(created.replace("Z", "+00:00")).timestamp() * 1e9)
    except ValueError:
        return 0


def _load(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None


def _is_decision(record: dict[str, Any]) -> bool:
    return (record.get("operation"), record.get("outcome")) in DECISION_KINDS


class StateDir:
    """The broker's state directory.  Created ``0700``: it holds requests and audit records."""

    def __init__(
        self,
        root: str | os.PathLike[str],
        *,
        clock_ns: Callable[[], int] = time.time_ns,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self.root = Path(root)
        self._clock_ns = clock_ns  # orders requests (``submitted_ns``)
        self._monotonic = monotonic  # paces prune_outbox
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        index_missing = not (self.root / "open").exists()
        for name in _SUBDIRS:
            d = self.root / name
            if d.is_symlink():
                raise StateError(f"{d} is a symlink; broker state directories must be real")
            d.mkdir(mode=0o700, exist_ok=True)
        self._seq = 0
        self._last_stamp = ""
        self._audit_lock = threading.Lock()  # a threaded server shares one instance
        self._key: bytes | None = None
        self._pruned = float("-inf")
        if index_missing:  # a state directory from before the index: build it once
            for rid in self.request_ids():
                if self.get_claim(rid) is None:
                    self._mark_open(rid, self.get_request(rid) or {})
        self._index_decisions()
        self.prune_outbox(force=True)

    def _index_decisions(self) -> None:
        """Rebuild ``decisions/`` from the whole trail until a rebuild has once completed; then
        re-index the newest :data:`RECONCILE_AUDIT` records (a decision whose index write a
        crash interrupted).  Both are idempotent: an existing index file is left as it is."""
        names = sorted(p.name for p in self._dir("audit").glob("*.json"))
        complete = (self.root / DECISIONS_COMPLETE).exists()
        for name in names if not complete else names[-RECONCILE_AUDIT:]:
            if (self._dir("decisions") / name).exists():
                continue
            doc = _load(self._dir("audit") / name)
            if isinstance(doc, dict) and _is_decision(doc):
                write_exclusive(self._dir("decisions") / name, _dumps(doc))
        if not complete:
            write_exclusive(self.root / DECISIONS_COMPLETE, b"1\n")

    def _dir(self, name: str) -> Path:
        return self.root / name

    @staticmethod
    def _checked(rid: str) -> str:
        if not is_id(rid):
            raise StateError(f"not a broker id: {rid!r}")
        return rid

    # ---------------------------------------------------------------- requests and transitions
    def put_request(self, rid: str, doc: dict[str, Any]) -> bool:
        """Store a request (``submitted_ns`` is added: the order requests are listed in)."""
        doc = {**doc, "submitted_ns": doc.get("submitted_ns", self._clock_ns())}
        if not write_exclusive(self._dir("requests") / f"{self._checked(rid)}.json", _dumps(doc)):
            return False
        self._mark_open(rid, doc)
        return True

    def _mark_open(self, rid: str, doc: dict[str, Any]) -> None:
        marker = {"request_id": rid, "submitted_ns": _order(doc)}
        write_exclusive(self._dir("open") / f"{rid}.json", _dumps(marker))

    def get_request(self, rid: str) -> dict[str, Any] | None:
        return _load(self._dir("requests") / f"{rid}.json") if is_id(rid) else None

    def request_ids(self) -> list[str]:
        """Every request id, oldest first.  Reads every request: the full-history path."""
        rids = [p.stem for p in self._dir("requests").glob("*.json") if is_id(p.stem)]
        return sorted(rids, key=lambda r: (_order(self.get_request(r) or {}), r))

    def open_request_ids(self) -> list[str]:
        """The ids of requests with no claim yet (``pending``), oldest first; reads only the
        ``open/`` index, dropping a marker whose request has since been claimed."""
        keyed = []
        for p in self._dir("open").glob("*.json"):
            rid = p.stem
            if not is_id(rid):
                continue
            if (self._dir("claims") / f"{rid}.json").exists():
                with contextlib.suppress(FileNotFoundError):
                    p.unlink()  # a claim whose marker removal was interrupted
                continue
            marker = _load(p) or {}
            keyed.append((marker.get("submitted_ns", 0), rid))
        return [rid for _, rid in sorted(keyed)]

    def claim(self, rid: str, doc: dict[str, Any]) -> bool:
        """Take the request's single transition; False when another one already took it."""
        if not write_exclusive(self._dir("claims") / f"{self._checked(rid)}.json", _dumps(doc)):
            return False
        with contextlib.suppress(FileNotFoundError):
            (self._dir("open") / f"{rid}.json").unlink()
        return True

    def get_claim(self, rid: str) -> dict[str, Any] | None:
        return _load(self._dir("claims") / f"{rid}.json") if is_id(rid) else None

    def put_result(self, rid: str, doc: dict[str, Any]) -> bool:
        return write_exclusive(self._dir("results") / f"{self._checked(rid)}.json", _dumps(doc))

    def get_result(self, rid: str) -> dict[str, Any] | None:
        return _load(self._dir("results") / f"{rid}.json") if is_id(rid) else None

    def state_of(self, rid: str) -> str:
        claim = self.get_claim(rid)
        if claim is None:
            return "pending"
        op = claim.get("op")
        if op == "cancel":
            return "cancelled"
        if op == "deny":
            return "denied"
        result = self.get_result(rid)
        return "running" if result is None else str(result.get("state", "error"))

    # ---------------------------------------------------------------- approvals
    def put_approval(self, approval: dict[str, Any]) -> bool:
        rid, aid = self._checked(approval["request_id"]), self._checked(approval["approval_id"])
        d = self._dir("approvals") / rid
        d.mkdir(mode=0o700, exist_ok=True)
        return write_exclusive(d / f"{aid}.json", _dumps(approval))

    def approvals(self, rid: str) -> list[dict[str, Any]]:
        """Every approval document filed for ``rid``, oldest first."""
        d = self._dir("approvals") / rid
        if not is_id(rid) or not d.is_dir():
            return []
        docs = [doc for p in d.glob("*.json") if (doc := _load(p)) is not None]
        return sorted(docs, key=lambda a: (a.get("approved_at", ""), a.get("approval_id", "")))

    # ---------------------------------------------------------------- audit and outbox
    def append_audit(self, record: dict[str, Any], stamp: str) -> Path:
        """Write one audit record.  ``stamp`` (sortable UTC) orders the trail; within one process
        it never goes backwards, and a sequence number breaks ties."""
        with self._audit_lock:
            stamp = max(stamp, self._last_stamp)
            self._last_stamp = stamp
            self._seq += 1
            seq = self._seq
        name = f"{stamp}-{os.getpid():07d}-{seq:08d}-{secrets.token_hex(3)}.json"
        path = self._dir("audit") / name
        if not write_exclusive(path, _dumps(record)):  # pragma: no cover - random suffix
            raise StateError(f"audit record {name} already exists")
        if _is_decision(record):
            write_exclusive(self._dir("decisions") / name, _dumps(record))
        return path

    def audit_records(self, *, newest_first: bool = False) -> Iterator[dict[str, Any]]:
        """Audit records in trail order (or newest first): names are listed, and a record is
        read only when the iteration reaches it, so a tail reads only the tail."""
        yield from self._records("audit", newest_first)

    def decision_records(self, *, newest_first: bool = False) -> Iterator[dict[str, Any]]:
        """The ``decisions/`` index: the audit records of filed approvals and denials only."""
        yield from self._records("decisions", newest_first)

    def _records(self, where: str, newest_first: bool) -> Iterator[dict[str, Any]]:
        for p in sorted(self._dir(where).glob("*.json"), reverse=newest_first):
            doc = _load(p)
            if doc is not None:
                yield doc

    # ---------------------------------------------------------------- the digest key
    def digest_key(self) -> bytes:
        """The broker-held key for the keyed hash of secret arguments (``digest.key``, 0600):
        created once, exclusively, so every process sharing this directory uses the same one."""
        if self._key is None:
            path = self.root / "digest.key"
            fresh = secrets.token_hex(_KEY_BYTES) + "\n"
            write_exclusive(path, fresh.encode("ascii"))  # False: another process made it first
            try:
                key = bytes.fromhex(path.read_text(encoding="ascii").strip())
            except ValueError:
                key = b""
            if len(key) != _KEY_BYTES:
                raise StateError(f"{path} is not a {_KEY_BYTES}-byte hex key")
            self._key = key
        return self._key

    def put_outbox(self, event: dict[str, Any]) -> bool:
        """Record an event (idempotent per event id: a repeat is a no-op) with its place in emit
        order, ``queued``: the next value of the persisted counter ``outbox.seq``.

        The counter is taken and the file linked under one exclusive ``flock`` (and this
        instance's lock), so across threads and processes an event becomes visible only after
        every event with a smaller ``queued`` is: a relay pass that sees event *n* sees every
        earlier one still pending.  No clock is involved, so a clock stepped back (or two
        processes' clocks) cannot reorder events."""
        eid = self._event_id(event.get("id"))
        path = self._dir("outbox") / f"{eid}.json"
        if path.exists():
            return False
        with self._audit_lock, self._outbox_seq() as take:
            if path.exists():
                return False
            doc = {"queued": take(), "event": event}
            # group-readable: the relay may run as its own user in the outbox's group
            written = write_exclusive(path, _dumps(doc), mode=0o640)
        self.prune_outbox()
        return written

    @contextlib.contextmanager
    def _outbox_seq(self) -> Iterator[Callable[[], int]]:
        """Hold ``outbox.seq``'s ``flock``; yields a function returning the next value (stored
        before it is returned, so a crash leaves a gap, never a repeat)."""
        import fcntl

        fd = os.open(self.root / OUTBOX_SEQ, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)

            def take() -> int:
                raw = os.pread(fd, 64, 0).decode("ascii", "replace").strip()
                last = int(raw) if raw.isdigit() else self._outbox_max_queued()
                value = last + 1
                os.pwrite(fd, f"{value:020d}\n".encode("ascii"), 0)
                os.fsync(fd)
                return value

            yield take
        finally:
            os.close(fd)  # releases the flock

    def _outbox_max_queued(self) -> int:
        """The largest ``queued`` in the outbox (a missing or unreadable ``outbox.seq``): every
        event still pending sorts before the next one."""
        best = 0
        for p in outbox_files(self._dir("outbox")):
            entry = self._outbox_entry(p)
            if entry is not None and entry[0][0] == 1:
                best = max(best, entry[0][1])
        return best

    @staticmethod
    def _event_id(eid: Any) -> str:
        eid = str(eid or "")
        if not eid or "/" in eid or eid.startswith(".") or len(eid) > 200:
            raise StateError(f"not an event id: {eid[:80]!r}")
        return eid

    def _outbox_entry(self, path: Path) -> tuple[tuple[int, int, str], dict[str, Any]] | None:
        try:
            return read_outbox_file(path)
        except (OutboxFileError, FileNotFoundError):
            return None  # malformed: the relay quarantines it (relay/quarantine/)

    def outbox(self) -> list[dict[str, Any]]:
        """Every event still in the outbox, in emit order (the relay may have published some;
        :meth:`prune_outbox` removes those)."""
        entries = (self._outbox_entry(p) for p in outbox_files(self._dir("outbox")))
        return [ev for _, ev in sorted(e for e in entries if e is not None)]

    def prune_outbox(self, *, force: bool = False) -> int:
        """Remove every outbox file the relay is done with (a marker under ``relay/delivered``,
        ``relay/undeliverable`` or ``relay/quarantine``), so ``outbox/`` holds what is pending and
        a relay pass costs O(pending).  The relay's marker keeps the event (and its receipt).
        Runs at most every :data:`PRUNE_INTERVAL_S` unless ``force``; returns how many it removed.
        The broker owns ``outbox/``, so it is the one that removes; the relay only reads it."""
        now = self._monotonic()
        if not force and now - self._pruned < PRUNE_INTERVAL_S:
            return 0
        self._pruned = now
        relay, removed = self.root / RELAY_DIR, 0
        try:  # never fails an emit: a relay directory the broker cannot read prunes nothing
            if not relay.is_dir():
                return 0
            for path in outbox_files(self._dir("outbox")):
                if any((relay / kind / path.name).exists() for kind in RELAY_DONE):
                    with contextlib.suppress(FileNotFoundError):
                        path.unlink()
                        removed += 1
        except OSError:
            pass
        return removed


class OutboxFileError(ValueError):
    """An outbox file that is not an event the relay can publish; ``reason`` is a short code."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def outbox_files(directory: Path) -> list[Path]:
    """The outbox's event files (``*.json``; never a temporary ``.name.tmp``)."""
    return [p for p in directory.glob("*.json") if not p.name.startswith(".")]


def read_outbox_file(path: Path) -> tuple[tuple[int, int, str], dict[str, Any]]:
    """``((format, position, name), event)`` of one outbox file, or :class:`OutboxFileError`.

    A current file is ``{"queued": <int>, "event": {...}}`` and sorts by ``queued``.  A file from
    before ``queued`` (the bare event, written by a broker without the relay) sorts before every
    current one, by its ``time`` (whole seconds) and then its id: it was emitted before anything
    with a ``queued``, and within one second the id is the only order there is.  Either way the
    event must name its id (the file's name) and its type.  A file that cannot be read (but
    exists: :class:`FileNotFoundError` passes through, it was pruned) is ``unreadable``: one file
    the relay may not read must cost that file, never every pass."""
    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        raise
    except OSError:  # permission, a directory named *.json, an I/O error
        raise OutboxFileError("unreadable") from None
    try:
        doc = json.loads(raw)
    except (UnicodeDecodeError, ValueError):
        raise OutboxFileError("not-json") from None
    if not isinstance(doc, dict):
        raise OutboxFileError("not-an-object")
    if "queued" in doc or "event" in doc:
        queued, event = doc.get("queued"), doc.get("event")
        if not isinstance(queued, int) or isinstance(queued, bool) or queued < 1:
            raise OutboxFileError("bad-queued")
        if not isinstance(event, dict):
            raise OutboxFileError("bad-event")
        key: tuple[int, int, str] = (1, queued, path.stem)
    else:
        event = doc
        key = (0, _order({"request": {"created": str(doc.get("time", ""))}}), path.stem)
    if event.get("id") != path.stem:
        raise OutboxFileError("bad-id")
    if not isinstance(event.get("type"), str) or not event["type"]:
        raise OutboxFileError("no-type")
    return key, event


class FileApprovalStore:
    """Durable :class:`homelabnext.broker.ApprovalStore`: ``consumed/<approval_id>.json``.

    ``consume`` is an exclusive create, so it is atomic across threads *and* processes and
    survives a restart: of any number of racing consumers exactly one gets True.
    """

    def __init__(self, directory: str | os.PathLike[str]) -> None:
        self.dir = Path(directory)
        self.dir.mkdir(mode=0o700, parents=True, exist_ok=True)

    def _path(self, approval_id: str) -> Path:
        if not is_id(approval_id):
            raise StateError(f"not an approval id: {approval_id!r}")
        return self.dir / f"{approval_id}.json"

    def consume(self, approval_id: str) -> bool:
        return write_exclusive(self._path(approval_id), _dumps({"approval_id": approval_id}))

    def consumed(self, approval_id: str) -> bool:
        return self._path(approval_id).exists()
