# SPDX-License-Identifier: Apache-2.0
"""Durable, conflict-free broker state under one directory (ADR-0014, ADR-0017).

Every write is a whole new file created exclusively (written to a temp name, fsynced, then
hard-linked to its final name, which fails when the name exists), so two processes never write
the same file and nothing is ever rewritten in place.  State is *derived* from which files exist:

``requests/<rid>.json``          the request as admitted (immutable)
``claims/<rid>.json``            the one terminal-or-running transition: ``run``, ``cancel`` or
                                 ``deny``.  Exclusive create: of a racing run and cancel, or two
                                 runs, exactly one wins
``results/<rid>.json``           how a claimed run ended (``done`` / ``error``)
``approvals/<rid>/<aid>.json``   approval and denial documents (``schemas/broker/approval``)
``consumed/<aid>.json``          consumed-approval markers: :class:`FileApprovalStore`, so an
                                 approval is single use across processes and restarts
``audit/<stamp>-<pid>-<n>-<rand>.json``  one audit record per file (``schemas/broker/audit``)
``outbox/<event id>.json``       events emitted when no bus is configured
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
from collections.abc import Iterator
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
_SUBDIRS = ("requests", "claims", "results", "approvals", "consumed", "audit", "outbox", "runs")


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


def _load(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None


class StateDir:
    """The broker's state directory.  Created ``0700``: it holds requests and audit records."""

    def __init__(self, root: str | os.PathLike[str]) -> None:
        self.root = Path(root)
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        for name in _SUBDIRS:
            d = self.root / name
            if d.is_symlink():
                raise StateError(f"{d} is a symlink; broker state directories must be real")
            d.mkdir(mode=0o700, exist_ok=True)
        self._seq = 0
        self._last_stamp = ""
        self._audit_lock = threading.Lock()  # a threaded server shares one instance

    def _dir(self, name: str) -> Path:
        return self.root / name

    @staticmethod
    def _checked(rid: str) -> str:
        if not is_id(rid):
            raise StateError(f"not a broker id: {rid!r}")
        return rid

    # ---------------------------------------------------------------- requests and transitions
    def put_request(self, rid: str, doc: dict[str, Any]) -> bool:
        return write_exclusive(self._dir("requests") / f"{self._checked(rid)}.json", _dumps(doc))

    def get_request(self, rid: str) -> dict[str, Any] | None:
        return _load(self._dir("requests") / f"{rid}.json") if is_id(rid) else None

    def request_ids(self) -> list[str]:
        return sorted(p.stem for p in self._dir("requests").glob("*.json") if is_id(p.stem))

    def claim(self, rid: str, doc: dict[str, Any]) -> bool:
        """Take the request's single transition; False when another one already took it."""
        return write_exclusive(self._dir("claims") / f"{self._checked(rid)}.json", _dumps(doc))

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
        return path

    def audit_records(self) -> Iterator[dict[str, Any]]:
        for p in sorted(self._dir("audit").glob("*.json")):
            doc = _load(p)
            if doc is not None:
                yield doc

    def put_outbox(self, event: dict[str, Any]) -> bool:
        """Record an event (idempotent per event id: a repeat is a no-op)."""
        eid = str(event["id"])
        if "/" in eid or eid.startswith("."):
            raise StateError(f"not an event id: {eid!r}")
        return write_exclusive(self._dir("outbox") / f"{eid}.json", _dumps(event))

    def outbox(self) -> list[dict[str, Any]]:
        return [d for p in sorted(self._dir("outbox").glob("*.json")) if (d := _load(p))]


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
