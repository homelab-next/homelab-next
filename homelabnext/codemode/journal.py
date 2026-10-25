# SPDX-License-Identifier: Apache-2.0
"""The Code Mode step journal: the runner's durable record of every broker call (CM-5b).

One record per broker call of an execution (``schemas/codemode/journal_step``), keyed by the
execution and the step, bound to the actor and the program's code digest.  A resume serves a
settled step from here instead of calling the broker again, and runs a pending one by its request
id (ADR-0031 decision 7).  Layout, under ``<state>/journal/``, following the broker's state-dir
conventions (``docs/broker.md``, "State"; ADR-0014): one file per fact, created exclusively, the
directory and every file the runner's own (``0700``/``0600``), no symlink followed:

``journal.key``                     32 random bytes: the key of each step's call fingerprint
``<key>/meta.json``                 the execution: actor, execution id, code digest, ``state``
                                    (``running``, ``paused``, ``finished``), its tokens in order,
                                    when it was created and last changed (replaced atomically)
``<key>/<step>-<seq>.json``         one record of one step (``seq`` 0, then 1 once a pending step
                                    settles), wrapping the ``journal_step`` record with the call's
                                    fingerprint; never rewritten (append-only)

``<key>`` is :func:`homelabnext.broker.tokens.execution_key` of the actor and the execution id,
so one actor's ids neither show nor block another's, as in the broker.  The latest record of a
step counts, and a step's only transition is pending to settled: nothing is appended after an
``ok``, ``denied`` or ``error`` record.

**The fingerprint.**  The schema's ``request_digest`` is the broker's (secret arguments enter it
keyed with the broker's digest key), so the runner cannot compute it for a call it has not sent.
To tell a replayed call from a different one, each record also keeps ``call``: an HMAC-SHA256,
under ``journal.key``, of the canonical JSON of ``{action, target, args}``, so a short secret
argument is not recoverable from it offline.  A resumed call is served from the journal only when
its action and fingerprint match the step's (with the actor and code digest, which the execution
key and ``meta.json`` bind); anything else is a different call, refused and never replayed.

**Bounds.**  An execution has at most ``max_calls`` steps (the broker's cap, at most 200) and two
records each; a result is kept whole only up to ``max_result_bytes`` of canonical JSON (default
256 KiB; above it the record keeps ``result: null`` and the real result's digest, and the program
is told ``result-too-large`` both times).  :meth:`Journal.sweep` drops a finished execution
``retention_days`` after it last changed (default 7, the broker's token retention) and a paused
or running one after ``paused_retention_days`` (default 30): a resume of a swept execution is
refused like an unknown one.
"""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import json
import os
import secrets
import shutil
import threading
from collections.abc import Iterator, Mapping
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from homelabnext.broker.state import write_exclusive, write_temp
from homelabnext.broker.tokens import execution_key

__all__ = [
    "DEFAULT_MAX_RESULT_BYTES",
    "DEFAULT_PAUSED_RETENTION_DAYS",
    "DEFAULT_RETENTION_DAYS",
    "JOURNAL_RECORD",
    "Journal",
    "JournalError",
    "canonical",
    "digest_of",
]

#: the journal record's schema (``schemas/codemode/journal_step``)
JOURNAL_RECORD = "codemode/journal_step"
DEFAULT_MAX_RESULT_BYTES = 256 * 1024
DEFAULT_RETENTION_DAYS = 7.0
DEFAULT_PAUSED_RETENTION_DAYS = 30.0
#: the most steps one execution may hold (schemas/codemode max_calls)
MAX_STEPS = 200
#: execution states after which nothing runs again
ENDED = frozenset({"finished"})


class JournalError(RuntimeError):
    """The journal cannot hold what it is asked to (a bug or a corrupted state directory)."""


def canonical(value: Any) -> bytes:
    """The canonical JSON the journal digests: sorted keys, compact, non-ASCII kept."""
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def digest_of(value: Any) -> str:
    """``sha256:<hex>`` of :func:`canonical`."""
    return "sha256:" + hashlib.sha256(canonical(value)).hexdigest()


def _stamp(t: datetime) -> str:
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def _load(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, ValueError):
        return None


def _dumps(doc: Any) -> bytes:
    return (json.dumps(doc, sort_keys=True, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def _real_dir(path: Path) -> None:
    if path.is_symlink():
        raise JournalError(f"{path} is a symlink; journal directories must be real")
    path.mkdir(mode=0o700, exist_ok=True)


class Journal:
    """The step journal of one runner (see the module doc).  Thread-safe within a process; one
    runner service per state directory, as one broker per broker state directory."""

    def __init__(
        self,
        state_dir: str | os.PathLike[str],
        *,
        max_result_bytes: int = DEFAULT_MAX_RESULT_BYTES,
        retention_days: float = DEFAULT_RETENTION_DAYS,
        paused_retention_days: float = DEFAULT_PAUSED_RETENTION_DAYS,
    ) -> None:
        root = Path(state_dir)
        if root.is_symlink():
            raise JournalError(f"{root} is a symlink; the runner's state directory must be real")
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.root = root / "journal"
        _real_dir(self.root)
        self.max_result_bytes = int(max_result_bytes)
        self.retention_days = float(retention_days)
        self.paused_retention_days = float(paused_retention_days)
        self._lock = threading.RLock()
        self._key: bytes | None = None

    # ---------------------------------------------------------------- the key
    def _secret(self) -> bytes:
        if self._key is None:
            path = self.root / "journal.key"
            write_exclusive(path, secrets.token_bytes(32))  # False: it exists already
            if path.is_symlink():
                raise JournalError(f"{path} is a symlink")
            key = path.read_bytes()
            if len(key) != 32:
                raise JournalError(f"{path} is not a 32-byte key")
            self._key = key
        return self._key

    def fingerprint(self, action: str, target: str | None, args: Any) -> str:
        """The keyed fingerprint of one call: what a replayed call must match."""
        body = canonical({"action": action, "target": target, "args": args})
        return "hmac-sha256:" + hmac.new(self._secret(), body, hashlib.sha256).hexdigest()

    # ---------------------------------------------------------------- executions
    def _dir(self, actor: str, execution_id: str) -> Path:
        return self.root / execution_key(actor, execution_id)

    def execution(self, actor: str, execution_id: str) -> dict[str, Any] | None:
        d = self._dir(actor, execution_id)
        if d.is_symlink():
            return None
        meta = _load(d / "meta.json")
        if not isinstance(meta, dict) or (meta.get("actor"), meta.get("execution_id")) != (
            actor,
            execution_id,
        ):
            return None
        return meta

    def begin(
        self, actor: str, execution_id: str, code_digest: str, token_id: str, now: datetime
    ) -> bool:
        """Start a fresh execution's journal; False when one exists (a fresh run never shares
        a journal with an earlier one)."""
        with self._lock:
            d = self._dir(actor, execution_id)
            if d.exists() or d.is_symlink():
                return False
            d.mkdir(mode=0o700)
            meta = {
                "actor": actor,
                "execution_id": execution_id,
                "code_digest": code_digest,
                "state": "running",
                "tokens": [token_id],
                "created": _stamp(now),
                "updated": _stamp(now),
            }
            return write_exclusive(d / "meta.json", _dumps(meta))

    def update(self, actor: str, execution_id: str, now: datetime, **fields: Any) -> None:
        """Change an execution's ``state`` or append to its ``tokens`` (``token=``)."""
        with self._lock:
            meta = self.execution(actor, execution_id)
            if meta is None:
                raise JournalError(f"no journal for execution {execution_id!r}")
            token = fields.pop("token", None)
            if token is not None:
                meta["tokens"] = [*meta["tokens"], token]
            meta.update(fields, updated=_stamp(now))
            d = self._dir(actor, execution_id)
            dir_fd = os.open(d, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                tmp = write_temp("meta.json", _dumps(meta), dir_fd=dir_fd)
                os.rename(tmp, "meta.json", src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
                with contextlib.suppress(OSError):
                    os.fsync(dir_fd)
            finally:
                os.close(dir_fd)

    # ---------------------------------------------------------------- steps
    def _entries(self, actor: str, execution_id: str) -> Iterator[tuple[int, int, dict]]:
        d = self._dir(actor, execution_id)
        if d.is_symlink() or not d.is_dir():
            return
        for p in d.glob("*-*.json"):
            step, _, seq = p.stem.partition("-")
            if not (step.isdigit() and seq.isdigit()) or p.is_symlink():
                continue
            doc = _load(p)
            if isinstance(doc, dict) and isinstance(doc.get("record"), dict):
                yield int(step), int(seq), doc

    def records(self, actor: str, execution_id: str) -> list[dict[str, Any]]:
        """Every record of the execution, in append order (step, then seq)."""
        rows = sorted(self._entries(actor, execution_id), key=lambda r: (r[0], r[1]))
        return [doc["record"] for _, _, doc in rows]

    def steps(self, actor: str, execution_id: str) -> dict[int, dict[str, Any]]:
        """The latest entry of each step (``{record, call}``): the one that counts."""
        out: dict[int, tuple[int, dict]] = {}
        for step, seq, doc in self._entries(actor, execution_id):
            if step not in out or seq > out[step][0]:
                out[step] = (seq, doc)
        return {step: doc for step, (_, doc) in sorted(out.items())}

    def append(self, record: Mapping[str, Any], call: str) -> None:
        """Append one validated record (the caller validates it against :data:`JOURNAL_RECORD`):
        refused when the step's latest record is settled, or past :data:`MAX_STEPS`."""
        actor, eid, step = record["actor"], record["execution_id"], int(record["step"])
        if not 0 <= step < MAX_STEPS:
            raise JournalError(f"step {step} is outside 0..{MAX_STEPS - 1}")
        with self._lock:
            latest = self.steps(actor, eid).get(step)
            if latest is not None and latest["record"]["outcome"] != "pending":
                raise JournalError(f"step {step} is settled; a journal is append-only")
            if latest is not None and record["outcome"] == "pending":
                raise JournalError(f"step {step} is already pending")
            seq = 0 if latest is None else 1
            path = self._dir(actor, eid) / f"{step:06d}-{seq}.json"
            if not write_exclusive(path, _dumps({"record": dict(record), "call": call})):
                raise JournalError(f"step {step} record {seq} exists")

    def kept_result(self, result: Any) -> tuple[Any, str, bool]:
        """(what the record keeps, the result's digest, whether it is kept whole)."""
        raw = canonical(result)
        digest = "sha256:" + hashlib.sha256(raw).hexdigest()
        if len(raw) > self.max_result_bytes:
            return None, digest, False
        return result, digest, True

    # ---------------------------------------------------------------- retention
    def sweep(self, now: datetime) -> int:
        """Remove executions past their retention (see the module doc); returns how many."""
        finished_before = _stamp(now - timedelta(days=self.retention_days))
        paused_before = _stamp(now - timedelta(days=self.paused_retention_days))
        removed = 0
        with self._lock:
            for d in sorted(self.root.iterdir()):
                if d.is_symlink() or not d.is_dir():
                    continue
                meta = _load(d / "meta.json")
                if not isinstance(meta, dict):
                    continue
                before = finished_before if meta.get("state") in ENDED else paused_before
                if str(meta.get("updated", "")) < before:
                    shutil.rmtree(d)
                    removed += 1
        return removed
