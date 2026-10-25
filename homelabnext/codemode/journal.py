# SPDX-License-Identifier: Apache-2.0
"""The Code Mode step journal: the runner's durable record of every broker call (CM-5b).

Every call the runner sends to the broker for a program is a **step** of its execution, in the
order the runner sent them, and the journal holds what the runner knew of it: the intent written
before the call was sent, and the answer written after.  A resume answers a step the journal
settled instead of calling the broker again, runs a pending one by its request id, and never
sends a step whose answer it does not know (ADR-0031 decision 7).  Layout, under
``<state>/journal/``, following the broker's state-dir conventions (``docs/broker.md``, "State";
ADR-0014): one file per fact, created exclusively and fsynced, the directories ``0700`` and the
files ``0600`` (an existing directory is tightened to it), no symlink followed:

``journal.key``                     32 random bytes: the key of each call's fingerprint
``<key>/meta.json``                 the execution: actor, execution id, code digest, ``state``
                                    (``running``, ``paused``, ``finished``, ``interrupted``), its
                                    tokens in order, the run owning it (``owner``: its runner
                                    instance and request), a ``version`` every change counts, when
                                    it was created and last changed (replaced atomically, changed
                                    under ``<key>/meta.lock``)
``live/<instance>``                 one per runner process, held under ``flock`` while it lives:
                                    what tells a crashed run's owner from a live one
``<key>/<step>-i.json``             the intent: the op, action, target and fingerprint of the call
                                    about to be sent, written **before** it is sent
``<key>/<step>-0.json``             the answer: a ``journal_step`` record (``record``) when the
                                    broker named a request, else the refusal (``refusal``: outcome
                                    and reason of a call refused before the broker built a request,
                                    a token refusal or a transport failure)
``<key>/<step>-r.json``             for a pending step: the intent to run it (``token_run``),
                                    written before the run is sent
``<key>/<step>-1.json``             the settled ``journal_step`` record of a pending step (or the
                                    refusal of its run, when that named no request)

An answer or a settled entry also keeps ``delivered``, what the program was told instead of an
ok result (``result-not-json``, ``result-too-large``), so a resume tells it the same.

``<key>`` is :func:`homelabnext.broker.tokens.execution_key` of the actor and the execution id,
so one actor's ids neither show nor block another's, as in the broker.  The latest answer of a
step counts, and a step's only transition is pending to settled: nothing is appended after a
settled answer.  :meth:`Journal.records` lists the ``journal_step`` records, the schema's view;
the intents and the refusals are the runner's own bookkeeping.

**Unknown steps.**  A step with an intent and no answer was sent (or may have been) and its
outcome is not known: the runner crashed, or the answer could not be written.  It is never sent
again.  A run whose answer cannot be written stops at once and ends ``error``, spending its token
``finished``, so its execution never resumes; a crashed run's token is spent ``crashed`` by the
broker's sweep, and its journal reads ``running`` with an owner that is gone, which the runner
marks ``interrupted``: an interrupted execution never resumes either.  The steps it sent are in
its journal for an operator to reconcile against the broker's audit trail.

**The fingerprint.**  The schema's ``request_digest`` is the broker's (secret arguments enter it
keyed with the broker's digest key), so the runner cannot compute it for a call it has not sent.
To tell a replayed call from a different one, every entry keeps ``call``: an HMAC-SHA256, under
``journal.key``, of the canonical JSON of ``{action, target, args}`` (the action prefixed with its
op), so a short secret argument is not recoverable from it offline.  The key sits beside the
records with the same owner and mode: it is a fingerprint against **offline guessing** by someone
who copies the journal, not tamper protection against the runner's own user, who can rewrite
records and key alike (as the broker's own user can rewrite its state).

**What is kept.**  An ``ok`` record keeps the broker's result (already redacted by the broker:
secrets a handler printed are ``<redacted>``), so the journal holds the agent's tool results for
as long as it is retained, and is as sensitive as the program's output: the directory is the
runner's only.  A result is kept whole up to ``max_result_bytes`` of canonical JSON (default 256
KiB) and while the execution's entries stay under ``max_execution_bytes`` (default 8 MiB); past
either, the record keeps ``result: null`` and the real digest, and the program is told
``result-too-large`` both times.  An execution has at most :data:`MAX_STEPS` steps.
:meth:`Journal.sweep` drops an ended execution (``finished``, ``interrupted``) ``retention_days``
after it last changed (default 7, the broker's token retention) and any other after
``paused_retention_days`` (default 30): a resume of a swept execution is refused like an unknown
one.
"""

from __future__ import annotations

import contextlib
import fcntl
import hashlib
import hmac
import json
import os
import re
import secrets
import shutil
import threading
from collections.abc import Iterator, Mapping
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from homelabnext.broker import validation
from homelabnext.broker.state import (
    _instance_held,
    hold_instance_lock,
    write_exclusive,
    write_temp,
)
from homelabnext.broker.tokens import execution_key

__all__ = [
    "DEFAULT_MAX_EXECUTION_BYTES",
    "DEFAULT_MAX_RESULT_BYTES",
    "DEFAULT_PAUSED_RETENTION_DAYS",
    "DEFAULT_RETENTION_DAYS",
    "DELIVERED",
    "ENDED",
    "JOURNAL_RECORD",
    "MAX_STEPS",
    "STATES",
    "Journal",
    "JournalError",
    "canonical",
    "digest_of",
]

#: the journal record's schema (``schemas/codemode/journal_step``)
JOURNAL_RECORD = "codemode/journal_step"
DEFAULT_MAX_RESULT_BYTES = 256 * 1024
DEFAULT_MAX_EXECUTION_BYTES = 8 * 1024 * 1024
DEFAULT_RETENTION_DAYS = 7.0
DEFAULT_PAUSED_RETENTION_DAYS = 30.0
#: the most steps one execution may hold (schemas/codemode max_calls and calls maxItems)
MAX_STEPS = 200
#: execution states after which nothing runs again
ENDED = frozenset({"finished", "interrupted"})
#: every state an execution's journal may be in
STATES = frozenset({"running", "paused", *ENDED})
#: what a call record's ``delivered_as`` may say (the program was told this instead)
DELIVERED = frozenset(
    {
        "output-truncated",
        "result-schema-mismatch",
        "result-too-large",
        "result-not-json",
        "journal-unavailable",
        "run-stopped",
    }
)
_REASON_RE = re.compile(r"[a-z][a-z0-9-]{0,63}")
#: the entry files of one step, by suffix
_KINDS = ("i", "0", "r", "1")


class JournalError(RuntimeError):
    """The journal cannot hold or read what it is asked to (a full disk, a removed directory, a
    malformed or foreign record)."""


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


def _tighten(path: Path) -> None:
    """Take group and other bits off a directory of the runner's (never adds any)."""
    with contextlib.suppress(OSError):
        if not path.is_symlink() and path.stat().st_mode & 0o077:
            os.chmod(path, 0o700)


def _meta_problem(meta: Any) -> str:
    """Why ``meta`` is not an execution's ``meta.json`` (empty: it is)."""
    if not isinstance(meta, dict):
        return "not a JSON object"
    for key in ("actor", "execution_id", "code_digest", "updated"):
        if not isinstance(meta.get(key), str):
            return f"{key} is not a string"
    if meta.get("state") not in STATES:
        return "an unknown state"
    tokens = meta.get("tokens")
    if not isinstance(tokens, list) or not tokens or not all(isinstance(t, str) for t in tokens):
        return "tokens is not a list of token ids"
    if not isinstance(meta.get("owner", {}), dict):
        return "owner is not an object"
    v = meta.get("version", 0)
    if not isinstance(v, int) or isinstance(v, bool) or v < 0:
        return "version is not a count"
    return ""


def _real_dir(path: Path) -> None:
    """A directory of the runner's only: created ``0700``, an existing one tightened to it."""
    if path.is_symlink():
        raise JournalError(f"{path} is a symlink; journal directories must be real")
    path.mkdir(mode=0o700, exist_ok=True)
    _tighten(path)


class Journal:
    """The step journal of one runner (see the module doc).  Thread-safe within a process, and
    a state change of an execution is atomic across processes (``meta.lock``)."""

    def __init__(
        self,
        state_dir: str | os.PathLike[str],
        *,
        max_result_bytes: int = DEFAULT_MAX_RESULT_BYTES,
        max_execution_bytes: int = DEFAULT_MAX_EXECUTION_BYTES,
        retention_days: float = DEFAULT_RETENTION_DAYS,
        paused_retention_days: float = DEFAULT_PAUSED_RETENTION_DAYS,
    ) -> None:
        root = Path(state_dir)
        if root.is_symlink():
            raise JournalError(f"{root} is a symlink; the runner's state directory must be real")
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        _tighten(root)
        self.root = root / "journal"
        _real_dir(self.root)
        self.max_result_bytes = int(max_result_bytes)
        self.max_execution_bytes = int(max_execution_bytes)
        self.retention_days = float(retention_days)
        self.paused_retention_days = float(paused_retention_days)
        self._lock = threading.RLock()
        self._key: bytes | None = None
        self._instance: tuple[str, int] | None = None  # (id, fd holding its live/ lock)

    # ---------------------------------------------------------------- the runner instance
    def instance_id(self) -> str:
        """This process's runner instance: ``journal/live/<id>``, held under an exclusive
        ``flock`` for as long as the process lives (the kernel drops it however the process
        dies), so any reader of this state directory, in any pid namespace, can tell a live
        run's owner from a gone one (:meth:`instance_alive`), as the broker does for its runs."""
        with self._lock:
            if self._instance is None:
                live = self.root / "live"
                _real_dir(live)
                self._instance = hold_instance_lock(live, "run")
            return self._instance[0]

    def instance_alive(self, instance: Any) -> bool:
        """Whether the runner instance ``instance`` may still be running: False only when its
        lock can be taken (or it never was one)."""
        if not isinstance(instance, str) or "/" in instance or instance.startswith("."):
            return False
        if self._instance is not None and self._instance[0] == instance:
            return True
        held = _instance_held(self.root / "live" / instance)
        return True if held is None else held

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
        """The execution's ``meta.json``, None when there is none (or it is another's); a
        malformed one is a :class:`JournalError`."""
        d = self._dir(actor, execution_id)
        if d.is_symlink() or not (d / "meta.json").is_file():
            return None
        _tighten(d)
        meta = _load(d / "meta.json")
        problem = _meta_problem(meta)
        if problem:
            raise JournalError(f"execution {execution_id!r}: meta.json: {problem}")
        if (meta["actor"], meta["execution_id"]) != (actor, execution_id):
            return None
        return meta

    @contextlib.contextmanager
    def _meta_lock(self, d: Path) -> Iterator[None]:
        with self._lock:
            fd = os.open(
                d / "meta.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600
            )
            try:
                fcntl.flock(fd, fcntl.LOCK_EX)
                yield
            finally:
                os.close(fd)

    def begin(
        self,
        actor: str,
        execution_id: str,
        code_digest: str,
        token_id: str,
        now: datetime,
        *,
        owner: Mapping[str, Any] | None = None,
    ) -> bool:
        """Start a fresh execution's journal; False when one exists (a fresh run never shares
        a journal with an earlier one).  A directory left without ``meta.json`` by a crash
        between its creation and its meta (and holding nothing else) is taken over."""
        with self._lock:
            d = self._dir(actor, execution_id)
            if d.is_symlink():
                return False
            try:
                d.mkdir(mode=0o700)
            except FileExistsError:
                leftovers = {p.name for p in d.iterdir()} - {"meta.lock"}
                if leftovers:
                    return False
            meta = {
                "actor": actor,
                "execution_id": execution_id,
                "code_digest": code_digest,
                "state": "running",
                "tokens": [token_id],
                "owner": dict(owner or {}),
                "version": 0,
                "created": _stamp(now),
                "updated": _stamp(now),
            }
            return write_exclusive(d / "meta.json", _dumps(meta))

    def update(
        self,
        actor: str,
        execution_id: str,
        now: datetime,
        *,
        expect: str | None = None,
        expect_version: int | None = None,
        **fields: Any,
    ) -> bool:
        """Change an execution's ``state`` (and ``owner``), or append to its ``tokens``
        (``token=``), atomically: with ``expect``, only while its state is that one, and with
        ``expect_version`` only while it is the version read before (every change counts one, so
        a claim can bind to everything read with it); False otherwise, nothing changed."""
        d = self._dir(actor, execution_id)
        if d.is_symlink() or not d.is_dir():
            raise JournalError(f"no journal for execution {execution_id!r}")
        with self._meta_lock(d):
            meta = self.execution(actor, execution_id)
            if meta is None:
                raise JournalError(f"no journal for execution {execution_id!r}")
            if expect is not None and meta.get("state") != expect:
                return False
            if expect_version is not None and meta.get("version", 0) != expect_version:
                return False
            token = fields.pop("token", None)
            if token is not None:
                meta["tokens"] = [*meta["tokens"], token]
            meta.update(fields, updated=_stamp(now), version=meta.get("version", 0) + 1)
            dir_fd = os.open(d, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                tmp = write_temp("meta.json", _dumps(meta), dir_fd=dir_fd)
                os.rename(tmp, "meta.json", src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
                with contextlib.suppress(OSError):
                    os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        return True

    # ---------------------------------------------------------------- steps
    def _entries(self, actor: str, execution_id: str) -> Iterator[tuple[int, str, dict]]:
        d = self._dir(actor, execution_id)
        if d.is_symlink() or not d.is_dir():
            return
        for p in d.glob("*-*.json"):
            step, _, kind = p.stem.partition("-")
            if not step.isdigit() or kind not in _KINDS or p.is_symlink():
                continue
            doc = _load(p)
            if not isinstance(doc, dict):
                raise JournalError(f"step {int(step)}: entry {kind} is not a JSON object")
            yield int(step), kind, doc

    def steps(self, actor: str, execution_id: str) -> dict[int, dict[str, Any]]:
        """Every step's entries, ``{intent, answer, run, settled}`` (each a dict or absent),
        checked: a record is a ``journal_step`` of this execution (its actor, id and code digest
        are the execution's), and an answer has its intent.  A malformed entry is a
        :class:`JournalError`, never a ``KeyError`` further on."""
        meta = self.execution(actor, execution_id)
        d = self._dir(actor, execution_id)
        if d.is_dir():
            _tighten(d)
        out: dict[int, dict[str, Any]] = {}
        names = {"i": "intent", "0": "answer", "r": "run", "1": "settled"}
        for step, kind, doc in self._entries(actor, execution_id):
            out.setdefault(step, {})[names[kind]] = doc
        for step, entry in out.items():
            for name in ("intent", "run", "answer", "settled"):
                doc = entry.get(name)
                if doc is not None and not isinstance(doc.get("call"), str):
                    raise JournalError(f"step {step}: a {name} entry without its fingerprint")
                if doc is not None and doc.get("delivered") not in (None, *DELIVERED):
                    raise JournalError(f"step {step}: an unknown delivered reason")
            intent = (entry.get("intent") or {}).get("intent")
            if "intent" in entry and not (
                isinstance(intent, dict)
                and intent.get("op") in ("call", "submit")
                and isinstance(intent.get("action"), str)
                and (intent.get("target") is None or isinstance(intent.get("target"), str))
            ):
                raise JournalError(f"step {step}: a malformed intent")
            for name in ("answer", "settled"):
                doc = entry.get(name)
                if doc is None:
                    continue
                rec = doc.get("record")
                if rec is not None:
                    problems = validation.named_errors(JOURNAL_RECORD, rec)
                    if problems:
                        raise JournalError(f"step {step}: a malformed record: {problems[0]}")
                    bound = (rec["actor"], rec["execution_id"], rec["code_digest"], rec["step"])
                    want = (actor, execution_id, (meta or {}).get("code_digest"), step)
                    if bound != want:
                        raise JournalError(f"step {step}: a record of another execution")
                else:
                    refusal = doc.get("refusal")
                    if not (
                        isinstance(refusal, dict)
                        and refusal.get("outcome") in ("denied", "error")
                        and isinstance(refusal.get("reason"), str)
                        and _REASON_RE.fullmatch(refusal["reason"])
                    ):
                        raise JournalError(
                            f"step {step}: an answer with neither record nor refusal"
                        )
            if "answer" in entry and "intent" not in entry:
                raise JournalError(f"step {step}: an answer without its intent")
            if "settled" in entry and "run" not in entry:
                raise JournalError(f"step {step}: a settled record without its run intent")
        return dict(sorted(out.items()))

    def records(self, actor: str, execution_id: str) -> list[dict[str, Any]]:
        """Every ``journal_step`` record of the execution, in append order (step, then the
        pending record before the settled one)."""
        out = []
        for _step, entry in self.steps(actor, execution_id).items():
            for name in ("answer", "settled"):
                rec = (entry.get(name) or {}).get("record")
                if rec is not None:
                    out.append(rec)
        return out

    def _write(self, actor: str, execution_id: str, step: int, kind: str, doc: Mapping) -> None:
        if not 0 <= step < MAX_STEPS:
            raise JournalError(f"step {step} is outside 0..{MAX_STEPS - 1}")
        d = self._dir(actor, execution_id)
        if d.is_symlink() or not (d / "meta.json").is_file():
            raise JournalError(f"no journal for execution {execution_id!r}")
        try:
            done = write_exclusive(d / f"{step:06d}-{kind}.json", _dumps(dict(doc)))
        except OSError as exc:
            raise JournalError(f"step {step}: {exc.strerror or exc}") from None
        if not done:
            raise JournalError(f"step {step}: entry {kind} exists; a journal is append-only")

    def intend(self, actor, execution_id, step, *, op, action, target, call) -> None:
        """Record that step ``step`` is about to be sent (before it is)."""
        with self._lock:
            self._write(
                actor,
                execution_id,
                step,
                "i",
                {"intent": {"op": op, "action": action, "target": target}, "call": call},
            )

    def answer(
        self, actor, execution_id, step, *, call, record=None, refusal=None, delivered=None
    ) -> None:
        """Record the broker's answer to step ``step``: a validated ``journal_step`` record, or
        the refusal of a call the broker built no request for; ``delivered``, what the program
        was told instead of an ok result (so a resume tells it the same)."""
        with self._lock:
            doc = {"record": record, "refusal": refusal, "call": call}
            if delivered is not None:
                doc["delivered"] = delivered
            self._write(actor, execution_id, step, "0", doc)

    def intend_run(self, actor, execution_id, step, *, call) -> None:
        """Record that the pending step ``step`` is about to be run by its request id."""
        with self._lock:
            self._write(actor, execution_id, step, "r", {"call": call})

    def settle(
        self, actor, execution_id, step, *, call, record=None, refusal=None, delivered=None
    ) -> None:
        """Record how a pending step ended once run: a record, or the refusal of its run that
        named no request (the step stays pending at the broker)."""
        with self._lock:
            doc = {"record": record, "refusal": refusal, "call": call}
            if delivered is not None:
                doc["delivered"] = delivered
            self._write(actor, execution_id, step, "1", doc)

    def used_bytes(self, actor: str, execution_id: str) -> int:
        d = self._dir(actor, execution_id)
        total = 0
        with contextlib.suppress(OSError):
            for p in d.iterdir():
                with contextlib.suppress(OSError):
                    total += p.lstat().st_size
        return total

    def kept_result(self, result: Any, *, used: int = 0) -> tuple[Any, str, str | None]:
        """(what the record keeps, the result's digest, why it is not kept whole or None): whole
        only when it is JSON (a non-finite number or a value JSON has no form for is
        ``result-not-json``: kept as null, digested by its type) under ``max_result_bytes`` and
        while ``used`` plus it stays under ``max_execution_bytes`` (``result-too-large``)."""
        try:
            raw = canonical(result)
        except (TypeError, ValueError, RecursionError):
            return None, digest_of({"not-json": type(result).__name__}), "result-not-json"
        digest = "sha256:" + hashlib.sha256(raw).hexdigest()
        if len(raw) > self.max_result_bytes or used + len(raw) > self.max_execution_bytes:
            return None, digest, "result-too-large"
        return result, digest, None

    # ---------------------------------------------------------------- retention
    def sweep(self, now: datetime, *, alive=None) -> dict[str, int]:
        """Mark a ``running`` execution whose owner is gone ``interrupted`` (``alive(owner)``
        decides; none given, nothing is marked) and remove executions past their retention
        (see the module doc)."""
        finished_before = _stamp(now - timedelta(days=self.retention_days))
        paused_before = _stamp(now - timedelta(days=self.paused_retention_days))
        counts = {"interrupted": 0, "removed": 0, "instances": 0}
        with self._lock:
            live = self.root / "live"
            if live.is_dir() and not live.is_symlink():  # the lock files of instances gone
                for f in sorted(live.iterdir()):
                    if f.name.startswith(".") or f.is_symlink() or not f.is_file():
                        continue  # one being created (locked, then renamed), or not ours
                    if not self.instance_alive(f.name):
                        with contextlib.suppress(FileNotFoundError):
                            f.unlink()
                            counts["instances"] += 1
            for d in sorted(self.root.iterdir()):
                if d.is_symlink() or not d.is_dir() or d.name == "live":
                    continue
                meta = _load(d / "meta.json")
                if _meta_problem(meta):  # malformed: left for an operator, never a crash here
                    continue
                stale = alive is not None and meta.get("state") == "running"
                if stale and not alive(meta.get("owner") or {}):
                    changed = self.update(
                        meta["actor"],
                        meta["execution_id"],
                        now,
                        expect="running",
                        state="interrupted",
                    )
                    counts["interrupted"] += int(changed)
                    meta = _load(d / "meta.json") or meta
                before = finished_before if meta.get("state") in ENDED else paused_before
                if str(meta.get("updated", "")) < before:
                    shutil.rmtree(d)
                    counts["removed"] += 1
        return counts
