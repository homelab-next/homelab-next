# SPDX-License-Identifier: Apache-2.0
"""Code Mode capability tokens: the broker's own, crash-safe record of each (ADR-0031, CM-5a).

The broker issues a token for one run of one execution (:meth:`BrokerService.issue_token`), and
a sandbox presents its secret on every call.  What makes the token mean anything is that its
state lives here, server side: whether it is live, paused or spent, and how many calls the
execution has made, are the broker's facts, so a program that resets its client, or calls the
socket directly, gains nothing.  Layout, under ``<state>/codemode/``:

``tokens/<token id>.json``         the claims (``schemas/codemode/token``), the sha256 of the
                                   secret, the runner that holds it, ``state`` (``live``,
                                   ``paused``, ``spent``), ``outcome`` once spent (``finished``,
                                   ``paused``, ``crashed``), ``calls`` and, once paused, the request
                                   it waits on (``paused_by``)
``secrets/<sha256 hex>.json``      the token id a secret's digest names (the secret itself is
                                   never written anywhere)
``live/<token id>.json``           an index of the tokens still live (actor and expiry), so the
                                   per-actor cap reads O(live), not O(history)
``executions/<key>.json``          one execution of one actor (``key`` is :func:`execution_key` of
                                   the actor and the execution id, so one actor's ids neither show
                                   nor block another's): its code digest, the call cap of its
                                   first run, its tokens in order, ``state`` (``running``,
                                   ``paused``, ``finished``, ``crashed``) and when it last changed
``runs/<request id>.json``         the token issued for that ``codemode.execute`` request
``inflight/<request id>.json``     a ``codemode.execute`` whose handler is running (actor, params,
                                   the broker instance running it, the runner it belongs to): only
                                   such a request can be issued a token; removed when the handler
                                   returns, or by :meth:`TokenStore.sweep` once its instance is gone
``tokens.lock``                    the ``flock`` every read-modify-write here holds

A call's check and its count are one step under the lock (``flock`` across processes, a
re-entrant lock and one descriptor within one), so two concurrent calls cannot both take the last
call of the cap.  Documents are replaced atomically (written beside, fsynced, renamed), so a
crash leaves the old or the new one, never half of either.  The ``flock`` is per host, as the
lanes' is: one broker host per state directory (``docs/broker.md``).
"""

from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import os
import threading
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

from .state import is_id, write_exclusive, write_temp

__all__ = ["TokenStore", "execution_key", "secret_digest"]

_DIRS = ("tokens", "secrets", "live", "executions", "inflight", "runs")
#: execution states after which nothing runs again (kept until the retention passes)
ENDED = frozenset({"finished", "crashed"})


def secret_digest(secret: Any) -> str:
    """The hex sha256 of a presented secret: the only form of it the broker keeps.  The secret
    is 256 random bits, so an unkeyed hash is as good as a keyed one; anything that is not a
    string digests to a value no secret has."""
    raw = secret.encode("utf-8", "replace") if isinstance(secret, str) else b"\0not-a-secret"
    return hashlib.sha256(raw).hexdigest()


def execution_key(actor: str, execution_id: str) -> str:
    """The file name of ``actor``'s execution ``execution_id``: execution ids are the agent's own,
    so they are scoped per actor."""
    raw = f"{actor}\0{execution_id}".encode("utf-8", "replace")
    return "x" + hashlib.sha256(raw).hexdigest()[:40]


def _dumps(doc: Any) -> bytes:
    return (json.dumps(doc, sort_keys=True, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def _load(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, ValueError):
        return None


class TokenStore:
    """The tokens of one state directory.  Every method that reads and then writes runs inside
    :meth:`locked`; the service holds it across a whole check-and-count."""

    def __init__(self, state_root: str | os.PathLike[str]) -> None:
        self.root = Path(state_root) / "codemode"
        self.root.mkdir(mode=0o700, exist_ok=True)
        for name in _DIRS:
            d = self.root / name
            if d.is_symlink():
                raise OSError(f"{d} is a symlink; broker state directories must be real")
            d.mkdir(mode=0o700, exist_ok=True)
        self._lock = threading.RLock()
        self._depth = 0  # how deeply the owning thread holds the lock
        self._fd: int | None = None  # the descriptor holding the flock, outermost entry only

    @contextlib.contextmanager
    def locked(self) -> Iterator[None]:
        """Hold the store's lock: this process's threads and every other process alike.
        Re-entrant: a nested entry by the thread that holds it neither opens a second descriptor
        nor waits on its own ``flock``."""
        with self._lock:
            if self._depth == 0:
                fd = os.open(
                    self.root / "tokens.lock",
                    os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
                    0o600,
                )
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX)
                except BaseException:
                    os.close(fd)
                    raise
                self._fd = fd
            self._depth += 1
            try:
                yield
            finally:
                self._depth -= 1
                if self._depth == 0 and self._fd is not None:
                    os.close(self._fd)  # releases the flock
                    self._fd = None

    def _replace(self, path: Path, doc: Any) -> None:
        dir_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            tmp = write_temp(path.name, _dumps(doc), dir_fd=dir_fd)
            os.rename(tmp, path.name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
            with contextlib.suppress(OSError):
                os.fsync(dir_fd)
        finally:
            os.close(dir_fd)

    def _path(self, where: str, name: str) -> Path:
        if not is_id(name):
            raise ValueError(f"not a broker id: {name[:80]!r}")
        return self.root / where / f"{name}.json"

    def _unlink(self, path: Path) -> None:
        with contextlib.suppress(FileNotFoundError):
            path.unlink()

    # ---------------------------------------------------------------- in-flight executions
    def begin(self, request_id: str, doc: dict[str, Any]) -> None:
        write_exclusive(self._path("inflight", request_id), _dumps(doc))

    def inflight(self, request_id: str) -> dict[str, Any] | None:
        return _load(self._path("inflight", request_id)) if is_id(request_id) else None

    def bind_inflight(self, doc: dict[str, Any]) -> None:
        self._replace(self._path("inflight", doc["request_id"]), doc)

    def end(self, request_id: str, now: str, *, outcome: str = "finished") -> list[dict]:
        """The ``codemode.execute`` has returned (or its broker is gone: ``crashed``): forget it,
        spend its token if still live (a token never outlives its run) and settle its
        execution.  Returns the tokens it spent."""
        spent = []
        with self.locked():
            self._unlink(self._path("inflight", request_id))
            tok = self.token_of_request(request_id)
            if tok is not None:
                if tok["state"] == "live":
                    self.set_state(tok, "spent", outcome=outcome)
                    spent.append(tok)
                self.settle(tok, now)
        return spent

    def token_of_request(self, request_id: str) -> dict[str, Any] | None:
        """The token issued for one run of ``codemode.execute`` (there is at most one)."""
        if not is_id(request_id):
            return None
        ref = _load(self.root / "runs" / f"{request_id}.json")
        return self.token(ref["token_id"]) if isinstance(ref, dict) else None

    def settle(self, tok: dict[str, Any], now: str) -> None:
        """An execution's state follows its latest token: paused while it waits on a request,
        else finished (or crashed) once that token is spent."""
        ex = self.execution(tok["exec_key"])
        if ex is None or not ex["tokens"] or ex["tokens"][-1] != tok["claims"]["token_id"]:
            return
        if tok["state"] == "live":
            state = "running"
        elif tok["state"] == "paused" or tok.get("outcome") == "paused":
            state = "paused"
        else:
            state = "crashed" if tok.get("outcome") == "crashed" else "finished"
        if ex.get("state") != state:
            ex.update(state=state, updated=now)
            self.put_execution(ex)

    # ---------------------------------------------------------------- tokens
    def token(self, token_id: str) -> dict[str, Any] | None:
        return _load(self._path("tokens", token_id)) if is_id(token_id) else None

    def by_secret(self, secret: Any) -> dict[str, Any] | None:
        """The token whose secret this is, or None (an unknown and a wrong secret alike)."""
        ref = _load(self.root / "secrets" / f"{secret_digest(secret)}.json")
        if not isinstance(ref, dict) or not isinstance(ref.get("token_id"), str):
            return None
        tok = self.token(ref["token_id"])
        return tok if tok and tok.get("secret_sha256") == secret_digest(secret) else None

    def put(self, tok: dict[str, Any]) -> None:
        """Store a new token: its document, its secret's index, its run's index and its live
        marker."""
        tid = tok["claims"]["token_id"]
        if not write_exclusive(self._path("tokens", tid), _dumps(tok)):
            raise OSError(f"token {tid} already exists")
        write_exclusive(
            self.root / "secrets" / f"{tok['secret_sha256']}.json", _dumps({"token_id": tid})
        )
        run = self.root / "runs" / f"{tok['claims']['request_id']}.json"
        write_exclusive(run, _dumps({"token_id": tid}))
        live = {"actor": tok["claims"]["actor"], "expires_at": tok["claims"]["expires_at"]}
        write_exclusive(self._path("live", tid), _dumps(live))

    def save(self, tok: dict[str, Any]) -> None:
        self._replace(self._path("tokens", tok["claims"]["token_id"]), tok)

    def set_state(self, tok: dict[str, Any], state: str, **extra: Any) -> None:
        """Move a token on: ``paused`` or ``spent`` take it off the live index for good."""
        tok.update(state=state, **extra)
        self.save(tok)
        if state != "live":
            self._unlink(self._path("live", tok["claims"]["token_id"]))

    def live_of(self, actor: str, now: str) -> list[str]:
        """The ids of ``actor``'s tokens that are live and unexpired at ``now`` (a stamp); an
        expired entry is dropped from the index on the way."""
        out = []
        for p in sorted((self.root / "live").glob("*.json")):
            doc = _load(p)
            if not isinstance(doc, dict):
                continue
            if doc["expires_at"] <= now:
                self._unlink(p)
            elif doc.get("actor") == actor:
                out.append(p.stem)
        return out

    # ---------------------------------------------------------------- executions
    def execution(self, key: str) -> dict[str, Any] | None:
        return _load(self._path("executions", key)) if is_id(key) else None

    def put_execution(self, doc: dict[str, Any]) -> None:
        self._replace(self._path("executions", doc["key"]), doc)

    def calls_of(self, ex: dict[str, Any]) -> int:
        """Every call the execution's tokens have made: the cap is per execution."""
        return sum((self.token(t) or {}).get("calls", 0) for t in ex["tokens"])

    # ---------------------------------------------------------------- the sweep
    def sweep(
        self, now: str, *, alive: Callable[[Any], bool], retention_before: str | None
    ) -> dict[str, int]:
        """Settle what a crash left behind and drop what is past its retention:

        * an in-flight run whose broker instance is gone is ended ``crashed``: its live token is
          spent (a crashed execution is not resumable; a paused one stays paused);
        * expired entries leave the live index;
        * an ended execution (``finished``, ``crashed``) last changed before
          ``retention_before`` is removed with its tokens and their secrets' index.
        """
        counts = {"crashed": 0, "expired": 0, "removed": 0}
        with self.locked():
            for p in sorted((self.root / "inflight").glob("*.json")):
                doc = _load(p)
                if isinstance(doc, dict) and not alive(doc.get("instance")):
                    self.end(p.stem, now, outcome="crashed")
                    counts["crashed"] += 1
            for p in sorted((self.root / "live").glob("*.json")):
                doc = _load(p)
                if isinstance(doc, dict) and doc.get("expires_at", "") <= now:
                    self._unlink(p)
                    counts["expired"] += 1
            if retention_before is None:
                return counts
            for p in sorted((self.root / "executions").glob("*.json")):
                ex = _load(p)
                if not isinstance(ex, dict) or ex.get("state") not in ENDED:
                    continue
                if ex.get("updated", "") >= retention_before:
                    continue
                for tid in ex["tokens"]:
                    tok = self.token(tid)
                    if tok is not None:
                        self._unlink(self.root / "secrets" / f"{tok['secret_sha256']}.json")
                        self._unlink(self.root / "runs" / f"{tok['claims']['request_id']}.json")
                        self._unlink(self._path("live", tid))
                    self._unlink(self._path("tokens", tid))
                self._unlink(p)
                counts["removed"] += 1
        return counts
