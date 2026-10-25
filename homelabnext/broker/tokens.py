# SPDX-License-Identifier: Apache-2.0
"""Code Mode capability tokens: the broker's own, crash-safe record of each (ADR-0031, CM-5a).

The broker issues a token for one run of one execution (:meth:`BrokerService.issue_token`), and
a sandbox presents its secret on every call.  What makes the token mean anything is that its
state lives here, server side: whether it is live, paused or spent, and how many calls it has
made, are the broker's facts, so a program that resets its client, or calls the socket directly,
gains nothing.  Layout, under ``<state>/codemode/``:

``tokens/<token id>.json``         the claims (``schemas/codemode/token``), the sha256 of the
                                   secret, ``state`` (``live``, ``paused``, ``spent``), ``calls``
                                   and, once paused, the request it waits on
``secrets/<sha256 hex>.json``      the token id a secret's digest names (the secret itself is
                                   never written anywhere)
``live/<token id>.json``           an index of the tokens still live (actor and expiry), so the
                                   per-actor cap reads O(live), not O(history)
``executions/<execution id>.json`` the execution's actor, code digest and its tokens in order
``inflight/<request id>.json``     a ``codemode.execute`` whose handler is running (actor, params,
                                   the broker instance running it): only such a request can be
                                   issued a token; removed when the handler returns
``tokens.lock``                    the ``flock`` every read-modify-write here holds

A call's check and its count are one step under the lock (``flock`` across processes, a thread
lock within one), so two concurrent calls cannot both take the last call of the cap.  Documents
are replaced atomically (written beside, fsynced, renamed), so a crash leaves the old or the new
one, never half of either.  The ``flock`` is per host, as the lanes' is: one broker host per state
directory (``docs/broker.md``).
"""

from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import os
import threading
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from .state import is_id, write_exclusive, write_temp

__all__ = ["TokenStore", "secret_digest"]

_DIRS = ("tokens", "secrets", "live", "executions", "inflight")


def secret_digest(secret: Any) -> str:
    """The hex sha256 of a presented secret: the only form of it the broker keeps.  The secret
    is 256 random bits, so an unkeyed hash is as good as a keyed one; anything that is not a
    string digests to a value no secret has."""
    raw = secret.encode("utf-8", "replace") if isinstance(secret, str) else b"\0not-a-secret"
    return hashlib.sha256(raw).hexdigest()


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

    @contextlib.contextmanager
    def locked(self) -> Iterator[None]:
        """Hold the store's lock: this process's threads and every other process alike."""
        with self._lock:
            fd = os.open(
                self.root / "tokens.lock",
                os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o600,
            )
            try:
                fcntl.flock(fd, fcntl.LOCK_EX)
                yield
            finally:
                os.close(fd)  # releases the flock

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

    # ---------------------------------------------------------------- in-flight executions
    def begin(self, request_id: str, doc: dict[str, Any]) -> None:
        write_exclusive(self._path("inflight", request_id), _dumps(doc))

    def inflight(self, request_id: str) -> dict[str, Any] | None:
        return _load(self._path("inflight", request_id)) if is_id(request_id) else None

    def end(self, request_id: str) -> list[dict[str, Any]]:
        """The ``codemode.execute`` has returned: forget it, and spend its tokens still live (a
        token never outlives its run).  Returns the tokens it spent."""
        spent = []
        with self.locked():
            with contextlib.suppress(FileNotFoundError):
                self._path("inflight", request_id).unlink()
            for p in sorted((self.root / "live").glob("*.json")):
                tok = self.token(p.stem)
                if tok and tok["claims"]["request_id"] == request_id and tok["state"] == "live":
                    self.set_state(tok, "spent")
                    spent.append(tok)
        return spent

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
        """Store a new token: its document, its secret's index and its live marker."""
        tid = tok["claims"]["token_id"]
        if not write_exclusive(self._path("tokens", tid), _dumps(tok)):
            raise OSError(f"token {tid} already exists")
        write_exclusive(
            self.root / "secrets" / f"{tok['secret_sha256']}.json", _dumps({"token_id": tid})
        )
        live = {"actor": tok["claims"]["actor"], "expires_at": tok["claims"]["expires_at"]}
        write_exclusive(self._path("live", tid), _dumps(live))

    def save(self, tok: dict[str, Any]) -> None:
        self._replace(self._path("tokens", tok["claims"]["token_id"]), tok)

    def set_state(self, tok: dict[str, Any], state: str, **extra: Any) -> None:
        """Move a token on: ``paused`` or ``spent`` take it off the live index for good."""
        tok.update(state=state, **extra)
        self.save(tok)
        if state != "live":
            with contextlib.suppress(FileNotFoundError):
                self._path("live", tok["claims"]["token_id"]).unlink()

    def live_of(self, actor: str, now: str) -> list[str]:
        """The ids of ``actor``'s tokens that are live and unexpired at ``now`` (a stamp)."""
        out = []
        for p in sorted((self.root / "live").glob("*.json")):
            doc = _load(p)
            if isinstance(doc, dict) and doc.get("actor") == actor and doc["expires_at"] > now:
                out.append(p.stem)
        return out

    # ---------------------------------------------------------------- executions
    def execution(self, execution_id: str) -> dict[str, Any] | None:
        return _load(self._path("executions", execution_id)) if is_id(execution_id) else None

    def put_execution(self, doc: dict[str, Any]) -> None:
        self._replace(self._path("executions", doc["execution_id"]), doc)
