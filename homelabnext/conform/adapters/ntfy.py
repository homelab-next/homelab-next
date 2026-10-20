# SPDX-License-Identifier: Apache-2.0
"""The ``notify`` contract on ntfy (pinned: ntfy 2.11), stdlib HTTP.

``make(**config)`` returns an :class:`NtfyTarget` on ``HNX_ENDPOINT_NOTIFY``:

* ``sender`` is the library's own :class:`homelabnext.notify.NtfySender` (the thing in production)
  publishing to a scratch topic, wrapped only to add two tags per message: ``hnxkey-<hex>`` (the
  dedupe key, hex-encoded so any key survives ntfy's comma-separated tag list) and
  ``hnxlevel-<level>``.  ntfy has no field for either; tags are its metadata channel.
* ``received()`` is observed independently of the sender: it reads the topic back from ntfy's
  message cache (``GET /<topic>/json?poll=1&since=all``, newline-delimited JSON, in arrival order)
  and rebuilds each message from what the server stored - title, message body and tags.  Nothing
  the sender did is consulted, so a duplicate, a drop or a rewrite on the way shows up here.

The topic is random per target (``hnxconf-<hex>``), so checks and runs never see each other.
``fault-injection`` is honoured with a real failure, not a canned exception: ``fail_next(n)``
sends the next ``n`` messages through a second ``NtfySender`` aimed at a loopback port this target
holds bound but never listens on, so the send fails on real I/O (connection refused) inside the
production sender's own error path, and nothing reaches ntfy - which ``received()`` then shows.

Findings (fidelity limits of the channel, not of this adapter):

* ntfy strips leading and trailing whitespace from the body (``strings.TrimSpace``) and replaces an
  empty body with ``triggered``; such bodies do not round-trip.
* ``NtfySender`` sends the title as one latin-1 header line (whitespace folded, other characters
  replaced) although ntfy accepts RFC 2047 encoded UTF-8 headers, so non-latin-1 titles are lossy.
* Messages live in ntfy's cache for ``cache-duration`` (12h by default); ``received()`` sees only
  what is still cached.
"""

from __future__ import annotations

import json
import secrets
import socket
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import replace
from typing import Any

from homelabnext._http import DEFAULT_MAX_BYTES, check_plaintext, read_bounded, safe_urlopen
from homelabnext.notify import LEVELS, Message, NtfySender, SendError

from ._env import resolve

__all__ = ["NtfyTarget", "make"]

_LOOPBACK = "127.0.0.1"  # no-raw-endpoint: allow the fault hook's dead port is local by design
KEY_TAG = "hnxkey-"
LEVEL_TAG = "hnxlevel-"


class _TaggingSender:
    """Adds the key and level tags, then hands the message to the real ``NtfySender`` (or, while
    a fault is armed, to one aimed at a dead port)."""

    def __init__(self, inner: NtfySender, dead: Callable[[], NtfySender]):
        self.inner = inner
        self._dead = dead
        self.fail_next = 0

    def __repr__(self) -> str:
        return f"_TaggingSender({self.inner!r})"

    def send(self, message: Message) -> None:
        tags = (
            *message.tags,
            KEY_TAG + message.key.encode("utf-8").hex(),
            LEVEL_TAG + message.level,
        )
        sender = self.inner
        if self.fail_next > 0:
            self.fail_next -= 1
            sender = self._dead()
        sender.send(replace(message, tags=tags))


class NtfyTarget:
    """:class:`conformance.protocols.notify.NotifyTarget` on one ntfy topic."""

    features = frozenset({"fault-injection"})

    def __init__(
        self,
        base_url: str,
        *,
        topic: str | None = None,
        auth: Callable[[], str | None] | None = None,
        timeout: float = 10.0,
        allow_plaintext: bool = False,
        max_bytes: int = 4 * DEFAULT_MAX_BYTES,
    ):
        if not base_url.startswith(("http://", "https://")):
            raise ValueError("base_url must be an http(s) URL supplied by the caller")
        check_plaintext(base_url, credentials=auth is not None, allow_plaintext=allow_plaintext)
        self._base = base_url.rstrip("/")
        self.topic = topic or f"hnxconf-{secrets.token_hex(8)}"
        self._auth = auth
        self.timeout = timeout
        self.max_bytes = max_bytes
        inner = NtfySender(
            self._base,
            default_topic=self.topic,
            auth=auth,
            timeout=timeout,
            allow_plaintext=allow_plaintext,
        )
        self._hole: socket.socket | None = None
        self.sender = _TaggingSender(inner, self._dead_sender)

    def __repr__(self) -> str:
        return f"NtfyTarget(topic={self.topic!r})"

    # ---------------------------------------------------------------- fault-injection hook
    def fail_next(self, n: int = 1) -> None:
        self.sender.fail_next = int(n)

    def _dead_sender(self) -> NtfySender:
        if self._hole is None:
            # bound, never listening: a connect to it is refused, deterministically
            self._hole = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._hole.bind((_LOOPBACK, 0))
        host, port = self._hole.getsockname()[:2]
        return NtfySender(f"http://{host}:{port}", default_topic=self.topic, timeout=self.timeout)

    def close(self) -> None:
        if self._hole is not None:
            self._hole.close()
            self._hole = None

    def _poll(self) -> list[dict[str, Any]]:
        url = f"{self._base}/{urllib.parse.quote(self.topic)}/json?poll=1&since=all"
        headers = {"Accept": "application/x-ndjson"}
        if self._auth is not None:
            token = self._auth()
            if token:
                headers["Authorization"] = token
        req = urllib.request.Request(url, headers=headers, method="GET")
        raw, failure = b"", ""
        try:
            with safe_urlopen(req, timeout=self.timeout) as resp:
                raw = read_bounded(resp, self.max_bytes)
        except urllib.error.HTTPError as exc:
            failure = f"HTTP {exc.code}"
        except (urllib.error.URLError, OSError, ValueError) as exc:
            failure = type(exc).__name__
        if failure:
            raise SendError(f"reading topic {self.topic} back from ntfy failed: {failure}")
        events = []
        for line in raw.decode("utf-8").splitlines():
            if line.strip():
                try:
                    events.append(json.loads(line))
                except ValueError:
                    raise SendError(f"ntfy poll of {self.topic}: a line is not JSON") from None
        return events

    def received(self) -> list[Message]:
        out: list[Message] = []
        for ev in self._poll():
            if ev.get("event") != "message":
                continue
            tags = [str(t) for t in ev.get("tags") or []]
            keys = [t[len(KEY_TAG) :] for t in tags if t.startswith(KEY_TAG)]
            levels = [t[len(LEVEL_TAG) :] for t in tags if t.startswith(LEVEL_TAG)]
            if len(keys) != 1:
                continue  # not published through this target
            try:
                key = bytes.fromhex(keys[0]).decode("utf-8")
            except ValueError:
                continue
            level = levels[0] if len(levels) == 1 and levels[0] in LEVELS else "info"
            rest = tuple(t for t in tags if not t.startswith((KEY_TAG, LEVEL_TAG)))
            priority = ev.get("priority")
            out.append(
                Message(
                    key=key,
                    title=str(ev.get("title") or "(untitled)"),
                    body=str(ev.get("message", "")),
                    level=level,
                    priority=int(priority)
                    if isinstance(priority, int) and 1 <= priority <= 5
                    else None,
                    tags=rest,
                    topic=str(ev.get("topic") or self.topic),
                )
            )
        return out


def make(
    *,
    topic: str | None = None,
    timeout: float = 10.0,
    allow_plaintext: bool = False,
    capability: str = "notify",
) -> NtfyTarget:
    """A target on the ``notify`` endpoint (unauthenticated, as the lab's ntfy is)."""
    return NtfyTarget(
        resolve(capability, env_only=True, schemes=("http", "https")).url,
        topic=topic,
        timeout=timeout,
        allow_plaintext=allow_plaintext,
    )
