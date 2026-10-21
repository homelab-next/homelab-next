# SPDX-License-Identifier: Apache-2.0
"""OpenProject -> ``homelabnext.project.changed`` events: a webhook as the trigger, a poll as
the guarantee.

OpenProject's webhooks are lossy (sent after the journal aggregation window, retried only on a
timeout, no delete or relation events, an unsigned SHA-1 HMAC with no timestamp): they are a
low-latency *hint*.  :meth:`ChangeFeed.poll` reads every work package whose ``updatedAt`` moved
since the cursor and is what makes the feed complete.  Both build the same event for the same
work package version -- the id derives from ``wp:<id>:v<lockVersion>`` -- and :class:`ChangeFeed`
emits each id once, so whichever path sees a version first wins and the other is a no-op.

:func:`verify_signature` checks ``X-OP-Signature: sha1=<hex HMAC-SHA1(secret, body)>`` in
constant time; :func:`make_webhook_server` refuses a request without a valid one (401) and
reads the secret by name (``secret:openproject/webhook-secret``) at each request.

A work package of a strategy type that someone other than the sync user changed is noted in
:attr:`ChangeFeed.strategy_edits`: the next ``sync-strategy`` writes the repository's version
back and reports it (the repository wins).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from collections.abc import Callable, Mapping, MutableSet
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from homelabnext._http import is_loopback
from homelabnext.registry.model import secret_env_name

from ..events import change_event
from .backend import OpenProjectBackend, _link_id, wp_href

__all__ = [
    "SIGNATURE_HEADER",
    "ChangeFeed",
    "adopt",
    "make_webhook_server",
    "verify_signature",
]

SIGNATURE_HEADER = "X-OP-Signature"
LOOPBACK = "127.0.0.1"  # no-raw-endpoint: allow the webhook receiver binds loopback by default
MAX_BODY = 1 << 20


def verify_signature(secret: bytes, body: bytes, header: str | None) -> bool:
    """True when ``header`` is ``sha1=<hex>`` of HMAC-SHA1(``secret``, ``body``)."""
    if not secret or not header or not header.startswith("sha1="):
        return False
    want = hmac.new(secret, body, hashlib.sha1).hexdigest()
    return hmac.compare_digest(want, header[5:].strip().lower())


def adopt(backend: OpenProjectBackend, new_uid: Callable[[], str]) -> list[str]:
    """Give every work item made by hand in OpenProject (no External key yet) a fresh uid, so it
    becomes a contract item; returns ``wp:<id>`` of each adopted package."""
    with backend.lock():
        backend.load()
        out = []
        for wid in backend.unadopted:
            wp = backend.client.get(wp_href(wid))
            backend.client.patch(
                wp_href(wid),
                {"lockVersion": wp.get("lockVersion", 0), backend._ext: new_uid()},
            )
            out.append(f"wp:{wid}")
        return out


class ChangeFeed:
    """Turns OpenProject changes into events and hands each new one to ``sink`` exactly once."""

    def __init__(
        self,
        backend: OpenProjectBackend,
        sink: Callable[[dict[str, Any]], Any],
        *,
        seen: MutableSet[str] | None = None,
    ) -> None:
        self.backend, self.sink = backend, sink
        self.seen: MutableSet[str] = set() if seen is None else seen
        self.strategy_edits: list[str] = []

    def _emit(self, event: dict[str, Any]) -> dict[str, Any] | None:
        if event["id"] in self.seen:
            return None
        self.sink(event)
        self.seen.add(event["id"])
        return event

    def poll(self, cursor: str | None) -> tuple[list[dict[str, Any]], str]:
        """Events for every work item changed since ``cursor`` (None: from now on), and the next
        cursor.  Safe to repeat: an event already emitted is not emitted again."""
        with self.backend.lock():
            changes, nxt = self.backend.changes(cursor)
        out = []
        for ch in changes:
            ev = change_event(ch, origin="openproject", lock_version=ch.version - 1)
            if self._emit(ev):
                out.append(ev)
        return out, nxt

    def on_webhook(self, payload: Mapping[str, Any]) -> dict[str, Any] | None:
        """One webhook delivery (already authenticated).  Work items become events; anything
        else is ignored, except strategy records changed by someone else (noted)."""
        action = str(payload.get("action") or "")
        wp = payload.get("work_package")
        if not action.startswith("work_package:") or not isinstance(wp, Mapping):
            return None
        b = self.backend
        type_id = _link_id(wp, "type") or -1
        if type_id not in b._kinds:
            names = {b.setup.types.get(n) for n in b.cfg.strategy_types}
            actor = (payload.get("actor") or {}).get("id")
            if type_id in names and actor != b.setup.me:
                self.strategy_edits.append(f"wp:{wp.get('id')} by user {actor}")
            return None
        if not wp.get(b._ext) or "lockVersion" not in wp or "id" not in wp:
            return None  # not adopted yet: the poll adopts and reports it
        with b.lock():
            doc = b.load().get(str(wp[b._ext]))  # the same view the poll has (its project)
        ch = b.change_of(wp, doc)
        return self._emit(change_event(ch, origin="openproject", lock_version=ch.version - 1))


def make_webhook_server(
    feed: ChangeFeed,
    *,
    secret: str = "secret:openproject/webhook-secret",
    env: Mapping[str, str] | None = None,
    host: str = LOOPBACK,
    port: int = 0,
    allow_remote: bool = False,
    path: str = "/openproject/webhook",
) -> ThreadingHTTPServer:
    """A receiver for OpenProject's webhook: ``POST path`` with a valid signature -> 204.

    401 without a valid signature (or with no secret configured: an unsigned webhook is never
    accepted), 400 for a body that is not a JSON object, 413 over 1 MiB, 404/405 elsewhere."""
    if not secret.startswith("secret:"):
        raise ValueError("secret is a secret reference (secret:<name>), never a value")
    if not is_loopback(host) and not allow_remote:
        raise ValueError(f"refusing to bind {host}: loopback only unless allow_remote is set")
    var = secret_env_name(secret)

    class Handler(BaseHTTPRequestHandler):
        server_version = "hnx-openproject-webhook"
        sys_version = ""
        timeout = 30

        def log_message(self, fmt, *args):  # no request logging: payloads are not logged
            return

        def _reply(self, code: int, text: str = "") -> None:
            body = text.encode()
            self.send_response(code)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:
            self._reply(405, "POST only\n")

        def do_POST(self) -> None:
            if self.path.partition("?")[0] != path:
                self._reply(404, "not found\n")
                return
            try:
                length = int(self.headers.get("Content-Length") or "0")
            except ValueError:
                length = -1
            if length < 0 or length > MAX_BODY:
                self._reply(413, "body too large\n")
                return
            body = self.rfile.read(length)
            key = (os.environ if env is None else env).get(var, "").encode()
            if not verify_signature(key, body, self.headers.get(SIGNATURE_HEADER)):
                self._reply(401, "bad signature\n")
                return
            try:
                payload = json.loads(body)
            except ValueError:
                payload = None
            if not isinstance(payload, dict):
                self._reply(400, "not a JSON object\n")
                return
            feed.on_webhook(payload)
            self._reply(204)

    return ThreadingHTTPServer((host, port), Handler)
