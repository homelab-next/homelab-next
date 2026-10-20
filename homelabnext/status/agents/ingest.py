# SPDX-License-Identifier: Apache-2.0
"""``POST /ingest/agent-activity``: the push ingest, on its own listener (``hnx status ingest``).

This is how agents that are not on the hub's host report: cloud coding sessions, the
orchestrator, the maintainer's own agent fleet, anything that can POST JSON.  It is a separate
listener from the read-only console so the console never accepts a write, and it is the only
writer besides the local collectors.

Every request, in order (the first failure answers):

==== =======================================================================================
403  ``Host``/``Origin`` outside the allowed names (DNS rebinding guard, as the console)
404  any other path; 405 any other method
401  no ``Authorization: Bearer <token>``, or a token that is not one of the configured senders'
     (each sender's token is a secret-store reference in ``agents.yml``; compared in constant
     time against every sender)
429  the sender is over its ``rate_per_min`` (a token bucket per sender, injected clock)
411  no ``Content-Length``; 413 a body over ``max_body_bytes`` or more than ``max_events``
     records; 415 not ``application/json``
400  not a JSON object ``{"summary": [...], "detail": [...]}``
422  any record invalid against its schema, a summary carrying a detail field, or a detail
     whose event is neither in the batch nor already stored -- the batch is all or nothing
403  the sender does not own what it writes: a runtime outside its ``runtimes``, a session
     another sender or a local source started, a detail for another session's event
200  ``{"added", "duplicates", "details", "detail_dropped"}``
==== =======================================================================================

Accepted records go through :meth:`ActivityStore.add` (redact, cap, store) with
``via = push:<sender>``.  A sender configured with ``detail: false`` has its detail records
dropped (counted).  ``publish`` (optional) receives each newly accepted batch's summary events;
the CLI turns them into ``homelabnext.agent.activity`` bus events -- the detail tier never goes
there.
"""

from __future__ import annotations

import hmac
import json
import logging
import threading
import time
from collections.abc import Callable, Iterable, Mapping
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from homelabnext._http import is_loopback

from ..serve import LOOPBACK, LOOPBACK_NAMES, host_allowed
from .config import IngestSettings, Sender
from .store import ActivityError, ActivityStore

PATH = "/ingest/agent-activity"
_log = logging.getLogger(__name__)
_HEADERS = {
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
}


class RateLimiter:
    """A token bucket per sender: ``per_min`` requests a minute, bursts up to ``per_min``."""

    def __init__(self, per_min: int, clock: Callable[[], float] = time.time):
        self.rate = per_min / 60.0
        self.burst = float(per_min)
        self.clock = clock
        self._state: dict[str, tuple[float, float]] = {}
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        with self._lock:
            now = self.clock()
            tokens, last = self._state.get(key, (self.burst, now))
            tokens = min(self.burst, tokens + (now - last) * self.rate)
            if tokens < 1:
                self._state[key] = (tokens, now)
                return False
            self._state[key] = (tokens - 1, now)
            return True


def sender_for(authorization: str | None, senders: Iterable[Sender]) -> Sender | None:
    """The sender whose token the ``Authorization`` header carries (constant-time, every sender
    compared so the time does not tell which one matched)."""
    if not authorization or not authorization.startswith("Bearer "):
        return None
    token = authorization[len("Bearer ") :].strip().encode()
    found = None
    for s in senders:
        if hmac.compare_digest(token, s.token.encode()) and token:
            found = s
    return found


def check_batch(
    body: Any, store: ActivityStore, settings: IngestSettings, sender: Sender | None = None
) -> tuple[int, list[str]]:
    """``(status, problems)`` for a decoded body before anything is stored.

    With ``sender``: the sender must own what it writes -- each summary's ``runtime`` is one it
    may report (``runtimes``), each session is new or was started by this sender (never one fed
    by another sender or by a local source), and each detail belongs to an event in the batch or
    to one this sender stored.  A violation is ``403``."""
    if not isinstance(body, Mapping) or set(body) - {"summary", "detail"}:
        return 400, ['the body is a JSON object {"summary": [...], "detail": [...]}']
    summary, detail = body.get("summary", []), body.get("detail", [])
    if not isinstance(summary, list) or not isinstance(detail, list):
        return 400, ["summary and detail are lists"]
    if len(summary) + len(detail) > settings.max_events:
        return 413, [f"more than {settings.max_events} records in one request"]
    from .model import detail_problems, summary_problems

    problems = [f"summary[{i}] {p}" for i, s in enumerate(summary) for p in summary_problems(s)]
    problems += [f"detail[{i}] {p}" for i, d in enumerate(detail) for p in detail_problems(d)]
    if problems:
        return 422, problems
    ids = {s["event_id"] for s in summary}
    stored: dict[str, Mapping[str, Any]] = {}
    for i, d in enumerate(detail):
        if d["event_id"] in ids:
            continue
        ev = store.event(d["event_id"])
        if ev is None:
            problems.append(f"detail[{i}]: event {d['event_id']!r} is not in the batch or stored")
        else:
            stored[d["event_id"]] = ev
    if problems:
        return 422, problems
    if sender is None:
        return 200, []
    via = f"push:{sender.name}"
    for i, s in enumerate(summary):
        if sender.runtimes and s["runtime"] not in sender.runtimes:
            problems.append(f"summary[{i}]: sender {sender.name} may not report {s['runtime']!r}")
    sessions = {s["session_id"] for s in summary} | {d["session_id"] for d in detail}
    for sid, vias in sorted(store.owners(sessions).items()):
        if vias != {via}:
            problems.append(f"session {sid!r} belongs to another sender or source")
    for i, d in enumerate(detail):
        ev = stored.get(d["event_id"])
        if ev is not None and ev["session_id"] != d["session_id"]:
            problems.append(f"detail[{i}]: session does not match its event")
    if problems:
        _log.warning("agent ingest refused sender %s: %s", sender.name, "; ".join(problems[:5]))
    return (403, problems) if problems else (200, [])


def make_ingest_server(
    store: ActivityStore,
    settings: IngestSettings,
    *,
    host: str = LOOPBACK,
    port: int = 0,
    allow_remote: bool = False,
    allowed_hosts: Iterable[str] = (),
    clock: Callable[[], float] = time.time,
    publish: Callable[[list[Mapping[str, Any]]], None] | None = None,
) -> ThreadingHTTPServer:
    """The ingest listener.  ``port=0`` picks a free port.  Loopback unless ``allow_remote``
    (which needs ``allowed_hosts``, the names senders use)."""
    extra = frozenset(h.strip().lower().rstrip(".") for h in allowed_hosts if h.strip())
    if allow_remote and not extra:
        raise ValueError("allow_remote needs allowed_hosts: the hostnames senders will use")
    if not is_loopback(host) and not allow_remote:
        raise ValueError(
            f"refusing to bind {host}: the ingest is loopback-only unless allow_remote"
        )
    allowed = LOOPBACK_NAMES | extra
    limiter = RateLimiter(settings.rate_per_min, clock)

    class Handler(BaseHTTPRequestHandler):
        server_version = "hnx-status-ingest"
        sys_version = ""

        def _reply(self, code: int, doc: Mapping[str, Any], extra: dict | None = None) -> None:
            body = (json.dumps(doc, sort_keys=True) + "\n").encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            for k, v in {**_HEADERS, **(extra or {})}.items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def _deny(self, code: int, error: str, problems: list[str] | None = None, **kw) -> None:
            doc: dict[str, Any] = {"error": error}
            if problems:
                doc["problems"] = problems[:50]
            self.close_connection = True
            self._reply(code, doc, kw.get("headers"))

        def do_POST(self) -> None:
            if not host_allowed(self.headers.get("Host"), self.headers.get("Origin"), allowed):
                return self._deny(403, "host not allowed")
            if self.path.split("?", 1)[0] != PATH:
                return self._deny(404, "not found")
            sender = sender_for(self.headers.get("Authorization"), settings.senders)
            if sender is None:
                return self._deny(
                    401, "a sender bearer token is required",
                    headers={"WWW-Authenticate": 'Bearer realm="hnx-status-ingest"'},
                )  # fmt: skip
            if not limiter.allow(sender.name):
                return self._deny(429, "rate limited", headers={"Retry-After": "60"})
            length = self.headers.get("Content-Length")
            if length is None or not length.isdigit():
                return self._deny(411, "Content-Length is required")
            if int(length) > settings.max_body_bytes:
                return self._deny(413, f"body larger than {settings.max_body_bytes} bytes")
            ctype = (self.headers.get("Content-Type") or "").split(";", 1)[0].strip().lower()
            if ctype != "application/json":
                return self._deny(415, "Content-Type must be application/json")
            raw = self.rfile.read(int(length))
            try:
                body = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, ValueError):
                return self._deny(400, "body is not JSON")
            code, problems = check_batch(body, store, settings, sender)
            if code != 200:
                return self._deny(code, "refused", problems)
            details = body.get("detail", []) if sender.detail else []
            try:
                res = store.add(body.get("summary", []), details, via=f"push:{sender.name}")
            except ActivityError as exc:
                return self._deny(422, "refused", exc.problems)
            if publish is not None and res.added:
                publish(list(body.get("summary", [])))
            self._reply(
                200,
                {
                    "added": res.added,
                    "duplicates": res.duplicates,
                    "details": res.details,
                    "detail_dropped": len(body.get("detail", [])) - len(details),
                },
            )

        def _refuse(self) -> None:
            if not host_allowed(self.headers.get("Host"), self.headers.get("Origin"), allowed):
                return self._deny(403, "host not allowed")
            self._deny(405, "POST only", headers={"Allow": "POST"})

        do_GET = do_HEAD = do_PUT = do_PATCH = do_DELETE = do_OPTIONS = _refuse

        def log_message(self, *a: Any) -> None:
            pass

    return ThreadingHTTPServer((host, port), Handler)
