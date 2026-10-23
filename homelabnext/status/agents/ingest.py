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
     another sender or a local source started, an event id already stored for another session
     or sender, a detail for another sender's or another session's event
409  a detail for an event that already has a different one (a detail is written once)
200  ``{"added", "duplicates", "details", "detail_dropped"}``
==== =======================================================================================

The listener's own bounds: a request must arrive within ``timeout_s`` (default 30 s, as the
console's) or its connection is closed, and at most ``max_connections`` (default
:data:`DEFAULT_INGEST_CONNECTIONS`) are served at once, more answered ``503`` without a thread
(:class:`homelabnext.status.serve.BoundedHTTPServer`): both before any token check, so a peer
that only connects cannot pin the hub's threads or descriptors.

Accepted records go through :meth:`ActivityStore.add` (redact, cap, store) with
``via = push:<sender>``.  A sender configured with ``detail: false`` has its detail records
dropped (counted) and its summaries' ``has_detail`` cleared.  ``publish`` (optional) receives
the summaries a batch actually stored -- the store's redacted copies, duplicates left out;
``hnx status ingest --publish-to`` turns them into ``homelabnext.agent.activity`` bus events --
the detail tier never goes there.
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

from ..serve import LOOPBACK, LOOPBACK_NAMES, BoundedHTTPServer, host_allowed
from .config import IngestSettings, Sender
from .store import ActivityError, ActivityStore

PATH = "/ingest/agent-activity"
#: seconds a connection may take to deliver its request; connections served at once
DEFAULT_TIMEOUT_S = 30
DEFAULT_INGEST_CONNECTIONS = 32
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

    **What is stored decides ownership**: an event id already stored belongs to the session and
    the ``via`` that stored it, whatever a later batch says.  With ``sender``: the sender must
    own what it writes -- each summary's ``runtime`` is one it may report (``runtimes``); a
    summary naming a stored event is that event (same session, same sender) or it is refused;
    each session is new or was started by this sender (never one fed by another sender or by a
    local source); and each detail's event (stored, or new in this batch) is this sender's and in
    the detail's session.  A violation is ``403``.  A detail is written once: a different
    second detail for an event is ``409`` (the same one again is an idempotent retry)."""
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
    stored = store.event_owners([s["event_id"] for s in summary] + [d["event_id"] for d in detail])
    batch: dict[str, str] = {}  # event_id -> session, of the summaries in this batch
    for i, s in enumerate(summary):
        if batch.setdefault(s["event_id"], s["session_id"]) != s["session_id"]:
            problems.append(f"summary[{i}]: event {s['event_id']!r} twice, in two sessions")
    seen: set[str] = set()
    for i, d in enumerate(detail):
        if d["event_id"] not in batch and d["event_id"] not in stored:
            problems.append(f"detail[{i}]: event {d['event_id']!r} is not in the batch or stored")
        if d["event_id"] in seen:
            problems.append(f"detail[{i}]: a second detail for event {d['event_id']!r}")
        seen.add(d["event_id"])
    if problems:
        return 422, problems
    if sender is not None:
        problems = _ownership(summary, detail, store, stored, batch, sender)
        if problems:
            # problems quote sender-supplied values: never let them forge or split a log line
            text = "; ".join(problems[:5]).replace("\r", "\\r").replace("\n", "\\n")
            _log.warning("agent ingest refused sender %s: %s", sender.name, text)
            return 403, problems
    have = store.details_of(seen)
    for i, d in enumerate(detail):
        old = have.get(d["event_id"])
        if old is not None and old != store.redactor.detail(d):
            problems.append(
                f"detail[{i}]: event {d['event_id']!r} already has a detail (written once)"
            )
    return (409, problems) if problems else (200, [])


def _ownership(
    summary: list[Mapping[str, Any]],
    detail: list[Mapping[str, Any]],
    store: ActivityStore,
    stored: Mapping[str, tuple[str, str]],
    batch: Mapping[str, str],
    sender: Sender,
) -> list[str]:
    """What ``sender`` writes that it does not own (see :func:`check_batch`)."""
    via = f"push:{sender.name}"
    problems = []
    for i, s in enumerate(summary):
        if sender.runtimes and s["runtime"] not in sender.runtimes:
            problems.append(f"summary[{i}]: sender {sender.name} may not report {s['runtime']!r}")
        own = stored.get(s["event_id"])
        if own is not None and own != (s["session_id"], via):
            problems.append(
                f"summary[{i}]: event {s['event_id']!r} is stored for another session or sender"
            )
    sessions = {s["session_id"] for s in summary} | {d["session_id"] for d in detail}
    for sid, vias in sorted(store.owners(sessions).items()):
        if vias != {via}:
            problems.append(f"session {sid!r} belongs to another sender or source")
    for i, d in enumerate(detail):
        own = stored.get(d["event_id"]) or (batch[d["event_id"]], via)
        if own[1] != via:
            problems.append(f"detail[{i}]: event {d['event_id']!r} belongs to another sender")
        elif own[0] != d["session_id"]:
            problems.append(f"detail[{i}]: session does not match its event")
    return problems


def bus_publisher(publisher: Any, source: str) -> Callable[[list[Mapping[str, Any]]], None]:
    """A ``publish`` hook for :func:`make_ingest_server`: each stored summary as one
    ``homelabnext.agent.activity`` event (:func:`.model.bus_event`) through ``publisher`` (a
    :class:`homelabnext.events.publisher.Publisher`: write-ahead, so a send that fails stays
    pending for its ``flush``).  It never raises: the ingest answers whatever the bus does."""
    from .model import bus_event

    lock = threading.Lock()  # the listener is threaded; the publisher's store is one file

    def publish(summaries: list[Mapping[str, Any]]) -> None:
        with lock:
            for s in summaries:
                try:
                    res = publisher.publish(bus_event(s, source))
                except Exception as exc:  # the bus must never fail an ingest
                    _log.warning("agent activity not published: %s", type(exc).__name__)
                    continue
                if not res.ok:
                    _log.warning("agent activity event %s is %s", res.id, res.status)

    return publish


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
    timeout_s: float = DEFAULT_TIMEOUT_S,
    max_connections: int = DEFAULT_INGEST_CONNECTIONS,
) -> ThreadingHTTPServer:
    """The ingest listener.  ``port=0`` picks a free port.  Loopback unless ``allow_remote``
    (which needs ``allowed_hosts``, the names senders use).  ``timeout_s`` bounds each read of a
    request, ``max_connections`` the connections served at once (see the module doc)."""
    if timeout_s <= 0:
        raise ValueError("timeout_s is positive")
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
        timeout = timeout_s  # a peer that sends nothing, or half a request, cannot hold a thread

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
            summaries = body.get("summary", [])
            details = body.get("detail", []) if sender.detail else []
            if not sender.detail:  # its details are dropped here, so none exists for these
                summaries = [{**s, "has_detail": False} if s.get("has_detail") else s
                             for s in summaries]  # fmt: skip
            try:
                res = store.add(summaries, details, via=f"push:{sender.name}")
            except ActivityError as exc:
                return self._deny(422, "refused", exc.problems)
            if publish is not None and res.accepted:
                publish(res.accepted)  # what was stored, redacted; never a duplicate
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

    return BoundedHTTPServer((host, port), Handler, max_connections=max_connections)
