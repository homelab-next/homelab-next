# SPDX-License-Identifier: Apache-2.0
"""Forwarders: the only thing a publisher talks to.

A forwarder accepts one envelope and acknowledges it.  Acknowledging the *same id* twice is
fine and reported as ``Ack.duplicate``; the same id with a *different body* is a permanent error
(an id collision is a bug in the publisher, never retried into success).

* :class:`FakeForwarder`   in-process; records what it accepted; fault injection for tests,
  including the lost-acknowledgement case (``lose_ack``: the event is stored, the caller sees a
  failure).
* :class:`FakeForwarderServer`  the same logic behind a loopback ``http.server`` so
  :class:`HttpForwarder` is exercised for real without any external service.
* :class:`HttpForwarder`   stdlib HTTP POST of the structured-mode JSON envelope.
"""

from __future__ import annotations

import contextlib
import json
import threading
import urllib.error
import urllib.request
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Protocol

from homelabnext._http import ResponseTooLarge, check_plaintext, read_bounded, safe_urlopen

from .envelope import body_digest, canonical_body

CONTENT_TYPE = "application/cloudevents+json"
IDEMPOTENCY_HEADER = "Idempotency-Key"
LOOPBACK = "127.0.0.1"  # no-raw-endpoint: allow test-fixture server binds loopback only


class TransientError(Exception):
    """Delivery failed in a way worth retrying (network, 5xx, 429, lost ack)."""


class PermanentError(Exception):
    """The forwarder refused the event for good (4xx other than 429, id collision)."""


@dataclass(frozen=True)
class Ack:
    id: str
    duplicate: bool = False  # True: the forwarder had already accepted this id


class Forwarder(Protocol):
    def forward(self, event: dict[str, Any]) -> Ack: ...


class FakeForwarder:
    """Records accepted events by id.

    ``fail_next``      the next N calls raise TransientError *before* storing anything.
    ``lose_ack_next``  the next N calls store the event, then raise TransientError (the crash
                       between send and ack).
    ``reject_next``    the next N calls raise PermanentError.
    """

    def __init__(self) -> None:
        self.accepted: dict[str, dict[str, Any]] = {}
        self._digests: dict[str, str] = {}
        self.calls: list[str] = []  # id of every call, including duplicates and failures
        self.fail_next = 0
        self.lose_ack_next = 0
        self.reject_next = 0
        self._lock = threading.Lock()

    def forward(self, event: dict[str, Any]) -> Ack:
        with self._lock:
            eid = event["id"]
            self.calls.append(eid)
            if self.reject_next > 0:
                self.reject_next -= 1
                raise PermanentError("fake forwarder configured to reject")
            if self.fail_next > 0:
                self.fail_next -= 1
                raise TransientError("fake forwarder unavailable")
            digest = body_digest(event)
            if eid in self._digests:
                if self._digests[eid] != digest:
                    raise PermanentError(f"id {eid!r} already accepted with a different body")
                duplicate = True
            else:
                self._digests[eid] = digest
                self.accepted[eid] = json.loads(canonical_body(event))
                duplicate = False
            if self.lose_ack_next > 0:
                self.lose_ack_next -= 1
                raise TransientError("fake forwarder lost the acknowledgement")
            return Ack(eid, duplicate)

    @property
    def ids(self) -> list[str]:
        return list(self.accepted)


class FakeForwarderServer:
    """A loopback HTTP server in front of a :class:`FakeForwarder` (use as a context manager).

    Answers 202 for a new id, 200 with ``{"duplicate": true}`` for a repeated one, 409 for an id
    collision, 503 when the fake is told to fail.
    """

    def __init__(self, fake: FakeForwarder | None = None) -> None:
        self.fake = fake or FakeForwarder()
        self.headers_seen: list[dict[str, str]] = []
        fake_ref, seen = self.fake, self.headers_seen

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                n = int(self.headers.get("Content-Length", "0"))
                raw = self.rfile.read(n)
                seen.append({k.lower(): v for k, v in self.headers.items()})
                try:
                    event = json.loads(raw)
                    ack = fake_ref.forward(event)
                    code, body = (200 if ack.duplicate else 202), {"duplicate": ack.duplicate}
                except PermanentError as exc:
                    code, body = 409, {"error": str(exc)}
                except TransientError as exc:
                    code, body = 503, {"error": str(exc)}
                except (ValueError, KeyError, TypeError):
                    code, body = 400, {"error": "malformed"}
                out = json.dumps(body).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(out)))
                self.end_headers()
                self.wfile.write(out)

            def log_message(self, *a: Any) -> None:  # silence
                pass

        self._httpd = ThreadingHTTPServer((LOOPBACK, 0), Handler)
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        return f"http://{LOOPBACK}:{self._httpd.server_address[1]}/events"

    def __enter__(self) -> FakeForwarderServer:
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()


class HttpForwarder:
    """POST the envelope (structured mode) to a forwarder URL.

    Status mapping: 200/201/202/204 accepted (a body of ``{"duplicate": true}`` or a 200 after a
    prior accept is reported as duplicate), 409 -> :class:`PermanentError` (id collision),
    408/425/429 and 5xx -> :class:`TransientError`, any other 4xx -> :class:`PermanentError`.
    Connection errors and timeouts are transient.  The id travels in ``Idempotency-Key`` too.

    Redirects are followed only within the same origin, and a reply body over ``max_reply_bytes``
    is refused (the ack is tiny).  ``auth`` (a callable returning an ``Authorization`` value,
    read per request) is refused over plain http to a non-loopback host unless
    ``allow_plaintext=True``.
    """

    def __init__(
        self,
        url: str,
        *,
        timeout: float = 5.0,
        opener: Any = None,
        auth: Any = None,
        allow_plaintext: bool = False,
        max_reply_bytes: int = 64 * 1024,
    ) -> None:
        if not url.startswith(("http://", "https://")):
            raise ValueError("forwarder url must be http(s)")
        check_plaintext(url, credentials=auth is not None, allow_plaintext=allow_plaintext)
        self.url = url
        self.timeout = timeout
        self._auth = auth
        self.max_reply_bytes = max_reply_bytes
        self._opener = opener or safe_urlopen

    def build_request(self, event: dict[str, Any]) -> urllib.request.Request:
        headers = {"Content-Type": CONTENT_TYPE, IDEMPOTENCY_HEADER: event["id"]}
        token = self._auth() if self._auth is not None else None
        if token:
            headers["Authorization"] = token
        return urllib.request.Request(
            self.url, data=canonical_body(event), headers=headers, method="POST"
        )

    def forward(self, event: dict[str, Any]) -> Ack:
        req = self.build_request(event)
        try:
            resp = self._opener(req, timeout=self.timeout)
        except urllib.error.HTTPError as exc:
            self._raise_for(exc.code)
            raise  # pragma: no cover
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            raise TransientError(f"forwarder unreachable: {type(exc).__name__}") from exc
        code = int(getattr(resp, "status", getattr(resp, "code", 200)))
        try:
            raw = read_bounded(resp, self.max_reply_bytes) if hasattr(resp, "read") else b""
        except ResponseTooLarge as exc:
            raise PermanentError(str(exc)) from None
        finally:
            close = getattr(resp, "close", None)
            if close:
                close()
        if code in (200, 201, 202, 204):
            dup = False
            with contextlib.suppress(ValueError, AttributeError):
                dup = bool(json.loads(raw or b"{}").get("duplicate", False))
            return Ack(event["id"], dup)
        self._raise_for(code)
        raise PermanentError(f"unexpected HTTP {code}")  # pragma: no cover

    @staticmethod
    def _raise_for(code: int) -> None:
        if code in (408, 425, 429) or code >= 500:
            raise TransientError(f"forwarder answered HTTP {code}")
        raise PermanentError(f"forwarder answered HTTP {code}")
