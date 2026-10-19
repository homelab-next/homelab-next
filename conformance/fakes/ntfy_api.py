# SPDX-License-Identifier: Apache-2.0
"""A loopback HTTP stand-in for the ntfy publish and poll API the ``notify`` adapter uses.

Shaped after ntfy 2.11 (``server/server.go``, ``message_cache.go``): ``POST /<topic>`` with the
``Title``/``Priority``/``Tags`` headers (``X-`` forms too) and the body as the message, trimmed
(``strings.TrimSpace``) and ``triggered`` when empty; ``GET /<topic>/json?poll=1&since=all``
answering the cached messages as newline-delimited JSON in arrival order, with ``priority`` and
``tags`` omitted when unset; ``GET /v1/health``.  Topics are ``[-_A-Za-z0-9]{1,64}``.

``duplicate=True`` stores every message twice (a defective channel); ``rewrite`` maps a stored
body to another one (a lossy channel) - both for proving the suite sees the far side.
"""

from __future__ import annotations

import itertools
import json
import re
import threading
import urllib.parse
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

LOOPBACK = "127.0.0.1"  # no-raw-endpoint: allow fake server binds loopback only
_TOPIC = re.compile(r"^[-_A-Za-z0-9]{1,64}$")
_PRIO = {
    "1": 1,
    "min": 1,
    "2": 2,
    "low": 2,
    "3": 3,
    "default": 3,
    "4": 4,
    "high": 4,
    "5": 5,
    "max": 5,
    "urgent": 5,
}


class FakeNtfy:
    def __init__(
        self,
        *,
        duplicate: bool = False,
        rewrite: Callable[[str], str] | None = None,
        host: str = LOOPBACK,
        port: int = 0,
    ):
        self.duplicate = duplicate
        self.rewrite = rewrite
        self.messages: list[dict[str, Any]] = []
        self.polls = 0
        self._ids = itertools.count(1)
        self._lock = threading.Lock()
        self._httpd = ThreadingHTTPServer((host, port), self._handler())
        self._thread: threading.Thread | None = None

    @property
    def url(self) -> str:
        host, port = self._httpd.server_address[:2]
        return f"http://{host}:{port}"

    def start(self) -> FakeNtfy:
        self._thread = threading.Thread(
            target=self._httpd.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True
        )
        self._thread.start()
        return self

    def stop(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()
        if self._thread:
            self._thread.join(timeout=5)

    def __enter__(self) -> FakeNtfy:
        return self.start()

    def __exit__(self, *exc: object) -> None:
        self.stop()

    def publish(self, topic: str, headers: Any, body: bytes) -> tuple[int, dict[str, Any]]:
        def param(*names: str) -> str:
            for n in names:
                v = headers.get(n)
                if v:
                    return v.strip()
            return ""

        try:
            text = body.decode("utf-8")
        except UnicodeDecodeError:
            return 400, {"code": 40011, "error": "message not UTF-8"}
        msg: dict[str, Any] = {
            "id": f"fake{next(self._ids):08d}",
            "time": 1_700_000_000,
            "event": "message",
            "topic": topic,
            "message": text.strip() or "triggered",
        }
        title = param("X-Title", "Title", "t")
        if title:
            msg["title"] = title
        prio = param("X-Priority", "Priority", "prio", "p")
        if prio:
            if prio.lower() not in _PRIO:
                return 400, {"code": 40007, "error": "invalid priority"}
            msg["priority"] = _PRIO[prio.lower()]
        tags = [t.strip() for t in param("X-Tags", "Tags", "tag", "ta").split(",") if t.strip()]
        if tags:
            msg["tags"] = tags
        if self.rewrite:
            msg["message"] = self.rewrite(msg["message"])
        self.messages.append(msg)
        if self.duplicate:
            self.messages.append({**msg, "id": f"fake{next(self._ids):08d}"})
        return 200, msg

    def _handler(self) -> type[BaseHTTPRequestHandler]:
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a: object) -> None:
                return

            def _send(self, status: int, body: bytes, ctype: str = "application/json") -> None:
                self.send_response(status)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self) -> None:
                n = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(n) if n else b""
                topic = urllib.parse.urlsplit(self.path).path.strip("/")
                if not _TOPIC.match(topic):
                    self._send(400, b'{"code":40009,"error":"invalid topic"}')
                    return
                with fake._lock:
                    status, doc = fake.publish(topic, self.headers, raw)
                self._send(status, json.dumps(doc).encode())

            def do_GET(self) -> None:
                url = urllib.parse.urlsplit(self.path)
                if url.path == "/v1/health":
                    self._send(200, b'{"healthy":true}')
                    return
                parts = url.path.strip("/").split("/")
                q = dict(urllib.parse.parse_qsl(url.query))
                if len(parts) != 2 or parts[1] != "json" or q.get("poll") != "1":
                    self._send(404, b'{"code":40401,"error":"page not found"}')
                    return
                with fake._lock:
                    fake.polls += 1
                    lines = [json.dumps(m) for m in fake.messages if m["topic"] == parts[0]]
                self._send(200, "".join(x + "\n" for x in lines).encode(), "application/x-ndjson")

        return Handler
