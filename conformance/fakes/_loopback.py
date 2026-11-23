# SPDX-License-Identifier: Apache-2.0
"""A JSON API on loopback, the shape of the gateways' log APIs the turn-source fakes stand in for:
a subclass answers a GET ``(path, query, headers)`` with ``(status, document)`` and, when it takes
writes, a POST ``(path, query, headers, body)`` (405 otherwise), and each request's path and
query are recorded, so a test can see what was asked."""

from __future__ import annotations

import http.server
import json
import threading
import urllib.parse
from typing import Any

from homelabnext._http import send_json

LOOPBACK = "127.0.0.1"  # no-raw-endpoint: allow the fake gateway binds loopback only


class LoopbackAPI:
    """Serves :meth:`answer` on loopback while inside ``with`` (or between start and stop)."""

    def __init__(self) -> None:
        self.requests: list[dict[str, str]] = []
        api = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                path, _, query = self.path.partition("?")
                q = {k: v[0] for k, v in urllib.parse.parse_qs(query).items()}
                api.requests.append({"path": path, **q})
                send_json(self, *api.answer(path, q, self.headers))

            def do_POST(self):
                path, _, query = self.path.partition("?")
                q = {k: v[0] for k, v in urllib.parse.parse_qs(query).items()}
                api.requests.append({"path": path, "method": "POST", **q})
                length = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(length) or b"null") if length else None
                send_json(self, *api.answer_post(path, q, self.headers, body))

            def log_message(self, *a):
                pass

        self.server = http.server.ThreadingHTTPServer((LOOPBACK, 0), Handler)
        self.url = f"http://{LOOPBACK}:{self.server.server_address[1]}"

    def answer(self, path: str, query: dict[str, str], headers: Any) -> tuple[int, Any]:
        raise NotImplementedError

    def answer_post(
        self, path: str, query: dict[str, str], headers: Any, body: Any
    ) -> tuple[int, Any]:
        return 405, {"error": "this API takes no writes"}

    def start(self):
        threading.Thread(
            target=self.server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True
        ).start()
        return self

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()

    def __enter__(self):
        return self.start()

    def __exit__(self, *a):
        self.stop()
