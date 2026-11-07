# SPDX-License-Identifier: Apache-2.0
"""A GET-only JSON API on loopback, the shape of the gateways' log APIs the turn-source fakes
stand in for: a subclass answers ``(path, query, headers)`` with ``(status, document)``, and each
request's path and query are recorded, so a test can see what was asked."""

from __future__ import annotations

import http.server
import json
import threading
import urllib.parse
from typing import Any

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
                code, doc = api.answer(path, q, self.headers)
                raw = json.dumps(doc).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def log_message(self, *a):
                pass

        self.server = http.server.ThreadingHTTPServer((LOOPBACK, 0), Handler)
        self.url = f"http://{LOOPBACK}:{self.server.server_address[1]}"

    def answer(self, path: str, query: dict[str, str], headers: Any) -> tuple[int, Any]:
        raise NotImplementedError

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
