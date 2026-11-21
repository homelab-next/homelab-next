# SPDX-License-Identifier: Apache-2.0
"""A stand-in for the enrichment service's HTTP surface (shared by the enrichment tests): the front's
liveness, the API (refused anonymously, one analyzer per path for the right token)."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TOKEN = "ab" * 20  # 40 characters, built from a short piece (no key-looking literal)


class Server:
    """``known`` the analyzer names the API answers 200 for (any other: 404); ``live`` the status of
    the liveness path; ``anonymous`` the status an anonymous API call gets (a broken deployment
    answers 200); ``token`` the token the API accepts (any other: 401)."""

    def __init__(self, known=("ThreatFox",), live=200, anonymous=401, token=TOKEN):
        outer = self
        self.paths: list[str] = []
        self.tokens: list[str] = []
        self.known, self.live, self.anonymous, self.token = set(known), live, anonymous, token

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, status, body=""):
                data = body.encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                outer.paths.append(self.path)
                auth = self.headers.get("Authorization", "")
                got = auth.removeprefix("Token ") if auth.startswith("Token ") else ""
                if got:
                    outer.tokens.append(got)
                if self.path == "/hc":
                    self._send(outer.live)
                elif self.path == "/api/analyzer":
                    self._send(outer.anonymous if not got else 200, json.dumps({"count": 0}))
                elif self.path.startswith("/api/analyzer/"):
                    name = self.path.rsplit("/", 1)[-1]
                    if got != outer.token:
                        self._send(401, json.dumps({"detail": "Invalid token."}))
                    elif name in outer.known:
                        self._send(200, json.dumps({"name": name}))
                    else:
                        self._send(404, json.dumps({"detail": "not found"}))
                else:
                    self.send_error(404)

        self._httpd = ThreadingHTTPServer(("localhost", 0), H)

    def __enter__(self):
        threading.Thread(
            target=self._httpd.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True
        ).start()
        return self

    def __exit__(self, *a):
        self._httpd.shutdown()
        self._httpd.server_close()

    @property
    def addr(self):
        return self._httpd.server_address[:2]
