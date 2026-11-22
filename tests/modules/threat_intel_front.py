# SPDX-License-Identifier: Apache-2.0
"""A stand-in for the threat-intel platform's HTTP surface (shared by the threat-intel tests): the
sign-in page, and the version call, which answers only a request that carries the key of an account
it knows (any other, or none, is refused)."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

#: short stand-in words, never key-looking literals
KNOWN = {"known-account-token"}


class Server:
    """``login`` the sign-in page's status; ``open_api`` makes a broken deployment that answers the
    version call to every caller."""

    def __init__(self, login=200, open_api=False):
        outer = self
        self.login, self.open_api = login, open_api
        self.paths: list[str] = []
        self.auth: list[str | None] = []

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, status, body="", ctype="application/json"):
                data = body.encode()
                self.send_response(status)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                outer.paths.append(self.path)
                outer.auth.append(self.headers.get("Authorization"))
                if self.path == "/users/login":
                    self._send(outer.login, "<html>sign in</html>", "text/html")
                elif self.path == "/servers/getVersion":
                    if outer.open_api or self.headers.get("Authorization") in KNOWN:
                        self._send(200, json.dumps({"version": "x"}))
                    else:
                        self._send(403, json.dumps({"name": "Authentication failed"}))
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
