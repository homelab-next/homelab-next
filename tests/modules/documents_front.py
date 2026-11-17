# SPDX-License-Identifier: Apache-2.0
"""A stand-in for the document library's HTTP surface (shared by the documents tests): the sign-in
page, the document list (refused anonymously, answered for the right token) and the status."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

AGENT_TOKEN = "cd" * 20  # the agents' token: reads the library, not the status
TOKEN = "ab" * 20  # 40 lowercase hex characters, built from a short piece (no key-looking literal)


class Server:
    """``count`` documents; ``login`` the sign-in page's status; ``anonymous`` the status an
    anonymous list read gets (a broken deployment answers 200); ``database``/``redis`` the status
    fields; ``pending`` the unapplied migrations."""

    def __init__(self, count=3, login=200, anonymous=401, database="OK", redis="OK", pending=()):
        outer = self
        self.paths: list[str] = []
        self.tokens: list[str] = []
        self.count, self.login, self.anonymous = count, login, anonymous
        self.database, self.redis, self.pending = database, redis, list(pending)

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
                auth = self.headers.get("Authorization", "")
                token = auth.removeprefix("Token ") if auth.startswith("Token ") else ""
                if token:
                    outer.tokens.append(token)
                if self.path == "/accounts/login/":
                    self._send(outer.login, "<html>sign in</html>", "text/html")
                elif self.path in ("/api/documents/?page_size=1", "/api/status/"):
                    if not token:
                        self._send(outer.anonymous, json.dumps({"detail": "denied"}))
                    elif token not in (TOKEN, AGENT_TOKEN):
                        self._send(401, json.dumps({"detail": "Invalid token."}))
                    elif self.path == "/api/status/" and token != TOKEN:
                        self._send(403, json.dumps({"detail": "administrators only"}))
                    elif self.path == "/api/status/":
                        self._send(200, json.dumps({
                            "database": {"status": outer.database,
                                         "migration_status": {"unapplied_migrations": outer.pending}},
                            "tasks": {"redis_status": outer.redis},
                        }))  # fmt: skip
                    else:
                        self._send(200, json.dumps({"count": outer.count, "results": []}))
                else:
                    self.send_error(404)

        self._httpd = ThreadingHTTPServer(("localhost", 0), H)

    def __enter__(self):
        threading.Thread(target=self._httpd.serve_forever, daemon=True).start()
        return self

    def __exit__(self, *a):
        self._httpd.shutdown()
        self._httpd.server_close()

    @property
    def addr(self):
        return self._httpd.server_address[:2]
