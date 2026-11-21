# SPDX-License-Identifier: Apache-2.0
"""A loopback HTTPS stand-in for the case-management service's API, with the behaviours the role's
health hook depends on: it refuses a caller with no key, answers the ping and the version to the
key, and can be made to misbehave (an open API, a refused key, another version, an error)."""

from __future__ import annotations

import json
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from forge_front import LOOPBACK


class Front:
    def __init__(self, chain: str, key: str, workdir: Path, *, api_key: str, version: str,
                 open_api=False, refuse_key=False, ping_status=200):  # fmt: skip
        outer = self
        self.api_key, self.version = api_key, version
        self.open_api, self.refuse_key, self.ping_status = open_api, refuse_key, ping_status
        self.requests: list[tuple[str, str | None]] = []
        self.posts: list[tuple[str, str]] = []  # (path, body) of the keyed POSTs

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, code, body):
                raw = json.dumps(body).encode()
                self.send_response(code)
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def do_GET(self):
                auth = self.headers.get("Authorization")
                outer.requests.append((self.path, auth))
                if self.path == "/login":
                    return self._send(200, {})
                keyed = auth == f"Bearer {outer.api_key}" and not outer.refuse_key
                if not (keyed or outer.open_api):
                    return self._send(401, {"status": "error"})
                if self.path.startswith("/manage/users/lookup/login/"):
                    return self._send(200, {"status": "success", "data": {"user_id": 1}})
                if self.path == "/api/ping":
                    return self._send(outer.ping_status, {"status": "success", "message": "pong"})
                if self.path == "/api/versions":
                    data = {"iris_current": outer.version}
                    return self._send(200, {"status": "success", "data": data})
                return self._send(404, {})

        def do_POST(handler):
            auth = handler.headers.get("Authorization")
            body = handler.rfile.read(int(handler.headers.get("Content-Length", 0))).decode()
            outer.requests.append((handler.path, auth))
            if auth != f"Bearer {outer.api_key}":
                return handler._send(401, {"status": "error"})
            outer.posts.append((handler.path, body))
            return handler._send(200, {"status": "success", "message": "User updated"})

        H.do_POST = do_POST
        self.httpd = ThreadingHTTPServer((LOOPBACK, 0), H)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        (workdir / "front-chain.pem").write_text(chain)
        (workdir / "front.key").write_text(key)
        ctx.load_cert_chain(str(workdir / "front-chain.pem"), str(workdir / "front.key"))
        self.httpd.socket = ctx.wrap_socket(self.httpd.socket, server_side=True)
        self.port = self.httpd.server_address[1]

    def __enter__(self):
        threading.Thread(
            target=self.httpd.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True
        ).start()
        return self

    def __exit__(self, *a):
        self.httpd.shutdown()
        self.httpd.server_close()
