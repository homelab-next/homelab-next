# SPDX-License-Identifier: Apache-2.0
"""A fake OpenBao on loopback for the vault password client and the ``hnx_secret`` lookup.

It answers the three calls those clients make, over a real socket so the stdlib opener's own
redirect handling is what is tested: an AppRole login (``POST /v1/auth/approle/login``, mints a
token), a KV v2 read (``GET /v1/<mount>/data/<name>``, needs a live token) and
``POST /v1/auth/token/revoke-self`` (kills the calling token).  With ``redirect_to`` set it
answers every request with a 307 to that origin instead, the way a hostile or misconfigured
proxy would.  Every request is recorded as ``(method, path, X-Vault-Token)``.
"""

from __future__ import annotations

import json
import ssl
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


class FakeOpenBao:
    def __init__(
        self,
        values: dict[str, dict[str, str]] | None = None,
        *,
        tls: ssl.SSLContext | None = None,
        redirect_to: str | None = None,
        revoke_status: int = 204,
    ):
        self.values = values or {}  # "<mount>/<name>" -> {field: value}
        self.redirect_to = redirect_to
        self.revoke_status = revoke_status
        self.calls: list[tuple[str, str, str | None]] = []
        self.live: set[str] = set()
        self.minted = 0
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):  # quiet
                pass

            def _reply(self, status: int, doc: object | None = None, headers=()):
                body = b"" if doc is None else json.dumps(doc).encode()
                self.send_response(status)
                for k, v in headers:
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _handle(self, method: str):
                token = self.headers.get("X-Vault-Token")
                fake.calls.append((method, self.path, token))
                n = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(n) if n else b""
                if fake.redirect_to:
                    # a fixed target: the request line never reaches a response header
                    return self._reply(
                        307, None, [("Location", fake.redirect_to + "/v1/redirected")]
                    )
                if method == "POST" and self.path == "/v1/auth/approle/login":
                    body = json.loads(raw or b"{}")
                    if not (body.get("role_id") and body.get("secret_id")):
                        return self._reply(400, {"errors": ["missing"]})
                    fake.minted += 1
                    tok = f"fake-minted-token-{fake.minted}"
                    fake.live.add(tok)
                    return self._reply(200, {"auth": {"client_token": tok}})
                if method == "POST" and self.path == "/v1/auth/token/revoke-self":
                    if fake.revoke_status == 204:
                        fake.live.discard(token or "")
                        return self._reply(204)
                    return self._reply(fake.revoke_status, {"errors": ["denied"]})
                if method == "GET" and self.path.startswith("/v1/"):
                    if token not in fake.live:
                        return self._reply(403, {"errors": ["permission denied"]})
                    mount, _, rest = self.path[len("/v1/") :].partition("/data/")
                    data = fake.values.get(f"{mount}/{rest}")
                    if data is None:
                        return self._reply(404, {"errors": []})
                    return self._reply(200, {"data": {"data": data}})
                return self._reply(404, {"errors": []})

            def do_GET(self):
                self._handle("GET")

            def do_POST(self):
                self._handle("POST")

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.scheme = "https" if tls else "http"
        if tls:
            self.server.socket = tls.wrap_socket(self.server.socket, server_side=True)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        host = "localhost" if self.scheme == "https" else "127.0.0.1"
        return f"{self.scheme}://{host}:{self.server.server_address[1]}"

    def __enter__(self) -> FakeOpenBao:
        self.thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self.server.shutdown()
        self.server.server_close()


def self_signed(directory: Path) -> tuple[ssl.SSLContext, Path] | None:
    """A server context with a fresh self-signed certificate for ``localhost`` and the CA file a
    client verifies it with; ``None`` without the ``openssl`` command."""
    key, cert = directory / "bao-key.pem", directory / "bao-cert.pem"
    try:
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
             "-keyout", str(key), "-out", str(cert), "-subj", "/CN=localhost",
             "-addext", "subjectAltName=DNS:localhost"],
            check=True, capture_output=True, timeout=60,
        )  # fmt: skip
    except (OSError, subprocess.SubprocessError):
        return None
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.minimum_version = ssl.TLSVersion.TLSv1_2
    server.load_cert_chain(cert, key)
    return server, cert
