# SPDX-License-Identifier: Apache-2.0
"""A TLS stand-in for the graph store's HTTPS API: answers as the active service, refuses a storm call
that carries no session (or accepts it, with ``open_api``), records what it was asked.  Its certificate
is made for the test and written next to the test's files."""

from __future__ import annotations

import json
import ssl
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from tests.suite_policy import require_tool

NAME = "graph.example.internal"  # the name the stand-in's certificate carries


def make_cert(directory: Path) -> tuple[Path, Path]:
    """A self-signed certificate and its private key, under ``directory`` (made with openssl)."""
    cert_path, key_path = directory / "cert.pem", directory / "tls.pem"
    subprocess.run(
        [
            require_tool("openssl"), "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
            "-nodes", "-days", "2", "-subj", f"/CN={NAME}", "-addext", f"subjectAltName=DNS:{NAME}",
            "-keyout", str(key_path), "-out", str(cert_path),
        ],
        check=True,
        capture_output=True,
    )  # fmt: skip
    return cert_path, key_path


class Server:
    def __init__(self, directory: Path, open_api: bool = False, active: bool = True) -> None:
        self.paths: list[str] = []
        self.cert, key = make_cert(directory)
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):  # silence
                return

            def _send(self, code: int, doc: dict) -> None:
                body = json.dumps(doc).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                outer.paths.append(self.path)
                if self.path == "/api/v1/active":
                    self._send(200, {"status": "ok", "result": {"active": active}})
                else:
                    self._send(404, {"status": "err"})

            def do_POST(self):
                outer.paths.append(self.path)
                self.rfile.read(int(self.headers.get("Content-Length", 0)))
                if open_api:
                    self._send(200, {"status": "ok"})
                else:
                    self._send(401, {"status": "err", "code": "NotAuthenticated"})

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(str(self.cert), str(key))
        self._srv = ThreadingHTTPServer(("localhost", 0), H)
        self._srv.socket = ctx.wrap_socket(self._srv.socket, server_side=True)
        self.addr = self._srv.server_address
        self._thread = threading.Thread(target=self._srv.serve_forever, daemon=True)

    def __enter__(self) -> Server:
        self._thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self._srv.shutdown()
        self._srv.server_close()
