# SPDX-License-Identifier: Apache-2.0
"""A TLS stand-in for the graph store's HTTPS API: answers as the active service, refuses a storm call
that carries no session (or accepts it, with ``open_api``), records what it was asked.  Its certificate
is made for the test and written next to the test's files."""

from __future__ import annotations

import datetime
import json
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


def make_cert(directory: Path) -> tuple[Path, Path]:
    """A self-signed certificate and its private key, under ``directory``."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "graph.example.internal")])
    utc = datetime.UTC
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime(2020, 1, 1, tzinfo=utc))
        .not_valid_after(datetime.datetime(2100, 1, 1, tzinfo=utc))
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = directory / "cert.pem", directory / "tls.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
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
