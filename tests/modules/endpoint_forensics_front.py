# SPDX-License-Identifier: Apache-2.0
"""A TLS stand-in for the endpoint-forensics server's two ports, for the probe's tests: a private
authority made with the ``openssl`` command, a server certificate issued by it to ``NAME`` and two
listeners on loopback, one that serves the certificate on ``/server.pem`` (the clients' port) and
one that answers ``gui_status`` to everything (the GUI). The tests that use it carry ``requires_tool("openssl")``."""

from __future__ import annotations

import socket
import ssl
import subprocess
import threading
from pathlib import Path

NAME = "ServerNameForTests"
LOOP = "localhost"  # the listeners bind the loopback by its name


def _run(*argv: str, cwd: Path) -> None:
    subprocess.run(argv, cwd=cwd, check=True, capture_output=True)


def make_authority(tmp: Path, name: str = NAME, tag: str = "ca") -> tuple[Path, Path, Path]:
    """(ca certificate, server certificate, server key), in ``tmp``."""
    _run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", f"{tag}.key",
         "-out", f"{tag}.pem", "-days", "2", "-subj", f"/CN={tag}-authority",
         "-addext", "basicConstraints=critical,CA:TRUE",
         "-addext", "keyUsage=critical,keyCertSign,cRLSign", cwd=tmp)  # fmt: skip
    _run("openssl", "req", "-newkey", "rsa:2048", "-nodes", "-keyout", f"{tag}-srv.key",
         "-out", f"{tag}-srv.csr", "-subj", f"/CN={name}", cwd=tmp)  # fmt: skip
    (tmp / f"{tag}.ext").write_text(f"subjectAltName=DNS:{name}\n")
    _run("openssl", "x509", "-req", "-in", f"{tag}-srv.csr", "-CA", f"{tag}.pem", "-CAkey",
         f"{tag}.key", "-CAcreateserial", "-out", f"{tag}-srv.pem", "-days", "2",
         "-extfile", f"{tag}.ext", cwd=tmp)  # fmt: skip
    return tmp / f"{tag}.pem", tmp / f"{tag}-srv.pem", tmp / f"{tag}-srv.key"


class _Listener:
    def __init__(self, ctx: ssl.SSLContext, respond) -> None:
        self._sock = socket.socket()
        self._sock.bind((LOOP, 0))
        self._sock.listen(8)
        self.port = self._sock.getsockname()[1]
        self._ctx, self._respond = ctx, respond
        self._stop = False
        self._t = threading.Thread(target=self._serve, daemon=True)
        self._t.start()

    def _serve(self) -> None:
        self._sock.settimeout(0.2)
        while not self._stop:
            try:
                raw, _ = self._sock.accept()
            except OSError:
                continue
            try:
                with self._ctx.wrap_socket(raw, server_side=True) as tls:
                    request = tls.recv(4096).decode("latin-1")
                    tls.sendall(self._respond(request.split(" ")[1] if " " in request else ""))
            except (OSError, ssl.SSLError):
                pass

    def close(self) -> None:
        self._stop = True
        self._t.join(timeout=2)
        self._sock.close()


def _http(status: str, body: bytes = b"") -> bytes:
    return f"HTTP/1.1 {status}\r\nContent-Length: {len(body)}\r\n\r\n".encode() + body


class Server:
    """Both ports; ``frontend_port`` and ``gui_port`` are loopback ports."""

    def __init__(self, tmp: Path, *, gui_status: str = "401 Unauthorized", serve_pem: bool = True,
                 tag: str = "ca") -> None:  # fmt: skip
        self.ca, cert, key = make_authority(tmp, tag=tag)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        pem = cert.read_bytes()
        self.paths: list[str] = []

        def frontend(path: str) -> bytes:
            self.paths.append(path)
            if serve_pem and path == "/server.pem":
                return _http("200 OK", pem)
            return _http("404 Not Found")

        def gui(path: str) -> bytes:
            self.paths.append(path)
            return _http(gui_status)

        self._frontend = _Listener(ctx, frontend)
        self._gui = _Listener(ctx, gui)
        self.frontend_port, self.gui_port = self._frontend.port, self._gui.port

    def __enter__(self) -> Server:
        return self

    def __exit__(self, *exc) -> None:
        self._frontend.close()
        self._gui.close()
