# SPDX-License-Identifier: Apache-2.0
"""A fake NUT upsd on loopback that answers from recorded protocol transcripts.

A transcript (``fixtures/nut/*.txt``) is ``C: <command>`` lines, each followed by the ``S:``
lines a real upsd 2.8.1 answered (see each file's header).  The fake indexes them by command:
the same command always gets the recorded reply, whatever the order, so one fake can serve
several transcripts (later ones win).  ``STARTTLS`` with a ``tls`` context answers
``OK STARTTLS`` and wraps the connection (a second one is ``ERR ALREADY-SSL-MODE``, as recorded);
without one it answers what the transcript recorded.  Everything a client sent is kept in
``received`` with whether it arrived inside TLS, so a test can prove a password never travels
in plaintext.  An unrecorded command is ``ERR UNKNOWN-COMMAND``.
"""

from __future__ import annotations

import socket
import ssl
import subprocess
import threading
from pathlib import Path

FIXTURES = Path(__file__).parent / "fixtures" / "nut"


def load_transcript(*names: str) -> dict[str, list[str]]:
    replies: dict[str, list[str]] = {}
    for name in names:
        cmd = None
        for line in (FIXTURES / f"{name}.txt").read_text(encoding="utf-8").splitlines():
            if line.startswith("C: "):
                cmd = line[3:]
                replies[cmd] = []
            elif line.startswith("S: ") and cmd is not None:
                replies[cmd].append(line[3:])
    return replies


class FakeUpsd:
    def __init__(self, *transcripts: str, tls: ssl.SSLContext | None = None, stall: bool = False):
        self.replies = load_transcript(*transcripts)
        self.tls = tls
        self.stall = stall  # accept, then never answer (a hung upsd)
        self.received: list[tuple[str, bool]] = []
        self._srv = socket.create_server(("127.0.0.1", 0))  # no-raw-endpoint: allow a loopback fake
        self._srv.settimeout(0.05)  # so the accept loop sees a stop promptly
        self.port = self._srv.getsockname()[1]
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def __enter__(self) -> FakeUpsd:
        self._thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self._stop.set()
        self._thread.join(timeout=5)
        self._srv.close()

    @property
    def url(self) -> str:
        return f"tcp://localhost:{self.port}"

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self._srv.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            threading.Thread(target=self._client, args=(conn,), daemon=True).start()

    def _client(self, conn: socket.socket) -> None:
        conn.settimeout(5)
        sock, in_tls, buf = conn, False, b""
        try:
            while True:
                while b"\n" not in buf:
                    chunk = sock.recv(4096)
                    if not chunk:
                        return
                    buf += chunk
                raw, _, buf = buf.partition(b"\n")
                cmd = raw.decode("utf-8")
                self.received.append((cmd, in_tls))
                if self.stall:
                    self._stop.wait(10)
                    return
                if cmd == "STARTTLS" and self.tls is not None and not in_tls:
                    sock.sendall(b"OK STARTTLS\n")
                    sock = self.tls.wrap_socket(sock, server_side=True)
                    in_tls = True
                    continue
                if cmd == "STARTTLS" and in_tls:
                    reply = ["ERR ALREADY-SSL-MODE"]
                else:
                    reply = self.replies.get(cmd, ["ERR UNKNOWN-COMMAND"])
                sock.sendall("".join(f"{r}\n" for r in reply).encode("utf-8"))
                if cmd == "LOGOUT":
                    return
        except (OSError, ssl.SSLError):
            return
        finally:
            sock.close()


def self_signed(directory: Path) -> tuple[ssl.SSLContext, Path] | None:
    """A server context with a fresh self-signed certificate for ``localhost`` and the CA file
    a client verifies it with; None without the ``openssl`` command."""
    key, cert = directory / "upsd-key.pem", directory / "upsd-cert.pem"
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
    server.load_cert_chain(cert, key)
    return server, cert
