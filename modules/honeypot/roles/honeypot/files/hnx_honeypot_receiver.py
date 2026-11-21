#!/usr/bin/python3
# SPDX-License-Identifier: Apache-2.0
# hnx-script:
#   id: honeypot-receiver
#   kind: service
#   purpose: Accept the honeypot's pushed newline-delimited JSON events on one TCP port and append each to the spool file; ingest only, no path back to the sender.
#   owner: platform
#   trigger: [role:honeypot]
#   inputs: environment HNX_HP_BIND, HNX_HP_PORT, HNX_HP_SPOOL, HNX_HP_MAX_LINE, HNX_HP_SPOOL_MAX_BYTES (honeypot.env)
#   outputs: lines appended to the spool file; counters on stderr
#   installs_to: /usr/local/libexec/homelabnext/hnx-honeypot-receiver
#   exit:
#     "0": stopped by a signal
#     "1": could not bind or open the spool
"""One-way honeypot event receiver.

The honeypot's log shipper pushes newline-delimited JSON over the network to this port, and this
is the only thing the sender may reach. The receiver is INGEST ONLY: it accepts a connection,
appends each JSON line to the spool file and does nothing else (no reply, no command channel).
Each object line gets ``peer_ip``, the address the connection really came from, overwriting
whatever the sender claimed. A line over the size limit, or any line once the spool is at its cap,
is dropped and counted (never written half), and the counts are logged.
"""

import contextlib
import json
import os
import socketserver
import sys
import threading

MAX_LINE_DEFAULT = 1_000_000
SPOOL_MAX_DEFAULT = 8 * 1024**3


def process_line(raw: bytes, peer: str, max_line: int = MAX_LINE_DEFAULT):
    """The text to append for one received line, or None to drop it (empty, over the limit)."""
    if len(raw) > max_line:
        return None
    line = raw.decode("utf-8", "replace").rstrip("\r\n")
    if not line.strip():
        return None
    try:
        obj = json.loads(line)
    except ValueError:
        return line  # kept as received: the lake writer counts what it cannot parse
    if isinstance(obj, dict):
        obj["peer_ip"] = peer
        return json.dumps(obj, separators=(",", ":"), ensure_ascii=False)
    return line


class Spool:
    """The append-only spool, one writer: a lock, a size cap, drop counters."""

    def __init__(self, path: str, cap: int):
        self.path, self.cap = path, cap
        self.fd = os.open(
            path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600
        )  # open for the life of the process
        self.lock = threading.Lock()
        self.dropped_cap = 0
        self.dropped_line = 0

    def append(self, text: str) -> bool:
        data = text.encode("utf-8", "replace") + b"\n"
        with self.lock:
            # copytruncate by the rotation shrinks the file under us: always ask the file itself
            if os.fstat(self.fd).st_size + len(data) > self.cap:
                self.dropped_cap += 1
                if self.dropped_cap in (1, 100) or self.dropped_cap % 10000 == 0:
                    print(
                        f"spool at its cap ({self.cap} bytes): dropped {self.dropped_cap} line(s)",
                        file=sys.stderr,
                        flush=True,
                    )
                return False
            view = memoryview(data)
            while view:  # a short write continues; the file is O_APPEND, so it lands at the end
                view = view[os.write(self.fd, view) :]
        return True


def make_handler(spool: Spool, max_line: int, idle_timeout: float = 120.0):
    class Handler(socketserver.StreamRequestHandler):
        # a sender that goes quiet mid-connection is dropped (readline raises the timeout)
        timeout = idle_timeout

        def handle(self):
            try:
                self._pump()
            except OSError:  # idle timeout, reset: this connection is over, the server is not
                return

        def _pump(self):
            peer = self.client_address[0]
            while True:
                raw = self.rfile.readline(max_line + 1)
                if not raw:
                    return
                if len(raw) > max_line and not raw.endswith(b"\n"):
                    # an over-long line: discard the rest of it, never write a fragment
                    while True:
                        rest = self.rfile.readline(65536)
                        if not rest or rest.endswith(b"\n"):
                            break
                    spool.dropped_line += 1
                    continue
                text = process_line(raw, peer, max_line)
                if text is None:
                    spool.dropped_line += 1
                    continue
                spool.append(text)

    return Handler


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    max_connections = 32

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._slots = threading.BoundedSemaphore(self.max_connections)

    def process_request(self, request, client_address):
        # a connection past the cap is closed at once, so a flood of idle ones cannot hold threads
        if not self._slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        super().process_request(request, client_address)

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()


def check_bind(host: str, allow_any: bool) -> str:
    """The address to listen on: the guest's own address the pushes arrive on. Empty, or all
    interfaces, is refused unless the site says so (a receiver with no authentication is held by
    the network ACL and the firewall, so it must not listen wider than it has to)."""
    if not host:
        raise ValueError("HNX_HP_BIND is not set (the guest address the pushes arrive on)")
    if host in ("0.0.0.0", "::") and not allow_any:
        raise ValueError(
            "HNX_HP_BIND is all interfaces; set a guest address, or HNX_HP_ALLOW_ANY_BIND=1"
        )
    return host


def main() -> int:
    allow_any = os.environ.get("HNX_HP_ALLOW_ANY_BIND", "") == "1"
    try:
        host = check_bind(os.environ.get("HNX_HP_BIND", ""), allow_any)
    except ValueError as exc:
        print(f"cannot start: {exc}", file=sys.stderr)
        return 1
    idle = float(os.environ.get("HNX_HP_IDLE_TIMEOUT_S", "120"))
    Server.max_connections = int(os.environ.get("HNX_HP_MAX_CONNECTIONS", "32"))
    port = int(os.environ.get("HNX_HP_PORT", "9000"))
    path = os.environ.get("HNX_HP_SPOOL", "")
    if not path:
        print("HNX_HP_SPOOL is not set", file=sys.stderr)
        return 1
    max_line = int(os.environ.get("HNX_HP_MAX_LINE", str(MAX_LINE_DEFAULT)))
    cap = int(os.environ.get("HNX_HP_SPOOL_MAX_BYTES", str(SPOOL_MAX_DEFAULT)))
    try:
        spool = Spool(path, cap)
        srv = Server((host, port), make_handler(spool, max_line, idle))
    except OSError as exc:
        print(f"cannot start: {exc}", file=sys.stderr)
        return 1
    with srv, contextlib.suppress(KeyboardInterrupt):
        srv.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
