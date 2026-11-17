# SPDX-License-Identifier: Apache-2.0
"""A stand-in for the speech service's anonymous endpoints (shared by the tts tests)."""

from __future__ import annotations

import io
import json
import threading
import wave
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

REFS = ["ref1.wav", "ref2.wav", "ref3.wav", "ref4.wav"]


def wav(rate=24000, seconds=1.0) -> bytes:
    buf = io.BytesIO()
    with wave.open(buf, "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(rate)
        w.writeframes(b"\x00\x00" * int(rate * seconds))
    return buf.getvalue()


class Server:
    """/health in the old shape, /ready and /synthesize, with what each answers settable."""

    def __init__(self, refs=None, ready=True, backend="cpu", status="ok"):
        outer = self
        self.paths = []
        self.refs = ["/voice/" + n for n in (REFS if refs is None else refs)]
        self.ready, self.backend, self.status = ready, backend, status

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, code, body, ctype="application/json"):
                self.send_response(code)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                outer.paths.append("GET " + self.path)
                if self.path == "/health":
                    doc = {"status": outer.status, "model_loaded": False, "refs": outer.refs}
                    self._send(200, json.dumps(doc).encode())
                elif self.path == "/ready":
                    doc = {"ready": outer.ready, "backend": outer.backend, "checks": {}}
                    self._send(200 if outer.ready else 503, json.dumps(doc).encode())
                else:
                    self._send(404, b'{"detail": "Not Found"}')

            def do_POST(self):
                outer.paths.append("POST " + self.path)
                self.rfile.read(int(self.headers.get("Content-Length", "0")))
                if self.path == "/synthesize":
                    self._send(200, wav(), "audio/wav")
                else:
                    self._send(404, b'{"detail": "Not Found"}')

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
