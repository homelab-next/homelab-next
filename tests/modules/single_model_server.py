# SPDX-License-Identifier: Apache-2.0
"""A stand-in for an engine that serves exactly one model, as the inference provider module's
tests need it (shared by tests/modules/test_inference_module.py and
tests/roles/test_inference_server_role.py). Measured on the real engine (build b12033, a CPU run
of the pinned image): ``GET /health`` is 200 once the model is loaded (503 while it loads),
``/v1/models`` carries the context each slot has in ``meta.n_ctx``, ``/metrics`` is Prometheus
text, and a chat call for **any** model id is answered with the one the server serves, never a 4xx.
Stdlib only, loopback only; replies are deterministic."""

from __future__ import annotations

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from conformance.fakes.openai_server import LOOPBACK

__all__ = ["SingleModelServer"]


class SingleModelServer:
    def __init__(
        self,
        model: str = "served",
        n_ctx: int = 8192,
        *,
        metric_prefix: str = "engine",
        loading: bool = False,
        metrics: bool = True,
        reports_ctx: bool = True,
        reply_tokens: int = 3,
        first_chat_delay: float = 0.0,
        chat_delay: float = 0.0,
    ):
        self.model = model
        self.n_ctx = n_ctx
        self.metric_prefix = metric_prefix
        self.loading = loading
        self.metrics = metrics
        self.reports_ctx = reports_ctx
        self.reply_tokens = reply_tokens
        # seconds the FIRST chat call takes (a cold server's warm-up) / every chat call takes
        self.first_chat_delay = first_chat_delay
        self.chat_delay = chat_delay
        self._chats = 0
        self.requests: list[tuple[str, str]] = []
        self._httpd = ThreadingHTTPServer((LOOPBACK, 0), self._handler())
        self._thread: threading.Thread | None = None

    @property
    def url(self) -> str:
        host, port = self._httpd.server_address[:2]
        return f"http://{host}:{port}"

    @property
    def port(self) -> int:
        return int(self._httpd.server_address[1])

    def __enter__(self) -> SingleModelServer:
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc: Any) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()
        if self._thread:
            self._thread.join(timeout=5)

    def _handler(self):
        srv = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args: Any) -> None:
                pass

            def _send(self, status: int, body: Any, ctype: str = "application/json") -> None:
                raw = body if isinstance(body, bytes) else json.dumps(body).encode()
                self.send_response(status)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def do_GET(self) -> None:
                srv.requests.append(("GET", self.path))
                if self.path == "/health":
                    if srv.loading:
                        self._send(503, {"error": {"code": 503, "message": "Loading model"}})
                    else:
                        self._send(200, {"status": "ok"})
                elif self.path == "/v1/models":
                    meta = {"n_ctx_train": 131072}
                    if srv.reports_ctx:
                        meta["n_ctx"] = srv.n_ctx
                    entry = {"id": srv.model, "object": "model", "meta": meta}
                    self._send(200, {"object": "list", "data": [entry]})
                elif self.path == "/metrics" and srv.metrics:
                    text = f"# TYPE {srv.metric_prefix}:requests_processing gauge\n"
                    text += f"{srv.metric_prefix}:requests_processing 0\n"
                    self._send(200, text.encode(), "text/plain; version=0.0.4")
                else:
                    self._send(404, {"error": {"code": 404, "message": "not found"}})

            def do_POST(self) -> None:
                n = int(self.headers.get("Content-Length") or 0)
                req = json.loads(self.rfile.read(n) or b"{}")
                srv.requests.append(("POST", self.path))
                if self.path != "/v1/chat/completions":
                    self._send(404, {"error": {"code": 404, "message": "not found"}})
                    return
                srv._chats += 1
                delay = srv.chat_delay + (srv.first_chat_delay if srv._chats == 1 else 0.0)
                if delay:
                    time.sleep(delay)
                words = ["Hello", "there", "friend"]
                k = max(1, min(int(req.get("max_tokens") or 64), srv.reply_tokens))
                text = " ".join(words[:k])
                prompt = sum(
                    len(str(m.get("content", "")).split()) for m in req.get("messages", [])
                )
                if req.get("stream"):
                    out = b""
                    for w in words[:k]:
                        piece = {"choices": [{"index": 0, "delta": {"content": w + " "}}]}
                        out += b"data: " + json.dumps(piece).encode() + b"\n\n"
                    self._send(200, out + b"data: [DONE]\n\n", "text/event-stream")
                    return
                finish = "length" if k < 3 else "stop"
                self._send(
                    200,
                    {
                        "id": "chatcmpl-stand-in",
                        "object": "chat.completion",
                        "model": srv.model,  # never the requested one: any id is answered
                        "choices": [
                            {
                                "index": 0,
                                "message": {"role": "assistant", "content": text},
                                "finish_reason": finish,
                            }
                        ],
                        "usage": {
                            "prompt_tokens": prompt,
                            "completion_tokens": k,
                            "total_tokens": prompt + k,
                        },
                    },
                )

        return Handler
