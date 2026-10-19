# SPDX-License-Identifier: Apache-2.0
# hnx-script:
#   id: fake-openai-server
#   kind: service
#   purpose: Serve the deterministic fake OpenAI-compatible inference API.
#   owner: conformance
#   trigger: [compose:lab-in-a-box/inference]
#   inputs: --host, --port, --model
#   outputs: the HTTP API; nothing on disk
#   exit:
#     "0": stopped cleanly
"""A fake OpenAI-compatible inference server (stdlib only, deterministic).

Serves ``GET /v1/models``, ``POST /v1/chat/completions`` (optionally streamed),
``/v1/completions`` and ``/v1/embeddings``, plus ``GET /health``.  Replies are canned or
rule-based: the first rule whose regex matches the last user message wins, otherwise the default
reply is used.  Latency and faults are configurable and can change while the server runs, so a
test can make a backend slow, erroring, malformed or hung.

Conformance use: this is the fake for the ``inference`` capability.  It speaks only the
protocol; nothing here is product specific.

    with FakeOpenAIServer(models=["example-4b"], rules=[label_rule("rollback", "accept", 0.97)]) as s:
        s.url  # scheme://host:port of the running server
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import math
import re
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

LOOPBACK = "127.0.0.1"  # no-raw-endpoint: allow fake server binds loopback only


@dataclass
class Rule:
    """``pattern`` is searched in the last user message; ``reply`` is text or ``f(request)``."""

    pattern: str
    reply: str | Callable[[dict], str]
    logprob: float | None = None  # per-token logprob reported when the client asks for logprobs

    def matches(self, text: str) -> bool:
        return re.search(self.pattern, text, re.IGNORECASE) is not None


def label_rule(pattern: str, label: str, confidence: float, **extra: Any) -> Rule:
    """A rule that answers with the JSON object a classifier tier expects."""
    return Rule(pattern, json.dumps({"label": label, "confidence": confidence, **extra}))


@dataclass
class Fault:
    """Inject a failure into matching requests.

    kind: ``http_error`` (status), ``hang`` (sleep ``hang_s`` then answer), ``malformed``
    (HTTP 200 with a non-JSON body), ``bad_shape`` (valid JSON, wrong structure), ``drop``
    (close the connection).  The fault applies to the matching calls numbered
    ``after+1 .. after+count`` (``count=None`` means every call after ``after``).
    """

    kind: str
    status: int = 503
    path: str | None = None  # substring of the request path
    model: str | None = None
    after: int = 0
    count: int | None = None
    hang_s: float = 2.0
    _seen: int = field(default=0, repr=False)

    def applies(self, path: str, model: str | None) -> bool:
        if self.path is not None and self.path not in path:
            return False
        if self.model is not None and self.model != model:
            return False
        self._seen += 1
        if self._seen <= self.after:
            return False
        return self.count is None or self._seen <= self.after + self.count


def embed_vector(text: str, dim: int) -> list[float]:
    """Deterministic unit vector derived from the text."""
    out: list[float] = []
    block = 0
    while len(out) < dim:
        digest = hashlib.sha256(f"{block}:{text}".encode()).digest()
        out += [(b - 127.5) / 127.5 for b in digest]
        block += 1
    vec = out[:dim]
    norm = math.sqrt(sum(v * v for v in vec)) or 1.0
    return [round(v / norm, 6) for v in vec]


class FakeOpenAIServer:
    def __init__(
        self,
        models: list[str] | None = None,
        rules: list[Rule] | None = None,
        default_reply: str = "ok",
        latency_ms: float = 0.0,
        faults: list[Fault] | None = None,
        logprob: float | None = None,
        embed_dim: int = 8,
        context_length: int | dict[str, int] | None = None,
        host: str = LOOPBACK,
        port: int = 0,
    ):
        self.models = list(models or ["example-model"])
        self.rules = list(rules or [])
        self.default_reply = default_reply
        self.latency_ms = latency_ms
        self.faults = list(faults or [])
        self.logprob = logprob
        self.embed_dim = embed_dim
        # loaded context length reported per model in /v1/models (``max_model_len``, as vLLM
        # does); an int applies to every model, a dict per model id, None reports nothing
        self.context_length = context_length
        self.requests: list[dict] = []
        self._lock = threading.Lock()
        self._httpd = ThreadingHTTPServer((host, port), self._handler())
        self._thread: threading.Thread | None = None

    # -------------------------------------------------------------- lifecycle
    @property
    def address(self) -> tuple[str, int]:
        host, port = self._httpd.server_address[:2]
        return str(host), int(port)

    @property
    def url(self) -> str:
        host, port = self.address
        return f"http://{host}:{port}"

    def start(self) -> FakeOpenAIServer:
        self._thread = threading.Thread(
            target=self._httpd.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True
        )
        self._thread.start()
        return self

    def stop(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()
        if self._thread:
            self._thread.join(timeout=5)

    def __enter__(self) -> FakeOpenAIServer:
        return self.start()

    def __exit__(self, *exc: object) -> None:
        self.stop()

    # -------------------------------------------------------------- behaviour
    def context_of(self, model: str) -> int | None:
        cl = self.context_length
        return cl.get(model) if isinstance(cl, dict) else cl

    def reply_for(self, text: str, request: dict) -> tuple[str, float | None]:
        for rule in self.rules:
            if rule.matches(text):
                body = rule.reply(request) if callable(rule.reply) else rule.reply
                return body, rule.logprob if rule.logprob is not None else self.logprob
        return self.default_reply, self.logprob

    def _find_fault(self, path: str, model: str | None) -> Fault | None:
        with self._lock:
            for f in self.faults:
                if f.applies(path, model):
                    return f
        return None

    def _handler(self):
        server = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args: Any) -> None:  # silence
                pass

            def _send(self, status: int, body: Any, raw: bytes | None = None) -> None:
                data = raw if raw is not None else json.dumps(body).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def _error(self, status: int, message: str, etype: str) -> None:
                self._send(status, {"error": {"message": message, "type": etype}})

            def do_GET(self) -> None:
                path = self.path.split("?")[0]
                server.requests.append({"method": "GET", "path": path})
                if server.latency_ms:
                    time.sleep(server.latency_ms / 1000)
                fault = server._find_fault(path, None)
                if fault and self._apply_fault(fault):
                    return
                if path == "/v1/models":
                    data = []
                    for m in server.models:
                        entry: dict[str, Any] = {
                            "id": m,
                            "object": "model",
                            "created": 0,
                            "owned_by": "fake",
                        }
                        if server.context_of(m) is not None:
                            entry["max_model_len"] = server.context_of(m)
                        data.append(entry)
                    self._send(200, {"object": "list", "data": data})
                elif path == "/health":
                    self._send(200, {"status": "ok"})
                else:
                    self._error(404, f"no route {path}", "not_found")

            def _apply_fault(self, fault: Fault) -> bool:
                if fault.kind == "http_error":
                    self._error(fault.status, "injected fault", "fault")
                    return True
                if fault.kind == "malformed":
                    self._send(200, None, raw=b"<<not json>>")
                    return True
                if fault.kind == "bad_shape":
                    self._send(200, {"unexpected": True})
                    return True
                if fault.kind == "drop":
                    self.close_connection = True
                    self.wfile.flush()
                    self.connection.close()
                    return True
                if fault.kind == "hang":
                    time.sleep(fault.hang_s)
                return False

            def do_POST(self) -> None:
                path = self.path.split("?")[0]
                n = int(self.headers.get("Content-Length") or 0)
                try:
                    req = json.loads(self.rfile.read(n) or b"{}")
                except ValueError:
                    self._error(400, "invalid JSON", "invalid_request_error")
                    return
                model = req.get("model") if isinstance(req, dict) else None
                server.requests.append({"method": "POST", "path": path, "body": req})
                if server.latency_ms:
                    time.sleep(server.latency_ms / 1000)
                fault = server._find_fault(path, model)
                if fault and self._apply_fault(fault):
                    return
                if path not in (
                    "/v1/chat/completions",
                    "/v1/completions",
                    "/v1/embeddings",
                ):
                    self._error(404, f"no route {path}", "not_found")
                    return
                if model not in server.models:
                    self._error(404, f"model {model!r} not served", "model_not_found")
                    return
                if path == "/v1/embeddings":
                    inp = req.get("input", [])
                    inputs = [inp] if isinstance(inp, str) else list(inp)
                    data = [
                        {
                            "object": "embedding",
                            "index": i,
                            "embedding": embed_vector(str(t), server.embed_dim),
                        }
                        for i, t in enumerate(inputs)
                    ]
                    self._send(200, {"object": "list", "data": data, "model": model})
                    return
                if path == "/v1/completions":
                    text, _ = server.reply_for(str(req.get("prompt", "")), req)
                    self._send(
                        200,
                        {
                            "id": "cmpl-fake",
                            "object": "text_completion",
                            "model": model,
                            "choices": [{"index": 0, "text": text, "finish_reason": "stop"}],
                            "usage": _usage(str(req.get("prompt", "")), text),
                        },
                    )
                    return
                msgs = req.get("messages") or []
                last_user = next(
                    (str(m.get("content", "")) for m in reversed(msgs) if m.get("role") == "user"),
                    "",
                )
                text, lp = server.reply_for(last_user, req)
                if req.get("stream"):
                    self._stream(model, text)
                    return
                choice: dict[str, Any] = {
                    "index": 0,
                    "message": {"role": "assistant", "content": text},
                    "finish_reason": "stop",
                }
                if req.get("logprobs") and lp is not None:
                    toks = text.split() or [text]
                    choice["logprobs"] = {
                        "content": [{"token": t, "logprob": lp, "top_logprobs": []} for t in toks]
                    }
                self._send(
                    200,
                    {
                        "id": "chatcmpl-fake",
                        "object": "chat.completion",
                        "model": model,
                        "choices": [choice],
                        "usage": _usage(last_user, text),
                    },
                )

            def _stream(self, model: str, text: str) -> None:
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Connection", "close")
                self.end_headers()
                for piece in text.split(" ") or [text]:
                    ch = {"choices": [{"index": 0, "delta": {"content": piece + " "}}]}
                    self.wfile.write(f"data: {json.dumps(ch)}\n\n".encode())
                done = {"choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]}
                self.wfile.write(f"data: {json.dumps(done)}\n\ndata: [DONE]\n\n".encode())
                self.close_connection = True

        return Handler


def _usage(prompt: str, completion: str) -> dict[str, int]:
    p, c = len(prompt.split()), len(completion.split())
    return {"prompt_tokens": p, "completion_tokens": c, "total_tokens": p + c}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Run the fake OpenAI-compatible server.")
    ap.add_argument("--host", default=LOOPBACK)
    ap.add_argument("--port", type=int, default=0)
    ap.add_argument("--model", action="append", default=[])
    ap.add_argument("--latency-ms", type=float, default=0.0)
    args = ap.parse_args(argv)
    srv = FakeOpenAIServer(
        models=args.model or None, latency_ms=args.latency_ms, host=args.host, port=args.port
    )
    print(f"fake openai server listening on {srv.url}", flush=True)
    with contextlib.suppress(KeyboardInterrupt):
        srv._httpd.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
