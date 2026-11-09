# SPDX-License-Identifier: Apache-2.0
"""The world an agent-runner session runs in, faked on loopback: a gateway and MCP servers.

:class:`FakeGateway` answers ``POST /v1/chat/completions`` from a per-tag script and records:
- every call: bearer, ``X-HNX-Tag``, ``traceparent`` and run token;
- the gateway's own usage records, the subset of ``orchestrator/internal/gateway`` usage records
  the launcher reads (``ts``, ``gateway_tag``, ``status``, ``error_code``, tokens, ``trace_id``).

Its refusals follow the gateway's wire format:
- ``400 upstream_rejected`` is recorded;
- ``429 concurrency_limited`` is refused before the model call, so it writes **no** record, as
  the real gateway does;
- ``403 run_budget_exhausted`` names ``budget``, ``limit`` and ``used`` (ADR-0047 decision 7) and
  is recorded.

``lag_s`` delays when a record becomes visible, and ``dropped`` stands for the gateway's
``usage_records_dropped``. The run token travels as ``X-HNX-Run-Token``: ADR-0047 names the token
but not its header, so this fake's header is the one its step 3 must match or change here.

:class:`FakeMCP` is an HTTP JSON-RPC MCP server that records each ``tools/call``'s params, its
``_meta`` included.
"""

from __future__ import annotations

import http.server
import itertools
import json
import threading
import time
from collections.abc import Callable
from typing import Any

from conformance.fakes._loopback import LOOPBACK

_IDS = itertools.count(1)


class _Server:
    def __init__(self, handle: Callable[[http.server.BaseHTTPRequestHandler], None]) -> None:
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                handle(self)

            def log_message(self, *a):
                pass

        self.httpd = http.server.ThreadingHTTPServer((LOOPBACK, 0), Handler)
        self.httpd.daemon_threads = True
        self.url = f"http://{LOOPBACK}:{self.httpd.server_address[1]}"
        threading.Thread(
            target=self.httpd.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True
        ).start()

    def close(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()


def _reply(h: http.server.BaseHTTPRequestHandler, status: int, doc: Any) -> None:
    raw = json.dumps(doc).encode()
    try:
        h.send_response(status)
        h.send_header("Content-Type", "application/json")
        h.send_header("Content-Length", str(len(raw)))
        h.end_headers()
        h.wfile.write(raw)
    except (BrokenPipeError, ConnectionResetError):
        pass  # the session was stopped while the reply waited


class FakeGateway:
    """A scripted gateway: ``script(tag, [step, ...])`` answers that tag's calls in order, the
    last step repeating. A step is:
    - ``{"content": text}``, a final answer, sized unless ``"usage": False``;
    - ``{"tool": [server, name]}``, a reply asking for one tool call;
    - ``{"status": 400 | 429 | 403, ...}``, a refusal (403 takes ``budget``);
    - ``{"hang": seconds}``, which answers only after that long."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []
        self.usage: list[dict[str, Any]] = []
        self.lag_s = 0.0
        self.dropped_records = 0
        self._scripts: dict[str, list[dict[str, Any]]] = {}
        self._lock = threading.Lock()
        self._server = _Server(self._handle)
        self.url = self._server.url

    def script(self, tag: str, steps: list[dict[str, Any]]) -> None:
        with self._lock:
            self._scripts[tag] = list(steps)

    # -- the launcher's view (conformance.protocols.agent_runner.GatewayView) ----------------
    def records(self, tag: str) -> list[dict[str, Any]]:
        mark = self.watermark()
        with self._lock:
            return [dict(r) for r in self.usage if r["gateway_tag"] == tag and r["_t"] <= mark]

    def dropped(self) -> int:
        return self.dropped_records

    def watermark(self) -> float:
        return time.time() - self.lag_s

    def close(self) -> None:
        self._server.close()

    # -- serving ----------------------------------------------------------------------------
    def _handle(self, h: http.server.BaseHTTPRequestHandler) -> None:
        length = int(h.headers.get("Content-Length") or 0)
        h.rfile.read(length)
        tag = h.headers.get("X-HNX-Tag") or ""
        tp = h.headers.get("traceparent") or ""
        auth = h.headers.get("Authorization") or ""
        call = {
            "tag": tag,
            "bearer": auth.removeprefix("Bearer "),
            "traceparent": tp,
            "run_token": h.headers.get("X-HNX-Run-Token"),
        }
        with self._lock:
            self.calls.append(call)
            steps = self._scripts.get(tag) or [{"content": "done"}]
            step = steps.pop(0) if len(steps) > 1 else steps[0]
        if "hang" in step:
            time.sleep(step["hang"])
            step = {"content": "late"}
        trace_id = tp.split("-")[1] if tp.count("-") == 3 else None

        def record(status: int, code: str | None, tokens: tuple[int, int] | None) -> None:
            with self._lock:
                self.usage.append(
                    {
                        "_t": time.time(),
                        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "gateway_tag": tag,
                        "status": status,
                        "error_code": code,
                        "input_tokens": tokens[0] if tokens else None,
                        "output_tokens": tokens[1] if tokens else None,
                        "trace_id": trace_id,
                    }
                )

        status = step.get("status")
        if status == 429:  # refused before the model call: no usage record
            return _reply(
                h, 429, {"error": {"code": "concurrency_limited", "type": "rate_limit_error"}}
            )
        if status == 400:
            record(400, "upstream_rejected", None)
            return _reply(
                h, 400, {"error": {"code": "upstream_rejected", "type": "invalid_request_error"}}
            )
        if status == 403:
            record(403, "run_budget_exhausted", None)
            return _reply(
                h,
                403,
                {
                    "error": {
                        "code": "run_budget_exhausted",
                        "budget": step.get("budget", "tool_calls"),
                        "limit": 1,
                        "used": 1,
                    }
                },
            )
        tokens = (100 + len(self.calls), 10)
        record(200, None, tokens)
        msg: dict[str, Any] = {"role": "assistant", "content": step.get("content")}
        if "tool" in step:
            server, name = step["tool"]
            msg = {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": f"call-{next(_IDS)}",
                        "type": "function",
                        "function": {"name": f"{server}__{name}", "arguments": "{}"},
                    }
                ],
            }
        doc: dict[str, Any] = {"id": f"cmpl-{next(_IDS)}", "choices": [{"message": msg}]}
        if step.get("usage", True):
            doc["usage"] = {"prompt_tokens": tokens[0], "completion_tokens": tokens[1]}
        _reply(h, 200, doc)


class FakeMCP:
    """An HTTP JSON-RPC MCP server answering every ``tools/call`` with ``ok``."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []
        self._server = _Server(self._handle)
        self.url = self._server.url + "/mcp"

    def close(self) -> None:
        self._server.close()

    def _handle(self, h: http.server.BaseHTTPRequestHandler) -> None:
        length = int(h.headers.get("Content-Length") or 0)
        req = json.loads(h.rfile.read(length) or b"{}")
        self.calls.append(req.get("params") or {})
        _reply(
            h,
            200,
            {
                "jsonrpc": "2.0",
                "id": req.get("id"),
                "result": {"content": [{"type": "text", "text": "ok"}]},
            },
        )
