# SPDX-License-Identifier: Apache-2.0
"""``/v1/systemone``: an HTTP wrapper that serves a cascade over a simple request/response.

Protocol ``systemone/1`` (JSON over HTTP):

``POST /v1/systemone/decide``  request ``{"spec": str, "id": str, "text": str,
"impact"?: low|medium|high|critical, "fields"?: object}``; response 200
``{"protocol": "systemone/1", "spec": str, "decision": {...}, "trace": [...]}`` where
``decision`` carries ``verdict`` (a label, or ``human``), ``tier``, ``confidence``, ``impact``,
``escalated``, ``acted``, ``interim`` and ``audit``.  ``verdict == "human"`` is an escalation and
never an answer.  Errors are ``{"error": {"code": str, "message": str}}`` with 400 (bad request),
404 (unknown spec) or 500 (adapter failure; the adapter never fabricates a decision).

``GET /v1/systemone/specs`` lists served spec ids; ``GET /v1/systemone/health`` answers ``ok``.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from .cascade import Cascade
from .spec import IMPACTS
from .tiers import Item

PROTOCOL = "systemone/1"
LOOPBACK = "127.0.0.1"  # no-raw-endpoint: allow default bind for a local adapter


def validate_request(doc: Any) -> list[str]:
    if not isinstance(doc, dict):
        return ["request must be a JSON object"]
    p: list[str] = []
    for key in ("spec", "id", "text"):
        if not isinstance(doc.get(key), str) or not doc[key]:
            p.append(f"{key}: required non-empty string")
    if "impact" in doc and doc["impact"] not in IMPACTS:
        p.append(f"impact: must be one of {list(IMPACTS)}")
    if "fields" in doc and not isinstance(doc["fields"], dict):
        p.append("fields: must be an object")
    extra = set(doc) - {"spec", "id", "text", "impact", "fields"}
    if extra:
        p.append(f"unknown keys: {sorted(extra)}")
    return p


def handle_decide(cascades: dict[str, Cascade], doc: Any) -> tuple[int, dict]:
    problems = validate_request(doc)
    if problems:
        return 400, {"error": {"code": "bad_request", "message": "; ".join(problems)}}
    cascade = cascades.get(doc["spec"])
    if cascade is None:
        return 404, {"error": {"code": "unknown_spec", "message": f"no spec {doc['spec']!r}"}}
    item = Item(doc["id"], doc["text"], doc.get("impact", "low"), doc.get("fields", {}))
    try:
        d = cascade.decide(item).to_dict()
    except Exception as exc:  # the cascade is exception-safe; anything here is an adapter bug
        return 500, {"error": {"code": "adapter_failure", "message": type(exc).__name__}}
    trace = d.pop("trace")
    d.pop("item_id")
    return 200, {"protocol": PROTOCOL, "spec": doc["spec"], "decision": d, "trace": trace}


class SystemOneServer:
    def __init__(self, cascades: dict[str, Cascade], host: str = LOOPBACK, port: int = 0):
        self.cascades = cascades
        self._httpd = ThreadingHTTPServer((host, port), self._handler())
        self._thread: threading.Thread | None = None

    @property
    def url(self) -> str:
        host, port = self._httpd.server_address[:2]
        return f"http://{host}:{port}"

    def start(self) -> SystemOneServer:
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

    def __enter__(self) -> SystemOneServer:
        return self.start()

    def __exit__(self, *exc: object) -> None:
        self.stop()

    def _handler(self):
        outer = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args: Any) -> None:
                pass

            def _send(self, status: int, doc: dict) -> None:
                data = json.dumps(doc).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self) -> None:
                if self.path == "/v1/systemone/health":
                    self._send(200, {"status": "ok", "protocol": PROTOCOL})
                elif self.path == "/v1/systemone/specs":
                    self._send(200, {"protocol": PROTOCOL, "specs": sorted(outer.cascades)})
                else:
                    self._send(404, {"error": {"code": "not_found", "message": self.path}})

            def do_POST(self) -> None:
                if self.path != "/v1/systemone/decide":
                    self._send(404, {"error": {"code": "not_found", "message": self.path}})
                    return
                n = int(self.headers.get("Content-Length") or 0)
                try:
                    doc = json.loads(self.rfile.read(n) or b"null")
                except ValueError:
                    self._send(400, {"error": {"code": "bad_request", "message": "invalid JSON"}})
                    return
                self._send(*handle_decide(outer.cascades, doc))

        return Handler
