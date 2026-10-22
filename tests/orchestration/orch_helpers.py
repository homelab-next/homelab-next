# SPDX-License-Identifier: Apache-2.0
"""Shared fixtures of the orchestration telemetry tests: the schema's own examples as the job
records, a fixed clock, and a loopback fake of the gateway's spend-log API serving a recorded-shape
page set (``fixtures/spend_logs_v2.json``, fictional)."""

from __future__ import annotations

import http.server
import json
import threading
import urllib.parse
from pathlib import Path

from homelabnext.events.envelope import canonical_body
from homelabnext.status.model import parse_iso

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
EXAMPLES = ROOT / "schemas" / "events" / "examples"
CONTROLLER_EXAMPLE = "agent.job.finished.controller.json"
#: well after every example job finished (the last at 03:00)
T0 = parse_iso("2026-01-01T06:00:00Z")
VIEWER_KEY = "fake-viewer-key-0001"
LOOPBACK = "127.0.0.1"  # no-raw-endpoint: allow the fake gateway binds loopback only
KEY_ENV = {"HNX_SECRET_LLM_GATEWAY_KEY_TELEMETRY_READER": VIEWER_KEY}
#: every value in the spend-log fixture that the store and the page must never hold
NEVER = (
    "fake prompt text",
    "fake model output",
    "fake free text",
    "fake upstream text",
    "upstream.example.com",
    "192.0.2.10",  # no-raw-endpoint: allow a planted client address the store must drop
    "user-fake",
    "end-user-fake",
    "fake-key-hash",
    "fake-cache-key",
    "team-fake",
    "fake-session",
    "agent-triage",
)


def examples() -> list[dict]:
    """The four triage ``agent.job.finished`` examples (completed, failed, no usage, shadow), in
    file order; ``controller`` is the controller's own test event, checked on its own."""
    return [
        json.loads(p.read_text(encoding="utf-8"))
        for p in sorted(EXAMPLES.glob("agent.job.finished.*.json"))
        if p.name != CONTROLLER_EXAMPLE
    ]


def body(event: dict) -> bytes:
    return canonical_body(event)


def pages() -> list[dict]:
    return json.loads((HERE / "fixtures" / "spend_logs_v2.json").read_text("utf-8"))["pages"]


class FakeSpendLogs:
    """``GET /spend/logs/v2`` on loopback: the fixture's pages by ``page``, 401 for any other key.
    Records each request's query, so a test can see the window and paging it asked for."""

    def __init__(self, pages_: list[dict] | None = None, *, status: int = 200):
        self.pages = pages() if pages_ is None else pages_
        self.status = status
        self.requests: list[dict[str, str]] = []
        fake = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                path, _, query = self.path.partition("?")
                q = {k: v[0] for k, v in urllib.parse.parse_qs(query).items()}
                fake.requests.append({"path": path, **q})
                if self.headers.get("Authorization") != f"Bearer {VIEWER_KEY}":
                    return self._reply(401, {"error": "invalid key"})
                if fake.status != 200:
                    return self._reply(fake.status, {"error": "fake failure"})
                n = int(q.get("page", "1"))
                doc = fake.pages[n - 1] if n <= len(fake.pages) else {"data": [], "total_pages": 0}
                return self._reply(200, doc)

            def _reply(self, code, doc):
                raw = json.dumps(doc).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def log_message(self, *a):
                pass

        self.server = http.server.ThreadingHTTPServer((LOOPBACK, 0), Handler)
        self.url = f"http://{LOOPBACK}:{self.server.server_address[1]}"

    def __enter__(self):
        threading.Thread(
            target=self.server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True
        ).start()
        return self

    def __exit__(self, *a):
        self.server.shutdown()
        self.server.server_close()
