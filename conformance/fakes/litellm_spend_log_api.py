# SPDX-License-Identifier: Apache-2.0
"""A loopback stand-in for LiteLLM's spend-log API, ``GET /spend/logs/v2``, serving a
recorded-shape page set (``conformance/fixtures/litellm_spend_logs_v2.json``, fictional values).

The fixture's rows carry every column the list endpoint returns, including the ones the turn
source must drop (key hash, upstream URL, user, client address, messages, response); :data:`NEVER`
lists those planted values so a test can prove none is kept.  Only the viewer key
:data:`VIEWER_KEY` is accepted (any other is a 401); each request's query is recorded, so a test
can see the window and paging asked for.
"""

from __future__ import annotations

import http.server
import json
import threading
import urllib.parse
from pathlib import Path

from homelabnext.status.model import parse_iso

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "litellm_spend_logs_v2.json"
VIEWER_KEY = "fake-viewer-key-0001"
KEY_ENV = {"HNX_SECRET_LLM_GATEWAY_KEY_TELEMETRY_READER": VIEWER_KEY}
LOOPBACK = "127.0.0.1"  # no-raw-endpoint: allow the fake gateway binds loopback only
#: the tags the fixture's rows carry for the four example jobs, and the window that holds them
TAGS = ("run-0001", "hnx-run-0002", "run-0003", "run-0004")
WINDOW = ("2026-01-01T00:00:00Z", "2026-01-01T03:00:00Z")
#: every value in the fixture that a store or a page must never hold
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


def pages() -> list[dict]:
    return json.loads(FIXTURE.read_text("utf-8"))["pages"]


def _within(rows: list, q: dict[str, str]) -> list:
    """The rows started in the query's ``[start_date, end_date]`` (UTC), as the API filters; a
    row without a readable start is kept (the reader must drop it itself)."""
    if "start_date" not in q or "end_date" not in q:
        return rows
    lo, hi = (parse_iso(q[k].replace(" ", "T") + "Z") for k in ("start_date", "end_date"))
    out = []
    for r in rows:
        try:
            start = parse_iso(r["startTime"]) if isinstance(r, dict) else None
        except (KeyError, TypeError, ValueError):
            start = None
        if start is None or lo <= start <= hi:
            out.append(r)
    return out


class FakeSpendLogs:
    """``GET /spend/logs/v2`` on loopback: the fixture's rows started in the window, by ``page``
    and ``page_size``, or ``pages_`` verbatim by ``page``; 401 for any other key,
    ``status`` for every request when it is not 200.  A context manager (serves while inside)."""

    def __init__(self, pages_: list[dict] | None = None, *, status: int = 200):
        #: the recorded rows are filtered by the window and paged as asked; given pages are
        #: served verbatim by page number (a test's own shape, a runaway page count)
        self.recorded = pages_ is None
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
                if fake.recorded:  # as the API: the rows of the window, paged by page_size
                    rows = _within([r for p in fake.pages for r in p["data"]], q)
                    size = int(q.get("page_size", "50"))
                    total = -(-len(rows) // size)
                    return self._reply(
                        200, {"data": rows[(n - 1) * size : n * size], "total_pages": total}
                    )
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

    def start(self) -> FakeSpendLogs:
        threading.Thread(
            target=self.server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True
        ).start()
        return self

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()

    def __enter__(self):
        return self.start()

    def __exit__(self, *a):
        self.stop()
