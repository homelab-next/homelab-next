# SPDX-License-Identifier: Apache-2.0
"""A loopback stand-in for the lab's own gateway's ``GET /v1/usage`` (ADR-0038 decision 6),
serving recorded-shape usage records (``conformance/fixtures/gateway_usage_records.json``,
fictional values) as the gateway does: the records whose ``ts`` is in ``[start, end]`` (whole
unix seconds, ``end`` included) and, with ``tag``, whose ``gateway_tag`` is that tag; the
earliest ``cap`` of them by ``ts``, with ``"truncated": true`` when more matched.  Only the
telemetry reader's key :data:`READER_KEY` is accepted (any other is a 401); each request's query
is recorded, so a test can see the windows and tags asked for.
"""

from __future__ import annotations

import http.server
import json
import threading
import urllib.parse
from pathlib import Path

from homelabnext.conform.adapters.gateway_usage import parse_ts

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "gateway_usage_records.json"
READER_KEY = "fake-telemetry-reader-key-0001"
KEY_ENV = {"HNX_SECRET_LLM_GATEWAY_KEY_TELEMETRY_READER": READER_KEY}
LOOPBACK = "127.0.0.1"  # no-raw-endpoint: allow the fake gateway binds loopback only
#: the tags of the fixture's two jobs and the window that holds them
TAGS = ("run-0001", "run-0002")
WINDOW = ("2026-01-01T00:00:00Z", "2026-01-01T01:00:00Z")
#: values in the fixture a turn must never hold
NEVER = ("upstream.example.com", "profile:responder", "agent-responder", "tlp_refused")


def records() -> list[dict]:
    return json.loads(FIXTURE.read_text("utf-8"))["records"]


class FakeUsage:
    """``GET /v1/usage`` on loopback over ``records_`` (default: the fixture's), capped at
    ``cap`` records a reply; ``status`` for every request when it is not 200.  A context manager
    (serves while inside)."""

    def __init__(self, records_: list[dict] | None = None, *, cap: int = 10000, status: int = 200):
        self.records = records() if records_ is None else records_
        self.cap, self.status = cap, status
        self.requests: list[dict[str, str]] = []
        fake = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                path, _, query = self.path.partition("?")
                q = {k: v[0] for k, v in urllib.parse.parse_qs(query).items()}
                fake.requests.append({"path": path, **q})
                if self.headers.get("Authorization") != f"Bearer {READER_KEY}":
                    return self._reply(401, {"error": {"message": "invalid or missing API key"}})
                if path != "/v1/usage":
                    return self._reply(404, {"error": {"message": "no such route"}})
                if fake.status != 200:
                    return self._reply(fake.status, {"error": {"message": "fake failure"}})
                lo, hi, tag = int(q["start"]), int(q["end"]) + 1, q.get("tag", "")
                hits = sorted(
                    (
                        r
                        for r in fake.records
                        if (t := parse_ts(r.get("ts"))) is not None
                        and lo <= t < hi
                        and (not tag or r.get("gateway_tag") == tag)
                    ),
                    key=lambda r: parse_ts(r["ts"]) or 0.0,
                )
                return self._reply(
                    200, {"records": hits[: fake.cap], "truncated": len(hits) > fake.cap}
                )

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

    def start(self) -> FakeUsage:
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
