# SPDX-License-Identifier: Apache-2.0
"""A fake case system (stdlib only, in memory) for the ``cases`` capability.

It speaks only the round-trip the contract needs: create a case (idempotent on ``dedup_key``),
read it back, list, comment, close.  Nothing here is product specific.

    POST /api/cases               {"title", "severity", "dedup_key"?, "observables"?} -> 201 / 200
    GET  /api/cases               -> {"cases": [...]}
    GET  /api/cases/<id>          -> case or 404
    POST /api/cases/<id>/comments {"body"} -> 201
    POST /api/cases/<id>/close    {"resolution"?} -> 200
    GET  /health                  -> {"status": "ok"}
"""

from __future__ import annotations

import argparse
import contextlib
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

SEVERITIES = ("info", "low", "medium", "high", "critical")


class CaseStore:
    """The whole state of the fake: thread-safe, with a fixed id sequence and no clock."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._cases: dict[str, dict[str, Any]] = {}
        self._by_key: dict[str, str] = {}

    def create(self, doc: dict[str, Any]) -> tuple[dict[str, Any], bool]:
        title = doc.get("title")
        severity = doc.get("severity", "medium")
        if not isinstance(title, str) or not title.strip():
            raise ValueError("title is required")
        if severity not in SEVERITIES:
            raise ValueError(f"severity must be one of {', '.join(SEVERITIES)}")
        key = doc.get("dedup_key")
        with self._lock:
            if key is not None and key in self._by_key:
                return self._cases[self._by_key[key]], False
            case_id = f"CASE-{len(self._cases) + 1:05d}"
            case = {
                "id": case_id,
                "title": title,
                "severity": severity,
                "status": "open",
                "dedup_key": key,
                "observables": list(doc.get("observables") or []),
                "comments": [],
            }
            self._cases[case_id] = case
            if key is not None:
                self._by_key[key] = case_id
            return case, True

    def get(self, case_id: str) -> dict[str, Any] | None:
        with self._lock:
            return self._cases.get(case_id)

    def listing(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._cases.values())

    def comment(self, case_id: str, body: Any) -> dict[str, Any] | None:
        if not isinstance(body, str) or not body:
            raise ValueError("body is required")
        with self._lock:
            case = self._cases.get(case_id)
            if case is not None:
                case["comments"].append({"n": len(case["comments"]) + 1, "body": body})
            return case

    def close(self, case_id: str, resolution: str | None) -> dict[str, Any] | None:
        with self._lock:
            case = self._cases.get(case_id)
            if case is not None:
                case["status"] = "closed"
                case["resolution"] = resolution or "resolved"
            return case


def make_handler(store: CaseStore) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args: Any) -> None:  # keep container logs quiet
            pass

        def _send(self, status: int, doc: Any) -> None:
            raw = json.dumps(doc).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def _body(self) -> dict[str, Any]:
            n = int(self.headers.get("Content-Length") or 0)
            if n == 0:
                return {}
            doc = json.loads(self.rfile.read(n))
            if not isinstance(doc, dict):
                raise ValueError("body must be a JSON object")
            return doc

        def do_GET(self) -> None:
            parts = self.path.split("?")[0].strip("/").split("/")
            if parts == ["health"]:
                self._send(200, {"status": "ok"})
            elif parts == ["api", "cases"]:
                self._send(200, {"cases": store.listing()})
            elif len(parts) == 3 and parts[:2] == ["api", "cases"]:
                case = store.get(parts[2])
                self._send(200, case) if case else self._send(404, {"error": "no such case"})
            else:
                self._send(404, {"error": "not found"})

        def do_POST(self) -> None:
            parts = self.path.split("?")[0].strip("/").split("/")
            try:
                doc = self._body()
                if parts == ["api", "cases"]:
                    case, created = store.create(doc)
                    self._send(201 if created else 200, case)
                elif len(parts) == 4 and parts[:2] == ["api", "cases"] and parts[3] == "comments":
                    case = store.comment(parts[2], doc.get("body"))
                    self._send(201, case) if case else self._send(404, {"error": "no such case"})
                elif len(parts) == 4 and parts[:2] == ["api", "cases"] and parts[3] == "close":
                    case = store.close(parts[2], doc.get("resolution"))
                    self._send(200, case) if case else self._send(404, {"error": "no such case"})
                else:
                    self._send(404, {"error": "not found"})
            except (ValueError, json.JSONDecodeError) as exc:
                self._send(400, {"error": str(exc)})

    return Handler


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Run the fake case system.")
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8000)
    args = ap.parse_args(argv)
    httpd = ThreadingHTTPServer((args.host, args.port), make_handler(CaseStore()))
    print(f"fake case system listening on port {httpd.server_address[1]}", flush=True)
    with contextlib.suppress(KeyboardInterrupt):
        httpd.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
