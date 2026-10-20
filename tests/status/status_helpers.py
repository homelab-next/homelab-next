# SPDX-License-Identifier: Apache-2.0
"""Fakes for the status hub tests (imported by the tests and by conftest.py): a settable clock, an HTTP client that never leaves the process,
and small source specs.  Nothing here reads the wall clock or opens a socket."""

from __future__ import annotations

import json
from pathlib import Path

from homelabnext.status import SourceSpec

ROOT = Path(__file__).resolve().parents[2]
REGISTRY = ROOT / "examples" / "services.yml"
VIEWS = ROOT / "examples" / "status" / "views.yml"
T0 = 1_790_000_000.0  # 2026-09-21T13:33:20Z


class Clock:
    def __init__(self, t: float = T0):
        self.t = t

    def __call__(self) -> float:
        return self.t

    def advance(self, s: float) -> None:
        self.t += s


class FakeHttp:
    """``routes``: url -> (status, JSON-able body), or path (no query) -> the same when
    ``by_path``; a service in ``down`` refuses connections; ``headers`` records what each call
    sent."""

    def __init__(self, by_path: bool = False) -> None:
        self.routes: dict[str, tuple[int, object]] = {}
        self.down: set[str] = set()
        self.calls: list[str] = []
        self.headers: list[dict[str, str]] = []
        self.by_path = by_path

    def get(self, url: str, timeout: float, headers=None) -> tuple[int, bytes]:
        self.calls.append(url)
        self.headers.append(dict(headers or {}))
        host, _, rest = url.split("//", 1)[1].partition("/")
        if host in self.down:
            raise ConnectionRefusedError(f"connection refused by {host}")
        key = "/" + rest.split("?", 1)[0] if self.by_path else url
        if key not in self.routes:
            return 404, b""
        status, body = self.routes[key]
        return status, json.dumps(body).encode()


FIXTURES = Path(__file__).resolve().parent / "fixtures"


def fixture(name: str):
    """A recorded (or source-verified) product response, ``tests/status/fixtures/<name>.json``."""
    return json.loads((FIXTURES / f"{name}.json").read_text(encoding="utf-8"))


def endpoint(service: str) -> str:
    """Registry name -> a base URL that only the fake answers (``.invalid`` never resolves)."""
    return f"http://{service}.status.invalid"


def spec(sid: str = "probe", **kw) -> SourceSpec:
    base = {
        "id": sid,
        "kind": "poll-http-json",
        "service": "svc-a",
        "capability": "cap-a",
        "interval_s": 60,
        "what": "a test source",
        "path": "/health",
        "timeout_s": 5,
        "mapping": {"state": "status"},
    }
    base.update(kw)
    return SourceSpec(**base)
