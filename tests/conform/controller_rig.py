# SPDX-License-Identifier: Apache-2.0
"""What the orchestration adapter's tests run against, since the recorded stand-in is retired
(ADR-0026 decision 15): this repository's controller binary, started by the conformance harness
(tools/orchestration_conformance.py) on loopback, or, for what a test must break on purpose (a
503, a state no controller has), :class:`FakeJobAPI`, a few lines of HTTP that models nothing
but the answers the adapter reads."""

from __future__ import annotations

import contextlib
import json
import os
import subprocess
import sys
import threading
from collections.abc import Callable, Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

from conformance.fakes.llm_orchestrator_hermes import LOOPBACK
from homelabnext.conform.adapters import orchestrator as adapter
from tests.suite_policy import require_tool

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
import orchestration_conformance as harness

#: no network in a test run: the module cache only (CI's Go leg fetches it first)
OFFLINE = dict(os.environ, GOFLAGS="-mod=readonly", GOWORK="off", GOPROXY="off")


def _builds_offline() -> bool:
    proc = subprocess.run(
        ["go", "list", "-deps", "./cmd/controller"],
        cwd=ROOT / "orchestrator",
        env=OFFLINE,
        capture_output=True,
        check=False,
    )
    return proc.returncode == 0


@pytest.fixture(scope="session")
def controller_binary(tmp_path_factory) -> Path:
    """The controller built from this checkout, once a session; skips (a registered reason)
    where Go or the cached module is missing, and fails instead under HNX_REQUIRE_GO=1."""
    require_tool(
        "go",
        available=_builds_offline,
        unusable="the orchestrator module is not available offline (its toolchain or its cached dependencies)",
    )
    binary = tmp_path_factory.mktemp("controller") / "controller"
    subprocess.run(
        ["go", "build", "-o", str(binary), "./cmd/controller"],
        cwd=ROOT / "orchestrator",
        check=True,
        env=OFFLINE,
    )
    return binary


@contextlib.contextmanager
def live_controller(binary: Path, work: Path, **kw: Any) -> Iterator[adapter.Controller]:
    """A :class:`Controller` subject on a freshly started controller in ``work`` (the harness's
    configuration: loopback, authentication off, concurrency 1, the runner body as each session),
    stopped with its sessions at the end."""
    work.mkdir(mode=0o700, parents=True, exist_ok=True)
    harness.write_config(work, harness.free_port())
    (work / "controller.bin").write_text(f"{binary}\n", encoding="utf-8")
    harness.start(work)
    url = (work / "endpoint").read_text(encoding="ascii").strip()
    subject = adapter.Controller(
        url, profiles_dir=work / "profiles", **{"poll": 0.05, "wait_floor": 0, **kw}
    )
    try:
        yield subject
    finally:
        subject.close()
        harness.stop(work)


class FakeJobAPI:
    """The job API's answers, scripted: ``inflight`` is the backend in-flight route's (status,
    body); ``job`` makes a GET /jobs/{id} body from the run's stored submit. A submit's job runs
    its handler through the runner body in-process on its first read, so the handler host sees
    the execution, as the controller's session would make it."""

    def __init__(
        self,
        inflight: tuple[int, Any] = (404, {"error": "not found"}),
        job: Callable[[dict[str, Any]], dict[str, Any]] | None = None,
    ) -> None:
        self.inflight, self.job = inflight, job
        self.jobs: dict[str, dict[str, Any]] = {}
        self._lock = threading.Lock()
        api = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args: Any) -> None:
                pass

            def _send(self, status: int, doc: Any) -> None:
                body = json.dumps(doc).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self) -> None:
                if self.path == "/admin/backend-inflight":
                    return self._send(*api.inflight)
                if self.path == "/healthz":
                    return self._send(200, {"ok": True})
                run = self.path.removeprefix("/jobs/")
                with api._lock:
                    sent = api.jobs.get(run)
                if sent is None:
                    return self._send(404, {"error": "not found"})
                return self._send(200, api._read(run, sent))

            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(length) or b"{}")
                if self.path == "/admin/reload-profiles":
                    return self._send(200, {"ok": True})
                if self.path == "/jobs":
                    run = f"{len(api.jobs) + 1:032x}"
                    with api._lock:
                        api.jobs[run] = {**body, "state": "queued"}
                    return self._send(201, {"run_id": run})
                if self.path.endswith("/cancel"):
                    run = self.path.removeprefix("/jobs/").removesuffix("/cancel")
                    with api._lock:
                        sent = api.jobs.get(run)
                        if sent is None or sent["state"] != "queued":
                            return self._send(409, {"error": "not cancellable"})
                        sent["state"] = "cancelled"
                    return self._send(200, {"state": "cancelled"})
                return self._send(404, {"error": "not found"})

        self._httpd = ThreadingHTTPServer((LOOPBACK, 0), Handler)
        self.url = f"http://{LOOPBACK}:{self._httpd.server_address[1]}"
        threading.Thread(target=self._httpd.serve_forever, daemon=True).start()

    def _read(self, run: str, sent: dict[str, Any]) -> dict[str, Any]:
        from conformance.fakes import llm_orchestrator_hermes as body

        if sent["state"] == "queued":
            code, out, err = body.run(["-z", sent["task_description"]])
            sent.update(
                {"state": "done", "response_body": out}
                if code == 0
                else {"state": "failed", "local_failed_reason": err}
            )
        doc = {"run_id": run, "state": sent["state"], "priority": sent.get("priority")}
        doc.update({k: sent[k] for k in ("response_body", "local_failed_reason") if k in sent})
        return self.job(doc) if self.job else doc

    def close(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()
