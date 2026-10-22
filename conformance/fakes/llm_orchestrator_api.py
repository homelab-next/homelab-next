# SPDX-License-Identifier: Apache-2.0
"""A loopback stand-in for the LLM orchestrator's job API (the Go controller at ``a52a1c4``).

Only what the ``orchestration`` adapter touches, each shape taken from the controller's code
(paths are relative to that repository):

* routes -- ``POST /jobs``, ``GET /jobs/{id}``, ``POST /jobs/{id}/cancel``,
  ``POST /admin/reload-profiles`` (``internal/api/server.go:39-42``); anything else is 404 (Go's
  ``ServeMux``);
* submit -- body ``SubmitRequest`` (``internal/api/handlers.go:16-46``); ``400`` on a bad body,
  an empty ``agent_key`` or a priority outside 1..100, ``0`` meaning 50 (``handlers.go:97-111``);
  ``201 {"run_id"}`` for a new job, ``200`` with the *existing* run id when the idempotency key is
  already used by any job, whatever its agent (``handlers.go:126-140``, the unique index in
  ``internal/store/store.go:57-58``);
* status -- ``JobResponse`` (``handlers.go:52-87``, ``omitempty`` honoured), ``404 job not
  found`` (``handlers.go:171-178``); there is no ``attempts`` field;
* cancel -- ``404``, ``409 job is not in a cancellable state`` unless the state may move to
  ``cancelled`` (``handlers.go:344-359``, transitions ``internal/store/job.go:18-23``), else
  ``200`` with an empty body;
* reload -- re-reads every ``*.yaml`` in the profiles directory, keyed by ``agent_key``, ``500``
  on a bad file with the old registry kept (``handlers.go:216-228``,
  ``internal/profile/profile.go:171-200``);
* scheduling -- one job at a time (``-concurrency`` defaults to 1, ``cmd/controller/main.go:31``),
  lowest priority number first, then submit order.  The live controller admits on a 2 s tick
  (``main.go:225``), so a cancel sent right after a submit nearly always lands first; to make that
  deterministic here a job becomes admittable once its status has been read (a client is waiting
  on it) or ``admit_delay`` seconds after it was submitted, whichever comes first;
* dispatch -- a job whose ``agent_key`` has a profile runs the profile's job through the hermes
  stand-in (:mod:`conformance.fakes.llm_orchestrator_hermes`) with the prompt starting with its
  task description (``scheduler.go:525-527``, ``internal/hermesagent/prompt.go:153``): stdout is
  the ``response_body``, a non-zero exit fails the job with ``hermes -z failed: exit status N
  (stderr: ...)`` as ``local_failed_reason`` (``internal/hermesagent/invoker.go:379-382``), once
  -- there is no retry.  Any other ``agent_key`` takes the passthrough
  (``scheduler.go:535-565``) to a backend that is not there: ``failed``, cloud fallback used.

``fixes`` turns on the controller changes proposed for the two failing MUST checks (the patch
series in docs/orchestration-controller.md): ``reject-unknown-agent-key`` answers ``404 unknown
agent_key`` for an unprofiled key without ``request_body``; ``max-attempts`` honours a profile's
``max_attempts`` (same run id, never after a cancel) and reports ``attempts``.
"""

from __future__ import annotations

import json
import secrets
import threading
import time
from collections.abc import Callable, Iterable
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import yaml

from conformance.fakes import llm_orchestrator_hermes as hermes

LOOPBACK = "127.0.0.1"  # no-raw-endpoint: allow fake server binds loopback only
FIXES = frozenset({"reject-unknown-agent-key", "max-attempts"})
TRANSITIONS = {
    "queued": ("admitted", "cancelled"),
    "admitted": ("running", "queued"),
    "running": ("awaiting_inference", "done", "failed", "budget_killed", "cancelled"),
    "awaiting_inference": ("running", "failed"),
}
#: what prompt.go appends after the task description (evidenceAppendixContract and the rest)
_CONTRACTS = "\n\nEvidence appendix contract (stand-in).\n\nLoop detection contract (stand-in)."


class FakeController:
    def __init__(
        self,
        profiles_dir: str | Path,
        *,
        fixes: Iterable[str] = (),
        admit_delay: float = 2.0,
        tick: float = 0.02,
        clock: Callable[[], float] = time.monotonic,
        runtime: Callable[..., tuple[int, str, str]] = hermes.run,
    ):
        self.fixes = frozenset(fixes)
        if not self.fixes <= FIXES:
            raise ValueError(f"unknown fixes {sorted(self.fixes - FIXES)}; known {sorted(FIXES)}")
        self.profiles_dir = Path(profiles_dir)
        self.admit_delay, self.tick = admit_delay, tick
        self._clock, self._runtime = clock, runtime
        self._lock = threading.Lock()
        self._jobs: dict[str, dict[str, Any]] = {}
        self._seq = 0
        self.profiles: dict[str, dict[str, Any]] = self._load_profiles()
        self._stop = threading.Event()
        self._server: ThreadingHTTPServer | None = None
        self._threads: list[threading.Thread] = []

    # ---------------------------------------------------------------- lifecycle
    @property
    def url(self) -> str:
        assert self._server is not None, "start() first"
        host, port = self._server.server_address[:2]
        return f"http://{host}:{port}"

    def start(self) -> FakeController:
        self._server = ThreadingHTTPServer((LOOPBACK, 0), _handler(self))
        self._server.daemon_threads = True
        serve = self._server.serve_forever
        for target in (lambda: serve(poll_interval=0.01), self._schedule):
            t = threading.Thread(target=target, daemon=True)
            t.start()
            self._threads.append(t)
        return self

    def stop(self) -> None:
        self._stop.set()
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
        for t in self._threads:
            t.join(timeout=5)

    # ---------------------------------------------------------------- the API
    def _load_profiles(self) -> dict[str, dict[str, Any]]:
        out: dict[str, dict[str, Any]] = {}
        for path in sorted(self.profiles_dir.glob("*.yaml")):
            doc = yaml.safe_load(path.read_text(encoding="utf-8"))
            key = doc.get("agent_key") if isinstance(doc, dict) else None
            if not key:
                raise ValueError(f"profile file {path} has no agent_key")
            if key in out:
                raise ValueError(f"duplicate agent_key {key!r} across profile files")
            out[key] = doc
        return out

    def reload(self) -> tuple[int, str]:
        try:
            profiles = self._load_profiles()
        except (OSError, ValueError, yaml.YAMLError) as exc:
            return 500, f"reload failed: {exc}"
        with self._lock:
            self.profiles = profiles
        return 200, ""

    def submit(self, body: Any) -> tuple[int, Any]:
        if not isinstance(body, dict):
            return 400, "invalid request body"
        agent = body.get("agent_key") or ""
        if not isinstance(agent, str) or not agent:
            return 400, "agent_key is required"
        prio = body.get("priority") or 0
        if not isinstance(prio, int):
            return 400, "invalid request body"
        if prio == 0:
            prio = 50
        elif not 1 <= prio <= 100:
            return 400, "priority must be between 1 and 100"
        key = body.get("idempotency_key") or ""
        with self._lock:
            if (
                "reject-unknown-agent-key" in self.fixes
                and not body.get("request_body")
                and agent not in self.profiles
            ):
                return 404, (
                    "unknown agent_key: no profile is registered for it "
                    "(send request_body for an explicit passthrough)"
                )
            if key:
                for job in self._jobs.values():
                    if job["idempotency_key"] == key:
                        return 200, {"run_id": job["run_id"]}
            self._seq += 1
            run_id = secrets.token_hex(16)
            self._jobs[run_id] = {
                "run_id": run_id,
                "agent_key": agent,
                "priority": prio,
                "seq": self._seq,
                "state": "queued",
                "idempotency_key": key,
                "task_description": body.get("task_description") or "",
                "request_body": body.get("request_body"),
                "submitted": self._clock(),
                "attempts": 0,
            }
        return 201, {"run_id": run_id}

    def status(self, run_id: str) -> tuple[int, Any]:
        with self._lock:
            job = self._jobs.get(run_id)
            if job is None:
                return 404, "job not found"
            job["read"] = True
            out: dict[str, Any] = {
                "run_id": job["run_id"],
                "agent_key": job["agent_key"],
                "state": job["state"],
                "priority": job["priority"],
                "cloud_fallback_used": bool(job.get("cloud")),
            }
            if "max-attempts" in self.fixes:
                out["attempts"] = job["attempts"]
            for field in (
                "task_description",
                "local_failed_reason",
                "started_at",
                "response_body",
                "local_backend_used",
            ):
                if job.get(field):
                    out[field] = job[field]
        return 200, out

    def cancel(self, run_id: str) -> tuple[int, str]:
        with self._lock:
            job = self._jobs.get(run_id)
            if job is None:
                return 404, "job not found"
            if "cancelled" not in TRANSITIONS.get(job["state"], ()):
                return 409, "job is not in a cancellable state"
            job["state"] = "cancelled"
        return 200, ""

    # ---------------------------------------------------------------- scheduling
    def _schedule(self) -> None:
        while not self._stop.wait(self.tick):
            job = self._admit()
            if job is not None:
                self._execute(job)

    def _admit(self) -> dict[str, Any] | None:
        now = self._clock()
        with self._lock:
            ready = [
                j
                for j in self._jobs.values()
                if j["state"] == "queued"
                and (j.get("read") or now - j["submitted"] >= self.admit_delay)
            ]
            if not ready:
                return None
            job = min(ready, key=lambda j: (j["priority"], j["seq"]))
            job["state"] = "running"
            job["started_at"] = datetime.fromtimestamp(0, UTC).isoformat().replace("+00:00", "Z")
            return job

    def _finish(self, job: dict[str, Any], state: str, **fields: Any) -> None:
        with self._lock:
            if job["state"] != "running":  # a cancel won the compare-and-swap: keep it
                return
            job.update(fields)
            job["state"] = state

    def _execute(self, job: dict[str, Any]) -> None:
        with self._lock:
            profile = self.profiles.get(job["agent_key"])
        if profile is None:
            self._finish(
                job, "failed", cloud=True, local_failed_reason="primary-local: unreachable"
            )
            return
        toolsets = (profile.get("toolsets") or {}).get("real") or ""
        if not toolsets:
            reason = f"{job['agent_key']} profile is missing its toolsets configuration"
            self._finish(job, "failed", local_failed_reason=reason)
            return
        prompt = (job["task_description"] or profile.get("default_task_description", "")) + (
            _CONTRACTS
        )
        limit = 1
        if "max-attempts" in self.fixes:
            limit = max(int(profile.get("max_attempts") or 1), 1)
        for attempt in range(1, limit + 1):
            code, out, err = self._runtime(["-z", prompt, "--toolsets", toolsets])
            with self._lock:
                job["attempts"] = attempt
                cancelled = job["state"] != "running"
            if code == 0 or cancelled:
                break
        if code == 0:
            self._finish(
                job, "done", response_body=out.rstrip("\n"), local_backend_used="primary-local"
            )
            return
        reason = f"hermes -z failed: exit status {code}"
        if err.strip():
            reason += f" (stderr: {err.strip()})"
        self._finish(job, "failed", local_failed_reason=reason)


def _handler(ctl: FakeController) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args: Any) -> None:  # keep test output clean
            pass

        def _send(self, status: int, payload: Any) -> None:
            if isinstance(payload, str):
                data = (payload + "\n").encode() if payload else b""
                ctype = "text/plain; charset=utf-8"
            else:
                data = (json.dumps(payload) + "\n").encode()
                ctype = "application/json"
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _body(self) -> Any:
            n = int(self.headers.get("Content-Length") or 0)
            try:
                return json.loads(self.rfile.read(n) or b"null")
            except ValueError:
                return None

        def do_GET(self) -> None:
            parts = self.path.split("?")[0].strip("/").split("/")
            if len(parts) == 2 and parts[0] == "jobs":
                self._send(*ctl.status(parts[1]))
            else:
                self._send(404, "404 page not found")

        def do_POST(self) -> None:
            parts = self.path.split("?")[0].strip("/").split("/")
            if parts == ["jobs"]:
                self._send(*ctl.submit(self._body()))
            elif len(parts) == 3 and parts[0] == "jobs" and parts[2] == "cancel":
                self._send(*ctl.cancel(parts[1]))
            elif parts == ["admin", "reload-profiles"]:
                self._send(*ctl.reload())
            else:
                self._send(404, "404 page not found")

    return Handler
