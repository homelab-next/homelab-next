# SPDX-License-Identifier: Apache-2.0
"""The ``orchestration`` contract on the LLM orchestrator (the Go controller; pinned: ``a52a1c4``).

``make(**config)`` returns an :class:`LLMOrchestrator`: a stdlib client of the controller's job
API on ``HNX_ENDPOINT_ORCHESTRATION`` plus a loopback *handler host* that runs the job bodies.
The mapping (docs/orchestration-controller.md has the whole table):

* ``define(name, handler, retries=n)`` -> a profile file ``<agent key>.yaml`` written into the
  controller's profiles directory (``profiles_dir``, or ``HNX_ORCHESTRATION_PROFILES_DIR``), then
  ``POST /admin/reload-profiles``.  The agent key is ``hnxconf-<run token>-<name>``; the profile
  is ``local_only`` and asks for ``max_attempts: n + 1``, a field only a controller with the
  proposed retry change reads.  The handler is kept by the handler host, never sent anywhere.
* ``submit`` -> ``POST /jobs`` with that agent key, the idempotency key namespaced by the run
  token (the controller's keys are global and never expire), and a task description holding one
  job line (``hnx-conform-job:<base64url JSON>``: handler host URL, a token per submit and its
  HMAC, the job and its parameters).  ``404`` is :class:`UnknownJob`.  The HMAC key never leaves
  the adapter process: the controller's ``GET /jobs/{id}`` (unauthenticated) shows the task
  description to anyone, so the line carries no host-wide secret, and the handler host runs only
  a token it issued, with a valid MAC, for that token's own job and parameters.  Its request
  body is bounded (``Content-Length``: not a number or negative is 400, over
  :data:`MAX_RUN_BODY` is 413).
* the job body -> the controller runs ``hermes -z PROMPT``; for a conformance run ``hermes`` is
  ``conformance/fakes/llm_orchestrator_hermes.py``, which posts the job line to the handler host
  and prints the handler's answer (or exits 1 with its error).
* ``wait`` -> polls ``GET /jobs/{id}`` until a terminal state: ``done`` is ``succeeded``,
  ``failed`` and ``budget_killed`` are ``failed``, ``cancelled`` is ``cancelled``; ``result`` is
  the answer decoded from ``response_body``, ``error`` is ``local_failed_reason``.  A controller
  that does not report ``attempts`` gets the number of executions the handler host saw for the
  run.  The timeout is at least ``wait_floor`` seconds: the controller admits on a 2 s tick.
* ``cancel`` -> ``POST /jobs/{id}/cancel``; ``409`` (a run that may no longer be cancelled) reads
  the run back unchanged, which is the contract for a finished run.

The adapter never answers for the controller: it does not raise ``UnknownJob`` for a name it was
not given and does not retry a failed run itself, so the suite sees what the controller does.

Controller limits (of ``a52a1c4``, not of this adapter): an unknown ``agent_key`` is accepted and
queued as an HTTP passthrough job (``unknown-job-raises`` fails); a run is attempted once
(``retries-until-success`` and ``retries-are-bounded`` fail); a submit cannot be held, so a cancel
races the next admission tick; the API has no authentication.
"""

from __future__ import annotations

import base64
import contextlib
import hmac
import json
import os
import re
import secrets
import shutil
import tempfile
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from homelabnext._http import read_bounded, safe_urlopen, send_json

from ._env import AdapterConfigError, resolve, run_token

__all__ = ["JOB_MARKER", "LLMOrchestrator", "encode_job", "make"]

JOB_MARKER = "hnx-conform-job:"
PROFILES_ENV = "HNX_ORCHESTRATION_PROFILES_DIR"
_LOOPBACK = "127.0.0.1"  # no-raw-endpoint: allow the handler host is local by design
#: the largest ``POST /run`` body the handler host reads (a job line's token, MAC and parameters)
MAX_RUN_BODY = 1 << 20
_AGENT_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$")
#: controller state -> contract state (internal/store/job.go:8-15)
STATES = {
    "queued": "queued",
    "admitted": "running",
    "running": "running",
    "awaiting_inference": "running",
    "done": "succeeded",
    "failed": "failed",
    "budget_killed": "failed",
    "cancelled": "cancelled",
}
TERMINAL = frozenset({"done", "failed", "budget_killed", "cancelled"})


def _protocol():
    try:
        from conformance.protocols.orchestration import OrchestrationError, RunStatus, UnknownJob
    except ImportError as exc:  # pragma: no cover - a wheel carries no conformance/
        raise AdapterConfigError("the orchestration adapter needs a source checkout") from exc
    return OrchestrationError, RunStatus, UnknownJob


def encode_job(doc: Mapping[str, Any]) -> str:
    """The job line for ``doc`` (what the hermes stand-in decodes)."""
    raw = json.dumps(dict(doc), ensure_ascii=False, separators=(",", ":")).encode()
    return JOB_MARKER + base64.urlsafe_b64encode(raw).decode().rstrip("=")


class _HandlerHost:
    """Runs a defined job's handler when the hermes stand-in asks, and counts executions.

    :meth:`issue` gives every submit a token and ``HMAC-SHA256(key, token)``; the key stays in
    this object.  :meth:`run` accepts only an issued token with its MAC, for the job and the
    parameters it was issued for."""

    def __init__(self) -> None:
        self._key = secrets.token_bytes(32)
        self.handlers: dict[str, Callable[[Mapping[str, Any]], Any]] = {}
        self.executions: dict[str, int] = {}
        self.issued: dict[str, tuple[str, str]] = {}  # token -> (job, canonical params)
        self._lock = threading.Lock()
        self._server = ThreadingHTTPServer((_LOOPBACK, 0), self._handler())
        self._server.daemon_threads = True
        self._thread = threading.Thread(
            target=self._server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True
        )
        self._thread.start()

    @property
    def url(self) -> str:
        host, port = self._server.server_address[:2]
        return f"http://{host}:{port}"

    def count(self, token: str) -> int:
        with self._lock:
            return self.executions.get(token, 0)

    def _mac(self, token: str) -> str:
        return hmac.new(self._key, token.encode(), "sha256").hexdigest()

    @staticmethod
    def _canon(params: Any) -> str:
        return json.dumps(params, sort_keys=True, ensure_ascii=False, separators=(",", ":"))

    def issue(self, job: str, params: Mapping[str, Any]) -> tuple[str, str]:
        """A fresh ``(token, mac)`` for one submit of ``job`` with ``params``."""
        token = secrets.token_hex(16)
        with self._lock:
            self.issued[token] = (job, self._canon(dict(params)))
        return token, self._mac(token)

    def run(self, body: Any) -> tuple[int, dict[str, Any]]:
        if not isinstance(body, dict):
            return 400, {"ok": False, "error": "the request is not a JSON object"}
        token, mac = body.get("token"), body.get("mac")
        with self._lock:
            issued = self.issued.get(token) if isinstance(token, str) else None
        if (
            issued is None
            or not isinstance(mac, str)
            or not hmac.compare_digest(mac, self._mac(token))
            or issued != (body.get("job"), self._canon(body.get("params") or {}))
        ):
            return 403, {"ok": False, "error": "not a job this handler host issued"}
        handler = self.handlers.get(str(body.get("job")))
        if handler is None:
            return 404, {"ok": False, "error": f"no handler for {body.get('job')!r}"}
        with self._lock:
            token = str(body.get("token"))
            self.executions[token] = self.executions.get(token, 0) + 1
        try:
            result = handler(body.get("params") or {})
            json.dumps(result)
        except Exception as exc:  # the job body's own failure is the run's error
            return 200, {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
        return 200, {"ok": True, "result": result}

    def _handler(self) -> type[BaseHTTPRequestHandler]:
        host = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args: Any) -> None:
                pass

            def do_POST(self) -> None:
                raw = self.headers.get("Content-Length") or ""
                n = int(raw) if raw.isascii() and raw.isdigit() else -1
                if n < 0:
                    self.close_connection = True
                    return send_json(self, 400, {"ok": False, "error": "bad Content-Length"})
                if n > MAX_RUN_BODY:
                    self.close_connection = True
                    return send_json(self, 413, {"ok": False, "error": "request too large"})
                try:
                    body = json.loads(self.rfile.read(n))
                except ValueError:
                    body = None
                status, doc = host.run(body) if self.path == "/run" else (404, {"ok": False})
                send_json(self, status, doc)

        return Handler

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)


class LLMOrchestrator:
    features = frozenset()

    def __init__(
        self,
        base_url: str,
        *,
        profiles_dir: str | Path,
        priority: int = 50,
        poll: float = 0.2,
        wait_floor: float = 60.0,
        timeout: float = 10.0,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
        on_close: Callable[[], None] | None = None,
    ):
        self._url = base_url.rstrip("/")
        self._profiles = Path(profiles_dir)
        if not self._profiles.is_dir():
            raise AdapterConfigError(f"profiles_dir {profiles_dir} is not a directory")
        self._priority, self._poll, self._floor, self._timeout = priority, poll, wait_floor, timeout
        self._clock, self._sleep, self._on_close = clock, sleep, on_close
        self._host = _HandlerHost()
        self._written: list[Path] = []
        self._tokens: dict[str, str] = {}

    def __repr__(self) -> str:
        return "LLMOrchestrator(<endpoint>)"

    # ---------------------------------------------------------------- HTTP
    def _request(self, method: str, path: str, body: Any = None) -> tuple[int, bytes]:
        data = None if body is None else json.dumps(body, ensure_ascii=False).encode()
        req = urllib.request.Request(self._url + path, data=data, method=method)
        if data is not None:
            req.add_header("Content-Type", "application/json")
        try:
            with safe_urlopen(req, timeout=self._timeout) as resp:
                return resp.status, read_bounded(resp)
        except urllib.error.HTTPError as exc:
            with contextlib.closing(exc):
                return exc.code, exc.read(4096)
        except OSError as exc:
            orch_error, _, _ = _protocol()
            raise orch_error(f"{method} {path}: controller unreachable ({exc})") from exc

    def _fail(self, what: str, status: int, raw: bytes) -> Exception:
        orch_error, _, _ = _protocol()
        return orch_error(f"{what}: HTTP {status}: {raw.decode('utf-8', 'replace').strip()[:300]}")

    def _agent_key(self, name: str) -> str:
        key = f"hnxconf-{run_token()}-{name}"
        if not _AGENT_KEY.match(key):
            raise ValueError(f"job name {name!r} cannot be an agent key")
        return key

    def _reload(self) -> None:
        status, raw = self._request("POST", "/admin/reload-profiles")
        if status == 501:
            raise AdapterConfigError("the controller has no profile reload (no scheduler wired)")
        if status != 200:
            raise self._fail("reload profiles", status, raw)

    # ---------------------------------------------------------------- contract
    def define(self, name, handler, *, retries=0):
        if retries < 0:
            raise ValueError("retries must be >= 0")
        key = self._agent_key(name)
        profile = {
            "id": f"{key}-v1",
            "agent_key": key,
            "toolsets": {"real": "hnx-conform", "shadow": "hnx-conform"},
            "local_only": True,
            "max_attempts": retries + 1,
            "default_task_description": "hnx orchestration conformance job",
        }
        path = self._profiles / f"{key}.yaml"
        header = "# written by homelabnext.conform.adapters.llm_orchestrator; removed on close\n"
        path.write_text(header + json.dumps(profile, indent=2) + "\n", encoding="utf-8")
        if path not in self._written:
            self._written.append(path)
        self._host.handlers[key] = handler
        self._reload()

    def submit(self, name, params, *, idempotency_key):
        _, _, unknown_job = _protocol()
        if not idempotency_key:
            raise ValueError("idempotency_key is required")
        key = self._agent_key(name)
        token, mac = self._host.issue(key, params)
        job = {
            "v": 1,
            "callback": self._host.url,
            "token": token,
            "mac": mac,
            "job": key,
            "params": dict(params),
        }
        body = {
            "agent_key": key,
            "priority": self._priority,
            "idempotency_key": f"hnxconf-{run_token()}-{idempotency_key}",
            "task_description": encode_job(job),
        }
        status, raw = self._request("POST", "/jobs", body)
        if status == 404:
            raise unknown_job(name)
        if status not in (200, 201):
            raise self._fail("submit", status, raw)
        run_id = json.loads(raw).get("run_id")
        if not isinstance(run_id, str) or not run_id:
            raise self._fail("submit (no run_id)", status, raw)
        self._tokens.setdefault(run_id, token)  # a repeated key keeps the first submit's token
        return run_id

    def _get(self, run_id: str) -> dict[str, Any]:
        status, raw = self._request("GET", f"/jobs/{run_id}")
        if status != 200:
            raise self._fail(f"run {run_id}", status, raw)
        doc = json.loads(raw)
        if not isinstance(doc, dict) or doc.get("state") not in STATES:
            raise self._fail(f"run {run_id} (unknown state)", status, raw)
        return doc

    def _status(self, run_id: str, doc: Mapping[str, Any]):
        _, run_status, _ = _protocol()
        state = STATES[doc["state"]]
        attempts = doc.get("attempts")
        if not isinstance(attempts, int):  # a52a1c4 reports none: count what the host ran
            attempts = self._host.count(self._tokens.get(run_id, ""))
        result = None
        if state == "succeeded":
            body = doc.get("response_body") or ""
            try:
                result = json.loads(body)["hnx_result"]
            except (ValueError, TypeError, KeyError):
                result = body
        error = doc.get("local_failed_reason") if state == "failed" else None
        return run_status(run_id, state, attempts, result, error or None)

    def wait(self, run_id, timeout=5.0):
        deadline = self._clock() + max(timeout, self._floor)
        doc = self._get(run_id)
        while doc["state"] not in TERMINAL and self._clock() < deadline:
            self._sleep(self._poll)
            doc = self._get(run_id)
        return self._status(run_id, doc)

    def cancel(self, run_id):
        status, raw = self._request("POST", f"/jobs/{run_id}/cancel")
        if status not in (200, 409):  # 409: no longer cancellable; read it back unchanged
            raise self._fail(f"cancel {run_id}", status, raw)
        return self._status(run_id, self._get(run_id))

    def close(self) -> None:
        try:
            for path in self._written:
                path.unlink(missing_ok=True)
            if self._written:
                with contextlib.suppress(Exception):
                    self._reload()
        finally:
            self._host.close()
            if self._on_close is not None:
                self._on_close()


def make(
    *,
    profiles_dir: str | None = None,
    recorded_fake: bool = False,
    fixes: list[str] | tuple[str, ...] = (),
    capability: str = "orchestration",
    priority: int = 50,
    poll: float = 0.2,
    wait_floor: float = 60.0,
) -> LLMOrchestrator:
    """An ``orchestration`` subject on a controller: the one ``HNX_ENDPOINT_<CAPABILITY>`` names,
    with its profiles directory, or (``recorded_fake``) a fresh loopback stand-in of its API,
    with ``fixes`` (``conformance/fakes/llm_orchestrator_api.py``) turned on."""
    if recorded_fake:
        return _on_recorded_fake(tuple(fixes), priority)
    if fixes:
        raise AdapterConfigError("fixes only apply to the recorded fake")
    directory = profiles_dir or os.environ.get(PROFILES_ENV)
    if not directory:
        raise AdapterConfigError(
            f"orchestration on the LLM orchestrator needs profiles_dir (or {PROFILES_ENV}): "
            "the directory the controller loads its profiles from"
        )
    ep = resolve(capability, env_only=True, schemes=("http", "https"))
    return LLMOrchestrator(
        ep.url, profiles_dir=directory, priority=priority, poll=poll, wait_floor=wait_floor
    )


def _on_recorded_fake(fixes: tuple[str, ...], priority: int) -> LLMOrchestrator:
    try:
        from conformance.fakes.llm_orchestrator_api import FakeController
    except ImportError as exc:  # pragma: no cover - a wheel carries no conformance/
        raise AdapterConfigError(
            "recorded_fake needs a source checkout (conformance/fakes)"
        ) from exc
    directory = tempfile.mkdtemp(prefix="hnx-orch-profiles-")
    fake = FakeController(directory, fixes=fixes).start()

    def stop() -> None:
        fake.stop()
        shutil.rmtree(directory, ignore_errors=True)

    try:
        return LLMOrchestrator(
            fake.url,
            profiles_dir=directory,
            priority=priority,
            poll=0.02,
            wait_floor=10.0,
            on_close=stop,
        )
    except BaseException:
        stop()
        raise
