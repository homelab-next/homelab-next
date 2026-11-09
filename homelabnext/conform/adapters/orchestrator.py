# SPDX-License-Identifier: Apache-2.0
"""The ``orchestration`` contract on the orchestration controller (``orchestrator/cmd/controller``).

``make(**config)`` returns a :class:`Controller`: a stdlib client of the controller's job API on
``HNX_ENDPOINT_ORCHESTRATION`` plus a loopback *handler host* that runs the job bodies. The
mapping (docs/orchestration-controller.md has the whole table):

* ``define(name, handler, retries=n)`` -> a profile file ``<agent key>.yaml`` written into the
  controller's profiles directory (``profiles_dir``, or ``HNX_ORCHESTRATION_PROFILES_DIR``), then
  ``POST /admin/reload-profiles``.  The agent key is ``hnxconf-<run token>-<name>``; the profile
  is ``local_only`` and asks for ``max_attempts: n + 1``.  The handler is kept by the handler
  host, never sent anywhere.
* ``submit`` -> ``POST /jobs`` with that agent key, the idempotency key namespaced by the run
  token (a submitter's keys never expire), and a task description holding one job line
  (``hnx-conform-job:<base64url JSON>``: handler host URL, a token per submit and its HMAC, the
  job and its parameters).  ``404`` is :class:`UnknownJob`.  The HMAC key never leaves the
  adapter process: any reader of the job's task sees the line, so it carries no host-wide
  secret, and the handler host runs only a token it issued, with a valid MAC, for that token's
  own job and parameters.  Its request body is bounded (``Content-Length``: not a number or
  negative is 400, over :data:`MAX_RUN_BODY` is 413).
* the job body -> the controller's runner session; for a conformance run it is
  ``conformance/fakes/llm_orchestrator_hermes.py`` under the exec runner
  (``tools/orchestration_conformance.py``), which posts the job line to the handler host and
  prints the handler's answer (or exits 1 with its error).
* ``wait`` -> polls ``GET /jobs/{id}`` until a terminal state: ``done`` is ``succeeded``,
  ``failed`` and ``budget_killed`` are ``failed``, ``cancelled`` is ``cancelled``; ``result`` is
  the answer decoded from ``response_body``, ``error`` is ``local_failed_reason``.  A controller
  that does not report ``attempts`` gets the number of executions the handler host saw for the
  run.  The timeout is at least ``wait_floor`` seconds (0 for the in-repository target: the
  controller admits on a one-second tick, and a floor would turn a read into a wait).
* ``cancel`` -> ``POST /jobs/{id}/cancel``; ``409`` (a run that may no longer be cancelled) reads
  the run back unchanged, which is the contract for a finished run.
* ``capacity`` (feature ``admission``) -> ``GET /admin/backend-inflight``: ``in_flight`` summed
  over the backends, ``holders`` the union of their ``reserved_runs``, ``limit`` ``None`` (the
  snapshot reports no limit).  ``admission`` is declared only when that route answers; a ``404``
  means no route, so the capacity checks skip, and any other answer (a 5xx, a timeout, a ``401``)
  makes the run unmeasured rather than skipped.  Without a limit the suite judges a release by
  the run leaving ``reserved_runs``: ``in_flight`` is a counter shared with any other traffic on
  the controller, so it is never compared.  With API authentication on, the route needs an admin
  token, which this adapter does not send.
* ``submit(..., priority=p)`` (feature ``priority``) -> the job's ``priority`` (1..100, lowest
  admitted first, then submit order); a value outside that range is refused with ``ValueError``
  before it is sent, and without one the adapter's own ``priority`` (default 50) is sent.
  ``priority`` is the only optional feature (``orchestration-features``) declared: the job API
  reports neither the backend nor the lane an attempt ran on (``shadow``, ``constraints``,
  ``local-only``) and has no list route (``list-runs``).  Its check needs a reported limit, which
  ``capacity()`` never has, so it skips; the claim is held on the binary instead
  (tests/conform/test_conform_orchestration_features.py).
* ``kill`` / ``restart`` (test hook ``fault-injection``) only with ``fault_injection: true`` and
  the harness that runs the controller as a process (:class:`ProcessFaults`). Elsewhere the
  adapter has no honest way to kill one job's worker or restart the service, so it does not
  declare the hook: there the checks needing it are ``untested`` (a MUST cannot be skipped by
  leaving a hook out), unless the controller lacks ``admission`` too, in which case they skip.

The adapter never answers for the controller: it does not raise ``UnknownJob`` for a name it was
not given and does not retry a failed run itself, so the suite sees what the controller does.
"""

from __future__ import annotations

import base64
import contextlib
import hmac
import json
import logging
import os
import re
import secrets
import signal
import subprocess
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from homelabnext._http import read_bounded, safe_opener, send_json

from ._env import AdapterConfigError, resolve, run_token

__all__ = ["JOB_MARKER", "Controller", "encode_job", "make"]

_log = logging.getLogger(__name__)

JOB_MARKER = "hnx-conform-job:"
PROFILES_ENV = "HNX_ORCHESTRATION_PROFILES_DIR"
#: fault injection on a real controller (``fault_injection: true``): the directory the runner
#: body records each session's pid in (``<dir>/<run id>.pid``), and the JSON argv that restarts
#: the controller in place (tools/orchestration_conformance.py restart)
PID_DIR_ENV = "HNX_ORCHESTRATION_PID_DIR"
RESTART_ENV = "HNX_ORCHESTRATION_RESTART"
_RUN_ID = re.compile(r"^[0-9a-f]{32}$")
_LOOPBACK = "127.0.0.1"  # no-raw-endpoint: allow the handler host is local by design
#: the largest ``POST /run`` body the handler host reads (a job line's token, MAC and parameters)
MAX_RUN_BODY = 1 << 20
_AGENT_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$")
#: controller state -> contract state (orchestrator/internal/store/job.go:10-19)
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
    """The job line for ``doc`` (what the runner body decodes)."""
    raw = json.dumps(dict(doc), ensure_ascii=False, separators=(",", ":")).encode()
    return JOB_MARKER + base64.urlsafe_b64encode(raw).decode().rstrip("=")


class _HandlerHost:
    """Runs a defined job's handler when the runner body asks, and counts executions.

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


def _is_session(pid: int, run_id: str) -> bool:
    """Whether ``pid`` (never 0, 1 or a negative group) is still the session of ``run_id``."""
    if pid <= 1:
        return False
    try:
        with open(f"/proc/{pid}/environ", "rb") as f:
            env = f.read().split(b"\0")
    except OSError:
        return False
    return f"HNX_RUN_ID={run_id}".encode() in env


class ProcessFaults:
    """Fault injection on a controller the harness runs as a process: ``kill`` sends SIGKILL to
    the session of a run (the pid its runner body recorded), as a crash would end it; ``restart``
    runs the harness's restart command (which kills the controller and every session, then starts
    the controller again on the same state) and waits for the API to answer."""

    def __init__(
        self,
        pid_dir: str | Path,
        restart: list[str],
        healthy: Callable[[], bool],
        *,
        wait_s: float = 30.0,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._dir = Path(pid_dir)
        if not self._dir.is_dir():
            raise AdapterConfigError(f"{PID_DIR_ENV} {pid_dir} is not a directory")
        if not restart or not all(isinstance(a, str) and a for a in restart):
            raise AdapterConfigError(f"{RESTART_ENV} must be a JSON list of strings (an argv)")
        self._restart, self._healthy = list(restart), healthy
        self._wait, self._clock, self._sleep = wait_s, clock, sleep

    def _pid(self, run_id: str) -> int:
        if not _RUN_ID.match(run_id):
            raise ValueError(f"not a controller run id: {run_id!r}")
        path = self._dir / f"{run_id}.pid"
        deadline = self._clock() + self._wait
        while True:
            try:
                return int(path.read_text(encoding="ascii").strip())
            except FileNotFoundError:
                if self._clock() > deadline:
                    orch_error, _, _ = _protocol()
                    raise orch_error(f"run {run_id} has no session pid in {self._dir}") from None
                self._sleep(0.05)

    def kill(self, run_id: str) -> None:
        pid = self._pid(run_id)
        # only a pid that is still the run's session (its environment carries the run id),
        # checked and signalled through one pidfd: the pid file can outlive the session and the
        # number be reused by another process
        try:
            fd = os.pidfd_open(pid) if pid > 1 else None
        except OSError as exc:
            _log.warning(
                "kill %s: pid %d is gone (%s): the session had already ended", run_id, pid, exc
            )
            return
        if fd is None:
            _log.warning("kill %s: refused pid %d (not a session's)", run_id, pid)
            return
        try:
            if not _is_session(pid, run_id):
                _log.warning(
                    "kill %s: pid %d is no longer that run's session: not signalled", run_id, pid
                )
                return
            with contextlib.suppress(ProcessLookupError):
                signal.pidfd_send_signal(fd, signal.SIGKILL)
        finally:
            os.close(fd)

    def restart(self) -> None:
        proc = subprocess.run(self._restart, capture_output=True, text=True, timeout=120)
        if proc.returncode != 0:
            orch_error, _, _ = _protocol()
            raise orch_error(
                f"the restart command failed ({proc.returncode}): {proc.stderr[-300:]}"
            )
        deadline = self._clock() + self._wait
        while not self._healthy():
            if self._clock() > deadline:
                orch_error, _, _ = _protocol()
                raise orch_error(f"the controller did not answer within {self._wait}s of a restart")
            self._sleep(0.1)


class Controller:
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
        faults: Any = None,
        cancel_grace_s: float = 10.0,
    ):
        self._url = base_url.rstrip("/")
        self._profiles = Path(profiles_dir)
        if not self._profiles.is_dir():
            raise AdapterConfigError(f"profiles_dir {profiles_dir} is not a directory")
        self._priority, self._poll, self._floor, self._timeout = priority, poll, wait_floor, timeout
        self._clock, self._sleep, self._on_close = clock, sleep, on_close
        self._host = _HandlerHost()
        # one opener per subject: building one loads the CA bundle (tens of ms of CPU), and the
        # capacity checks poll the controller many times a second
        self._opener = safe_opener()
        self._written: list[Path] = []
        self._tokens: dict[str, str] = {}
        #: a cancel is a process kill plus a poll: generous for a live controller under load
        self.cancel_grace_s = cancel_grace_s
        self._faults = faults  # an object with kill(run_id) and restart(): ProcessFaults
        self._features: frozenset[str] | None = None

    def __repr__(self) -> str:
        return "Controller(<endpoint>)"

    # ---------------------------------------------------------------- HTTP
    def _request(self, method: str, path: str, body: Any = None) -> tuple[int, bytes]:
        data = None if body is None else json.dumps(body, ensure_ascii=False).encode()
        req = urllib.request.Request(self._url + path, data=data, method=method)
        if data is not None:
            req.add_header("Content-Type", "application/json")
        try:
            with self._opener.open(req, timeout=self._timeout) as resp:
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

    def healthy(self) -> bool:
        """Whether the controller answers ``GET /healthz`` with 200 (False when unreachable)."""
        orch_error, _, _ = _protocol()
        try:
            status, _ = self._request("GET", "/healthz")
        except orch_error:  # unreachable: not healthy yet
            return False
        return status == 200

    def _reload(self) -> None:
        status, raw = self._request("POST", "/admin/reload-profiles")
        if status == 501:
            raise AdapterConfigError("the controller has no profile reload (no scheduler wired)")
        if status != 200:
            raise self._fail("reload profiles", status, raw)

    @property
    def features(self) -> frozenset[str]:
        """``admission`` when the controller serves its in-flight route, ``fault-injection``
        only with process faults that can kill and restart (probed once per subject).

        Only ``404`` means "no route": any other answer, or no answer, raises
        :class:`OrchestrationError`, so a transient fault makes the run unmeasured instead of
        quietly skipping the capacity checks."""
        if self._features is None:
            feats = {"priority"} | ({"fault-injection"} if self._faults is not None else set())
            status, raw = self._request("GET", "/admin/backend-inflight")
            if status == 200:
                self._parse_inflight(status, raw)
                feats.add("admission")
            elif status != 404:
                raise self._fail("backend in-flight (feature probe)", status, raw)
            self._features = frozenset(feats)
        return self._features

    def _inflight(self) -> dict[str, Any]:
        status, raw = self._request("GET", "/admin/backend-inflight")
        if status != 200:
            raise self._fail("backend in-flight", status, raw)
        return self._parse_inflight(status, raw)

    def _parse_inflight(self, status: int, raw: bytes) -> dict[str, Any]:
        try:
            doc = json.loads(raw)
        except ValueError:
            doc = None
        backends = doc.get("backends") if isinstance(doc, dict) else None
        if not isinstance(backends, dict):
            raise self._fail("backend in-flight (no backends)", status, raw)
        return backends

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
        header = "# written by homelabnext.conform.adapters.orchestrator; removed on close\n"
        path.write_text(header + json.dumps(profile, indent=2) + "\n", encoding="utf-8")
        if path not in self._written:
            self._written.append(path)
        self._host.handlers[key] = handler
        self._reload()

    def submit(self, name, params, *, idempotency_key, priority=None):
        _, _, unknown_job = _protocol()
        if not idempotency_key:
            raise ValueError("idempotency_key is required")
        if priority is None:
            priority = self._priority
        elif (
            isinstance(priority, bool) or not isinstance(priority, int) or not 1 <= priority <= 100
        ):
            raise ValueError("priority must be an int from 1 to 100 (the controller's range)")
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
            "priority": priority,
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
        if not isinstance(attempts, int):  # a controller that reports none: count what the host ran
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

    def capacity(self):
        """``(limit, in_flight, holders)`` from ``GET /admin/backend-inflight``."""
        from conformance.protocols.orchestration import Capacity

        in_flight, holders = 0, set()
        for entry in self._inflight().values():
            if isinstance(entry, dict):
                in_flight += int(entry.get("in_flight") or 0)
                holders.update(str(r) for r in entry.get("reserved_runs") or ())
        return Capacity(None, in_flight, frozenset(holders))

    def kill(self, run_id: str) -> None:
        if self._faults is None:
            orch_error, _, _ = _protocol()
            raise orch_error(
                "kill needs fault injection (fault_injection: true, run by the harness): a live worker is not ours to kill"
            )
        self._faults.kill(run_id)

    def restart(self) -> None:
        if self._faults is None:
            orch_error, _, _ = _protocol()
            raise orch_error(
                "restart needs fault injection (fault_injection: true, run by the harness): a live controller is not ours to restart"
            )
        self._faults.restart()

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
    capability: str = "orchestration",
    priority: int = 50,
    poll: float = 0.2,
    wait_floor: float = 60.0,
    fault_injection: bool = False,
) -> Controller:
    """An ``orchestration`` subject on a controller: the one ``HNX_ENDPOINT_<CAPABILITY>`` names,
    with its profiles directory; with ``fault_injection``, the harness's process faults."""
    directory = profiles_dir or os.environ.get(PROFILES_ENV)
    if not directory:
        raise AdapterConfigError(
            f"orchestration on the controller needs profiles_dir (or {PROFILES_ENV}): "
            "the directory the controller loads its profiles from"
        )
    ep = resolve(capability, env_only=True, schemes=("http", "https"))
    subject = Controller(
        ep.url, profiles_dir=directory, priority=priority, poll=poll, wait_floor=wait_floor
    )
    if fault_injection:
        pid_dir, raw = os.environ.get(PID_DIR_ENV), os.environ.get(RESTART_ENV)
        if not pid_dir or not raw:
            raise AdapterConfigError(
                f"fault_injection needs {PID_DIR_ENV} and {RESTART_ENV} (a JSON argv): the "
                "harness that runs the controller (tools/orchestration_conformance.py) sets both"
            )
        try:
            argv = json.loads(raw)
        except ValueError:
            raise AdapterConfigError(f"{RESTART_ENV} is not JSON") from None
        if not isinstance(argv, list):
            raise AdapterConfigError(f"{RESTART_ENV} must be a JSON list of strings (an argv)")
        subject._faults = ProcessFaults(pid_dir, argv, subject.healthy)
    return subject
