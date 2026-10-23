# SPDX-License-Identifier: Apache-2.0
"""In-memory orchestrator: a queue of runs, each started when waited on, on its own worker.

A run starts only when a caller waits on it (so a submit followed by a cancel never races a
scheduler) and a slot is free; it then executes on a worker thread holding one of ``slots``
slots, so a check can cancel, kill or restart around a run that is genuinely running.  Every
hold is tied to its worker: cancel, kill, deadline expiry and restart end the run and release
the slot at once, without waiting for the job body, and a result the stopped worker produces
later is discarded (``conformance/protocols/orchestration.py``, clauses a-e).
"""

from __future__ import annotations

import copy
import itertools
import threading
import time
from collections.abc import Callable, Mapping
from typing import Any

from conformance.protocols.orchestration import TERMINAL, Capacity, RunStatus, UnknownJob


class FakeOrchestrator:
    features = frozenset({"admission", "deadline", "fault-injection"})
    cancel_grace_s = 0.2  # every release is synchronous here; this only bounds a leak's wait

    def __init__(self, slots: int = 2) -> None:
        if slots < 1:
            raise ValueError("slots must be >= 1")
        self.slots = slots
        self._cv = threading.Condition()
        self._jobs: dict[str, tuple[Callable[[Mapping[str, Any]], Any], int]] = {}
        self._runs: dict[str, dict[str, Any]] = {}
        self._keys: dict[tuple[str, str], str] = {}
        self._n = 0
        self._holds: dict[str, int] = {}  # run id -> the worker token holding its slot
        self._tokens = itertools.count(1)
        self._timers: list[threading.Timer] = []

    # ---------------------------------------------------------------- contract
    def define(self, name, handler, *, retries=0):
        if retries < 0:
            raise ValueError("retries must be >= 0")
        with self._cv:
            self._jobs[name] = (handler, retries)

    def submit(self, name, params, *, idempotency_key, deadline_s=None):
        with self._cv:
            if name not in self._jobs:
                raise UnknownJob(name)
            if not idempotency_key:
                raise ValueError("idempotency_key is required")
            if deadline_s is not None and deadline_s <= 0:
                raise ValueError("deadline_s must be > 0")
            key = (name, idempotency_key)
            if key in self._keys and self._dedupe():
                return self._keys[key]
            self._n += 1
            run_id = f"run-{self._n}"
            self._runs[run_id] = {
                "name": name,
                "params": copy.deepcopy(dict(params)),
                "state": "queued",
                "attempts": 0,
                "result": None,
                "error": None,
                "deadline": None if deadline_s is None else time.monotonic() + deadline_s,
            }
            self._keys[key] = run_id
            if deadline_s is not None:
                timer = threading.Timer(deadline_s, self._expire, (run_id,))
                timer.daemon = True
                self._timers.append(timer)
                timer.start()
            return run_id

    def wait(self, run_id, timeout=5.0):
        end = time.monotonic() + timeout
        with self._cv:
            r = self._runs[run_id]
            while True:
                if r["state"] == "queued" and len(self._holds) < self.slots:
                    self._start(run_id)
                if r["state"] in TERMINAL:
                    break
                left = end - time.monotonic()
                if left <= 0:
                    break
                self._cv.wait(left)
            return self._status(run_id)

    def cancel(self, run_id):
        with self._cv:
            r = self._runs[run_id]
            if r["state"] == "queued":
                r["state"] = "cancelled"
            elif r["state"] == "running":
                self._stop(run_id, "cancelled", None, why="cancel")
            return self._status(run_id)

    # ---------------------------------------------------------------- admission
    def capacity(self) -> Capacity:
        with self._cv:
            return Capacity(self.slots, len(self._holds), frozenset(self._holds))

    # ---------------------------------------------------------------- fault injection
    def kill(self, run_id: str) -> None:
        """The worker of ``run_id`` dies: the run fails and its slot is released."""
        with self._cv:
            if self._runs[run_id]["state"] == "running":
                self._stop(run_id, "failed", "worker died", why="kill")

    def restart(self) -> None:
        """Restart in place: every worker is lost; runs and idempotency keys are kept."""
        with self._cv:
            self._reconcile()

    def close(self) -> None:
        for timer in self._timers:
            timer.cancel()

    # ---------------------------------------------------------------- internals
    def _dedupe(self) -> bool:
        return True

    def _status(self, run_id: str) -> RunStatus:
        r = self._runs[run_id]
        return RunStatus(run_id, r["state"], r["attempts"], r["result"], r["error"])

    def _start(self, run_id: str) -> None:
        token = next(self._tokens)
        self._runs[run_id]["state"] = "running"
        self._holds[run_id] = token
        threading.Thread(target=self._work, args=(run_id, token), daemon=True).start()

    def _live(self, run_id: str, token: int) -> bool:
        return self._holds.get(run_id) == token and self._runs[run_id]["state"] == "running"

    def _work(self, run_id: str, token: int) -> None:
        with self._cv:
            r = self._runs[run_id]
            handler, retries = self._jobs[r["name"]]
        for _ in range(retries + 1):
            with self._cv:
                if not self._live(run_id, token):
                    return
                r["attempts"] += 1
                params = copy.deepcopy(r["params"])
            try:
                result, error = handler(params), None
            except Exception as exc:
                result, error = None, f"{type(exc).__name__}: {exc}"
            with self._cv:
                if not self._live(run_id, token):
                    return  # stopped while the body ran: its result is discarded
                r["result"], r["error"] = result, error
                if error is None:
                    break
        with self._cv:
            if self._live(run_id, token):
                r["state"] = "succeeded" if r["error"] is None else "failed"
                self._release(run_id, "done")
            self._cv.notify_all()

    def _stop(self, run_id: str, state: str, error: str | None, *, why: str) -> None:
        r = self._runs[run_id]
        r["state"], r["error"] = state, error
        self._release(run_id, why)
        self._cv.notify_all()

    def _release(self, run_id: str, why: str) -> None:
        self._holds.pop(run_id, None)

    def _expire(self, run_id: str) -> None:
        with self._cv:
            r = self._runs.get(run_id)
            if r is None or r["state"] in TERMINAL:
                return
            if r["state"] == "queued":
                r["state"], r["error"] = "failed", "deadline exceeded before the run started"
                self._cv.notify_all()
            else:
                self._stop(run_id, "failed", "deadline exceeded", why="deadline")

    def _reconcile(self) -> None:
        for r in self._runs.values():
            if r["state"] == "running":
                r["state"], r["error"] = "failed", "orchestrator restarted: worker lost"
        self._holds.clear()  # rebuilt from live workers, and there are none
        self._cv.notify_all()


class NoDedupeOrchestrator(FakeOrchestrator):
    """Defect: the idempotency key is ignored, so a repeated submit runs the job again."""

    def _dedupe(self) -> bool:
        return False


class LeakOnCancelOrchestrator(FakeOrchestrator):
    """Defect: cancelling a running run marks it cancelled but never returns its slot."""

    def _release(self, run_id: str, why: str) -> None:
        if why != "cancel":
            super()._release(run_id, why)
        else:  # the hold stays, but no worker owns it any more
            self._holds[run_id] = -1


class LeakOnKillOrchestrator(FakeOrchestrator):
    """Defect: a worker that dies fails its run but its slot is never returned."""

    def _release(self, run_id: str, why: str) -> None:
        if why != "kill":
            super()._release(run_id, why)
        else:
            self._holds[run_id] = -1


class NoRestartReconcileOrchestrator(FakeOrchestrator):
    """Defect: a restart loses the workers but leaves their runs ``running`` and their slots
    held -- the ghost a TTL-only reaper leaves until the timer fires."""

    def _reconcile(self) -> None:
        for run_id in self._holds:
            self._holds[run_id] = -1  # the worker is gone; its hold and its run state are not
        self._cv.notify_all()
