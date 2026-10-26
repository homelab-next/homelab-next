# SPDX-License-Identifier: Apache-2.0
"""In-memory orchestrator: a queue of runs, each started when waited on, on its own worker.

A run starts only when a caller waits on it (so a submit followed by a cancel never races a
scheduler) and a slot is free; it then executes on a worker thread holding one of ``slots``
slots, so a check can cancel, kill or restart around a run that is genuinely running.  Every
hold is tied to its worker: cancel, kill, deadline expiry and restart end the run and release
the slot at once, without waiting for the job body, and a result the stopped worker produces
later is discarded (``conformance/protocols/orchestration.py``, clauses a-e).

It also offers every optional feature (clauses f-j).  A free slot goes to the waited-on queued run
with the lowest ``priority`` (then the earliest), and a slot freed by a finished run is handed on
at once.  Each run is placed on one of :data:`BACKENDS` that satisfies its job's constraints and
exclusivity; a retry of a job that is not local-only escalates to a cloud backend that satisfies
them, as the controller re-runs a session on cloud.  Every attempt is recorded with its backend
and lane.
"""

from __future__ import annotations

import copy
import itertools
import threading
import time
from collections.abc import Callable, Mapping
from typing import Any

from conformance.protocols.orchestration import (
    TERMINAL,
    Backend,
    Capacity,
    ConstraintsUnsatisfiable,
    Placement,
    RunStatus,
    ShadowRunPending,
    UnknownJob,
)

#: the fake's backends: two local ones and a cloud one (fictional names)
BACKENDS = (
    Backend("local-a", "local", frozenset({"gpu", "large"}), 131072),
    Backend("local-b", "local", frozenset({"gpu"}), 32768),
    Backend("cloud-a", "cloud", frozenset({"large"}), 200000),
)
CONSTRAINT_KEYS = frozenset({"require_tags", "min_context", "exclusive"})
DEFAULT_PRIORITY = 50


class FakeOrchestrator:
    features = frozenset(
        {
            "admission",
            "deadline",
            "fault-injection",
            "priority",
            "shadow",
            "constraints",
            "local-only",
            "list-runs",
        }
    )
    cancel_grace_s = 0.01  # every release is synchronous here; this only bounds a leak's wait

    def __init__(self, slots: int = 2) -> None:
        if slots < 1:
            raise ValueError("slots must be >= 1")
        self.slots = slots
        self._cv = threading.Condition()
        self._jobs: dict[str, tuple[Callable[[Mapping[str, Any]], Any], int]] = {}
        self._opts: dict[str, dict[str, Any]] = {}  # job -> constraints, local_only
        self._runs: dict[str, dict[str, Any]] = {}
        self._keys: dict[tuple[str, str], str] = {}
        self._n = 0
        self._holds: dict[str, int] = {}  # run id -> the worker token holding its slot
        self._tokens = itertools.count(1)
        self._timers: list[threading.Timer] = []

    # ---------------------------------------------------------------- contract
    def define(self, name, handler, *, retries=0, constraints=None, local_only=False):
        if retries < 0:
            raise ValueError("retries must be >= 0")
        c = _constraints(constraints)
        opts = {"constraints": c, "local_only": bool(local_only)}
        with self._cv:
            if self._reject_unsatisfiable() and not any(
                self._meets(b, opts) for b in self.backends()
            ):
                raise ConstraintsUnsatisfiable(f"no backend satisfies {name}'s constraints {c}")
            self._jobs[name] = (handler, retries)
            self._opts[name] = opts

    def submit(
        self, name, params, *, idempotency_key, deadline_s=None, priority=None, shadow=False
    ):
        with self._cv:
            if name not in self._jobs:
                raise UnknownJob(name)
            if not idempotency_key:
                raise ValueError("idempotency_key is required")
            if deadline_s is not None and deadline_s <= 0:
                raise ValueError("deadline_s must be > 0")
            if priority is not None and (
                isinstance(priority, bool) or not isinstance(priority, int) or priority < 1
            ):
                raise ValueError("priority must be an int >= 1")
            key = (name, idempotency_key)
            if key in self._keys and self._dedupe():
                return self._keys[key]
            if shadow and self._unfinished_shadow(name):
                raise ShadowRunPending(f"{name} already has an unfinished shadow run")
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
                "priority": DEFAULT_PRIORITY if priority is None else priority,
                "seq": self._n,
                "shadow": bool(shadow),
                "wanted": False,  # a caller has waited on it: only such a run is admitted
                "backend": None,
                "placements": [],
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
            r["wanted"] = True
            while True:
                if r["state"] == "queued":
                    self._admit()
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

    # ---------------------------------------------------------------- placements, list-runs
    def backends(self) -> tuple[Backend, ...]:
        return BACKENDS

    def placements(self, run_id: str) -> tuple[Placement, ...]:
        with self._cv:
            return tuple(self._runs[run_id]["placements"])

    def runs(self, state: str | None = None) -> list[RunStatus]:
        with self._cv:
            return [
                self._status(rid)
                for rid, r in self._runs.items()
                if state is None or r["state"] == state
            ]

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

    def _order(self, run_id: str) -> tuple[int, int]:
        """Which queued run a free slot goes to first: the lowest priority, then the earliest."""
        r = self._runs[run_id]
        return (r["priority"], r["seq"])

    def _admit(self) -> None:
        """Start waited-on queued runs, best first, while a slot is free and a backend takes
        them."""
        while len(self._holds) < self.slots:
            ready = [
                rid
                for rid, r in self._runs.items()
                if r["state"] == "queued" and r["wanted"] and self._place(rid) is not None
            ]
            if not ready:
                return
            self._start(min(ready, key=self._order))

    def _start(self, run_id: str) -> None:
        token = next(self._tokens)
        r = self._runs[run_id]
        r["backend"] = self._place(run_id)
        r["state"] = "running"
        r["placements"].append(Placement(len(r["placements"]) + 1, r["backend"], self._lane(r)))
        self._holds[run_id] = token
        threading.Thread(target=self._work, args=(run_id, token), daemon=True).start()

    # ---------------------------------------------------------------- placement
    def _meets(self, b: Backend, opts: Mapping[str, Any]) -> bool:
        """``b`` satisfies the job's constraints and locality, whatever runs on it."""
        c = opts["constraints"]
        if opts["local_only"] and b.locality != "local":
            return False
        if not set(c.get("require_tags", ())) <= b.tags:
            return False
        need = c.get("min_context")
        return need is None or (b.max_context is not None and b.max_context >= need)

    def _occupants(self, backend: str, run_id: str) -> list[str]:
        return [
            rid
            for rid, r in self._runs.items()
            if rid != run_id and r["state"] == "running" and r["backend"] == backend
        ]

    def _free_for(self, b: Backend, run_id: str) -> bool:
        """Exclusivity: no exclusive run on ``b``, and an exclusive run only on an idle one."""
        others = self._occupants(b.name, run_id)
        if any(self._exclusive(rid) for rid in others):
            return False
        return not (self._exclusive(run_id) and others)

    def _exclusive(self, run_id: str) -> bool:
        return bool(self._opts[self._runs[run_id]["name"]]["constraints"].get("exclusive"))

    def _eligible(self, run_id: str) -> list[Backend]:
        opts = self._opts[self._runs[run_id]["name"]]
        return [b for b in self.backends() if self._meets(b, opts) and self._free_for(b, run_id)]

    def _place(self, run_id: str) -> str | None:
        """The backend a starting run goes to: an eligible local one first, else a cloud one."""
        ok = self._eligible(run_id)
        ok.sort(key=lambda b: b.locality != "local")
        return ok[0].name if ok else None

    def _retry_backend(self, run_id: str) -> str:
        """Where a retry runs: a job that is not local-only escalates to an eligible cloud
        backend (the controller's cloud re-run); otherwise the run stays where it is."""
        r = self._runs[run_id]
        if not self._opts[r["name"]]["local_only"]:
            for b in self._eligible(run_id):
                if b.locality == "cloud":
                    return b.name
        return r["backend"]

    def _lane(self, r: Mapping[str, Any]) -> str:
        return "shadow" if r["shadow"] else "real"

    def _retry_lane(self, r: Mapping[str, Any]) -> str:
        return self._lane(r)

    def _unfinished_shadow(self, name: str) -> bool:
        return any(
            r["name"] == name and r["shadow"] and r["state"] not in TERMINAL
            for r in self._runs.values()
        )

    def _reject_unsatisfiable(self) -> bool:
        return True

    def _live(self, run_id: str, token: int) -> bool:
        return self._holds.get(run_id) == token and self._runs[run_id]["state"] == "running"

    def _accepts(self, run_id: str, token: int) -> bool:
        """Whether the worker ``token`` may still record what its body returned."""
        return self._live(run_id, token)

    def _work(self, run_id: str, token: int) -> None:
        with self._cv:
            r = self._runs[run_id]
            handler, retries = self._jobs[r["name"]]
        for n in range(retries + 1):
            with self._cv:
                if not self._live(run_id, token):
                    return
                r["attempts"] += 1
                if n:  # the first attempt was placed when the run started
                    r["backend"] = self._retry_backend(run_id)
                    r["placements"].append(Placement(n + 1, r["backend"], self._retry_lane(r)))
                params = copy.deepcopy(r["params"])
            try:
                result, error = handler(params), None
            except Exception as exc:
                result, error = None, f"{type(exc).__name__}: {exc}"
            with self._cv:
                if not self._accepts(run_id, token):
                    return  # stopped while the body ran: its result is discarded
                r["result"], r["error"] = result, error
                if error is None:
                    break
                self._attempt_failed(run_id)
        with self._cv:
            if self._accepts(run_id, token):
                r["state"] = "succeeded" if r["error"] is None else "failed"
                self._release(run_id, "done")
                self._admit()
            self._cv.notify_all()

    def _attempt_failed(self, run_id: str) -> None:
        """An attempt failed and the run may retry: it stays live and keeps its hold."""

    def _stop(self, run_id: str, state: str, error: str | None, *, why: str) -> None:
        r = self._runs[run_id]
        r["state"], r["error"] = state, error
        self._release(run_id, why)
        self._admit()
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


class TTLReleaseOrchestrator(FakeOrchestrator):
    """Defect: holds end by a timer, not by events -- each slot is dropped a fixed time after it
    was granted, whether the run is still executing or not, and cancel/kill/deadline/restart
    release nothing.  The TTL is shorter than the grace, so every release looks prompt."""

    TTL_S = 0.005

    def _release(self, run_id: str, why: str) -> None:
        if why == "done":
            super()._release(run_id, why)

    def _start(self, run_id: str) -> None:
        super()._start(run_id)
        token = self._holds[run_id]

        def expire() -> None:
            with self._cv:
                if self._holds.get(run_id) == token:
                    del self._holds[run_id]
                    self._cv.notify_all()

        timer = threading.Timer(self.TTL_S, expire)
        timer.daemon = True
        timer.start()


class LyingCapacityOrchestrator(FakeOrchestrator):
    """Defect: a stopped run's slot leaks, so admission stays blocked, but ``capacity()`` lists
    only the holders whose run is still ``running``: the report looks clean, the effect is not."""

    def _release(self, run_id: str, why: str) -> None:
        if why == "done":
            super()._release(run_id, why)
        else:
            self._holds[run_id] = -1

    def capacity(self) -> Capacity:
        with self._cv:
            live = frozenset(r for r in self._holds if self._runs[r]["state"] == "running")
            return Capacity(self.slots, len(live), live)


class RestartRerunsLiveRunOrchestrator(FakeOrchestrator):
    """Defect: a restart requeues the runs that were executing and clears the slots but never
    stops their old workers, so a requeued run executes a second time beside its first worker,
    and either may report."""

    def _reconcile(self) -> None:
        for r in self._runs.values():
            if r["state"] == "running":
                r["state"] = "queued"
        self._holds.clear()
        self._cv.notify_all()

    def _live(self, run_id: str, token: int) -> bool:
        return self._runs[run_id]["state"] == "running"


class LateResultLandsOrchestrator(FakeOrchestrator):
    """Defect: holds are released on time, but a stopped worker's result is still recorded when
    its body returns (no compare-and-swap on the run's state)."""

    def _accepts(self, run_id: str, token: int) -> bool:
        return self._holds.get(run_id) in (token, None)


class LeakOnFailureOrchestrator(FakeOrchestrator):
    """Defect: only the success path releases; a run whose last attempt failed keeps its slot."""

    def _release(self, run_id: str, why: str) -> None:
        if why == "done" and self._runs[run_id]["state"] == "failed":
            self._holds[run_id] = -1
        else:
            super()._release(run_id, why)


class AttemptScopedHoldOrchestrator(FakeOrchestrator):
    """Defect: the hold belongs to an attempt, not to the run.  A failed attempt returns the slot
    and the retry runs holding nothing, as when liveness is judged by an attempt's process: the
    run is live between attempts, but admission no longer counts it."""

    def _attempt_failed(self, run_id: str) -> None:
        self._holds.pop(run_id, None)
        self._cv.notify_all()

    def _live(self, run_id: str, token: int) -> bool:
        return self._runs[run_id]["state"] == "running"


def _constraints(raw: Mapping[str, Any] | None) -> dict[str, Any]:
    if raw is None:
        return {}
    if not isinstance(raw, Mapping) or set(raw) - CONSTRAINT_KEYS:
        raise ValueError(f"constraints take only {sorted(CONSTRAINT_KEYS)}")
    out: dict[str, Any] = {}
    tags = raw.get("require_tags", ())
    if isinstance(tags, str) or not all(isinstance(t, str) and t for t in tags):
        raise ValueError("require_tags must be a list of tag names")
    if tags:
        out["require_tags"] = tuple(tags)
    ctx = raw.get("min_context")
    if ctx is not None:
        if isinstance(ctx, bool) or not isinstance(ctx, int) or ctx < 1:
            raise ValueError("min_context must be an int >= 1")
        out["min_context"] = ctx
    if raw.get("exclusive"):
        out["exclusive"] = True
    return out


# ---------------------------------------------------------------- optional-feature defects
class FirstComeFirstServedOrchestrator(FakeOrchestrator):
    """Defect: ``priority`` is accepted and ignored; queued runs start in submit order."""

    def _order(self, run_id: str) -> tuple[int, int]:
        return (0, self._runs[run_id]["seq"])


class ShadowRetryOnRealLaneOrchestrator(FakeOrchestrator):
    """Defect: the lane is chosen per attempt from the default, so a shadow run's retry
    executes on the real lane."""

    def _retry_lane(self, r: Mapping[str, Any]) -> str:
        return "real"


class ShadowLimitCountsRunningOrchestrator(FakeOrchestrator):
    """Defect: the one-shadow-run limit counts only running shadow runs, so a second one is
    accepted while the first is still queued."""

    def _unfinished_shadow(self, name: str) -> bool:
        return any(
            r["name"] == name and r["shadow"] and r["state"] == "running"
            for r in self._runs.values()
        )


class BestEffortPlacementOrchestrator(FakeOrchestrator):
    """Defect: a job no backend can satisfy is accepted and its runs are placed on the first
    backend anyway (best-effort placement)."""

    def _reject_unsatisfiable(self) -> bool:
        return False

    def _place(self, run_id: str) -> str | None:
        opts = self._opts[self._runs[run_id]["name"]]
        if not any(self._meets(b, opts) for b in self.backends()):
            return self.backends()[0].name
        return super()._place(run_id)


class RetryIgnoresConstraintsOrchestrator(FakeOrchestrator):
    """Defect: the first attempt is placed by the constraints, but a retry escalates to the
    first cloud backend without them (the cloud re-run path skips the affinity check)."""

    def _retry_backend(self, run_id: str) -> str:
        r = self._runs[run_id]
        if not self._opts[r["name"]]["local_only"]:
            for b in self.backends():
                if b.locality == "cloud":
                    return b.name
        return r["backend"]


class ExclusiveNotEnforcedOrchestrator(FakeOrchestrator):
    """Defect: ``exclusive`` is recorded but placement never looks at what else runs on a
    backend."""

    def _free_for(self, b: Backend, run_id: str) -> bool:
        return True


class LocalOnlyEscalatesOrchestrator(FakeOrchestrator):
    """Defect: a failed attempt of a local-only job is re-run on cloud anyway (the escalation
    path does not read ``local_only``)."""

    def _retry_backend(self, run_id: str) -> str:
        r = self._runs[run_id]
        opts = {**self._opts[r["name"]], "local_only": False}
        for b in self.backends():
            if b.locality == "cloud" and self._meets(b, opts) and self._free_for(b, run_id):
                return b.name
        return r["backend"]


class RowPerAttemptOrchestrator(FakeOrchestrator):
    """Defect: ``runs()`` reads a table with one row per attempt, so a retried run is listed
    once per attempt."""

    def runs(self, state: str | None = None) -> list[RunStatus]:
        with self._cv:
            return [
                self._status(rid)
                for rid, r in self._runs.items()
                if state is None or r["state"] == state
                for _ in range(max(1, r["attempts"]))
            ]
