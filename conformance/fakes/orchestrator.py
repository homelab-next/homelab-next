# SPDX-License-Identifier: Apache-2.0
"""In-memory orchestrator: a queue of runs, executed when waited on (deterministic)."""

from __future__ import annotations

import copy
from collections.abc import Callable, Mapping
from typing import Any

from conformance.protocols.orchestration import RunStatus, UnknownJob


class FakeOrchestrator:
    features = frozenset()

    def __init__(self) -> None:
        self._jobs: dict[str, tuple[Callable[[Mapping[str, Any]], Any], int]] = {}
        self._runs: dict[str, dict[str, Any]] = {}
        self._keys: dict[tuple[str, str], str] = {}
        self._n = 0

    def define(self, name, handler, *, retries=0):
        if retries < 0:
            raise ValueError("retries must be >= 0")
        self._jobs[name] = (handler, retries)

    def submit(self, name, params, *, idempotency_key):
        if name not in self._jobs:
            raise UnknownJob(name)
        if not idempotency_key:
            raise ValueError("idempotency_key is required")
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
        }
        self._keys[key] = run_id
        return run_id

    def _dedupe(self) -> bool:
        return True

    def _status(self, run_id: str) -> RunStatus:
        r = self._runs[run_id]
        return RunStatus(run_id, r["state"], r["attempts"], r["result"], r["error"])

    def wait(self, run_id, timeout=5.0):
        r = self._runs[run_id]
        if r["state"] == "queued":
            handler, retries = self._jobs[r["name"]]
            r["state"] = "running"
            for _ in range(retries + 1):
                r["attempts"] += 1
                try:
                    r["result"] = handler(copy.deepcopy(r["params"]))
                    r["state"], r["error"] = "succeeded", None
                    break
                except Exception as exc:
                    r["state"], r["error"] = "failed", f"{type(exc).__name__}: {exc}"
        return self._status(run_id)

    def cancel(self, run_id):
        r = self._runs[run_id]
        if r["state"] == "queued":
            r["state"] = "cancelled"
        return self._status(run_id)


class NoDedupeOrchestrator(FakeOrchestrator):
    """Defect: the idempotency key is ignored, so a repeated submit runs the job again."""

    def _dedupe(self) -> bool:
        return False
