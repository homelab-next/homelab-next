# SPDX-License-Identifier: Apache-2.0
"""Contract for ``orchestration``: named jobs, idempotent submission, bounded retries.

``define`` registers a job (a real adapter maps it onto a workflow/pack; the in-process form
takes a callable).  ``submit`` is idempotent per ``idempotency_key``: a repeat returns the same
run and the job body executes once.  ``wait`` drives/awaits a run to a terminal state.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

__all__ = ["TERMINAL", "OrchestrationError", "Orchestrator", "RunStatus", "UnknownJob"]

TERMINAL = ("succeeded", "failed", "cancelled")


class OrchestrationError(Exception):
    pass


class UnknownJob(OrchestrationError):
    pass


@dataclass(frozen=True)
class RunStatus:
    run_id: str
    state: str  # queued | running | succeeded | failed | cancelled
    attempts: int
    result: Any = None
    error: str | None = None


@runtime_checkable
class Orchestrator(Protocol):
    def define(
        self, name: str, handler: Callable[[Mapping[str, Any]], Any], *, retries: int = 0
    ) -> None: ...

    def submit(self, name: str, params: Mapping[str, Any], *, idempotency_key: str) -> str:
        """Returns a run id.  Raises UnknownJob."""

    def wait(self, run_id: str, timeout: float = 5.0) -> RunStatus: ...

    def cancel(self, run_id: str) -> RunStatus:
        """Cancels a run that has not started; a finished run is returned unchanged."""
