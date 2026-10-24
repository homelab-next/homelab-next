# SPDX-License-Identifier: Apache-2.0
"""Contract for ``orchestration``: named jobs, idempotent submission, bounded retries.

``define`` registers a job (a real adapter maps it onto a workflow/pack; the in-process form
takes a callable).  ``submit`` is idempotent per ``idempotency_key``: a repeat returns the same
run and the job body executes once.  ``wait`` drives/awaits a run to a terminal state and returns
the run as it stands when ``timeout`` runs out.

**Holds.**  An orchestrator that admits work holds capacity for it: a slot, an exclusive lease,
a token or KV-cache reservation on a model backend.  The contract on every such hold (added
additively, ADR-0001; the reasoning is ADR-0029):

a. *Capacity is held only by live work, and live work keeps it.*  A hold exists only while the
   worker it was granted to is alive, and that worker keeps it until it ends: a hold that goes
   away on its own while its run is still executing is a timer, not a release.  A run in a
   terminal state holds nothing.  Holds are released on success, failure,
   cancel, deadline expiry, worker death and orchestrator restart -- never only by a TTL.  A TTL
   is a backstop for a defect in this contract, not the way holds end: a hold that outlives its
   worker until a timer fires is capacity taken from live work by dead work.  A run between
   attempts (an attempt failed and a retry is pending, backing off or waiting for a backend) is
   live: it stays ``running`` and keeps its holds.  Liveness is the orchestrator's own record
   of the run's worker, never whether an attempt's process happens to exist at that moment.
b. *Cancelling a running run stops it.*  ``cancel`` on a ``running`` run stops its worker; the
   run ends ``cancelled`` within ``cancel_grace_s`` (the subject's attribute, else
   :data:`CANCEL_GRACE_S`) and its holds are released, whether or not the job body cooperates.
   A result the stopped worker produces afterwards is discarded.
c. *A restart reconciles.*  After the orchestrator restarts, no run is ``running`` without a live
   worker, and holds are rebuilt from live workers only.  A run that was executing is ended
   (``failed``), never run a second time: its old worker may still be executing elsewhere, and
   nothing it produces is recorded.  A run admitted but not yet executing may be requeued.  Queued runs survive and still run; idempotency keys survive, so a repeat
   submit after the restart returns the same run.
d. *Capacity is observable* (product feature ``admission``): ``capacity()`` returns a
   :class:`Capacity` -- the limit (``None`` when the implementation does not report one), the
   number of holds in flight, and the run ids holding them.
e. *Faults can be injected* (test hook ``fault-injection``): ``kill(run_id)`` makes the worker of a
   running run die as a crashed process would (the run must end ``failed`` and release its
   holds); ``restart()`` restarts the orchestrator in place, keeping its durable state and losing
   everything else, workers included.

A per-run deadline is the product feature ``deadline``: ``submit(..., deadline_s=s)``; a run
still unfinished ``s`` seconds after it was submitted ends ``failed``, with an error that names
the deadline, and releases its holds.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, NamedTuple, Protocol, runtime_checkable

__all__ = [
    "CANCEL_GRACE_S",
    "MAX_CANCEL_GRACE_S",
    "TERMINAL",
    "Admission",
    "Capacity",
    "Deadlines",
    "FaultInjection",
    "OrchestrationError",
    "Orchestrator",
    "RunStatus",
    "UnknownJob",
]

TERMINAL = ("succeeded", "failed", "cancelled")
#: how long a cancel, kill, deadline or restart may take to end the run and release its holds
CANCEL_GRACE_S = 5.0
#: the most an implementation may declare as its ``cancel_grace_s``: a grace as long as a job body
#: would let "released when the body returned" pass for "released on cancel"
MAX_CANCEL_GRACE_S = 10.0


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


class Capacity(NamedTuple):
    """What ``capacity()`` reports: ``(limit, in_flight, holders)``."""

    limit: int | None  # the most holds at once; None when the implementation does not say
    in_flight: int  # holds granted and not yet released
    holders: frozenset[str]  # run ids holding them


@runtime_checkable
class Orchestrator(Protocol):
    def define(
        self, name: str, handler: Callable[[Mapping[str, Any]], Any], *, retries: int = 0
    ) -> None: ...

    def submit(self, name: str, params: Mapping[str, Any], *, idempotency_key: str) -> str:
        """Returns a run id.  Raises UnknownJob."""

    def wait(self, run_id: str, timeout: float = 5.0) -> RunStatus: ...

    def cancel(self, run_id: str) -> RunStatus:
        """Cancels a queued run (it never executes) or a running one (its worker is stopped and
        its holds released within ``cancel_grace_s``); a finished run is returned unchanged."""


@runtime_checkable
class Admission(Protocol):
    """Product feature ``admission``: the holds the orchestrator has granted."""

    def capacity(self) -> Capacity: ...


@runtime_checkable
class Deadlines(Protocol):
    """Product feature ``deadline``: a run that outlives ``deadline_s`` ends ``failed``."""

    def submit(
        self,
        name: str,
        params: Mapping[str, Any],
        *,
        idempotency_key: str,
        deadline_s: float | None = None,
    ) -> str: ...


@runtime_checkable
class FaultInjection(Protocol):
    """Test hook ``fault-injection``: reach the states a crash leaves behind."""

    def kill(self, run_id: str) -> None:
        """The worker of running ``run_id`` dies (as a killed process would)."""

    def restart(self) -> None:
        """The orchestrator restarts in place: durable state kept, workers and memory lost."""
