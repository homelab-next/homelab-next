# SPDX-License-Identifier: Apache-2.0
"""Run each due source in isolation, each under its own timeout (checklist O-07).

Every source runs in its own daemon thread and the pass waits for each one only until *that*
source's ``timeout_s`` has passed since the pass started, so a pass takes at most the longest
timeout, never the sum, and a source that hangs or raises yields a :class:`SourceResult` with an
``error`` for itself alone.  Python cannot kill a thread: a hung collector keeps its thread, and
until it returns that source is not started again (its next result says it is still running), so
one blackholed source can never pile up threads either.

The scheduler only decides *what runs* and *what came back*.  What that means -- staleness, the
history, notifications -- is the hub's job (``homelabnext.status.hub``).
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass

from .collectors import COLLECTORS, CollectContext, Collector
from .mapping import Draft
from .model import SourceSpec


@dataclass(frozen=True)
class SourceResult:
    source: str
    drafts: tuple[Draft, ...] = ()
    error: str | None = None
    duration_s: float = 0.0

    @property
    def ok(self) -> bool:
        return self.error is None


def due(
    specs: Iterable[SourceSpec], last_attempts: Mapping[str, float | None], now: float
) -> list[SourceSpec]:
    """Polled sources whose interval has passed since their last attempt (or never attempted)."""
    out = []
    for s in specs:
        last = last_attempts.get(s.id)
        if s.polled and (last is None or now - last >= s.interval_s):
            out.append(s)
    return out


class Scheduler:
    def __init__(
        self,
        collectors: Mapping[str, Collector] | None = None,
        *,
        timer: Callable[[], float] = time.monotonic,
    ):
        self.collectors = dict(COLLECTORS if collectors is None else collectors)
        self.timer = timer
        self._inflight: dict[str, threading.Thread] = {}
        self._lock = threading.Lock()

    def running(self) -> list[str]:
        """Sources whose collector from an earlier pass has not returned yet."""
        with self._lock:
            return sorted(k for k, t in self._inflight.items() if t.is_alive())

    def run(self, specs: Sequence[SourceSpec], ctx: CollectContext) -> list[SourceResult]:
        """One pass over ``specs``; results in the order given."""
        slots: dict[str, SourceResult] = {}
        started: list[tuple[SourceSpec, threading.Thread, float]] = []
        for spec in specs:
            with self._lock:
                prev = self._inflight.get(spec.id)
                if prev is not None and prev.is_alive():
                    slots[spec.id] = SourceResult(
                        spec.id, error="previous poll still running (hung source)"
                    )
                    continue
            collector = self.collectors.get(spec.kind)
            if collector is None:
                slots[spec.id] = SourceResult(spec.id, error=f"no collector for kind {spec.kind}")
                continue
            t0 = self.timer()
            th = threading.Thread(
                target=self._one,
                args=(collector, spec, ctx, slots, t0),
                name=f"status-{spec.id}",
                daemon=True,
            )
            with self._lock:
                self._inflight[spec.id] = th
            th.start()
            started.append((spec, th, t0))
        for spec, th, t0 in started:
            th.join(max(0.0, t0 + spec.timeout_s - self.timer()))
            with self._lock:
                if spec.id not in slots:  # still running at its deadline
                    slots[spec.id] = SourceResult(
                        spec.id,
                        error=f"timeout after {spec.timeout_s:g}s",
                        duration_s=round(self.timer() - t0, 3),
                    )
                else:
                    self._inflight.pop(spec.id, None)
        return [slots[s.id] for s in specs]

    def _one(
        self,
        collector: Collector,
        spec: SourceSpec,
        ctx: CollectContext,
        slots: dict[str, SourceResult],
        t0: float,
    ) -> None:
        try:
            drafts = tuple(collector.collect(spec, ctx))
            res = SourceResult(spec.id, drafts, duration_s=round(self.timer() - t0, 3))
        except Exception as exc:  # a source's failure is its own result, never the pass's
            res = SourceResult(
                spec.id,
                error=f"{type(exc).__name__}: {' '.join(str(exc).split())[:300]}",
                duration_s=round(self.timer() - t0, 3),
            )
        with self._lock:
            # a result that arrives after the deadline is dropped: the pass already reported it
            if spec.id not in slots:
                slots[spec.id] = res
