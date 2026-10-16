# SPDX-License-Identifier: Apache-2.0
"""Keyed check state on top of :class:`StateStore`: last_seen, first_red, counters.

A check calls ``observe(key, ok)`` each run.  The record per key tracks when it was last seen,
when it first went red (and stays that value while it remains red), and how many consecutive
reds there have been.  The clock is injected; nothing here reads the wall clock directly.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any

from .store import StateStore


class KeyedState:
    def __init__(
        self, store: StateStore, namespace: str = "checks", clock: Callable[[], float] = time.time
    ):
        self.store = store
        self.namespace = namespace
        self.clock = clock

    def _k(self, key: str) -> str:
        return f"{self.namespace}/{key}"

    def record(self, key: str) -> dict[str, Any]:
        return dict(self.store.get(self._k(key), {}))

    def observe(self, key: str, ok: bool) -> dict[str, Any]:
        """Record one run of check ``key``; returns the updated record."""
        now = self.clock()

        def upd(rec: Any) -> dict[str, Any]:
            rec = dict(rec or {})
            rec["last_seen"] = now
            rec["runs"] = int(rec.get("runs", 0)) + 1
            if ok:
                rec["first_red"] = None
                rec["consecutive_red"] = 0
                rec["last_green"] = now
            else:
                if rec.get("first_red") is None:
                    rec["first_red"] = now
                rec["consecutive_red"] = int(rec.get("consecutive_red", 0)) + 1
            return rec

        return self.store.update(self._k(key), upd, {})

    def last_seen(self, key: str) -> float | None:
        return self.record(key).get("last_seen")

    def first_red(self, key: str) -> float | None:
        return self.record(key).get("first_red")

    def red_for(self, key: str) -> float:
        """Seconds the key has been continuously red (0.0 when green or unknown)."""
        first = self.first_red(key)
        return 0.0 if first is None else max(0.0, self.clock() - first)

    def incr(self, key: str, name: str = "count", by: int = 1) -> int:
        def upd(rec: Any) -> dict[str, Any]:
            rec = dict(rec or {})
            rec[name] = int(rec.get(name, 0)) + by
            return rec

        return int(self.store.update(self._k(key), upd, {})[name])

    def counter(self, key: str, name: str = "count") -> int:
        return int(self.record(key).get(name, 0))

    def reset(self, key: str) -> None:
        self.store.delete(self._k(key))
