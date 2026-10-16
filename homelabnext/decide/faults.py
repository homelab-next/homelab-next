# SPDX-License-Identifier: Apache-2.0
"""Fault injection for tiers: prove that a failing tier escalates and never answers."""

from __future__ import annotations

import time

from .tiers import Item, Tier, TierAnswer, TierError, TierTimeout


class FaultyTier:
    """Wrap ``inner`` and misbehave.

    mode: ``error`` (raise TierError), ``timeout`` (raise TierTimeout), ``hang`` (sleep
    ``hang_s``, so a real deadline fires), ``garbage`` (confident answer with an unknown label),
    ``bad_confidence`` (confidence outside 0..1).  ``after`` calls pass through first;
    ``count`` bounds the number of faulty calls (None = all following).
    """

    def __init__(
        self,
        inner: Tier,
        mode: str,
        *,
        after: int = 0,
        count: int | None = None,
        hang_s: float = 1.0,
    ):
        self.inner = inner
        self.name = inner.name
        self.mode = mode
        self.after = after
        self.count = count
        self.hang_s = hang_s
        self.calls = 0

    def decide(self, item: Item) -> TierAnswer:
        self.calls += 1
        n = self.calls - self.after
        faulty = n > 0 and (self.count is None or n <= self.count)
        if not faulty:
            return self.inner.decide(item)
        if self.mode == "error":
            raise TierError("injected error")
        if self.mode == "timeout":
            raise TierTimeout("injected timeout")
        if self.mode == "hang":
            time.sleep(self.hang_s)
            return self.inner.decide(item)
        if self.mode == "garbage":
            return TierAnswer("definitely-not-a-label", 1.0)
        if self.mode == "bad_confidence":
            return TierAnswer("accept", 7.0)
        raise ValueError(f"unknown fault mode {self.mode!r}")
