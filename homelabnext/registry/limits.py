# SPDX-License-Identifier: Apache-2.0
"""Rate and cost limits on model calls (G-10): exceeding a budget throttles and alerts.

A :class:`Budget` bounds calls in a sliding window: requests, tokens (prompt + completion, from
the backend's ``usage``) and cost (tokens priced at ``cost_per_1k_tokens``).  Budgets come from a
role's ``limits`` in the role table (key ``mdl:<role>``) or from an agent profile's ``budgets``
(key ``profile:<id>``; tokens = input + output, window = ``max_runtime_s``).

:class:`Limiter` wraps a chat function.  Before each call it checks every budget that applies;
a call that would exceed one is **refused** with :class:`Throttled` (a ``ModelError`` of kind
``throttled``: a decision tier that is throttled escalates, it never answers) and the key is
reported through the state-diffed notifier, so a sustained overrun pages once and its recovery
pages once.  Usage is recorded after the call, so the call that crosses a token or cost limit
completes and the *next* one is refused.
"""

from __future__ import annotations

import time
from collections import deque
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from homelabnext.notify.core_pairs import MODEL_CALL_BUDGET

from .models import ChatResult, ModelError, RoleTable

KEY_PREFIX = "model-budget/"
PROBLEM, RECOVERY = MODEL_CALL_BUDGET


class Throttled(ModelError):
    def __init__(self, key: str, reason: str):
        self.key = key
        self.reason = reason
        super().__init__("throttled", f"{key}: {reason}")


@dataclass(frozen=True)
class Budget:
    window_s: float
    max_requests: int | None = None
    max_tokens: int | None = None
    max_cost: float | None = None
    cost_per_1k_tokens: float = 0.0

    def __post_init__(self) -> None:
        if not self.window_s > 0:
            raise ValueError("budget window_s must be > 0")

    @classmethod
    def from_limits(cls, limits: Mapping[str, Any]) -> Budget:
        def opt(k: str, conv: Callable[[Any], Any]) -> Any:
            return conv(limits[k]) if limits.get(k) is not None else None

        return cls(
            float(limits["window_s"]),
            opt("max_requests", int),
            opt("max_tokens", int),
            opt("max_cost", float),
            float(limits.get("cost_per_1k_tokens") or 0.0),
        )

    @classmethod
    def from_profile(cls, budgets: Mapping[str, Any]) -> Budget:
        """An agent profile's run budget: input + output tokens over its maximum runtime."""
        return cls(
            float(budgets["max_runtime_s"]),
            max_tokens=int(budgets["max_input_tokens"]) + int(budgets["max_output_tokens"]),
        )


@dataclass
class _Event:
    t: float
    tokens: int = 0
    cost: float = 0.0


class Limiter:
    def __init__(
        self,
        budgets: Mapping[str, Budget],
        *,
        clock: Callable[[], float] = time.monotonic,
        notifier: Any | None = None,
        topic: str | None = None,
    ):
        self.budgets = dict(budgets)
        self.clock = clock
        self.notifier = notifier
        self.topic = topic
        self._events: dict[str, deque[_Event]] = {k: deque() for k in self.budgets}
        self.throttled = 0
        if notifier is not None:
            notifier.register_pair(PROBLEM, RECOVERY)

    @classmethod
    def for_roles(cls, table: RoleTable, **kw: Any) -> Limiter:
        return cls(
            {f"mdl:{n}": Budget.from_limits(r.limits) for n, r in table.roles.items() if r.limits},
            **kw,
        )

    # ---------------------------------------------------------------- accounting
    def _window(self, key: str, now: float) -> deque[_Event]:
        ev = self._events[key]
        while ev and now - ev[0].t >= self.budgets[key].window_s:
            ev.popleft()
        return ev

    def usage(self, key: str) -> dict[str, float]:
        ev = self._window(key, self.clock())
        return {
            "requests": len(ev),
            "tokens": sum(e.tokens for e in ev),
            "cost": round(sum(e.cost for e in ev), 6),
        }

    def over(self, key: str) -> str | None:
        """Why the next call under ``key`` would exceed its budget, or None."""
        b, u = self.budgets[key], self.usage(key)
        if b.max_requests is not None and u["requests"] >= b.max_requests:
            return f"{u['requests']} requests in {b.window_s:g}s (limit {b.max_requests})"
        if b.max_tokens is not None and u["tokens"] >= b.max_tokens:
            return f"{u['tokens']} tokens in {b.window_s:g}s (limit {b.max_tokens})"
        if b.max_cost is not None and u["cost"] >= b.max_cost:
            return f"cost {u['cost']:g} in {b.window_s:g}s (limit {b.max_cost:g})"
        return None

    def _report(self, key: str, reason: str | None) -> None:
        if self.notifier is None:
            return
        from homelabnext.notify import Message

        nkey = KEY_PREFIX + key
        if reason is None:
            self.notifier.report(nkey, "ok", Message(nkey, RECOVERY, f"{key} within budget"))
        else:
            msg = Message(nkey, PROBLEM, f"{key} throttled: {reason}", level="warn",
                          tags=("model", "budget"), topic=self.topic)  # fmt: skip
            self.notifier.report(nkey, "throttled", msg)

    def acquire(self, keys: list[str]) -> list[_Event]:
        """Admit one call under every budget in ``keys`` (unknown keys are unlimited)."""
        keys = [k for k in keys if k in self.budgets]
        for k in keys:
            reason = self.over(k)
            if reason is not None:
                self.throttled += 1
                self._report(k, reason)
                raise Throttled(k, reason)
        now = self.clock()
        events = []
        for k in keys:
            e = _Event(now)
            self._events[k].append(e)
            events.append(e)
            self._report(k, None)
        return events

    def record(self, keys: list[str], events: list[_Event], usage: Mapping[str, Any]) -> None:
        tokens = usage.get("total_tokens")
        if not isinstance(tokens, int):
            tokens = int(usage.get("prompt_tokens") or 0) + int(usage.get("completion_tokens") or 0)
        keys = [k for k in keys if k in self.budgets]
        for k, e in zip(keys, events, strict=True):
            e.tokens = tokens
            e.cost = tokens / 1000 * self.budgets[k].cost_per_1k_tokens

    def wrap(
        self, chat: Callable[[list[dict]], ChatResult], *keys: str
    ) -> Callable[[list[dict]], ChatResult]:
        """``chat`` guarded by every budget named in ``keys`` (e.g. ``mdl:x``, ``profile:y``)."""
        names = list(keys)

        def limited(messages: list[dict]) -> ChatResult:
            events = self.acquire(names)
            res = chat(messages)
            self.record(names, events, res.usage)
            return res

        return limited
