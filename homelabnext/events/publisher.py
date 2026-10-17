# SPDX-License-Identifier: Apache-2.0
"""The publisher: validate, record intent, send with bounded retries, never duplicate.

Protocol (each step exists because the opposite loses or doubles an event):

1. **Validate** the envelope against its schema; an invalid event is refused before any I/O.
2. **Write ahead.**  The event is stored as ``pending`` (full body) *before* the first send.  A
   crash anywhere afterwards leaves a record that :meth:`Publisher.flush` can resend.
3. **Send** to the forwarder.  Transient errors back off (exponential, capped, bounded attempts);
   a permanent error marks the event ``rejected`` and stops.
4. **Acknowledge.**  Only an ack moves the record to ``sent``.

The crash window is between "forwarder stored it" and "publisher recorded the ack".  The record is
still ``pending``, so the event is sent again with the *same id*; the forwarder reports
``duplicate`` and the publisher marks it ``sent``.  Delivery is at-least-once on the wire and
exactly-once in effect, because the id is the idempotency key.  Publishing an id already ``sent``
makes no call at all; the same id with a different body is refused (:class:`EventError`).
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol

from .envelope import EventError, body_digest, validate_event
from .forwarder import Forwarder, PermanentError, TransientError


class _Store(Protocol):
    def get(self, key: str, default: Any = None) -> Any: ...
    def put(self, key: str, value: Any) -> None: ...
    def keys(self) -> list[str]: ...


@dataclass(frozen=True)
class RetryPolicy:
    max_attempts: int = 5
    base_s: float = 0.5
    factor: float = 2.0
    max_s: float = 30.0

    def __post_init__(self) -> None:
        if self.max_attempts < 1 or self.base_s < 0 or self.factor < 1 or self.max_s < 0:
            raise ValueError("invalid retry policy")

    def delay(self, attempt: int) -> float:
        """Seconds to wait after failed attempt number ``attempt`` (1-based)."""
        return min(self.max_s, self.base_s * self.factor ** (attempt - 1))


@dataclass(frozen=True)
class PublishResult:
    id: str
    status: str  # sent | duplicate | pending | rejected
    attempts: int  # forwarder calls made by this publish() call

    @property
    def ok(self) -> bool:
        return self.status in ("sent", "duplicate")


class Publisher:
    def __init__(
        self,
        forwarder: Forwarder,
        store: _Store,
        *,
        policy: RetryPolicy | None = None,
        sleep: Callable[[float], None] = time.sleep,
        namespace: str = "events",
    ) -> None:
        self.forwarder = forwarder
        self.store = store
        self.policy = policy or RetryPolicy()
        self.sleep = sleep
        self.namespace = namespace

    def _k(self, event_id: str) -> str:
        return f"{self.namespace}/{event_id}"

    def status_of(self, event_id: str) -> str | None:
        rec = self.store.get(self._k(event_id))
        return rec["status"] if rec else None

    def pending_ids(self) -> list[str]:
        pre = f"{self.namespace}/"
        out = []
        for k in sorted(self.store.keys()):
            if k.startswith(pre):
                rec = self.store.get(k)
                if rec and rec.get("status") == "pending":
                    out.append(k[len(pre) :])
        return out

    def publish(self, event: dict[str, Any]) -> PublishResult:
        validate_event(event)
        eid = event["id"]
        digest = body_digest(event)
        rec = self.store.get(self._k(eid))
        if rec is not None:
            if rec["digest"] != digest:
                raise EventError(
                    "id reuse with a different body",
                    [f"id {eid!r} was already published with other content"],
                )
            if rec["status"] == "sent":
                return PublishResult(eid, "duplicate", 0)
            if rec["status"] == "rejected":
                return PublishResult(eid, "rejected", 0)
        else:
            self.store.put(
                self._k(eid),
                {"status": "pending", "digest": digest, "event": event, "attempts": 0},
            )
        return self._deliver(event, digest)

    def flush(self) -> list[PublishResult]:
        """Resend every pending event (after a crash or an outage).  Safe to call repeatedly."""
        out = []
        for eid in self.pending_ids():
            rec = self.store.get(self._k(eid))
            out.append(self._deliver(rec["event"], rec["digest"]))
        return out

    def _deliver(self, event: dict[str, Any], digest: str) -> PublishResult:
        eid = event["id"]
        calls = 0
        for attempt in range(1, self.policy.max_attempts + 1):
            calls += 1
            try:
                ack = self.forwarder.forward(event)
            except PermanentError as exc:
                self._save(eid, event, digest, "rejected", error=str(exc))
                return PublishResult(eid, "rejected", calls)
            except TransientError as exc:
                self._save(eid, event, digest, "pending", error=str(exc), bump=1)
                if attempt < self.policy.max_attempts:
                    self.sleep(self.policy.delay(attempt))
                continue
            self._save(eid, event, digest, "sent", bump=1)
            return PublishResult(eid, "duplicate" if ack.duplicate else "sent", calls)
        return PublishResult(eid, "pending", calls)

    def _save(
        self,
        eid: str,
        event: dict[str, Any],
        digest: str,
        status: str,
        *,
        error: str = "",
        bump: int = 0,
    ) -> None:
        prev = self.store.get(self._k(eid)) or {}
        rec = {
            "status": status,
            "digest": digest,
            "event": event if status != "sent" else None,  # the body is only needed to resend
            "attempts": int(prev.get("attempts", 0)) + bump,
            "error": error,
        }
        self.store.put(self._k(eid), rec)
