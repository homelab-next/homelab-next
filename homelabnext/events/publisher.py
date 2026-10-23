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

The state is bounded by age: a ``sent`` record carries the time it was sent (``sent_at``, from
the injected clock) and is removed once it is older than ``retain_s`` (default 24 h, the longest
duplicate window the event bus allows); expired records go in one write, checked every
``PRUNE_EVERY`` sends.  So an id is never sent twice, and the same id with a different body is
refused, for ``retain_s`` after it was sent, whichever process sent it: the age comes from the
record, not from a per-process counter.  Published again after that, the id is sent again, and
the forwarder answers ``duplicate`` only within its own window.  A ``sent`` record written
before ``sent_at`` existed counts as expired.  Pending and rejected records are never removed.
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


#: how long a ``sent`` record is kept by default: the longest bus duplicate window (24 h)
RETAIN_S = 86_400.0
#: sends between two checks for expired ``sent`` records
PRUNE_EVERY = 100


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
        retain_s: float = RETAIN_S,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if not retain_s > 0:
            raise ValueError("retain_s must be positive")
        self.forwarder = forwarder
        self.store = store
        self.policy = policy or RetryPolicy()
        self.sleep = sleep
        self.namespace = namespace
        self.retain_s = float(retain_s)
        self.clock = clock
        self._until_prune = 0  # sends until the next check for expired records (0: at once)

    def _k(self, event_id: str) -> str:
        return f"{self.namespace}/{event_id}"

    def status_of(self, event_id: str) -> str | None:
        rec = self.store.get(self._k(event_id))
        return rec["status"] if rec else None

    def _records(self) -> dict[str, dict[str, Any]]:
        """Every record of this namespace by event id, in one read when the store allows it."""
        pre = f"{self.namespace}/"
        items = getattr(self.store, "items", None)
        if callable(items):
            pairs = list(dict(items()).items())
        else:
            names = list(self.store.keys())  # the protocol has keys(), not iteration
            pairs = [(k, self.store.get(k)) for k in names]
        return {k[len(pre) :]: v for k, v in pairs if k.startswith(pre) and isinstance(v, dict)}

    def pending_ids(self) -> list[str]:
        return sorted(i for i, r in self._records().items() if r.get("status") == "pending")

    def prune(self) -> int:
        """Remove the ``sent`` records older than ``retain_s``, in one write; returns how many.
        Only expired records are named, so a record another process just wrote is never one."""
        delete_many = getattr(self.store, "delete_many", None)
        delete = getattr(self.store, "delete", None)
        if delete_many is None and delete is None:
            return 0  # a store that cannot delete keeps everything
        cutoff = self.clock() - self.retain_s
        old = [
            self._k(i)
            for i, r in self._records().items()
            if r.get("status") == "sent" and _sent_at(r) < cutoff
        ]
        if not old:
            return 0
        if delete_many is not None:
            return int(delete_many(old))
        for k in old:
            delete(k)
        return len(old)

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
        if status == "sent":
            rec["sent_at"] = float(self.clock())  # its age decides when it is pruned
        self.store.put(self._k(eid), rec)
        if status == "sent":
            self._until_prune -= 1
            if self._until_prune <= 0:
                self._until_prune = PRUNE_EVERY
                self.prune()


def _sent_at(rec: dict[str, Any]) -> float:
    try:
        return float(rec.get("sent_at"))  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return float("-inf")  # written before records carried their time: expired
