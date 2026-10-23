# SPDX-License-Identifier: Apache-2.0
"""Contract for ``events``: a durable pub/sub bus with at-least-once delivery and a DLQ.

* ``publish(subject, data, msg_id=)`` is idempotent per ``msg_id`` (a repeat is dropped).
* A *consumer* (durable, named) sees every matching message published after it was created, and
  nothing published before (a new consumer does not replay the history: JetStream's default
  ``DeliverPolicy.All`` would), in publish order per subject.  ``*`` matches one dotted token,
  ``>`` the rest.
* ``fetch`` never blocks: it returns what is deliverable now (possibly nothing).
* A delivery must be settled: ``ack`` (done), ``nack`` (redeliver, attempt + 1) or ``term``
  (never redeliver).  After ``max_deliver`` failed attempts, or on ``term``, the message goes to
  the consumer's dead-letter list and is never delivered again.  A delivery that is never settled
  (its consumer crashed and was reopened) is a failed attempt too, as JetStream counts every
  delivery against ``MaxDeliver``: a poison message that kills its consumer each time ends in the
  dead letters, not in an endless redelivery loop.  The dead letters are durable state of the
  consumer: a reopened consumer still has them.
* Durables are independent: a message one consumer acked is still delivered to every other
  (no work-queue retention).
* Only the first settlement of a delivery counts; settling it again is a no-op.
* At least once: re-opening a durable consumer (``consumer()`` with the same name, as a
  restarted process does) resumes where it left off.  Acked messages are not delivered again,
  messages published in between are, and every delivery that was fetched but never settled is
  redelivered (attempt + 1).  A delivery handed out before the reopen can no longer be settled:
  its ``ack``, ``nack`` or ``term`` is a no-op, whether the live delivery is still in flight or
  already settled (a stale ``nack`` does not requeue an acked message, a stale ``term`` does not
  dead-letter the live one).
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

__all__ = ["Consumer", "Delivery", "EventBus", "EventsError"]


class EventsError(Exception):
    pass


@dataclass
class Delivery:
    seq: int
    subject: str
    data: bytes
    msg_id: str | None
    attempt: int  # 1 on first delivery
    _settle: Callable[[str], None] | None = field(default=None, repr=False)  # impl hook

    def _do(self, how: str) -> None:
        if self._settle is None:
            raise EventsError("delivery is not attached to a consumer")
        self._settle(how)

    def ack(self) -> None:
        self._do("ack")

    def nack(self) -> None:
        self._do("nack")

    def term(self) -> None:
        self._do("term")


@runtime_checkable
class Consumer(Protocol):
    def fetch(self, n: int = 1) -> Sequence[Delivery]: ...

    def dead_letters(self) -> Sequence[Delivery]: ...


@runtime_checkable
class EventBus(Protocol):
    def publish(self, subject: str, data: bytes, *, msg_id: str | None = None) -> int:
        """Returns the sequence number (the existing one for a repeated ``msg_id``)."""

    def consumer(self, name: str, subject: str, *, max_deliver: int = 3) -> Consumer:
        """Create (or reopen, same name) a durable consumer on a subject pattern."""
