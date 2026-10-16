# SPDX-License-Identifier: Apache-2.0
"""Contract for ``events``: a durable pub/sub bus with at-least-once delivery and a DLQ.

* ``publish(subject, data, msg_id=)`` is idempotent per ``msg_id`` (a repeat is dropped).
* A *consumer* (durable, named) sees every matching message published after it was created, in
  publish order per subject.  ``*`` matches one dotted token, ``>`` the rest.
* ``fetch`` never blocks: it returns what is deliverable now (possibly nothing).
* A delivery must be settled: ``ack`` (done), ``nack`` (redeliver, attempt + 1) or ``term``
  (never redeliver).  After ``max_deliver`` failed attempts, or on ``term``, the message goes to
  the consumer's dead-letter list and is never delivered again.
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
