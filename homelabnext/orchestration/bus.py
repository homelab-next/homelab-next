# SPDX-License-Identifier: Apache-2.0
"""Draining ``homelabnext.agent.job.finished`` from the bus into the telemetry store.

One durable pull consumer (:class:`conformance.protocols.events.EventBus`; NATS JetStream in a
lab, :mod:`homelabnext.conform.adapters.nats_jetstream`) on the type's subject.  Each delivery is
settled after the store answered, so the semantics are those of the st2 bridge
(:mod:`homelabnext.workflows.st2_bridge`):

* stored, a duplicate of what is stored, or expired (older than the store's retention, so not
  stored): ``ack``;
* poison (not JSON, invalid, another type or source, an id or run conflict): ``term`` -- the
  bus's dead-letter stream is the quarantine, it is never retried, and only the event id and the
  reason are logged, never the body;
* the store failed (a locked or full disk: :class:`sqlite3.Error` or :class:`OSError`): ``nack``
  -- redelivered, and the pass stops, since every later delivery would fail the same way.  Any
  other exception comes from the record itself (the store refuses every content defect it knows
  as :class:`EventError`), so it is poison too: retrying it would only fail again, hold back the
  valid deliveries behind it and finally drop it without a dead letter.

A pass ends when a fetch returns nothing or after ``max_batches`` fetches, so a timer can run it.
"""

from __future__ import annotations

import logging
from collections import Counter
from typing import Any

from homelabnext.events.envelope import EventError

from .model import FINISHED_EVENT
from .store import STORE_ERRORS, TelemetryStore

log = logging.getLogger(__name__)
DURABLE = "hnx-orchestration-telemetry"
MAX_EVENT_BYTES = 64 * 1024  # a job record is a few KB; a bigger body is not one


def drain(
    bus: Any,
    store: TelemetryStore,
    *,
    durable: str = DURABLE,
    batch: int = 50,
    max_batches: int = 100,
    max_deliver: int = 5,
) -> Counter:
    """One pass over the durable (see the module docstring); returns counts by outcome
    (``processed``, ``duplicate``, ``expired``, ``quarantined``, ``retried``)."""
    consumer = bus.consumer(durable, FINISHED_EVENT, max_deliver=max_deliver)
    counts: Counter = Counter()
    for _ in range(max_batches):
        deliveries = list(consumer.fetch(batch))
        if not deliveries:
            break
        for i, d in enumerate(deliveries):
            reason = _poison(d)
            if reason is None:
                try:
                    counts[store.consume(d.data).status] += 1
                except EventError as exc:
                    reason = str(exc).splitlines()[0]
                except STORE_ERRORS as exc:  # the store, not the event: retry it later
                    log.error("orchestration: store failed (%s); retrying", type(exc).__name__)
                    for rest in deliveries[i:]:
                        rest.nack()
                    counts["retried"] += len(deliveries) - i
                    return counts
                except Exception as exc:  # the content of this one record: never retried
                    reason = f"refused by the store ({type(exc).__name__})"
                else:
                    d.ack()
                    continue
            log.warning("orchestration: quarantined delivery seq %s: %s", d.seq, reason)
            d.term()
            counts["quarantined"] += 1
    return counts


def _poison(d: Any) -> str | None:
    if d.subject != FINISHED_EVENT:
        return "wrong subject"
    if len(d.data) > MAX_EVENT_BYTES:
        return "too large"
    return None


__all__ = ["DURABLE", "drain"]
