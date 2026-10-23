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
* a record the store cannot hold for what it contains (:class:`EventError`, or one of
  :data:`RECORD_ERRORS`: a body nested so deep that its canonical form cannot be encoded, though
  it parsed): ``term`` as poison too;
* anything else -- the store failed (a locked or full disk: :data:`.store.STORE_ERRORS`) or the
  environment did (``jsonschema`` missing, a schema file half-written by a deploy, a ``$ref``
  that resolves to nothing, out of memory): ``nack`` -- redelivered, and the pass stops, since
  every later delivery would fail the same way.  An unknown exception is never taken for poison:
  that would dead-letter every valid record behind an outage.

The validator is built, and its ``$ref``s resolved, before the first fetch
(:func:`homelabnext.events.envelope.load_validator`), so a broken environment fails the pass up
front, with nothing fetched.

A pass ends when a fetch returns nothing or after ``max_batches`` fetches, so a timer can run it.
"""

from __future__ import annotations

import logging
from collections import Counter
from typing import Any

from homelabnext.events.envelope import EventError, load_validator

from .model import FINISHED_EVENT
from .store import STORE_ERRORS, TelemetryStore

log = logging.getLogger(__name__)
DURABLE = "hnx-orchestration-telemetry"
MAX_EVENT_BYTES = 64 * 1024  # a job record is a few KB; a bigger body is not one
#: the exceptions besides EventError that the content of one record raises from the store: a body
#: nested deeper than the encoder's stack (it parses, then body_digest cannot encode it; Python
#: 3.11).  KeyError, TypeError, OverflowError and UnicodeEncodeError are not here: the schema
#: requires and types every field the store reads, timestamps are checked, and every string bound
#: to SQL is ASCII by its pattern, so none of them can come from a record that validated.
RECORD_ERRORS: tuple[type[BaseException], ...] = (RecursionError,)


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
    load_validator(FINISHED_EVENT)  # an environment fault raises here, before anything is fetched
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
                except RECORD_ERRORS as exc:  # the content of this one record: never retried
                    reason = f"refused by the store ({type(exc).__name__})"
                except Exception as exc:  # the store or the environment: retry it later
                    what = "store" if isinstance(exc, STORE_ERRORS) else "environment"
                    log.error("orchestration: %s failed (%s); retrying", what, type(exc).__name__)
                    for rest in deliveries[i:]:
                        rest.nack()
                    counts["retried"] += len(deliveries) - i
                    return counts
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


__all__ = ["DURABLE", "RECORD_ERRORS", "drain"]
