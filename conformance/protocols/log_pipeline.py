# SPDX-License-Identifier: Apache-2.0
"""Contract for ``log-pipeline`` (extended suite): the move-and-shape stage labels model runtimes.

The pipeline carries events from collectors to the index and the lake.  Its one contractual duty
is the runtime label the ``det:model-runtime-*`` detections match (``labels.hnx_runtime``,
docs/log-pipeline.md):

* ``load_runtimes(table)`` installs a :class:`~homelabnext.logpipeline.RuntimeTable` (generated
  from the guest model by ``hnx guests render --target runtime-labels``); a later load replaces
  the earlier table entirely.
* ``process(records)`` takes :class:`Observed` records, each an event and the **observed source**:
  the address the collector itself saw (the peer of the connection the log arrived on, or the
  client address a resolver or proxy recorded), or None when the collector saw none.  It returns
  one event per record, in order.
* Each returned event's ``hnx_runtime`` label is the table's value for the observed address
  (``model`` or ``none``); an address the table does not hold, an absent one, or a value that is
  not a bare IP address (a port, a zone id, a host name) gives an event **without** the label.
  The event's own label, nested (``labels.hnx_runtime``) or as the flat dotted key
  (``"labels.hnx_runtime"``, which the engine also reads), is never kept, nor is any spelling of
  either that differs only in case or surrounding white space (a back end that folds field names
  would read it); no field of the event body (``source.ip``, ``host.name``, ...) is consulted:
  the body is what the watched runtime wrote.  An IPv4-mapped IPv6 address is its IPv4 address.
* A record whose event is not an object (an array, a string, null) comes back unchanged in its
  place: it has nowhere to carry the label, and one malformed record does not cost its batch.
* Everything else in the event, other labels included, leaves unchanged, and the records passed
  in are not modified.
* A provider SHOULD count the events it leaves without a label, per collector: an unknown address
  and ``none`` are the same to the detections, so a model runtime seen from an address the table
  lacks is silent, and that count is the only sign of it.

:func:`homelabnext.logpipeline.enrich` is the rule for one event; a provider may implement it in
its own engine (a lookup table processor), and this suite proves the result.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

from homelabnext.logpipeline import LABEL, RuntimeTable

__all__ = ["LABEL", "LogPipeline", "Observed", "RuntimeTable"]


@dataclass(frozen=True)
class Observed:
    """One event as the collector delivered it, with the address the collector saw."""

    event: Any  # a JSON object; anything else passes through unchanged
    observed: str | None


@runtime_checkable
class LogPipeline(Protocol):
    def load_runtimes(self, table: RuntimeTable) -> None: ...

    def process(self, records: Sequence[Observed]) -> list[Any]: ...
