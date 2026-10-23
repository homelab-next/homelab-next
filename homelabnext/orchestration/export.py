# SPDX-License-Identifier: Apache-2.0
"""Export and import of the telemetry store in a neutral format (JSON lines), so a store can be
moved to another host, rebuilt, or carried across a swap of its upstreams.

``homelabnext.orchestration.export/1``: one JSON object per line, each with ``schema`` and
``kind``::

    {"schema": "homelabnext.orchestration.export/1", "kind": "job",
     "event": {<the agent.job.finished envelope as consumed>}, "turns_settled_at": "<ISO>"|null}
    {"schema": "homelabnext.orchestration.export/1", "kind": "turn", "turn": {<a turn record>}}

Jobs come first (oldest finish first), then turns (oldest start first).  A job is its whole
event, so an import goes through :meth:`.store.TelemetryStore.consume` exactly as the bus does:
the same id with the same body is a ``duplicate``, a conflicting, foreign or invalid record is
refused (poison), one past retention is ``expired``; ``turns_settled_at`` is kept for a job the
import stores, so its turns are not read again.  A turn is the neutral turn record
(:data:`conformance.protocols.inference.TURN_FIELDS`), written by its ``turn_id`` through
:meth:`~.store.TelemetryStore.add_turns`, which refuses any other shape; the same record again is
a ``duplicate``.  Every line is self-describing, so an import refuses a line of another schema or
kind rather than guessing.  Evolve additively; an incompatible change is ``export/2``.
"""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Iterable, Iterator, Mapping
from typing import Any

from homelabnext.events.consumer import parse_json
from homelabnext.events.envelope import EventError
from homelabnext.status.model import iso, parse_iso

from .store import TelemetryStore

EXPORT_SCHEMA = "homelabnext.orchestration.export/1"
#: what an import counts, per kind
STATUSES = ("processed", "duplicate", "expired")


class ImportRefused(ValueError):
    """One line of an export that cannot be imported (the reason is the message)."""


def export_lines(store: TelemetryStore) -> Iterator[str]:
    """The store as export lines (see the module docstring), without line ends."""
    for kind, item in store.dump():
        if kind == "job":
            event, settled = item
            rec: dict[str, Any] = {
                "event": event,
                "turns_settled_at": None if settled is None else iso(settled),
            }
        else:
            rec = {"turn": item}
        yield json.dumps({"schema": EXPORT_SCHEMA, "kind": kind, **rec}, sort_keys=True)


def import_line(store: TelemetryStore, line: str) -> tuple[str, str]:
    """Import one export line: ``(kind, status)`` with status one of :data:`STATUSES`;
    :class:`ImportRefused` (or :class:`EventError` for a job record) when it is refused."""
    try:
        rec = parse_json(line)  # the consumer's own parse: every failure is a ValueError
    except ValueError as exc:
        raise ImportRefused(f"not JSON ({str(exc).splitlines()[0]:.200})") from None
    if not isinstance(rec, dict):
        raise ImportRefused("a line is an object")
    if rec.get("schema") != EXPORT_SCHEMA:
        raise ImportRefused(f"schema {str(rec.get('schema'))[:80]!r}: not {EXPORT_SCHEMA}")
    kind = rec.get("kind")
    if kind == "job" and set(rec) == {"schema", "kind", "event", "turns_settled_at"}:
        return "job", _import_job(store, rec["event"], rec["turns_settled_at"])
    if kind == "turn" and set(rec) == {"schema", "kind", "turn"}:
        return "turn", _import_turn(store, rec["turn"])
    raise ImportRefused(f"not a job or turn line of {EXPORT_SCHEMA}")


def _import_job(store: TelemetryStore, event: Any, settled_at: Any) -> str:
    if not isinstance(event, Mapping):
        raise ImportRefused("a job line carries its event (a store before exports kept none)")
    settled = None
    if settled_at is not None:
        try:
            settled = parse_iso(settled_at) if isinstance(settled_at, str) else None
        except ValueError:
            settled = None
        if settled is None:
            raise ImportRefused("turns_settled_at is not a time")
    status = store.consume(event).status
    if status == "processed" and settled is not None:
        store.settle([event["data"]["run_id"]], settled)
    return status


def _import_turn(store: TelemetryStore, turn: Any) -> str:
    if not isinstance(turn, Mapping):
        raise ImportRefused("a turn line carries its turn record")
    try:
        started = parse_iso(turn["started_at"])
    except (KeyError, TypeError, ValueError):
        started = None
    if started is not None and started < store.clock() - store.retention_s:
        return "expired"
    if isinstance(turn.get("turn_id"), str) and store.turn(turn["turn_id"]) == dict(turn):
        return "duplicate"
    try:
        store.add_turns([turn])
    except ValueError as exc:
        raise ImportRefused(str(exc)) from None
    return "processed"


def import_lines(
    store: TelemetryStore, lines: Iterable[str]
) -> tuple[Counter, list[tuple[int, str]]]:
    """Import every non-blank line: ``(counts, refusals)``, counts keyed ``(kind, status)`` and
    ``"refused"``, refusals ``(line number, reason)``.  A refused line does not stop the rest."""
    counts: Counter = Counter()
    refused: list[tuple[int, str]] = []
    for n, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            counts[import_line(store, line)] += 1
        except (ImportRefused, EventError) as exc:
            counts["refused"] += 1
            refused.append((n, str(exc).splitlines()[0]))
    return counts, refused


__all__ = [
    "EXPORT_SCHEMA",
    "STATUSES",
    "ImportRefused",
    "export_lines",
    "import_line",
    "import_lines",
]
