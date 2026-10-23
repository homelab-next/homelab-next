# SPDX-License-Identifier: Apache-2.0
"""Export and import of the telemetry store in a neutral format (JSON lines), so a store can be
moved to another host, rebuilt, or carried across a swap of its upstreams.

``homelabnext.orchestration.export/1``: one JSON object per line, each with ``schema`` and
``kind``, the first a header naming the store it came from (an import does not need it, and
reads it only to explain a job refused for its source)::

    {"schema": "homelabnext.orchestration.export/1", "kind": "header",
     "sources": ["svc:..."], "retention_days": 90, "exported_at": "<ISO>"}
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

from conformance.protocols.inference import turn_problems
from homelabnext.events.consumer import parse_json
from homelabnext.events.envelope import EventError
from homelabnext.status.model import iso, parse_iso

from .store import FUTURE_S, TelemetryStore

EXPORT_SCHEMA = "homelabnext.orchestration.export/1"
#: what an import counts, per kind
STATUSES = ("processed", "duplicate", "expired")


_HEADER = {"schema", "kind", "sources", "retention_days", "exported_at"}


def _is_sources(v: Any) -> bool:
    return isinstance(v, list) and all(isinstance(s, str) for s in v)


class ImportRefused(ValueError):
    """One line of an export that cannot be imported (the reason is the message)."""


def export_lines(store: TelemetryStore, refusable: Counter | None = None) -> Iterator[str]:
    """The store as export lines (see the module docstring), without line ends: the header,
    then the records.  ``refusable``, when given, counts the records written that an import
    would refuse, by kind (``"job"``: kept without its envelope by a store before exports;
    ``"turn"``: not a neutral turn record, such as one written before a field was renamed)."""
    header = {
        "schema": EXPORT_SCHEMA,
        "kind": "header",
        "sources": list(store.sources),
        "retention_days": store.retention_s / 86400,
        "exported_at": iso(store.clock()),
    }
    yield json.dumps(header, sort_keys=True)
    for kind, item in store.dump():
        if kind == "job":
            event, settled = item
            rec: dict[str, Any] = {
                "event": event,
                "turns_settled_at": None if settled is None else iso(settled),
            }
            bad = not isinstance(event, Mapping)
        else:
            rec = {"turn": item}
            bad = bool(turn_problems(item))
        if bad and refusable is not None:
            refusable[kind] += 1
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
    if kind == "header" and set(rec) == _HEADER and _is_sources(rec["sources"]):
        return "header", "read"
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
        if settled > store.clock() + FUTURE_S:
            raise ImportRefused(f"turns_settled_at is in the future ({settled_at[:40]})")
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
    if started is not None and started > store.clock() + FUTURE_S:
        raise ImportRefused(f"started_at is in the future ({turn['started_at'][:40]})")
    tag = turn.get("gateway_tag")
    if isinstance(tag, str) and not store.holds_tag(tag):
        raise ImportRefused(
            f"no job holds gateway tag {tag[:80]!r}: a turn is imported after its job"
        )
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
    ``"refused"``, refusals ``(line number, reason)``.  A refused line does not stop the rest.
    The header, when there is one, is the first line; it is not counted, and when it names other
    sources than the store's, a job refused for its source says so."""
    counts: Counter = Counter()
    refused: list[tuple[int, str]] = []
    hint, first = "", True
    for n, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            got = import_line(store, line)
            if got[0] == "header":
                if not first:
                    raise ImportRefused("a header is the first line of an export")
                hint = _source_hint(json.loads(line)["sources"], store.sources)
            else:
                counts[got] += 1
        except (ImportRefused, EventError) as exc:
            counts["refused"] += 1
            why = str(exc).splitlines()[0]
            if hint and why.startswith("not the controller's job record"):
                why += f" ({hint})"
            refused.append((n, why))
        first = False
    return counts, refused


def _source_hint(theirs: list[str], ours: tuple[str, ...]) -> str:
    if set(theirs) == set(ours):
        return ""
    return (
        f"the export's store took {', '.join(theirs)[:200]}; this store takes "
        f"{', '.join(ours)}: import with the same --source"
    )


__all__ = [
    "EXPORT_SCHEMA",
    "FUTURE_S",
    "STATUSES",
    "ImportRefused",
    "export_lines",
    "import_line",
    "import_lines",
]
