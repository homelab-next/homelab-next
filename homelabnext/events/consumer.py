# SPDX-License-Identifier: Apache-2.0
"""The consumer side of the event seam.

:func:`decode_event` is what every consumer runs on a received body before acting on it: parse
the structured-mode JSON, validate the envelope and the per-type schema, and (optionally) refuse
types it does not handle.  Extension attributes it does not know are kept and ignored, as
CloudEvents requires, so a publisher can add one without breaking consumers.

:class:`Consumer` dispatches by type and is idempotent by id, the mirror of the publisher: a
redelivered id is acknowledged as a duplicate without running the handler again, and the same id
with a different body is refused (an id collision, never "processed").
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from .envelope import EventError, body_digest, validate_event

Handler = Callable[[dict[str, Any]], None]


def decode_event(
    body: bytes | str | Mapping[str, Any], *, types: Iterable[str] | None = None
) -> dict[str, Any]:
    """Parse and validate a received event; raise :class:`EventError` on any defect."""
    if isinstance(body, bytes | str):
        try:
            event = json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise EventError("event body is not JSON", [str(exc)]) from None
    else:
        event = dict(body)
    if not isinstance(event, dict):
        raise EventError("invalid event", ["event must be a JSON object"])
    validate_event(event)
    if types is not None:
        allowed = set(types)
        if event["type"] not in allowed:
            raise EventError(
                "unexpected event type", [f"{event['type']!r} not in {sorted(allowed)}"]
            )
    return event


@dataclass(frozen=True)
class Delivery:
    id: str
    status: str  # processed | duplicate


class Consumer:
    """Type-dispatching, id-idempotent consumer.  ``seen`` maps id -> body digest."""

    def __init__(self, handlers: Mapping[str, Handler], seen: dict[str, str] | None = None):
        if not handlers:
            raise ValueError("a consumer needs at least one handler")
        self.handlers = dict(handlers)
        self.seen: dict[str, str] = seen if seen is not None else {}

    def handle(self, body: bytes | str | Mapping[str, Any]) -> Delivery:
        event = decode_event(body, types=self.handlers)
        eid, digest = event["id"], body_digest(event)
        prev = self.seen.get(eid)
        if prev is not None:
            if prev != digest:
                raise EventError(
                    "id reuse with a different body", [f"id {eid!r} was already consumed"]
                )
            return Delivery(eid, "duplicate")
        self.handlers[event["type"]](event)
        self.seen[eid] = digest  # only after the handler succeeded: a failure is redelivered
        return Delivery(eid, "processed")
