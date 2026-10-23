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
import math
import re
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from .envelope import EventError, body_digest, validate_event

Handler = Callable[[dict[str, Any]], None]


def _no_constant(name: str) -> Any:
    raise ValueError(f"{name} is not a JSON number")


def _finite(text: str) -> float:
    value = float(text)
    if not math.isfinite(value):  # 1e999: JSON, but no number a consumer can compute or re-emit
        raise ValueError(f"{text} is not a finite number")
    return value


_SURROGATE = re.compile(r"[\ud800-\udfff]")


def _has_lone_surrogate(value: Any) -> bool:
    """True when a key or string anywhere in ``value`` holds a surrogate code point.  The parser
    joins an escaped pair (``\\ud83d\\ude00``) into one character, so what is left is a lone
    half (``\\ud800``): a ``str`` that no UTF-8 encoder accepts, so a consumer that stored it
    fails later, wherever it writes it out (a page, a log).  Walked without recursion: the body
    parsed, so it may be nested as deep as the parser's own stack."""
    stack = [value]
    while stack:
        v = stack.pop()
        if isinstance(v, str):
            if _SURROGATE.search(v):
                return True
        elif isinstance(v, dict):
            stack.extend(v.keys())
            stack.extend(v.values())
        elif isinstance(v, list):
            stack.extend(v)
    return False


def decode_event(
    body: bytes | str | Mapping[str, Any], *, types: Iterable[str] | None = None
) -> dict[str, Any]:
    """Parse and validate a received event; raise :class:`EventError` on any defect.  ``NaN``,
    ``Infinity`` and a number too large for a float (``1e999``) are refused at the parse: Python's
    parser accepts them, a schema's ``minimum`` does not reject ``NaN``, and a consumer that kept
    one would emit invalid JSON (or ``nan`` in a page) downstream.  So is a string holding a lone
    surrogate (``"\\ud800"``), which is no Unicode text and fails whatever encodes it later."""
    if isinstance(body, bytes | str):
        try:
            event = json.loads(body, parse_constant=_no_constant, parse_float=_finite)
        except ValueError as exc:
            raise EventError("event body is not JSON", [str(exc)]) from None
        except RecursionError:  # nested deeper than the parser's stack: never a valid envelope
            raise EventError("event body is not JSON", ["nested too deeply"]) from None
    else:
        event = dict(body)
    if not isinstance(event, dict):
        raise EventError("invalid event", ["event must be a JSON object"])
    if _has_lone_surrogate(event):
        raise EventError("invalid event", ["a string holds a lone surrogate (not Unicode text)"])
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
