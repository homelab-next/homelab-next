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


#: Largest body a consumer parses: 1 MiB, the NATS default ``max_payload`` (the lab's
#: ``compose/lab-in-a-box/config/nats/nats.conf`` keeps the default), so no body the bus delivers is
#: refused for its size and a body nothing could have published is refused before it is parsed.
MAX_EVENT_BYTES = 1 << 20

#: Deepest nesting a consumer accepts, on every Python.  The parser's own stack is not a portable
#: limit: 3.11's C scanner gives up near 1,000 levels (the recursion limit less the caller's
#: depth), 3.12 and 3.13 parse 5,000 and refuse 20,000, and 3.14 parses 20,000, so the same body
#: was "not JSON" on one version and a schema failure on another.  256 sits far below where 3.11 gives up
#: whatever the caller's depth, and far above any event this platform defines.
MAX_JSON_DEPTH = 256


def parse_json(body: bytes | str) -> Any:
    """``body`` parsed as a consumer parses it: :class:`ValueError` (its message says why) for
    text that is not JSON, ``NaN``/``Infinity``, a number no float holds (``1e999``), an integer
    past Python's digit limit, or containers nested deeper than :data:`MAX_JSON_DEPTH` (never a
    :class:`RecursionError`).  It does not limit the size: :func:`decode_event` refuses a body
    over :data:`MAX_EVENT_BYTES` before it gets here."""
    value, _ = _parse(body)
    return value


def _parse(body: bytes | str) -> tuple[Any, bool]:
    """:func:`parse_json`, plus whether a string in the value holds a lone surrogate (one walk)."""
    try:
        value = json.loads(body, parse_constant=_no_constant, parse_float=_finite)
    except RecursionError:  # nested past 3.11's parser stack: past MAX_JSON_DEPTH too
        raise ValueError("nested too deeply") from None
    too_deep, surrogate = _scan(value, MAX_JSON_DEPTH)
    if too_deep:
        raise ValueError("nested too deeply")
    return value, surrogate


_SURROGATE = re.compile(r"[\ud800-\udfff]")


def _scan(value: Any, limit: int | None) -> tuple[bool, bool]:
    """``(too_deep, lone_surrogate)`` for ``value`` in one walk, without recursion: whether it
    nests containers deeper than ``limit`` (``None``: no limit), and whether a key or string
    anywhere holds a surrogate code point.  The parser joins an escaped pair (``\\ud83d\\ude00``)
    into one character, so what is left is a lone half (``\\ud800``): a ``str`` that no UTF-8
    encoder accepts, so a consumer that stored it fails later, wherever it writes it out (a
    page, a log).  The walk stops at the first container past the limit, so a deep body costs no
    more than ``limit`` levels of it."""
    surrogate = False
    search = _SURROGATE.search
    if isinstance(value, str):
        return False, search(value) is not None
    if not isinstance(value, dict | list):
        return False, False
    # one stack of containers and one of their depths: no per-child tuple or generator
    stack: list[Any] = [value]
    depths: list[int] = [1]
    while stack:
        v = stack.pop()
        depth = depths.pop()
        if limit is not None and depth > limit:
            return True, surrogate
        if isinstance(v, dict):
            if not surrogate:
                for k in v:
                    if search(k):
                        surrogate = True
                        break
            children = v.values()
        else:
            children = v
        for c in children:
            if isinstance(c, str):
                if not surrogate and search(c):
                    surrogate = True
            elif isinstance(c, dict | list):
                stack.append(c)
                depths.append(depth + 1)
    return False, surrogate


def decode_event(
    body: bytes | str | Mapping[str, Any], *, types: Iterable[str] | None = None
) -> dict[str, Any]:
    """Parse and validate a received event; raise :class:`EventError` on any defect.  ``NaN``,
    ``Infinity`` and a number too large for a float (``1e999``) are refused at the parse: Python's
    parser accepts them, a schema's ``minimum`` does not reject ``NaN``, and a consumer that kept
    one would emit invalid JSON (or ``nan`` in a page) downstream.  So is a string holding a lone
    surrogate (``"\\ud800"``), which is no Unicode text and fails whatever encodes it later.  A body
    given as a mapping gets the same refusals: the surrogate walk here, and a number that is not
    finite in :func:`~homelabnext.events.envelope.validate_event` (which a producer runs too)."""
    if isinstance(body, bytes | str):
        size = len(body)
        if size > MAX_EVENT_BYTES or (isinstance(body, str) and _utf8_len(body) > MAX_EVENT_BYTES):
            raise EventError(
                "event body is not JSON", [f"larger than MAX_EVENT_BYTES ({MAX_EVENT_BYTES} bytes)"]
            )
        try:
            event, surrogate = _parse(body)
        except ValueError as exc:
            raise EventError("event body is not JSON", [str(exc)]) from None
    else:
        event = dict(body)
        surrogate = _scan(event, None)[1]
    if not isinstance(event, dict):
        raise EventError("invalid event", ["event must be a JSON object"])
    if surrogate:
        raise EventError("invalid event", ["a string holds a lone surrogate (not Unicode text)"])
    validate_event(event)
    if types is not None:
        allowed = set(types)
        if event["type"] not in allowed:
            raise EventError(
                "unexpected event type", [f"{event['type']!r} not in {sorted(allowed)}"]
            )
    return event


def _utf8_len(text: str) -> int:
    """``text``'s length in UTF-8, a lone surrogate counted as the 3 bytes its escape decodes to."""
    return len(text.encode("utf-8", "surrogatepass"))


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
