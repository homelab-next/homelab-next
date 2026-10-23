# SPDX-License-Identifier: Apache-2.0
"""Build and validate the CloudEvents-shaped envelope.

Validation uses the shipped schemas: ``schemas/events/envelope.schema.json`` for every event, plus
``schemas/events/<type>.schema.json`` when the event type has one (``homelabnext.task.queued`` ->
``task.queued``).  An event of a type without a schema is checked against the envelope only.

The ``id`` is the idempotency key.  :func:`derive_event_id` makes it a pure function of the
event's *identity* (type, source, subject and a caller-supplied dedupe key), never of the clock or
a random number, so the same logical occurrence always carries the same id.
"""

from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from homelabnext import paths

_VALIDATORS: dict[str, Any] = {}
_LOADED: set[str] = set()  # the schema files load_validator has built and resolved


class EventError(ValueError):
    """The event is not valid.  ``problems`` lists every defect found."""

    def __init__(self, message: str, problems: list[str] | None = None):
        self.problems = list(problems or [])
        super().__init__(message + "".join(f"\n  - {p}" for p in self.problems))


def _events_dir() -> Path:
    return paths.schemas_dir() / "events"


def schema_for_type(event_type: str) -> Path | None:
    """The per-type schema file for ``homelabnext.<a>.<b>``, or None when there is none."""
    prefix = "homelabnext."
    if not isinstance(event_type, str) or not event_type.startswith(prefix):
        return None
    p = _events_dir() / f"{event_type[len(prefix) :]}.schema.json"
    return p if p.is_file() else None


def _registry():
    from referencing import Registry, Resource
    from referencing.jsonschema import DRAFT202012

    reg: Registry = Registry()
    for p in sorted(paths.schemas_dir().rglob("*.json")):
        if "_frozen" in p.parts or p.parent.name in ("examples", "negative"):
            continue
        d = json.loads(p.read_text(encoding="utf-8"))
        if isinstance(d, dict) and "$id" in d:
            reg = reg.with_resource(
                d["$id"], Resource.from_contents(d, default_specification=DRAFT202012)
            )
    return reg


def _validator(path: Path):
    key = str(path)
    if key not in _VALIDATORS:
        from jsonschema import Draft202012Validator

        schema = json.loads(path.read_text(encoding="utf-8"))
        _VALIDATORS[key] = Draft202012Validator(schema, registry=_registry())
    return _VALIDATORS[key]


def load_validator(event_type: str) -> None:
    """Build the validator events of ``event_type`` are checked with, and resolve every ``$ref``
    it can reach, so an environment fault raises here, once, and not on the first event checked:
    a missing ``jsonschema``/``referencing`` (:class:`ImportError`), a schema file that is not
    JSON (:class:`ValueError`), a ``$ref`` that resolves to nothing
    (:class:`referencing.exceptions.Unresolvable`).  A consumer calls it before its first
    delivery, so it can tell those from a defect of the event it is checking."""
    path = schema_for_type(event_type) or (_events_dir() / "envelope.schema.json")
    if str(path) in _LOADED:
        return
    schema = _validator(path).schema
    seen: set[int] = set()
    todo = [(schema, _registry().resolver(base_uri=schema.get("$id", "")))]
    while todo:
        node, resolver = todo.pop()
        if isinstance(node, list):
            todo.extend((n, resolver) for n in node)
        elif isinstance(node, dict):
            if isinstance(node.get("$ref"), str):
                hit = resolver.lookup(node["$ref"])
                if id(hit.contents) not in seen:
                    seen.add(id(hit.contents))
                    todo.append((hit.contents, hit.resolver))
            todo.extend((v, resolver) for k, v in node.items() if k != "$ref")
    _LOADED.add(str(path))


def _non_finite(value: Any) -> list[str]:
    """Where ``value`` holds a float that is not finite (``NaN``, ``Infinity``): none is JSON, a
    schema's ``minimum`` does not reject ``NaN``, and every consumer refuses them on the wire.
    Walked without recursion (a body may be nested as deep as a parser allows)."""
    out: list[str] = []
    stack: list[tuple[str, Any]] = [("", value)]
    while stack and len(out) < 20:
        where, v = stack.pop()
        if isinstance(v, float) and not math.isfinite(v):
            out.append(f"{where or '$'}: not a finite number ({v!r} is not JSON)")
        elif isinstance(v, Mapping):
            stack.extend((f"{where}/{k}".lstrip("/"), x) for k, x in v.items())
        elif isinstance(v, list | tuple):
            stack.extend((f"{where}/{i}".lstrip("/"), x) for i, x in enumerate(v))
    return sorted(out)


def event_problems(event: Any) -> list[str]:
    """Every schema problem of ``event`` (empty list = valid), and every number in it that is not
    finite."""
    if not isinstance(event, Mapping):
        return ["event must be a JSON object"]
    if bad := _non_finite(event):
        return bad  # the schema validator cannot reason about NaN
    path = schema_for_type(event.get("type", "")) or (_events_dir() / "envelope.schema.json")
    out = []
    for err in sorted(
        _validator(path).iter_errors(dict(event)), key=lambda e: [str(p) for p in e.absolute_path]
    ):
        where = "/".join(str(p) for p in err.absolute_path) or "$"
        out.append(f"{where}: {err.message[:200]}")
    return out


def validate_event(event: Any) -> None:
    """Raise :class:`EventError` unless ``event`` satisfies the envelope and its type schema."""
    problems = event_problems(event)
    if problems:
        raise EventError("invalid event", problems)


def derive_event_id(
    event_type: str, source: str, dedupe_key: str, *, subject: str | None = None
) -> str:
    """A stable id from the event's identity.  Same inputs, same id, on every host and run."""
    if not dedupe_key:
        raise ValueError("dedupe_key must be non-empty")
    material = json.dumps(
        [event_type, source, subject or "", dedupe_key], separators=(",", ":"), ensure_ascii=True
    )
    return "evt-" + hashlib.sha256(material.encode("utf-8")).hexdigest()[:32]


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_event(
    event_type: str,
    source: str,
    data: Mapping[str, Any],
    *,
    id: str | None = None,
    dedupe_key: str | None = None,
    time: str | None = None,
    subject: str | None = None,
    severity: str | None = None,
    correlationid: str | None = None,
    dataschema: str | None = None,
    validate: bool = True,
) -> dict[str, Any]:
    """Build an envelope.  Give ``id`` or ``dedupe_key`` (a derived id); one of them is required.

    ``time`` defaults to now (UTC); pass it explicitly for a reproducible event.
    """
    if (id is None) == (dedupe_key is None):
        raise ValueError("give exactly one of id= or dedupe_key=")
    ev: dict[str, Any] = {
        "specversion": "1.0",
        "id": id
        if id is not None
        else derive_event_id(event_type, source, dedupe_key, subject=subject),  # type: ignore[arg-type]
        "source": source,
        "type": event_type,
        "time": time or _now(),
    }
    for k, v in (
        ("subject", subject),
        ("severity", severity),
        ("correlationid", correlationid),
        ("dataschema", dataschema),
    ):
        if v is not None:
            ev[k] = v
    ev["data"] = dict(data)
    if validate:
        validate_event(ev)
    return ev


def canonical_body(event: Mapping[str, Any]) -> bytes:
    """The deterministic wire form (sorted keys, no whitespace); :class:`ValueError` for a number
    that is not finite, which is not JSON (``NaN``, ``Infinity``)."""
    return json.dumps(
        event, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode()


def body_digest(event: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_body(event)).hexdigest()
