# SPDX-License-Identifier: Apache-2.0
"""Append-only sidecar events: the machine-mutated state of a record, one file per event.

A record file (``lessons/<uid>.md``, ``docs/systems/dns.md``) holds what people write: prose and
stable fields.  Everything that several writers append to over time lives beside it, in
``<RECORD>.events/`` (``lessons/<uid>.events/``), one small YAML file per event::

    20261019T093000Z-review-agent-example-checker.yml
    20261019T093000Z-review-agent-example-checker-2.yml     # same second, same writer
    20261020T120000Z-recurrence-agent-example-checker.yml

The name is ``<UTC YYYYMMDDTHHMMSSZ>-<event>-<actor slug>[-<n>].yml``; :func:`create_event`
creates it exclusively (a hard link that fails when the name exists, never an overwrite) and
takes the next ``-<n>`` when the name is taken, so two writers never collide and never touch the
same file.  Events are never edited: a correction is a new event.

Kinds (``schemas/registers/register_event.schema.json``):

``review``      the review entry of :mod:`homelabnext.reviews` (``by kind role date verdict digest
                note``); the event without its ``event`` key *is* the review.
``recurrence``  the pitfall happened again (``date``, ``note``, ``evidence``).
``verified``    the record's observable was run (``outcome: pass|fail``, ``result``).
``transition``  an applied lifecycle change (``from``, ``to``, ``set``, the intent it applied);
                written only by the decider (:mod:`homelabnext.registers.decide`).
``value``       one reading of a strategy measure (``homelabnext.strategy``): ``value`` (or a
                ``finding`` when there is none), ``observed_at``, ``sample``, the
                ``definition_digest`` / ``definition_version`` it was read under, ``evidence``.
``rekey``       the record's content digest changed without its content changing (``from`` ->
                ``to``, ``reason``): written only by the uid migration (``by: hnx:migrate``),
                which rewrote numbered references as uids.  Every review recorded before it
                whose digest was ``from`` counts for ``to``, so the identity rewrite does not
                send every reviewed record back to review; a later edit still does.

:func:`derive` computes the derived fields on load, so the document every consumer sees keeps
its shape: ``reviews`` (inline reviews, then review events in order, each carried across any
later ``rekey`` whose ``from`` it reviewed), ``recurrences`` (the inline
base, 0 when absent, plus one per recurrence event; pitfalls only), ``last_verified`` (the latest
passing ``verified`` event; never written by hand), ``values`` (a measure's readings, in order;
never written by hand), and the current status (the record's base
status with every transition applied in order; a transition whose ``from`` is not the status at
that point is fatal).  Derived values are never edited in place.
"""

from __future__ import annotations

import datetime as dt
import itertools
import json
import pathlib
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from functools import cache
from typing import Any

import yaml

from homelabnext._yaml import UniqueKeyLoader
from homelabnext.state import atomic_write_text

__all__ = [
    "DERIVED_ONLY",
    "EVENTS_SUFFIX",
    "EVENT_KINDS",
    "Event",
    "actor_slug",
    "backfill",
    "check_event",
    "create_event",
    "current_status",
    "derive",
    "event_name",
    "events_dir",
    "read_events",
    "render_event",
]

EVENT_KINDS = ("review", "recurrence", "verified", "transition", "value", "rekey")
EVENTS_SUFFIX = ".events"
DERIVED_ONLY = ("last_verified", "values")  # computed from events; a record file never has them
#: registers whose records have a lifecycle (every event kind); any other caller is a system page
LIFECYCLE_REGISTERS = (
    *("lessons", "runbooks"),
    *("strategy", "objectives", "measures", "requirements", "rfis"),
)
HEADER = "# SPDX-License-Identifier: Apache-2.0\n"
FILE_MODE = 0o644  # register files are committed documents, not secrets
BACKFILL_BY = "hnx:migrate"
_NAME = re.compile(
    r"^(?P<ts>\d{8}T\d{6}Z)-(?P<event>[a-z]+)-(?P<rest>[a-z0-9]+(?:-[a-z0-9]+)*)\.yml$"
)
_ORDER = ("event", "by", "kind", "role", "date", "verdict", "digest", "outcome", "result")
_ORDER += ("from", "to", "set", "intent", "requested_by", "reason")
_ORDER += ("value", "finding", "observed_at", "sample", "definition_digest", "definition_version")
_ORDER += ("evidence", "note")


@dataclass(frozen=True)
class Event:
    name: str
    data: dict[str, Any]
    stamp: str
    seq: int

    @property
    def kind(self) -> str:
        return str(self.data.get("event"))

    def sort_key(self) -> tuple[str, int, str]:
        return (self.stamp, self.seq, self.name)


def events_dir(record_path) -> pathlib.Path:
    """``lessons/<uid>.md`` -> ``lessons/<uid>.events``."""
    p = pathlib.Path(record_path)
    return p.with_name(p.stem + EVENTS_SUFFIX)


def actor_slug(by) -> str:
    """``agent:example-checker`` -> ``agent-example-checker`` (the writer part of a name)."""
    return re.sub(r"[^a-z0-9]+", "-", str(by).lower()).strip("-") or "unknown"


def stamp_of(when: dt.datetime) -> str:
    if when.tzinfo is None:
        raise ValueError("event times are timezone-aware (UTC)")
    return when.astimezone(dt.UTC).strftime("%Y%m%dT%H%M%SZ")


def event_name(data: Mapping[str, Any], when: dt.datetime, n: int = 1) -> str:
    seq = f"-{n}" if n > 1 else ""
    return f"{stamp_of(when)}-{data.get('event')}-{actor_slug(data.get('by'))}{seq}.yml"


def _name_parts(name: str, data: Mapping[str, Any]) -> tuple[str, int] | str:
    """(stamp, sequence) of a well-formed name for ``data``, else the problem."""
    m = _NAME.match(name)
    if not m:
        return f"{name}: an event file is named <YYYYMMDDTHHMMSSZ>-<event>-<actor>[-<n>].yml"
    try:
        dt.datetime.strptime(m["ts"], "%Y%m%dT%H%M%SZ")
    except ValueError:
        return f"{name}: {m['ts']} is not a UTC time"
    if m["event"] != data.get("event"):
        return f"{name}: the name says {m['event']} but the file is a {data.get('event')} event"
    actor = actor_slug(data.get("by"))
    rest = m["rest"]
    if rest == actor:
        return m["ts"], 1
    if rest.startswith(actor + "-") and re.fullmatch(r"[1-9]\d*", rest[len(actor) + 1 :]):
        n = int(rest[len(actor) + 1 :])
        if n >= 2:
            return m["ts"], n
    return f"{name}: the name's writer part must be {actor!r} (from `by`), optionally -<n>"


@cache
def schema_validator(family: str, name: str):
    """A Draft 2020-12 validator for ``schemas/<family>/<name>`` with the shared ``ids`` schemas
    registered (what every register and strategy schema ``$ref``s)."""
    from jsonschema import Draft202012Validator
    from referencing import Registry, Resource
    from referencing.jsonschema import DRAFT202012

    from homelabnext import paths

    base = paths.schemas_dir()
    reg = Registry()
    for f in sorted((base / "ids").glob("*.json")):
        doc = json.loads(f.read_text(encoding="utf-8"))
        reg = reg.with_resource(
            doc["$id"], Resource.from_contents(doc, default_specification=DRAFT202012)
        )
    schema = json.loads(paths.schema_file(family, name).read_text("utf-8"))
    return Draft202012Validator(schema, registry=reg)


def _validator():
    return schema_validator("registers", "register_event.schema.json")


def _iso(v) -> str:
    """A date or a datetime (an unquoted YAML timestamp) as its ISO text, anything else as str."""
    return v.isoformat() if isinstance(v, dt.date) else str(v)


def check_event(data, name: str | None = None) -> list[str]:
    """Every problem with one event (its schema and, given ``name``, the file name rule)."""
    if not isinstance(data, dict):
        return [f"{name or 'event'}: must be a mapping"]
    plain = json.loads(json.dumps(data, default=_iso))  # dates as ISO strings, as JSON has them
    where = f"{name}: " if name else ""
    out = [
        f"{where}{'/'.join(map(str, e.absolute_path)) or '$'}: {e.message}"
        for e in sorted(
            _validator().iter_errors(plain), key=lambda e: list(map(str, e.absolute_path))
        )
    ]
    if name is not None and not out:
        parts = _name_parts(name, data)
        if isinstance(parts, str):
            out.append(parts)
    return out


class _Dumper(yaml.SafeDumper):
    def ignore_aliases(self, data):
        return True


def render_event(data: Mapping[str, Any]) -> str:
    keys = [k for k in _ORDER if k in data] + sorted(k for k in data if k not in _ORDER)
    body = yaml.dump(
        {k: data[k] for k in keys}, Dumper=_Dumper, sort_keys=False, allow_unicode=True, width=100
    )
    return HEADER + body


def read_events(d, problems: list[str], who: str = "") -> list[Event]:
    """Every event of the sidecar directory ``d`` in order (time, then sequence, then name);
    problems are appended.  A missing directory has no events."""
    d = pathlib.Path(d)
    if not d.is_dir():
        return []
    pre = f"{who}: " if who else ""
    out = []
    for f in sorted(d.iterdir()):
        if f.name.startswith("."):
            continue  # an in-flight temp file of a writer
        if not f.is_file() or f.suffix != ".yml":
            problems.append(f"{pre}{d.name}/{f.name}: an events directory holds *.yml files only")
            continue
        try:
            data = yaml.load(f.read_text(encoding="utf-8"), Loader=UniqueKeyLoader)
        except yaml.YAMLError as ex:  # a duplicate key too: the reader and the file would differ
            problems.append(f"{pre}{d.name}/{f.name}: not YAML ({ex})".replace("\n", " "))
            continue
        bad = check_event(data, f.name)
        if bad:
            problems += [f"{pre}{d.name}/{p}" for p in bad]
            continue
        stamp, seq = _name_parts(f.name, data)  # type: ignore[misc]
        out.append(Event(f.name, data, stamp, seq))
    return sorted(out, key=Event.sort_key)


def create_event(d, data: Mapping[str, Any], *, when: dt.datetime) -> pathlib.Path:
    """Write one event file into ``d`` under a fresh name; never overwrites.

    The caller validates first (:func:`homelabnext.registers.write.write_event`).  The name takes
    the next free ``-<n>`` when another writer got the same second first.
    """
    d = pathlib.Path(d)
    d.mkdir(parents=True, exist_ok=True)
    text = render_event(data)
    for n in itertools.count(1):
        target = d / event_name(data, when, n)
        try:
            return atomic_write_text(target, text, exclusive=True, mode=FILE_MODE)
        except FileExistsError:
            continue
    raise AssertionError("unreachable")  # pragma: no cover


# --- derivation ----------------------------------------------------------------------------------


def current_status(entry: Mapping[str, Any], register: str) -> str | None:
    """A lesson's ``status``; a runbook is ``superseded`` once it names ``superseded_by``."""
    if register == "runbooks":
        return "superseded" if entry.get("superseded_by") else "active"
    s = entry.get("status")
    return str(s) if s is not None else None


def apply_transition(entry: dict[str, Any], data: Mapping[str, Any], register: str) -> None:
    entry.update(dict(data.get("set") or {}))
    if register != "runbooks":
        entry["status"] = data["to"]


def derive(
    entry: Mapping[str, Any],
    events: Iterable[Event],
    register: str,
    problems: list[str],
    who: str = "",
) -> dict[str, Any]:
    """``entry`` (a record as written) with its derived fields computed from ``events``."""
    out = dict(entry)
    pre = f"{who}: " if who else ""
    events = list(events)
    for f in DERIVED_ONLY:
        if f in entry:
            problems.append(f"{pre}`{f}` is derived from events; never write it")
    reviews: list[dict[str, Any]] = []
    for e in events:
        if e.kind == "review":
            reviews.append({k: v for k, v in e.data.items() if k != "event"})
        elif e.kind == "rekey":
            reviews = [_rekeyed(r, e.data) for r in reviews]
    rekeys = [e.data for e in events if e.kind == "rekey"]
    if reviews or (rekeys and entry.get("reviews")):
        inline = entry.get("reviews")
        if isinstance(inline, list):  # the older inline form: reviewed before any event
            for rk in rekeys:
                inline = [_rekeyed(r, rk) for r in inline]
            entry = {**entry, "reviews": inline}
        inline = entry.get("reviews")
        if inline is not None and not isinstance(inline, list):
            problems.append(f"{pre}`reviews` must be a list")
        else:
            out["reviews"] = list(inline or []) + reviews
    pitfall = register == "lessons" and entry.get("kind") == "pitfall"
    rec = [e for e in events if e.kind == "recurrence"]
    if rec and not pitfall:
        problems.append(f"{pre}recurrence events belong to a pitfall")
    if pitfall:
        base = entry.get("recurrences", 0)
        if isinstance(base, int) and not isinstance(base, bool):
            out["recurrences"] = base + len(rec)
    passed = [
        e.data["date"] for e in events if e.kind == "verified" and e.data["outcome"] == "pass"
    ]
    if passed:
        out["last_verified"] = max(passed, key=str)
    values = [
        {k: v for k, v in e.data.items() if k != "event"} for e in events if e.kind == "value"
    ]
    if values and register != "measures":
        problems.append(f"{pre}value events belong to a measure")
    elif values:
        out["values"] = values
    if register not in LIFECYCLE_REGISTERS and any(e.kind != "review" for e in events):
        problems.append(f"{pre}a system page has review events only")
    for e in events:
        if e.kind != "transition":
            continue
        cur = current_status(out, register)
        if e.data["from"] != cur:
            problems.append(
                f"{pre}transition {e.name} is from {e.data['from']} but the record is {cur} at "
                "that point (delete the event, or restore the base status it was applied to)"
            )
            break
        apply_transition(out, e.data, register)
        if current_status(out, register) != e.data["to"]:
            problems.append(f"{pre}transition {e.name} does not reach {e.data['to']}")
            break
    return out


def _rekeyed(review: Any, rekey: Mapping[str, Any]) -> Any:
    """``review`` carried across one ``rekey``: a review of ``from`` (its digest a prefix of
    it, as :func:`homelabnext.reviews.evaluate` compares) now reviews ``to``."""
    if not isinstance(review, dict):
        return review
    d = review.get("digest")
    if isinstance(d, str) and d and str(rekey.get("from", "")).startswith(d):
        return {**review, "digest": rekey["to"]}
    return review


# --- backfill (the migration of inline state into events) ----------------------------------------


def _at(day) -> dt.datetime:
    d = day if isinstance(day, dt.date) else dt.date.fromisoformat(str(day))
    return dt.datetime(d.year, d.month, d.day, tzinfo=dt.UTC)


def backfill(
    entry: Mapping[str, Any], register: str
) -> tuple[dict[str, Any], list[tuple[dict[str, Any], dt.datetime]]]:
    """Split a record's inline ``reviews`` / ``recurrences`` (and a joined file's
    ``last_verified``) into (the record without them,
    [(event, time)]).  Deterministic, and order-keeping: a review's time is midnight of its date,
    pushed one second past the previous review's when that is not later (so the events load in
    the list's order); the recurrences take the record's date the same way."""
    rest = dict(entry)
    out: list[tuple[dict[str, Any], dt.datetime]] = []

    def chain(days) -> list[dt.datetime]:
        times: list[dt.datetime] = []
        for day in days:
            t = _at(day)
            if times and t <= times[-1]:
                t = times[-1] + dt.timedelta(seconds=1)
            times.append(t)
        return times

    reviews = rest.pop("reviews", None) or []
    for r, t in zip(reviews, chain(r.get("date") for r in reviews), strict=True):
        out.append(({"event": "review", **r}, t))
    if register == "lessons" and entry.get("kind") == "pitfall" and "recurrences" in rest:
        count = rest.pop("recurrences")
        n = count if isinstance(count, int) and not isinstance(count, bool) else 0
        author = entry.get("author")
        by = author if isinstance(author, str) and ":" in author else BACKFILL_BY
        ev = {
            "event": "recurrence",
            "by": by,
            "date": entry.get("date"),
            "note": "backfilled from the inline recurrences count (its dates were not kept)",
        }
        out += [(dict(ev), t) for t in chain([entry.get("date")] * n)]
    if "last_verified" in rest:  # a joined (single-file) register carries it inline
        day = rest.pop("last_verified")
        result = "carried over from an inline last_verified (the run's output was not kept)"
        ev = {"event": "verified", "by": BACKFILL_BY, "date": day, "outcome": "pass"}
        out.append(({**ev, "result": result}, _at(day)))
    return rest, out


def same_event(a: Mapping[str, Any], b: Mapping[str, Any]) -> bool:
    return json.dumps(a, sort_keys=True, default=str) == json.dumps(b, sort_keys=True, default=str)


def is_events_dir(p: pathlib.Path) -> bool:
    return p.is_dir() and p.name.endswith(EVENTS_SUFFIX) and not p.name.startswith(".")
