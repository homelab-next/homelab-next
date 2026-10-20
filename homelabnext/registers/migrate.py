# SPDX-License-Identifier: Apache-2.0
"""``hnx registers events migrate``: move inline machine state into sidecar events, losslessly.

For every record of a record directory (``lessons/``, ``runbooks/``) the inline ``reviews:`` and
``recurrences:`` front-matter keys become event files in ``<id>.events/``
(:func:`homelabnext.registers.events.backfill`) and are removed from the record; for every page
of a ``docs/systems/`` directory the ``reviews:`` key does.  Lossless or not at all: the whole
directory is converted in memory first and must load to a document deep-equal to the one
before (every derived field, every review digest unchanged), or nothing is written.  The keys
are cut out of the front-matter text, so the rest of each file stays byte-for-byte.

Re-running is safe: events that already exist (a crash between writing the events and the
record) are not written twice, and a record without inline state is left alone.
"""

from __future__ import annotations

import pathlib
import re
from collections.abc import Mapping

from . import events as ev
from .records import RECORD_KINDS, _diff, dir_events, load_texts, parse_record, read_dir
from .schema import RegisterError

__all__ = ["migrate", "migrate_pages", "migrate_records", "strip_keys"]

_TOP_KEY = re.compile(r"^[A-Za-z_][\w-]*:")
_FRONT = re.compile(r"\A---\n(?P<fm>.*?\n)---[ \t]*(?:\n|\Z)", re.S)


def strip_keys(text: str, keys) -> str:
    """``text`` with the top-level front-matter ``keys`` (and their block values) removed."""
    m = _FRONT.match(text)
    if not m:
        return text
    out, skip = [], False
    for line in m["fm"].splitlines(keepends=True):
        if _TOP_KEY.match(line):
            skip = line.split(":", 1)[0] in keys
        if not skip:
            out.append(line)
    return "---\n" + "".join(out) + text[m.end("fm") :]


def _split_done(planned, existing: list[ev.Event]):
    """(the planned events not on disk yet, the events on disk that are not planned): a
    multiset difference both ways, so an interrupted run's events are neither lost nor doubled."""
    left = list(existing)
    todo = []
    for data, when in planned:
        hit = next((i for i, x in enumerate(left) if ev.same_event(x.data, data)), None)
        if hit is None:
            todo.append((data, when))
        else:
            left.pop(hit)
    return todo, left


def _new_only(planned, existing: list[ev.Event]):
    return _split_done(planned, existing)[0]


def migrate_records(d) -> list[pathlib.Path]:
    from .write import write_events

    d = pathlib.Path(d)
    kind = d.name
    if kind not in RECORD_KINDS:
        raise RegisterError(kind, [f"{d}: not a lessons/ or runbooks/ record directory"])
    texts, problems = read_dir(d)
    on_disk = dir_events(d, problems)
    if problems:
        raise RegisterError(kind, problems)
    plan: dict[str, tuple[str, list]] = {}
    unmatched = {n: list(v) for n, v in on_disk.items()}  # events not from an earlier attempt
    for name, text in sorted(texts.items()):
        rec = parse_record(text, name, kind, problems)
        if rec is None or "retired" in rec:
            continue
        keys = [k for k in ("reviews", "recurrences") if k in rec]
        if not keys:
            continue
        _, planned = ev.backfill(rec, kind)
        new, unmatched[name] = _split_done(planned, on_disk.get(name, []))
        plan[name] = (strip_keys(text, keys), new)
    if problems:
        raise RegisterError(kind, problems)
    # what the register said before any attempt: the inline state plus the events that are not
    # copies of it (an interrupted earlier run wrote some of those)
    before = load_texts(texts, kind, unmatched)
    if not plan:
        return []
    after_texts = {**texts, **{n: t for n, (t, _) in plan.items()}}
    after_events = {n: list(v) for n, v in on_disk.items()}
    for name, (_, new) in plan.items():
        pending = [ev.Event(ev.event_name(x, w), x, ev.stamp_of(w), 1) for x, w in new]
        after_events[name] = sorted([*after_events.get(name, []), *pending], key=ev.Event.sort_key)
    after = load_texts(after_texts, kind, after_events)
    if diff := _diff(before, after):
        raise RegisterError(kind, [f"the migration would change the loaded register ({diff})"])
    written: list[pathlib.Path] = []
    for name, (text, new) in plan.items():
        written += write_events(d / name, new, record_text=text, policy=False)
    return written


def migrate_pages(d) -> list[pathlib.Path]:
    """The ``reviews:`` of every docs/systems page into ``<service>.events/``."""
    import yaml

    from homelabnext.sop.pages import FRONT_RE, page_digest

    from .write import write_events

    d = pathlib.Path(d)
    written: list[pathlib.Path] = []
    plans = []
    for p in sorted(d.glob("*.md")):
        if p.name.startswith("_"):
            continue  # the template is the generator's skeleton, not a page
        text = p.read_text(encoding="utf-8")
        m = FRONT_RE.match(text)
        fm = yaml.safe_load(m["fm"]) if m else None
        if not isinstance(fm, Mapping) or fm.get("type") != "system" or "reviews" not in fm:
            continue
        _, planned = ev.backfill({"reviews": fm["reviews"]}, "system-page")
        problems: list[str] = []
        existing = ev.read_events(ev.events_dir(p), problems, p.name)
        if problems:
            raise RegisterError("system page", problems)
        new = _new_only(planned, existing)
        stripped = strip_keys(text, ("reviews",))
        if page_digest(stripped) != page_digest(text):
            raise RegisterError("system page", [f"{p.name}: the migration changed its digest"])
        pending = [ev.Event(ev.event_name(x, w), x, ev.stamp_of(w), 1) for x, w in new]
        fm_after = yaml.safe_load(FRONT_RE.match(stripped)["fm"])
        got = ev.derive(fm_after, [*existing, *pending], "system-page", problems, p.name)
        if list(got.get("reviews") or []) != list(fm["reviews"] or []):
            raise RegisterError("system page", [f"{p.name}: the reviews would not load back"])
        plans.append((p, stripped, new))
    for p, stripped, new in plans:
        written += write_events(p, new, record_text=stripped, policy=False)
    return written


def migrate(path) -> list[pathlib.Path]:
    """A record directory or a docs/systems page directory."""
    p = pathlib.Path(path)
    if p.name in RECORD_KINDS:
        return migrate_records(p)
    return migrate_pages(p)
