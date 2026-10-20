# SPDX-License-Identifier: Apache-2.0
"""The one write path for register records, their sidecar events and system-page reviews.

:func:`write_record` and :func:`write_event` (and :func:`write_events`, the batch both build on)
validate BEFORE a byte is written, with the build's own fatal rules, against the register as it
will be: every record file of the directory, every sidecar event, the other register (links
resolve across lessons and runbooks), the invariants (``retired_by``) and the review policy
(identity rules: allowlist, no self-review, audit independence).  Invalid content raises
:class:`~homelabnext.registers.schema.RegisterError` and nothing is written.

One rule of the build is opt-in here: ``require_reviews=True`` also demands the review tiers
the policy names for the record's status.  It is off by default because a write that creates
review debt is the normal first half of a two-step change (edit the prose, then a reviewer
writes a review event of the new digest; a recurrence of a controlled pitfall, which should send
the control claim back to review), and refusing it would make the change impossible.  The build
(``hnx registers build``, ``make check``, CI) still fails while the debt is unpaid, and the
decider (:mod:`homelabnext.registers.decide`) checks the tiers itself before it applies a
transition.

Writes are atomic: a record replaces its file through a temp file and ``os.replace``; an event
is created exclusively under a fresh name (:func:`homelabnext.registers.events.create_event`).
A batch writes its events first and the record last, so a crash in between leaves duplicates a
re-run detects (the migration skips events that already exist), never a lost review.
``transition`` events are written only through the decider.
"""

from __future__ import annotations

import datetime as dt
import pathlib
from collections.abc import Iterable, Mapping
from typing import Any

from homelabnext.state import atomic_write_text

from . import events as ev
from .records import (
    RECORD_KINDS,
    _canonical,
    dir_events,
    load_texts,
    parse_record,
    read_dir,
    register_source,
    render_record,
)
from .schema import RegisterError, check_links, validate_lessons, validate_runbooks

__all__ = [
    "check_page",
    "check_register",
    "write_event",
    "write_events",
    "write_record",
    "write_register",
]

INLINE_EVENTS = ("reviews", "recurrences")  # the record file no longer carries these
_VALIDATE = {"lessons": validate_lessons, "runbooks": validate_runbooks}


def _now() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


def _policy(src: pathlib.Path, policy):
    if policy is not None:
        return None if policy is False else policy
    from homelabnext.reviews import ReviewError, load_policy

    from .render import find_policy

    pp = find_policy(src)
    try:
        return load_policy(pp) if pp else None
    except ReviewError as ex:
        raise RegisterError("review policy", ex.problems) from None


def _pending(record_path: pathlib.Path, new: Iterable[tuple[Mapping, dt.datetime]]):
    """The new events as :class:`Event` objects named as they will (at least) be named."""
    out = []
    for data, when in new:
        out.append(ev.Event(ev.event_name(data, when), dict(data), ev.stamp_of(when), 1 << 30))
    return out


def check_register(
    record_path,
    *,
    text: str | None = None,
    new_events: Iterable[tuple[Mapping, dt.datetime]] = (),
    require_reviews: bool = False,
    policy=None,
) -> dict[str, Any]:
    """Validate the register ``record_path`` lives in as it would be with ``text`` as the
    record's content and ``new_events`` appended; returns the record as it would load.

    ``policy``: a :class:`homelabnext.reviews.Policy`, ``False`` for none, or ``None`` to use
    ``review-policy.yml`` in or beside the register directory's parent (like the build).
    """
    p = pathlib.Path(record_path)
    d, kind = p.parent, p.parent.name
    if kind not in RECORD_KINDS:
        raise RegisterError(kind, [f"{p}: a record lives in a lessons/ or runbooks/ directory"])
    texts, problems = read_dir(d) if d.is_dir() else ({}, [])
    if text is not None:
        texts[p.name] = text
    if p.name not in texts:
        problems.append(f"{p.name}: no such record file")
    events = dir_events(d, problems) if d.is_dir() else {}
    pending = _pending(p, new_events)
    if pending:
        events[p.name] = sorted([*events.get(p.name, []), *pending], key=ev.Event.sort_key)
    if problems:
        raise RegisterError(kind, problems)
    doc = _check_dir(d, texts, events, require_reviews=require_reviews, policy=policy)
    return next((e for e in doc[kind] if _file_of(e, p.name)), {})


def _check_dir(
    d: pathlib.Path,
    texts: Mapping[str, str],
    events: Mapping[str, list[ev.Event]],
    *,
    require_reviews: bool,
    policy,
    check_refs: bool = True,
) -> dict:
    """The build's rules over one record directory as it will be (texts and events in memory),
    resolving references against its sibling registers on disk."""
    from .records import load_register
    from .render import repo_root

    kind = d.name
    doc = load_texts(texts, kind, events)
    src = d.parent
    _VALIDATE[kind](doc, _policy(src, policy), require_reviews=require_reviews)
    if not check_refs:
        return doc
    regs = {kind: doc[kind]}
    for other in RECORD_KINDS:
        if other != kind and (path := register_source(src, other)):
            regs[other] = load_register(path, other)[other]
    criteria = None
    if (src / "invariants.yml").is_file():
        inv = load_register(src / "invariants.yml") or {}
        criteria = {str(c.get("id")) for c in inv.get("criteria") or () if isinstance(c, dict)}
    check_links(regs.get("lessons", []), regs.get("runbooks", []), criteria, repo_root(src))
    return doc


def write_register(
    d,
    files: Mapping[str, tuple[Mapping[str, Any], list[tuple[Mapping[str, Any], dt.datetime]]]],
    *,
    check_refs: bool = True,
    policy=None,
) -> list[pathlib.Path]:
    """Write a whole record directory ``d`` (which must be empty or missing): ``files`` maps a
    record file name to (its entry, its events).  Validated as one register before anything is
    written.  ``check_refs=False`` skips resolving references into sibling registers, for a
    conversion into a fresh directory that has none (the build still resolves them)."""
    d = pathlib.Path(d)
    kind = d.name
    if kind not in RECORD_KINDS:
        raise RegisterError(kind, [f"{d}: not a lessons/ or runbooks/ record directory"])
    if d.exists() and any(d.iterdir()):
        raise RegisterError(kind, [f"{d} exists and is not empty"])
    problems: list[str] = []
    texts, events = {}, {}
    for name, (entry, evs) in files.items():
        bad = [k for k in (*INLINE_EVENTS, *ev.DERIVED_ONLY) if k in entry]
        if bad:
            problems.append(f"{name}: {', '.join(bad)} are derived from events")
        for data, _ in evs:
            problems += ev.check_event(data)
        texts[name] = render_record(dict(entry), kind)
        events[name] = sorted(
            [ev.Event(ev.event_name(x, w), dict(x), ev.stamp_of(w), 1) for x, w in evs],
            key=ev.Event.sort_key,
        )
    if problems:
        raise RegisterError(kind, problems)
    _check_dir(d, texts, events, require_reviews=False, policy=policy, check_refs=check_refs)
    d.mkdir(parents=True, exist_ok=True)
    written = []
    for name, (_, evs) in files.items():
        written += [ev.create_event(ev.events_dir(d / name), x, when=w) for x, w in evs]
        written.append(atomic_write_text(d / name, texts[name], mode=ev.FILE_MODE))
    return written


def _file_of(entry: Mapping, name: str) -> bool:
    ident = str(entry.get("id"))
    return name == f"{ident}.md" or (ident.endswith("-NEW") and name.startswith(ident))


def check_page(
    page_path,
    *,
    text: str | None = None,
    new_events: Iterable[tuple[Mapping, dt.datetime]] = (),
    policy=None,
) -> None:
    """Validate a docs/systems page's reviews (inline plus sidecar events plus ``new_events``):
    the review identity rules, and the policy's tiers when the page claims ``reviewed``."""
    import yaml

    from homelabnext.reviews import evaluate, load_policy, missing_message
    from homelabnext.sop.pages import FRONT_RE, page_digest

    from .render import repo_root

    p = pathlib.Path(page_path)
    text = p.read_text(encoding="utf-8") if text is None else text
    m = FRONT_RE.match(text)
    fm = yaml.safe_load(m["fm"]) if m else None
    if not isinstance(fm, dict) or fm.get("type") != "system":
        raise RegisterError("system page", [f"{p.name}: not a docs/systems page"])
    problems: list[str] = []
    events = ev.read_events(ev.events_dir(p), problems, p.name) + _pending(p, new_events)
    entry = ev.derive(fm, events, "system-page", problems, p.name)
    if policy is None:
        pp = repo_root(p.parent) / "examples" / "review-policy.yml"
        policy = load_policy(pp) if pp.is_file() else None
    status = fm.get("status", "draft")
    digest = page_digest(text)
    res = evaluate(
        entry.get("reviews"),
        author=fm.get("author"),
        digest=digest,
        artefact="system-page",
        state=status if status in ("draft", "reviewed") else "draft",
        policy=policy or None,
        who=p.name,
    )
    problems += res.problems
    if status == "reviewed" and res.missing:
        problems.append(missing_message(p.name, status, res, digest))
    if problems:
        raise RegisterError("system page", problems)


def _is_register_record(p: pathlib.Path) -> bool:
    return p.parent.name in RECORD_KINDS


def write_events(
    record_path,
    events: Iterable[Mapping[str, Any] | tuple[Mapping[str, Any], dt.datetime]],
    *,
    record_text: str | None = None,
    when: dt.datetime | None = None,
    require_reviews: bool = False,
    policy=None,
    _decider: bool = False,
) -> list[pathlib.Path]:
    """Validate, then append ``events`` to ``record_path``'s sidecar (and, with
    ``record_text``, replace the record file last).  Each item is an event mapping (written at
    ``when``, default now) or an ``(event, time)`` pair.  Returns the files written."""
    p = pathlib.Path(record_path)
    at = when or _now()
    pairs = [(dict(x[0]), x[1]) if isinstance(x, tuple) else (dict(x), at) for x in events]
    problems = []
    for data, _ in pairs:
        problems += ev.check_event(data)
        if data.get("event") == "transition" and not _decider:
            problems.append(
                "a transition event is written only by the decider (`hnx registers decide`);"
                " file a register-transition intent in the records inbox instead"
            )
    if problems:
        raise RegisterError(p.parent.name or "events", problems)
    if _is_register_record(p):
        check_register(
            p,
            text=record_text,
            new_events=pairs,
            require_reviews=require_reviews,
            policy=policy,
        )
    else:
        check_page(p, text=record_text, new_events=pairs, policy=policy)
    written = [ev.create_event(ev.events_dir(p), data, when=t) for data, t in pairs]
    if record_text is not None:
        written.append(atomic_write_text(p, record_text, mode=_mode(p)))
    return written


def _mode(p: pathlib.Path) -> int:
    try:
        return p.stat().st_mode & 0o7777
    except FileNotFoundError:
        return ev.FILE_MODE


def write_event(record_path, event: Mapping[str, Any], **kw) -> pathlib.Path:
    """Validate one event against the register as it will be, then create its file."""
    return write_events(record_path, [event], **kw)[0]


_ABSENT = object()


def _base_of(p: pathlib.Path, doc: Mapping[str, Any], kind: str) -> dict[str, Any]:
    """``doc`` with every field that ``p``'s sidecar events contribute (reviews, the recurrences
    count, last_verified, a transition's status and ``set`` fields) put back to the record
    file's own value, or dropped where the file has none.  Such a field changed in ``doc`` is
    refused: it is written as an event, or through the decider."""
    out = dict(doc)
    if not p.is_file():
        return out
    problems: list[str] = []
    base = parse_record(p.read_text(), p.name, kind, problems)
    events = ev.read_events(ev.events_dir(p), problems, p.name)
    if problems or base is None or "retired" in base:
        return out  # the register check names what is wrong with the file on disk
    derived = ev.derive(base, events, kind, problems, p.name)
    derived = _canonical({kind: [derived]}, kind)[kind][0]
    changed = []
    for k in sorted(set(derived) | set(base)):
        now = derived.get(k, _ABSENT)
        if now == base.get(k, _ABSENT) or k not in out:
            continue  # not derived, or not given
        if out[k] != now:
            changed.append(k)
        elif k in base:
            out[k] = base[k]
        else:
            del out[k]
    if changed:
        raise RegisterError(
            kind,
            [
                f"{p.name}: {', '.join(changed)} are derived from events (reviews, recurrences,"
                " verified runs, transitions); write events or file a transition intent instead"
            ],
        )
    return out


def write_record(
    path, doc: Mapping[str, Any], *, require_reviews: bool = False, policy=None
) -> pathlib.Path:
    """Validate the record ``doc`` (front-matter fields and prose fields, as
    :func:`homelabnext.registers.load_register` returns an entry) in its register, then write
    ``path`` atomically in the canonical record form.  What the record's events derive (reviews,
    recurrences, last_verified, a transition's status and fields) is put back to the base record
    first, so load -> edit the prose -> write round-trips; changing a derived field is refused:
    reviews and recurrences are events (:func:`write_event`), the status changes through the
    decider."""
    p = pathlib.Path(path)
    kind = p.parent.name
    if kind not in RECORD_KINDS:
        raise RegisterError(kind, [f"{p}: a record lives in a lessons/ or runbooks/ directory"])
    doc = _base_of(p, doc, kind)
    bad = [k for k in (*INLINE_EVENTS, *ev.DERIVED_ONLY) if k in doc]
    if bad:
        raise RegisterError(
            kind, [f"{p.name}: {', '.join(bad)} are derived from events; write events instead"]
        )
    text = render_record(dict(doc), kind)
    check_register(p, text=text, require_reviews=require_reviews, policy=policy)
    return atomic_write_text(p, text, mode=_mode(p))
