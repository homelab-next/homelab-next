# SPDX-License-Identifier: Apache-2.0
"""The strategy tree on disk: one record per file, read and written with the registers' code.

::

    <root>/strategy.md            the one strategy record (``type: strategy``)
    <root>/doctrine.yml           the doctrine policy (:mod:`.doctrine`)
    <root>/objectives/SO-001.md   SO / OO / TO / TT
    <root>/measures/MOE-001.md    MOP / MOE (readings are ``value`` events in MOE-001.events/)
    <root>/requirements/PIR-001.md   CCIR / FFIR / PIR
    <root>/rfis/RFI-001.md

Each file is parsed by :func:`homelabnext.registers.records.parse_record` (front-matter fields,
``## Heading`` prose sections, the generated ``## Links`` block) and its sidecar events are
applied by :func:`homelabnext.registers.events.derive` (reviews, values, transitions), exactly
like a lesson.  Ids are allocated by ``hnx ids`` (``SO-NEW`` until merged) and guarded by
``check-lost``: the four directories are registers of :data:`homelabnext.registers.ids.SPECS`.

Writes go through :func:`write_events` and :func:`write_new_record`: the whole tree is validated
as it will be (:func:`homelabnext.strategy.rules.validate`) before a byte is written.
"""

from __future__ import annotations

import datetime as dt
import pathlib
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from typing import Any

import yaml

from homelabnext.registers import events as ev
from homelabnext.registers.ids import RECORD_SUFFIX, SPECS
from homelabnext.registers.records import parse_record, read_dir
from homelabnext.registers.schema import RegisterError, record_digest_of
from homelabnext.reviews import content_digest
from homelabnext.state import atomic_write_text

__all__ = [
    "ARTEFACT",
    "DIRS",
    "STRATEGY_FILE",
    "Tree",
    "definition_digest",
    "dir_for",
    "file_digest",
    "load_tree",
    "record_digest",
    "write_events",
    "write_new_record",
]

STRATEGY_FILE = "strategy.md"
DOCTRINE_FILE = "doctrine.yml"
#: record directory -> the review-policy artefact kind (homelabnext.reviews.ARTEFACT_STATES)
ARTEFACT = {
    "strategy": "strategy",
    "objectives": "objective",
    "measures": "measure",
    "requirements": "requirement",
    "rfis": "rfi",
}
DIRS = ("objectives", "measures", "requirements", "rfis")
_PREFIX_DIR = {p: d for d in DIRS for p in SPECS[d].prefixes}


def dir_for(ident: str) -> str | None:
    """``PIR-003`` -> ``requirements`` (None for an id no strategy directory holds)."""
    return _PREFIX_DIR.get(str(ident).rsplit("-", 1)[0])


@dataclass
class Tree:
    """A loaded strategy tree: every record as the validators see it (events applied).

    ``records[dir]`` maps a record's key (its id; a placeholder's file stem, since several
    ``RFI-NEW-<slug>.md`` may coexist) to its entry; ``paths`` maps the key to its file."""

    root: pathlib.Path
    strategy: dict[str, Any] | None = None
    records: dict[str, dict[str, dict[str, Any]]] = field(default_factory=dict)
    paths: dict[str, pathlib.Path] = field(default_factory=dict)
    retired: dict[str, dict[str, Any]] = field(default_factory=dict)  # tombstones by id

    def of(self, kind: str) -> dict[str, dict[str, Any]]:
        return self.records.get(kind, {})

    def get(self, ident: str) -> dict[str, Any] | None:
        kind = dir_for(ident)
        return self.of(kind).get(str(ident)) if kind else None

    def items(self) -> Iterator[tuple[str, str, dict[str, Any]]]:
        """(directory, key, entry) of every record, the strategy first (directory ``strategy``)."""
        if self.strategy is not None:
            yield "strategy", "strategy", self.strategy
        for kind in DIRS:
            for key, entry in self.of(kind).items():
                yield kind, key, entry


def _key(name: str, entry: Mapping[str, Any]) -> str:
    ident = str(entry.get("id"))
    return name[: -len(RECORD_SUFFIX)] if ident.endswith("-NEW") else ident


def load_tree(
    root,
    *,
    texts: Mapping[str, str] | None = None,
    new_events: Mapping[str, Iterable[tuple[Mapping[str, Any], dt.datetime]]] | None = None,
) -> Tree:
    """Read the tree at ``root`` (fatal on an unparseable record or event).

    ``texts`` replaces or adds record files (``{"rfis/RFI-NEW-x.md": text}``) and
    ``new_events`` appends events (``{"rfis/RFI-001.md": [(event, time)]}``), both in memory:
    the tree as it would be after a write, which is what the write path validates."""
    root = pathlib.Path(root)
    texts = dict(texts or {})
    pending = {k: list(v) for k, v in (new_events or {}).items()}
    tree, problems = Tree(root), []

    def events_of(rel: str, path: pathlib.Path) -> list[ev.Event]:
        out = ev.read_events(ev.events_dir(path), problems, rel)
        for data, when in pending.pop(rel, ()):
            out.append(ev.Event(ev.event_name(data, when), dict(data), ev.stamp_of(when), 1 << 30))
        return sorted(out, key=ev.Event.sort_key)

    spath = root / STRATEGY_FILE
    stext = texts.pop(STRATEGY_FILE, None) or (
        spath.read_text("utf-8") if spath.is_file() else None
    )
    if stext is not None:
        entry = parse_record(stext, STRATEGY_FILE, "strategy", problems)
        if entry is not None:
            tree.strategy = ev.derive(entry, events_of(STRATEGY_FILE, spath), "strategy", problems)
            tree.paths["strategy"] = spath
    for kind in DIRS:
        d = root / kind
        found, bad = read_dir(d) if d.is_dir() else ({}, [])
        problems += [f"{kind}/{p}" for p in bad]
        for rel in [r for r in texts if r.startswith(f"{kind}/")]:
            found[rel.split("/", 1)[1]] = texts.pop(rel)
        if d.is_dir():
            orphans = {
                p.name[: -len(ev.EVENTS_SUFFIX)] + RECORD_SUFFIX
                for p in d.iterdir()
                if ev.is_events_dir(p)
            } - set(found)
            problems += [f"{kind}/{n}: an events directory without its record" for n in orphans]
        recs: dict[str, dict[str, Any]] = {}
        for name in sorted(found):
            rel = f"{kind}/{name}"
            entry = parse_record(found[name], name, kind, problems)
            if entry is None:
                continue
            if "retired" in entry:  # a tombstone: an id that must never be reused
                tree.retired[str(entry.get("id"))] = entry["retired"]
                continue
            key = _key(name, entry)
            if key in recs:
                problems.append(f"{rel}: id {key} is also the id of {tree.paths[key].name}")
                continue
            recs[key] = ev.derive(entry, events_of(rel, d / name), kind, problems, rel)
            tree.paths[key] = d / name
        tree.records[kind] = recs
    problems += [f"{rel}: no such record" for rel in [*texts, *pending]]
    if problems:
        raise RegisterError("strategy", problems)
    return tree


# --- digests -------------------------------------------------------------------------------------


def record_digest(entry: Mapping[str, Any]) -> str:
    """The content digest a review carries: the registers' digest (no id, reviews or verified
    stamps) without the readings either, so recording a value never makes a review stale."""
    return record_digest_of({k: v for k, v in entry.items() if k != "values"})


def definition_digest(measure: Mapping[str, Any]) -> str:
    """What a measure *is*: its definition, source binding and unit.  A trend is only drawn
    between readings taken under the same digest (the target is a grade, not the definition)."""
    return content_digest(
        {k: str(measure.get(k) or "").strip() for k in ("definition", "source", "unit")}
    )


def _front(text: str) -> dict | None:
    if not text.startswith("---"):
        return None
    try:
        fm = yaml.safe_load(text.split("\n---", 1)[0][3:])
    except yaml.YAMLError:
        return None
    return fm if isinstance(fm, dict) else None


def file_digest(path, text: str | None = None) -> str | None:
    """``hnx reviews digest`` for a strategy record file, or None when ``path`` is not one (a
    record in objectives/, measures/, requirements/ or rfis/, or a ``type: strategy`` file)."""
    p = pathlib.Path(path)
    text = p.read_text(encoding="utf-8") if text is None else text
    kind = p.parent.name
    if kind not in DIRS:
        fm = _front(text)
        if not (fm and fm.get("type") == "strategy"):
            return None
        kind = "strategy"
    problems: list[str] = []
    entry = parse_record(text, p.name, kind, problems)
    events = ev.read_events(ev.events_dir(p), problems, p.name)
    if entry is not None and not problems:
        entry = ev.derive(entry, events, kind, problems, p.name)
    if problems or entry is None:
        raise RegisterError(kind, problems or [f"{p.name}: not a record"])
    return record_digest(entry)


# --- the write path ------------------------------------------------------------------------------


def _check(root: pathlib.Path, **kw) -> Tree:
    """The tree as it will be, validated with the build's rules (review tiers aside: an edit
    or a closing transition may create review debt that a later review event pays; the check
    still fails until it is paid, and the decider checks tiers before it applies anything)."""
    from .rules import validate

    tree = load_tree(root, **kw)
    report = validate(tree, require_reviews=False)
    if report.errors:
        raise RegisterError("strategy", report.errors)
    return tree


def _rel(root: pathlib.Path, path) -> str:
    return pathlib.Path(path).resolve().relative_to(root.resolve()).as_posix()


def write_events(
    root,
    batch: Mapping[Any, Iterable[tuple[Mapping[str, Any], dt.datetime]]],
    *,
    _decider: bool = False,
) -> list[pathlib.Path]:
    """Validate the tree with every event of ``batch`` (record path -> [(event, time)])
    appended, then create the event files (exclusively; never an overwrite).  A ``transition``
    is written only by a decider.  Nothing is written when anything is invalid."""
    root = pathlib.Path(root)
    pairs = {_rel(root, p): [(dict(d), w) for d, w in evs] for p, evs in batch.items()}
    problems = [p for evs in pairs.values() for d, _ in evs for p in ev.check_event(d)]
    if not _decider and any(d.get("event") == "transition" for e in pairs.values() for d, _ in e):
        problems.append(
            "a transition event is written only by the decider (`hnx strategy decide`); file a"
            " strategy-transition intent in the records inbox instead"
        )
    if problems:
        raise RegisterError("strategy", problems)
    _check(root, new_events=pairs)
    out = []
    for rel, evs in pairs.items():
        d = ev.events_dir(root / rel)
        out += [ev.create_event(d, data, when=when) for data, when in evs]
    return out


def write_new_record(root, rel: str, text: str) -> pathlib.Path:
    """Validate the tree with the new record file ``rel`` (``rfis/RFI-NEW-<slug>.md``), then
    create it exclusively."""
    root = pathlib.Path(root)
    if (root / rel).exists():
        raise RegisterError("strategy", [f"{rel} exists; a new record never overwrites one"])
    _check(root, texts={rel: text})
    (root / rel).parent.mkdir(parents=True, exist_ok=True)
    return atomic_write_text(root / rel, text, exclusive=True, mode=ev.FILE_MODE)
