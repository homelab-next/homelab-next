# SPDX-License-Identifier: Apache-2.0
"""The one seam to the strategy records: what projects link to, and what the sync mirrors.

:func:`strategy_records` yields one :class:`StrategyRecord` per strategy record -- ``uid``,
``type`` (SO, OO, TO, TT, CCIR, FFIR, PIR, RFI, MOP, MOE), ``title``, ``parent_uid`` and
``links`` (``(relation, uid)`` pairs) -- plus what a mirror shows (the display ``id``, ``status``,
the prose ``text``).  Nothing else in :mod:`homelabnext.projects` reads the strategy tree.

**Today** it reads the current loader (:func:`homelabnext.strategy.load_tree`) and maps today's
ids to uids: a record that carries a ``uid`` field keeps it; one that does not gets
:func:`~.uid.derived_uid` of its id and date (stable across runs, so a sync keys it the same each
time).  Edges map as ``parent`` -> ``parent_uid``; ``supports`` and ``serves`` keep their names; a
measure's ``objective`` becomes ``measures``; an RFI's ``raised_by`` becomes ``raised_by``.

**When ADR-0019 lands** (UUIDv7 ``uid`` on every record, display numbers computed), point
:func:`strategy_records` at the new loader and drop the id mapping; callers do not change.  The
records' own ``uid`` wins over the derived one already, so a tree that carries uids needs no
change here at all -- but OpenProject items mirrored under a *derived* uid would be keyed anew:
mint each record's uid as ``derived_uid(NAMESPACE, id, date)`` in that migration, or re-key the
mirror once (``docs/projects.md``, "Identity").
"""

from __future__ import annotations

import datetime as dt
import pathlib
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from typing import Any

from .uid import derived_uid, is_uid

__all__ = ["NAMESPACE", "StrategyRecord", "record_uids", "strategy_records"]

NAMESPACE = "homelabnext:strategy"
#: the prose sections a mirror carries, by record directory (first one present wins first)
_TEXT = ("statement", "definition", "question", "decision_supported", "acceptance")
_EDGES = (("supports", "supports"), ("serves", "serves"), ("objective", "measures"))


@dataclass(frozen=True)
class StrategyRecord:
    uid: str
    type: str
    title: str
    parent_uid: str | None
    links: tuple[tuple[str, str], ...]  # (relation, target uid)
    id: str = ""  # today's display id (SO-001)
    status: str = ""
    text: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "uid": self.uid,
            "type": self.type,
            "title": self.title,
            "parent_uid": self.parent_uid,
            "links": [list(x) for x in self.links],
        }


def _type_of(ident: str, entry: Mapping[str, Any]) -> str:
    return str(entry.get("level") or ident.rsplit("-", 1)[0])


def _uid_of(ident: str, entry: Mapping[str, Any]) -> str:
    own = entry.get("uid")
    if is_uid(own):
        return str(own)
    when = entry.get("date")
    day = when if isinstance(when, dt.date) else dt.date.fromisoformat(str(when or "1970-01-01"))
    return derived_uid(NAMESPACE, ident, day)


def strategy_records(root: str | pathlib.Path) -> Iterator[StrategyRecord]:
    """Every strategy record under ``root`` (objectives, measures, requirements, RFIs), in id
    order; the strategy record itself is not one (it has no type in the cascade)."""
    from homelabnext.strategy import load_tree

    tree = load_tree(root)
    entries: dict[str, Mapping[str, Any]] = {}
    for kind, key, entry in tree.items():
        if kind != "strategy" and not key.endswith("-NEW") and "-NEW-" not in key:
            entries[key] = entry
    uids = {k: _uid_of(k, e) for k, e in entries.items()}
    for key in sorted(entries):
        e = entries[key]
        links: list[tuple[str, str]] = []
        for field, rel in _EDGES:
            vals = e.get(field)
            for v in [vals] if isinstance(vals, str) else vals or ():
                if str(v) in uids:
                    links.append((rel, uids[str(v)]))
        if e.get("raised_by") and str(e["raised_by"]) in uids:
            links.append(("raised_by", uids[str(e["raised_by"])]))
        parent = e.get("parent")
        text = next((str(e[s]).strip() for s in _TEXT if e.get(s)), "")
        yield StrategyRecord(
            uid=uids[key],
            type=_type_of(key, e),
            title=str(e.get("title") or key),
            parent_uid=uids.get(str(parent)) if parent else None,
            links=tuple(links),
            id=key,
            status=str(e.get("status") or ""),
            text=text,
        )


def record_uids(root: str | pathlib.Path | None):
    """A resolver for :class:`~.store.ProjectStore`: the uids of the records under ``root``
    (read at each call, so a new record is linkable at once); no root, no records."""

    def uids() -> tuple[str, ...]:
        return tuple(r.uid for r in strategy_records(root)) if root else ()

    return uids
