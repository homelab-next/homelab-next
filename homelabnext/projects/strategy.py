# SPDX-License-Identifier: Apache-2.0
"""The one seam to the strategy records: what projects link to, and what the sync mirrors.

:func:`strategy_records` yields one :class:`StrategyRecord` per strategy record -- ``uid``,
``type`` (SO, OO, TO, TT, CCIR, FFIR, PIR, RFI, MOP, MOE), ``title``, ``parent_uid`` and
``links`` (``(relation, uid)`` pairs) -- plus what a mirror shows: the display ``label``
(``OO 1.2``, computed by :mod:`homelabnext.identity` from type, parent and order, never stored),
``status`` and the prose ``text``.  Nothing else in :mod:`homelabnext.projects` reads the
strategy tree.

It reads :func:`homelabnext.strategy.load_tree` (ADR-0019: every record is ``<uid>.md`` with
``uid``, ``type``, ``parent``, ``order`` and links by uid).  ``parent`` is the cascade (an
objective's parent objective, a measure's objective, a requirement's parent requirement);
``supports`` and ``serves`` keep their names and an RFI's ``raised_by`` becomes ``raised_by``.

:func:`resolve_record` turns what a person types into a uid: a uid, a display label
(``OO 1.1``) or a legacy code (``OO-001``, through ``aliases.yml`` with a deprecation warning).
"""

from __future__ import annotations

import pathlib
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from typing import Any

from homelabnext.identity import is_uid

__all__ = ["StrategyRecord", "record_uids", "resolve_record", "strategy_records"]

#: the prose sections a mirror carries (the first one present)
_TEXT = ("statement", "definition", "question", "decision_supported", "acceptance")
_EDGES = (("supports", "supports"), ("serves", "serves"), ("raised_by", "raised_by"))


@dataclass(frozen=True)
class StrategyRecord:
    uid: str
    type: str
    title: str
    parent_uid: str | None
    links: tuple[tuple[str, str], ...]  # (relation, target uid)
    label: str = ""  # the computed display number (``OO 1.2``): shown, never stored
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


def _uids(value: Any) -> list[str]:
    vals = [value] if isinstance(value, str) else list(value or ())
    return [str(v) for v in vals if is_uid(str(v))]


def strategy_records(root: str | pathlib.Path) -> Iterator[StrategyRecord]:
    """Every strategy record under ``root`` (objectives, measures, requirements, RFIs) in
    display-number order; the strategy record itself is not one (it has no type in the cascade)."""
    from homelabnext.strategy import load_tree

    tree = load_tree(root)
    for kind, uid, e in tree.items():
        if kind == "strategy" or not is_uid(uid):
            continue
        links = [(rel, t) for field, rel in _EDGES for t in _uids(e.get(field))]
        parent = e.get("parent")
        yield StrategyRecord(
            uid=uid,
            type=str(e.get("type") or ""),
            title=str(e.get("title") or uid),
            parent_uid=str(parent) if parent and is_uid(str(parent)) else None,
            links=tuple(links),
            label=tree.label(uid),
            status=str(e.get("status") or ""),
            text=next((str(e[s]).strip() for s in _TEXT if e.get(s)), ""),
        )


def resolve_record(
    ref: str, root: str | pathlib.Path, records: Iterable[StrategyRecord] | None = None
) -> str:
    """A record's uid from a uid, its display label (``OO 1.1``, any spacing) or a legacy code
    (``aliases.yml``, with a deprecation warning); anything else comes back unchanged."""
    from homelabnext.identity.aliases import load_aliases, resolve

    if is_uid(ref):
        return ref
    want = " ".join(str(ref).split())
    for r in records if records is not None else strategy_records(root):
        if r.label == want:
            return r.uid
    return resolve(ref, load_aliases(root), "hnx projects")


def record_uids(root: str | pathlib.Path | None):
    """A resolver for :class:`~.store.ProjectStore`: the uids of the records under ``root``
    (read at each call, so a new record is linkable at once); no root, no records."""

    def uids() -> tuple[str, ...]:
        return tuple(r.uid for r in strategy_records(root)) if root else ()

    return uids
