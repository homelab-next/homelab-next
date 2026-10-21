# SPDX-License-Identifier: Apache-2.0
"""Display numbers: computed at render time from type, parent and sibling order, never stored.

A record stores its ``uid``, its ``type``, its ``parent`` (a uid, where the type has a
hierarchy) and optionally an ``order`` (a number, the sort key among its siblings).  Its number
is its position among its *siblings* -- the records of the same type with the same parent --
appended to its parent's number::

    SO 1            SO 2
      OO 1.1          OO 2.1
        TO 1.1.1        MOE 2.1.1   (the first MOE of OO 2.1)
    PIR 1           PIR 2
                      PIR 2.1       (a PIR whose parent is PIR 2)
    LL 1  LL 2  ...  (a register: one flat sibling group)

Siblings sort by ``order`` (ascending) and then by uid -- a UUIDv7 sorts in creation order --
so a record without an ``order`` lands after every ordered sibling, in the order it was
created.  Inserting, reordering or re-parenting a record changes the numbers that are *shown*;
no record, link or file name changes, because nothing refers to a number.

Numbers are a view: two renders of the same files give the same numbers, and a number printed
yesterday may name another record today.  Refer to a record by its uid; show its number.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from .types import label_prefix

__all__ = ["Node", "label_map", "node_of", "number_map", "order_problems", "sibling_key"]


@dataclass(frozen=True)
class Node:
    uid: str
    type: str
    parent: str | None = None
    order: float | None = None


def node_of(entry: Mapping[str, Any]) -> Node:
    """A record entry (as loaded) -> its numbering node."""
    order = entry.get("order")
    num = order if isinstance(order, int | float) and not isinstance(order, bool) else None
    parent = entry.get("parent")
    return Node(str(entry.get("uid")), str(entry.get("type")), str(parent) if parent else None, num)


def sibling_key(n: Node) -> tuple[bool, float, str]:
    """Ordered siblings first (by ``order``), then the rest; ties and the rest by uid."""
    return (n.order is None, n.order if n.order is not None else 0.0, n.uid)


def number_map(nodes: Iterable[Node]) -> dict[str, str]:
    """uid -> its number (``2.1``).  A parent that is not among ``nodes`` (or a cycle) shows as
    ``?``: the validation reports it; the number never hides it."""
    nodes = list(nodes)
    by_uid = {n.uid: n for n in nodes}
    groups: dict[tuple[str, str | None], list[Node]] = {}
    for n in nodes:
        groups.setdefault((n.type, n.parent), []).append(n)
    pos: dict[str, int] = {}
    for members in groups.values():
        for i, n in enumerate(sorted(members, key=sibling_key), 1):
            pos[n.uid] = i
    out: dict[str, str] = {}

    def number(uid: str, seen: frozenset[str]) -> str:
        if uid in out:
            return out[uid]
        n = by_uid[uid]
        if n.parent is None:
            got = str(pos[uid])
        elif n.parent in seen or n.parent not in by_uid:
            got = f"?.{pos[uid]}"
        else:
            got = f"{number(n.parent, seen | {uid})}.{pos[uid]}"
        out[uid] = got
        return got

    for n in nodes:
        number(n.uid, frozenset({n.uid}))
    return out


def label_map(nodes: Iterable[Node]) -> dict[str, str]:
    """uid -> its display label (``PIR 2.1``, ``LL 3``)."""
    nodes = list(nodes)
    nums = number_map(nodes)
    return {n.uid: f"{label_prefix(n.type)} {nums[n.uid]}" for n in nodes}


def order_problems(nodes: Iterable[Node], who: Mapping[str, str] | None = None) -> list[str]:
    """Siblings that share an ``order`` value (two records cannot hold one place)."""
    seen: dict[tuple[str, str | None, float], str] = {}
    out = []
    for n in sorted(nodes, key=lambda n: n.uid):
        if n.order is None:
            continue
        key = (n.type, n.parent, float(n.order))
        name = (who or {}).get(n.uid, n.uid)
        if key in seen:
            other = (who or {}).get(seen[key], seen[key])
            out.append(f"{name}: order {n.order:g} is also the order of its sibling {other}")
        else:
            seen[key] = n.uid
    return out
