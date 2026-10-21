# SPDX-License-Identifier: Apache-2.0
"""Field checks and the board rules, shared by every backend of :class:`.store.ProjectStore`.

The board rules (``docs/projects.md``), each one a MUST of the conformance suite:

1. **Unique identities.** Every item has its own UUIDv7 ``uid``; an ``external_key`` names at
   most one item (a second create with it returns the first).
2. **A step belongs to an open project.** A step names an existing project; a step (or a task
   that names a project) cannot be created under, or reopened in, a closed project, and a
   project with an unfinished step or task cannot be closed.
3. **A finished project closes.** When the last unfinished step or task of a project with steps
   reaches ``done`` or ``cancelled``, the project closes in the same write; a project whose
   steps and tasks are all finished is never open, and it is not reopened (start a new one).

Plus link integrity: every link names a uid that resolves (an external record for
``supports``/``serves``/``measures``/``answers``, a step or task for ``blocks``/``precedes``),
never the item itself, and the dependency and parent graphs have no cycles.

:func:`board_problems` re-checks all of it over a whole store, for files a person edited by hand
(``hnx projects check``).
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Iterable, Mapping

from homelabnext.identity import is_uid

from .model import (
    ASSIGNEE_RE,
    DEPENDENCY_RELATIONS,
    ITEM_KINDS,
    ITEM_STATUSES,
    KINDS,
    LINK_RELATIONS,
    PROJECT_STATUSES,
    RELATIONS,
    TERMINAL,
    InvalidField,
    InvalidReference,
    WorkItem,
)

__all__ = [
    "board_problems",
    "check_assignee",
    "check_due",
    "check_external_key",
    "check_result",
    "check_title",
    "find_cycle",
    "steps_of",
    "unfinished_of",
]

MAX_TITLE = 200


def _line(value, what: str, limit: int) -> str:
    if not isinstance(value, str) or not value.strip():
        raise InvalidField(f"{what} must be a non-empty string")
    if "\n" in value or "\r" in value:
        raise InvalidField(f"{what} must be one line")
    if len(value) > limit:
        raise InvalidField(f"{what} is longer than {limit} characters")
    return value.strip()


def check_title(value) -> str:
    return _line(value, "title", MAX_TITLE)


def check_result(value) -> str:
    """The one-line result a finished item (or a closed project) carries."""
    return _line(value, "result", 500)


def check_external_key(value) -> str | None:
    return None if value is None else _line(value, "external_key", 200)


def check_assignee(value) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not ASSIGNEE_RE.match(value):
        raise InvalidField("assignee must be profile:<id>, human:<id> or agent:<id>")
    return value


def check_due(value) -> str | None:
    if value is None:
        return None
    if isinstance(value, dt.date) and not isinstance(value, dt.datetime):
        return value.isoformat()
    text = str(value)
    try:
        if len(text) == 10:
            return dt.date.fromisoformat(text).isoformat()
    except ValueError:
        pass
    raise InvalidField("due must be a date, YYYY-MM-DD")


def check_status(kind: str, status) -> str:
    allowed = PROJECT_STATUSES if kind == "project" else ITEM_STATUSES
    if status not in allowed:
        raise InvalidField(f"status of a {kind} must be one of {', '.join(allowed)}")
    return status


def steps_of(items: Iterable[WorkItem], project: str) -> list[WorkItem]:
    """The project's steps in order."""
    out = [i for i in items if i.kind == "step" and i.project == project]
    return sorted(out, key=lambda s: (s.order or 0, s.uid))


def unfinished_of(items: Iterable[WorkItem], project: str) -> list[WorkItem]:
    """The project's steps and tasks that have not finished (they hold the project open)."""
    return [
        i
        for i in items
        if i.kind in ITEM_KINDS and i.project == project and i.status not in TERMINAL
    ]


def find_cycle(edges: Mapping[str, Iterable[str]], start: str) -> list[str] | None:
    """A path from ``start`` back to itself following ``edges``, or None."""
    stack: list[tuple[str, list[str]]] = [(start, [start])]
    seen: set[str] = set()
    while stack:
        node, path = stack.pop()
        for nxt in edges.get(node, ()):
            if nxt == start:
                return [*path, nxt]
            if nxt not in seen:
                seen.add(nxt)
                stack.append((nxt, [*path, nxt]))
    return None


def dependency_edges(items: Iterable[WorkItem], relation: str) -> dict[str, list[str]]:
    return {i.uid: [lk.target for lk in i.links if lk.relation == relation] for i in items}


def parent_edges(items: Iterable[WorkItem]) -> dict[str, list[str]]:
    return {i.uid: [i.parent] for i in items if i.parent}


def check_link(
    item: WorkItem,
    target: str,
    relation: str,
    items: Mapping[str, WorkItem],
    records: frozenset[str],
) -> None:
    """Raise :class:`InvalidReference` unless ``item -relation-> target`` may exist."""
    if relation not in RELATIONS:
        raise InvalidReference(f"unknown relation {relation!r}; one of {', '.join(RELATIONS)}")
    if not isinstance(target, str) or not is_uid(target):
        raise InvalidReference("a link target is a uid (UUIDv7)")
    if target == item.uid:
        raise InvalidReference("an item cannot link to itself")
    if relation in LINK_RELATIONS:
        if target not in records:
            raise InvalidReference(f"{relation}: no external record with uid {target}")
        return
    other = items.get(target)
    if other is None or other.kind not in ITEM_KINDS or item.kind not in ITEM_KINDS:
        raise InvalidReference(f"{relation}: both ends must be existing steps or tasks")
    edges = dependency_edges(items.values(), relation)
    edges.setdefault(item.uid, []).append(target)
    if find_cycle(edges, item.uid):
        raise InvalidReference(f"{relation}: linking would make a cycle")


def check_parent(item: WorkItem, parent: str | None, items: Mapping[str, WorkItem]) -> None:
    if parent is None:
        return
    p = items.get(parent) if isinstance(parent, str) else None
    if p is None or p.kind not in ITEM_KINDS:
        raise InvalidReference("parent must be an existing step or task")
    if parent == item.uid:
        raise InvalidReference("an item cannot be its own parent")
    if p.project != item.project:
        raise InvalidReference("parent must be in the same project")
    edges = parent_edges(items.values())
    edges[item.uid] = [parent]
    if find_cycle(edges, item.uid):
        raise InvalidReference("parent would make a cycle")


def board_problems(items: Iterable[WorkItem], records: Iterable[str] | None = None) -> list[str]:
    """Every board-rule and link-integrity violation of a whole store (``records``: the external
    record uids links may name; None skips that check)."""
    items = list(items)
    by_uid: dict[str, WorkItem] = {}
    keys: dict[str, str] = {}
    out: list[str] = []
    for i in items:
        if not is_uid(i.uid):
            out.append(f"{i.uid}: the uid is not a UUIDv7")
        if i.uid in by_uid:
            out.append(f"{i.uid}: two items share this uid")
        by_uid[i.uid] = i
        if i.external_key:
            if i.external_key in keys:
                out.append(
                    f"{i.uid}: external_key {i.external_key!r} is also {keys[i.external_key]}"
                )
            keys.setdefault(i.external_key, i.uid)
        if i.kind not in KINDS:
            out.append(f"{i.uid}: unknown kind {i.kind!r}")
            continue
        allowed = PROJECT_STATUSES if i.kind == "project" else ITEM_STATUSES
        if i.status not in allowed:
            out.append(f"{i.uid}: status {i.status!r} is not a {i.kind} status")
        if i.status in TERMINAL and not (i.result and i.closed_on):
            out.append(f"{i.uid}: a finished {i.kind} needs a result and a date")
    recs = None if records is None else frozenset(records)
    for i in items:
        if i.kind == "step" or (i.kind == "task" and i.project):
            p = by_uid.get(i.project or "")
            if p is None or p.kind != "project":
                out.append(f"{i.uid}: {i.kind} names project {i.project}, which does not exist")
            elif p.status == "closed" and i.status not in TERMINAL:
                out.append(f"{i.uid}: unfinished {i.kind} in closed project {p.uid}")
        if i.kind == "project":
            steps = steps_of(items, i.uid)
            if steps and i.status == "open" and not unfinished_of(items, i.uid):
                out.append(
                    f"{i.uid}: every step and task is finished, so the project must be closed"
                )
        for lk in i.links:
            if lk.relation in LINK_RELATIONS:
                if recs is not None and lk.target not in recs:
                    out.append(f"{i.uid}: {lk.relation} {lk.target} resolves to no record")
            elif lk.relation in DEPENDENCY_RELATIONS:
                if lk.target not in by_uid:
                    out.append(f"{i.uid}: {lk.relation} {lk.target} resolves to no item")
            else:
                out.append(f"{i.uid}: unknown relation {lk.relation!r}")
        if i.parent and i.parent not in by_uid:
            out.append(f"{i.uid}: parent {i.parent} resolves to no item")
    for rel in DEPENDENCY_RELATIONS:
        edges = dependency_edges(items, rel)
        for uid in sorted(edges):
            if find_cycle(edges, uid):
                out.append(f"{uid}: {rel} links form a cycle")
                break
    edges = parent_edges(items)
    for uid in sorted(edges):
        if find_cycle(edges, uid):
            out.append(f"{uid}: parents form a cycle")
            break
    return out
