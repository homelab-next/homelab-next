# SPDX-License-Identifier: Apache-2.0
"""The project store: the contract's operations and board rules over a pluggable backend.

:class:`ProjectStore` holds every rule (:mod:`.rules`); a *backend* only stores items and reports
changes.  Three backends exist:

* :class:`MemoryBackend` -- in memory (the conformance fake);
* :class:`homelabnext.projects.markdown.MarkdownBackend` -- one ``<uid>.md`` per item (the
  reference implementation, ``hnx projects``);
* :class:`homelabnext.projects.openproject.backend.OpenProjectBackend` -- work packages in an
  OpenProject instance.

Each operation runs under the backend's lock: load the items, apply one change (and the
auto-close it may cause), then hand the new documents to ``backend.write`` with the versions
they were read at.  A backend refuses a write whose stored version moved since (another writer):
:class:`~.model.Conflict`, and nothing is written.

``records`` is the external-record resolver: a callable returning the uids links may name
(strategy records, :func:`homelabnext.projects.strategy.record_uids`).
"""

from __future__ import annotations

import contextlib
import copy
import dataclasses
import datetime as dt
import threading
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from typing import Any, Protocol

from homelabnext.identity import UidGenerator, is_uid

from . import rules
from .model import (
    KINDS,
    TERMINAL,
    UPDATABLE,
    Change,
    ChangeSet,
    Conflict,
    InvalidField,
    InvalidReference,
    InvalidTransition,
    Link,
    NotFound,
    WorkItem,
)

__all__ = [
    "Backend",
    "MemoryBackend",
    "ProjectStore",
    "doc_of",
    "item_of",
]

RULE_ACTOR = "hnx:projects"  # who a rule's own write (the auto-close) is recorded as


class Backend(Protocol):
    def lock(self) -> contextlib.AbstractContextManager[None]: ...

    def load(self) -> dict[str, dict[str, Any]]: ...

    def write(
        self, docs: Sequence[tuple[dict[str, Any], int | None]], changes: Sequence[Change]
    ) -> dict[str, dict[str, Any]]:
        """Store ``(document, version it was read at | None for a new item)`` pairs; raise
        Conflict when a stored version moved; return the stored documents by uid."""

    def changes(self, cursor: str | None) -> tuple[list[Change], str]: ...


def doc_of(item: WorkItem) -> dict[str, Any]:
    d = dataclasses.asdict(item)
    d.pop("extra", None)
    d["links"] = [{"relation": lk.relation, "target": lk.target} for lk in item.links]
    return d


def item_of(doc: Mapping[str, Any]) -> WorkItem:
    names = {f.name for f in dataclasses.fields(WorkItem)} - {"links", "extra"}
    kw = {k: doc[k] for k in names if k in doc}
    links = tuple(
        sorted(Link(str(x["relation"]), str(x["target"])) for x in doc.get("links") or ())
    )
    return WorkItem(**kw, links=links)


def _utcnow() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


class MemoryBackend:
    """Items and the change journal in memory (the conformance fake's storage)."""

    def __init__(self) -> None:
        self._docs: dict[str, dict[str, Any]] = {}
        self._journal: list[Change] = []
        self._lock = threading.RLock()

    def lock(self):
        return self._lock

    def load(self):
        return copy.deepcopy(self._docs)

    def write(self, docs, changes):
        for doc, expected in docs:
            cur = self._docs.get(doc["uid"])
            if (cur is None) != (expected is None) or (cur and cur["version"] != expected):
                raise Conflict(f"{doc['uid']}: changed by another writer")
        for doc, _ in docs:
            self._docs[doc["uid"]] = copy.deepcopy(doc)
        self._journal.extend(changes)
        return {d["uid"]: copy.deepcopy(d) for d, _ in docs}

    def changes(self, cursor):
        if cursor is None:
            return [], str(len(self._journal))  # the store snapshots the current state itself
        try:
            n = int(cursor)
        except ValueError:
            raise InvalidField(f"not a cursor of this store: {cursor!r}") from None
        if not 0 <= n <= len(self._journal):
            raise InvalidField(f"not a cursor of this store: {cursor!r}")
        return list(self._journal[n:]), str(len(self._journal))


class ProjectStore:
    """The ``projects`` contract (``conformance/protocols/projects.py``) over a backend."""

    features: frozenset[str] = frozenset()

    def __init__(
        self,
        backend: Backend,
        *,
        records: Callable[[], Iterable[str]] = tuple,
        clock: Callable[[], dt.datetime] = _utcnow,
        new_uid: Callable[[], str] | None = None,
        actor: str = "hnx:projects",
    ) -> None:
        self.backend = backend
        self._records = records
        self._clock = clock
        self._new_uid = new_uid or UidGenerator(lambda: int(clock().timestamp() * 1000))
        self.actor = actor

    # ------------------------------------------------------------------ helpers
    def _now(self) -> tuple[str, str]:
        t = self._clock().astimezone(dt.UTC)
        return t.strftime("%Y-%m-%dT%H:%M:%S.%fZ"), t.date().isoformat()

    @contextlib.contextmanager
    def _txn(self) -> Iterator[dict[str, WorkItem]]:
        with self.backend.lock():
            yield {u: item_of(d) for u, d in self.backend.load().items()}

    @staticmethod
    def _get(items: Mapping[str, WorkItem], uid: str) -> WorkItem:
        it = items.get(uid) if isinstance(uid, str) else None
        if it is None:
            raise NotFound(f"no item {uid!r}")
        return it

    @staticmethod
    def _check_version(item: WorkItem, version: int | None) -> None:
        if version is not None and version != item.version:
            raise Conflict(f"{item.uid}: version {version} is stale (now {item.version})")

    def _change(self, item: WorkItem, op: str, at: str, by: str | None = None) -> Change:
        return Change(
            item.uid, item.kind, item.version, op, item.status, item.title, item.project, at,
            by or self.actor,
        )  # fmt: skip

    def _commit(
        self,
        items: dict[str, WorkItem],
        changed: list[tuple[WorkItem, int | None, str, str | None]],
        at: str,
    ) -> dict[str, WorkItem]:
        docs = [(doc_of(new), old) for new, old, _op, _by in changed]
        changes = [self._change(new, op, at, by) for new, _old, op, by in changed]
        stored = self.backend.write(docs, changes)
        return {u: item_of(d) for u, d in stored.items()}

    def _bump(self, item: WorkItem, at: str, **fields: Any) -> WorkItem:
        return dataclasses.replace(item, version=item.version + 1, updated=at, **fields)

    def _auto_close(
        self, items: dict[str, WorkItem], project: str | None, at: str, day: str
    ) -> list[tuple[WorkItem, int | None, str, str | None]]:
        """Rule 3: the project closes when its last unfinished step finishes."""
        p = items.get(project or "")
        if p is None or p.kind != "project" or p.status != "open":
            return []
        steps = rules.steps_of(items.values(), p.uid)
        if not steps or not all(s.status in TERMINAL for s in steps):
            return []
        done = sum(1 for s in steps if s.status == "done")
        result = f"all {len(steps)} steps finished ({done} done, {len(steps) - done} cancelled)"
        closed = self._bump(p, at, status="closed", result=result, closed_on=day)
        return [(closed, p.version, "closed", RULE_ACTOR)]

    def records(self) -> tuple[str, ...]:
        """The external record uids links may name."""
        return tuple(sorted(set(self._records())))

    # ------------------------------------------------------------------ the contract
    def create(
        self,
        kind: str,
        title: str,
        *,
        project: str | None = None,
        parent: str | None = None,
        external_key: str | None = None,
        status: str | None = None,
        assignee: str | None = None,
        due: str | None = None,
        description: str = "",
    ) -> WorkItem:
        if kind not in KINDS:
            raise InvalidField(f"kind must be one of {', '.join(KINDS)}")
        title = rules.check_title(title)
        key = rules.check_external_key(external_key)
        assignee, due = rules.check_assignee(assignee), rules.check_due(due)
        if not isinstance(description, str):
            raise InvalidField("description must be text")
        status = rules.check_status(kind, status or ("open" if kind == "project" else "todo"))
        if status in TERMINAL:
            raise InvalidTransition("an item is created unfinished; close it afterwards")
        with self._txn() as items:
            if key is not None:
                for it in items.values():
                    if it.external_key == key:
                        if it.kind != kind:
                            raise InvalidReference(f"external_key {key!r} names a {it.kind}")
                        return it  # rule 1: idempotent create
            order = None
            if kind == "project":
                if project is not None or parent is not None:
                    raise InvalidReference("a project has no project or parent")
            else:
                if kind == "step" and project is None:
                    raise InvalidReference("a step belongs to a project")
                if project is not None:
                    p = items.get(project) if isinstance(project, str) else None
                    if p is None or p.kind != "project":
                        raise InvalidReference(f"no project {project!r}")
                    if p.status != "open":
                        raise InvalidTransition(f"project {project} is closed")  # rule 2
                if kind == "step":
                    order = 1 + max((s.order or 0 for s in rules.steps_of(items.values(), project)), default=0)  # fmt: skip
            at, _day = self._now()
            uid = self._new_uid()
            if not is_uid(uid) or uid in items:
                raise AssertionError(f"uid generator produced {uid!r}")
            item = WorkItem(
                uid=uid, kind=kind, title=title, status=status, version=1, project=project,
                parent=None, order=order, external_key=key, assignee=assignee, due=due,
                description=description, created=at, updated=at,
            )  # fmt: skip
            rules.check_parent(item, parent, items)
            item = dataclasses.replace(item, parent=parent)
            return self._commit(items, [(item, None, "created", None)], at)[uid]

    def get(self, uid: str) -> WorkItem:
        with self._txn() as items:
            return self._get(items, uid)

    def list(
        self,
        *,
        kind: str | None = None,
        status: str | None = None,
        project: str | None = None,
        assignee: str | None = None,
        linked_to: str | None = None,
    ) -> list[WorkItem]:
        with self._txn() as items:
            out = [
                i
                for i in items.values()
                if kind in (None, i.kind)
                and status in (None, i.status)
                and project in (None, i.project)
                and assignee in (None, i.assignee)
                and (linked_to is None or linked_to in i.linked())
            ]
        return sorted(out, key=lambda i: i.uid)

    def update(self, uid: str, version: int, **fields: Any) -> WorkItem:
        unknown = sorted(set(fields) - set(UPDATABLE))
        if unknown:
            raise InvalidField(f"cannot update {', '.join(unknown)}; updatable: {UPDATABLE}")
        if not isinstance(version, int):
            raise InvalidField("update needs the version the item was read at")
        with self._txn() as items:
            item = self._get(items, uid)
            self._check_version(item, version)
            at, day = self._now()
            new: dict[str, Any] = {}
            if "title" in fields:
                new["title"] = rules.check_title(fields["title"])
            if "assignee" in fields:
                new["assignee"] = rules.check_assignee(fields["assignee"])
            if "due" in fields:
                new["due"] = rules.check_due(fields["due"])
            if "description" in fields:
                if not isinstance(fields["description"], str):
                    raise InvalidField("description must be text")
                new["description"] = fields["description"]
            if "parent" in fields:
                if item.kind == "project":
                    raise InvalidReference("a project has no parent")
                rules.check_parent(item, fields["parent"], items)
                new["parent"] = fields["parent"]
            if "status" in fields and fields["status"] != item.status:
                new.update(self._status_change(items, item, fields["status"], fields, day))
            elif "result" in fields:
                if not item.terminal:
                    raise InvalidField("only a finished item has a result")
                new["result"] = rules.check_result(fields["result"])
            if all(getattr(item, k) == v for k, v in new.items()):
                return item  # nothing changed: not a change, no new version
            updated = self._bump(item, at, **new)
            op = "closed" if updated.terminal and not item.terminal else "updated"
            changed = [(updated, item.version, op, None)]
            items[uid] = updated
            if updated.kind == "step" and updated.terminal:
                changed += self._auto_close(items, updated.project, at, day)
            return self._commit(items, changed, at)[uid]

    def _status_change(
        self, items: dict[str, WorkItem], item: WorkItem, status: str, fields, day: str
    ) -> dict[str, Any]:
        status = rules.check_status(item.kind, status)
        if status in TERMINAL:
            if "result" not in fields:
                raise InvalidField(f"finishing a {item.kind} needs a one-line result")
            result = rules.check_result(fields["result"])
            if item.kind == "project":
                self._closable_project(items, item)
            elif status == "done":
                self._unblocked(items, item)
            return {"status": status, "result": result, "closed_on": day}
        if item.terminal:  # reopening
            if item.kind == "project":
                if rules.steps_of(items.values(), item.uid):
                    raise InvalidTransition("a finished project stays closed; start a new one")
            else:
                p = items.get(item.project or "")
                if p is not None and p.status != "open":
                    raise InvalidTransition(f"project {p.uid} is closed")  # rule 2
            return {"status": status, "result": None, "closed_on": None}
        return {"status": status}

    def _closable_project(self, items: Mapping[str, WorkItem], project: WorkItem) -> None:
        left = [s for s in rules.steps_of(items.values(), project.uid) if not s.terminal]
        if left:
            raise InvalidTransition(f"{len(left)} unfinished step(s): finish or cancel them first")

    def _unblocked(self, items: Mapping[str, WorkItem], item: WorkItem) -> None:
        blockers = [
            b.uid for b in items.values() if Link("blocks", item.uid) in b.links and not b.terminal
        ]
        if blockers:
            raise InvalidTransition(f"blocked by unfinished {', '.join(sorted(blockers))}")

    def close(
        self, uid: str | None = None, result: str | None = None, *, version: int | None = None
    ) -> WorkItem | None:
        """Finish ``uid``: a project closes, a step or task is done; ``result`` is one line.

        Called with no arguments it releases the store (the conformance harness's teardown)."""
        if uid is None and result is None:
            closer = getattr(self.backend, "close", None)
            if callable(closer):
                closer()
            return None
        with self._txn() as items:
            item = self._get(items, uid)
            self._check_version(item, version)
            if item.terminal:
                raise InvalidTransition(f"{uid} is already {item.status}")
        status = "closed" if item.kind == "project" else "done"
        return self.update(uid, item.version, status=status, result=result)

    def link(self, uid: str, target: str, relation: str, *, version: int | None = None) -> WorkItem:
        with self._txn() as items:
            item = self._get(items, uid)
            self._check_version(item, version)
            rules.check_link(item, target, relation, items, frozenset(self.records()))
            lk = Link(relation, target)
            if lk in item.links:
                return item  # already linked: not a change
            at, _ = self._now()
            new = self._bump(item, at, links=tuple(sorted((*item.links, lk))))
            return self._commit(items, [(new, item.version, "linked", None)], at)[uid]

    def unlink(
        self, uid: str, target: str, relation: str, *, version: int | None = None
    ) -> WorkItem:
        with self._txn() as items:
            item = self._get(items, uid)
            self._check_version(item, version)
            lk = Link(relation, target)
            if lk not in item.links:
                raise NotFound(f"{uid} has no {relation} link to {target}")
            at, _ = self._now()
            new = self._bump(item, at, links=tuple(x for x in item.links if x != lk))
            return self._commit(items, [(new, item.version, "unlinked", None)], at)[uid]

    def changes_since(self, cursor: str | None = None) -> ChangeSet:
        """Every item changed after ``cursor``, at least at its latest version, oldest first.
        ``None``: every item as it is now (a snapshot) and the cursor to continue from."""
        with self.backend.lock():
            got, nxt = self.backend.changes(cursor)
            if cursor is None:
                items = [item_of(d) for d in self.backend.load().values()]
                got = [
                    self._change(i, _snapshot_op(i), i.updated)
                    for i in sorted(items, key=lambda i: (i.updated, i.uid))
                ]
        return ChangeSet(tuple(got), nxt)

    def check(self) -> list[str]:
        """Every board-rule violation of the stored items (files edited by hand)."""
        with self._txn() as items:
            return rules.board_problems(items.values(), self.records())


def _snapshot_op(item: WorkItem) -> str:
    return "created" if item.version == 1 else "closed" if item.terminal else "updated"
