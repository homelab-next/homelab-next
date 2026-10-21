# SPDX-License-Identifier: Apache-2.0
"""Contract for ``projects``: projects, their steps and one-off tasks, linked to records by uid.

The vocabulary (:class:`WorkItem`, :class:`Link`, :class:`Change`, the statuses and the errors) is
the library's own, :mod:`homelabnext.projects.model`, re-exported here.  An item is a
``project`` (``open`` / ``closed``), a ``step`` of a project or a ``task`` (``blocked``,
``todo``, ``in_progress``, ``done``, ``cancelled``).  Every item has a ``uid`` (UUIDv7) and a
``version`` that grows by one on every change.

The board rules are MUSTs of the suite: uids are unique and an ``external_key`` names at most one
item (create is idempotent by it); a step belongs to an existing open project; a project with
unfinished steps cannot close, and the project closes in the same write as its last step
finishes, never to be reopened; a finished item carries a one-line result and its date; a
``blocks`` link holds back the blocked item's completion.  Links name uids that resolve: an
external record (``records()``) for ``supports``/``serves``/``measures``/``answers``, a step or
task for ``blocks``/``precedes``; no self-links, no cycles.

Adding a product: write an adapter whose factory returns an object with these methods (the
library's :class:`homelabnext.projects.ProjectStore` over a new backend is the short way: the
rules come with it), name it in a target file and run ``hnx conform run projects --target
FILE``.  ``close()`` with no arguments releases the subject (the harness's teardown).
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any, Protocol, runtime_checkable

from homelabnext.projects.model import (
    DEPENDENCY_RELATIONS,
    ITEM_KINDS,
    ITEM_STATUSES,
    KINDS,
    LINK_RELATIONS,
    PROJECT_STATUSES,
    RELATIONS,
    Change,
    ChangeSet,
    Conflict,
    InvalidField,
    InvalidReference,
    InvalidTransition,
    Link,
    NotFound,
    ProjectsError,
    WorkItem,
)

__all__ = [
    "DEPENDENCY_RELATIONS",
    "ITEM_KINDS",
    "ITEM_STATUSES",
    "KINDS",
    "LINK_RELATIONS",
    "PROJECT_STATUSES",
    "RELATIONS",
    "Change",
    "ChangeSet",
    "Conflict",
    "InvalidField",
    "InvalidReference",
    "InvalidTransition",
    "Link",
    "NotFound",
    "ProjectStore",
    "ProjectsError",
    "WorkItem",
]


@runtime_checkable
class ProjectStore(Protocol):
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
        """A new item at version 1.  With an ``external_key`` that already names an item, that
        item is returned unchanged (idempotent create)."""

    def get(self, uid: str) -> WorkItem: ...

    def list(
        self,
        *,
        kind: str | None = None,
        status: str | None = None,
        project: str | None = None,
        assignee: str | None = None,
        linked_to: str | None = None,
    ) -> Sequence[WorkItem]:
        """Matching items in creation (uid) order; every filter given must match."""

    def update(self, uid: str, version: int, **fields: Any) -> WorkItem:
        """Change ``title``, ``status``, ``assignee``, ``due``, ``description``, ``parent`` or
        ``result``; ``version`` must be the current one (else :class:`Conflict`)."""

    def close(
        self, uid: str | None = None, result: str | None = None, *, version: int | None = None
    ) -> WorkItem | None:
        """Finish an item: a project closes, a step or task becomes ``done``."""

    def link(
        self, uid: str, target: str, relation: str, *, version: int | None = None
    ) -> WorkItem: ...

    def unlink(
        self, uid: str, target: str, relation: str, *, version: int | None = None
    ) -> WorkItem: ...

    def changes_since(self, cursor: str | None = None) -> ChangeSet:
        """Every item changed after ``cursor``, at least at its latest version; ``None`` is a
        snapshot of every item.  The returned cursor continues the feed."""

    def records(self) -> Sequence[str]:
        """The uids of the external records links may name."""
