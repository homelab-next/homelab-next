# SPDX-License-Identifier: Apache-2.0
"""The project-management data model: work items, links, changes and the errors.

Everything is a :class:`WorkItem` of one of three kinds:

``project``  a piece of multi-step work; ``open`` or ``closed``.  Its steps are the items of
             kind ``step`` that name it, in ``order``.
``step``     one step of a project: the work queue.  Always belongs to a project.
``task``     a one-off piece of work; may name a project, need not.

Steps and tasks move through ``blocked``, ``todo``, ``in_progress``, ``done`` and
``cancelled`` (the last two are terminal and carry a one-line ``result`` and the date).  Every
item has a ``uid`` (UUIDv7, :mod:`homelabnext.identity`) and a ``version`` that grows by one on every change,
which is what an update must quote (optimistic concurrency).  ``links`` relate an item to an
external record (a strategy objective, a requirement, an RFI: ``supports``, ``serves``,
``measures``, ``answers``) or to another item (``blocks``, ``precedes``), always by uid.

This module is the contract's vocabulary; ``conformance/protocols/projects.py`` re-exports it
next to the :class:`ProjectStore` protocol, and the suite proves any implementation of it.
"""

from __future__ import annotations

import datetime as dt
import re
from dataclasses import dataclass, field
from typing import Any

__all__ = [
    "DEPENDENCY_RELATIONS",
    "ITEM_KINDS",
    "ITEM_STATUSES",
    "KINDS",
    "LINK_RELATIONS",
    "PROJECT_STATUSES",
    "RELATIONS",
    "STATUSES",
    "TERMINAL",
    "Change",
    "ChangeSet",
    "Conflict",
    "InvalidField",
    "InvalidReference",
    "InvalidTransition",
    "Link",
    "NotFound",
    "ProjectsError",
    "WorkItem",
]

KINDS = ("project", "step", "task")
ITEM_KINDS = ("step", "task")
PROJECT_STATUSES = ("open", "closed")
ITEM_STATUSES = ("blocked", "todo", "in_progress", "done", "cancelled")
STATUSES = (*PROJECT_STATUSES, *ITEM_STATUSES)
TERMINAL = frozenset({"done", "cancelled", "closed"})
#: relations to an external record (by its uid)
LINK_RELATIONS = ("supports", "serves", "measures", "answers")
#: relations to another work item: ``A blocks B`` (B cannot finish first), ``A precedes B``
DEPENDENCY_RELATIONS = ("blocks", "precedes")
RELATIONS = (*LINK_RELATIONS, *DEPENDENCY_RELATIONS)
#: who an item is assigned to: a profile or a person id (``profile:responder``, ``human:alex``)
ASSIGNEE_RE = re.compile(r"^(profile|human|agent):[a-z0-9][a-z0-9._-]{0,63}$")
#: fields ``update`` may change
UPDATABLE = ("title", "status", "assignee", "due", "description", "parent", "result")


class ProjectsError(Exception):
    """Base of every error the contract defines."""


class NotFound(ProjectsError, LookupError):
    """No item (or no such link) with that uid."""


class Conflict(ProjectsError):
    """The quoted version is not the current one: re-read and retry."""


class InvalidTransition(ProjectsError):
    """The status change (or the write) breaks a board rule."""


class InvalidReference(ProjectsError, ValueError):
    """A uid that resolves to nothing, an unknown relation, a self-reference or a cycle."""


class InvalidField(ProjectsError, ValueError):
    """A field value of the wrong shape (title, assignee, due date, status name)."""


@dataclass(frozen=True, order=True)
class Link:
    relation: str
    target: str  # a uid


@dataclass(frozen=True)
class WorkItem:
    uid: str
    kind: str
    title: str
    status: str
    version: int
    project: str | None = None  # the project's uid (steps always, tasks optionally)
    parent: str | None = None  # a parent step/task (sub-items), same project
    order: int | None = None  # a step's position in its project
    external_key: str | None = None  # the caller's idempotency key
    assignee: str | None = None
    due: str | None = None  # YYYY-MM-DD
    description: str = ""
    result: str | None = None  # one line, set when terminal
    closed_on: str | None = None  # YYYY-MM-DD, set when terminal
    links: tuple[Link, ...] = ()
    created: str = ""
    updated: str = ""
    extra: dict[str, Any] = field(default_factory=dict, compare=False)

    @property
    def terminal(self) -> bool:
        return self.status in TERMINAL

    def linked(self, relations=RELATIONS) -> tuple[str, ...]:
        return tuple(lk.target for lk in self.links if lk.relation in relations)


@dataclass(frozen=True)
class Change:
    """One change of one item: the item as it is at ``version`` after ``op``."""

    uid: str
    kind: str
    version: int
    op: str  # created | updated | closed | linked | unlinked
    status: str
    title: str = ""
    project: str | None = None
    at: str = ""
    by: str = ""
    ref: str | None = None  # the backend's own key, e.g. ``wp:42`` for OpenProject


@dataclass(frozen=True)
class ChangeSet:
    changes: tuple[Change, ...]
    cursor: str


OPS = ("created", "updated", "closed", "linked", "unlinked")


def iso_date(value: dt.date | dt.datetime) -> str:
    return value.date().isoformat() if isinstance(value, dt.datetime) else value.isoformat()
