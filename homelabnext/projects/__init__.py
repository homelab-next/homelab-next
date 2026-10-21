# SPDX-License-Identifier: Apache-2.0
"""Project management: projects, their steps and one-off tasks, linked to strategy records.

The ``projects`` capability (``docs/projects.md``, ADR-0020).  :class:`ProjectStore` holds the
contract and the board rules over a backend; the Markdown backend (one ``<uid>.md`` per item) is
the reference implementation behind ``hnx projects`` and the hub's Projects page, and
:mod:`homelabnext.projects.openproject` binds an OpenProject instance (the same contract, plus the
one-way strategy sync, the change feed and ``doctor``).
"""

from __future__ import annotations

from .markdown import MarkdownBackend
from .model import (
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
from .store import MemoryBackend, ProjectStore
from .strategy import StrategyRecord, record_uids, strategy_records
from .uid import UidGenerator, derived_uid, is_uid

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
    "MarkdownBackend",
    "MemoryBackend",
    "NotFound",
    "ProjectStore",
    "ProjectsError",
    "StrategyRecord",
    "UidGenerator",
    "WorkItem",
    "derived_uid",
    "is_uid",
    "markdown_store",
    "record_uids",
    "reference_subject",
    "strategy_records",
]


def markdown_store(root, *, strategy=None, create: bool = True, **kw) -> ProjectStore:
    """The reference store over ``root`` (``<uid>.md`` files); links resolve against the
    strategy records under ``strategy`` (none: no external record is linkable)."""
    return ProjectStore(MarkdownBackend(root, create=create), records=record_uids(strategy), **kw)


def reference_subject(**_config) -> ProjectStore:
    """Conformance factory (``conformance/targets/projects-reference.yml``): a Markdown store in
    a fresh temporary directory, removed when the harness closes it, linking to the example
    strategy records' uids."""
    import shutil
    import tempfile

    from homelabnext import paths

    tmp = tempfile.mkdtemp(prefix="hnx-projects-")
    backend = MarkdownBackend(tmp)
    backend.close = lambda: shutil.rmtree(tmp, ignore_errors=True)  # type: ignore[attr-defined]
    strategy = paths.examples_dir() / "strategy"
    return ProjectStore(backend, records=record_uids(strategy))
