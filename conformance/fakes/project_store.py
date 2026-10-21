# SPDX-License-Identifier: Apache-2.0
"""In-memory project store (the library's rules over :class:`MemoryBackend`) and its mutants.

The fake links to three fixed external records (:data:`RECORDS`), standing in for strategy
records.  Each mutant breaks exactly one rule of the contract; the suite must catch every one.
"""

from __future__ import annotations

import dataclasses
import datetime as dt
import itertools

from homelabnext.projects import MemoryBackend, ProjectStore
from homelabnext.projects.model import LINK_RELATIONS, WorkItem
from homelabnext.projects.store import doc_of

#: three fictional external record uids (UUIDv7) the fake can link to
RECORDS = (
    "01941f29-7c00-7a3e-8b2c-000000000001",
    "01941f29-7c00-7a3e-8b2c-000000000002",
    "01941f29-7c00-7a3e-8b2c-000000000003",
)
_EPOCH = dt.datetime(2026, 1, 1, tzinfo=dt.UTC)


def _clock():
    """A deterministic clock: one millisecond per reading."""
    ticks = itertools.count()
    return lambda: _EPOCH + dt.timedelta(milliseconds=next(ticks))


class FakeProjectStore(ProjectStore):
    def __init__(self) -> None:
        super().__init__(MemoryBackend(), records=lambda: RECORDS, clock=_clock())


class ClosedProjectStepStore(FakeProjectStore):
    """Accepts a step under a closed project (rule 2)."""

    def create(self, kind, title, **kw):
        p = self.backend._docs.get(kw.get("project") or "")
        if kind == "step" and p and p["status"] == "closed":
            p["status"] = "open"
            try:
                return super().create(kind, title, **kw)
            finally:
                p["status"] = "closed"
        return super().create(kind, title, **kw)


class NeverClosesStore(FakeProjectStore):
    """Leaves a project open after its last step finished (rule 3)."""

    def _auto_close(self, items, project, at, day):
        return []


class DuplicateKeyStore(FakeProjectStore):
    """Creates a new item for an external key it already holds (rule 1)."""

    def create(self, kind, title, *, external_key=None, **kw):
        item = super().create(kind, title, **kw)
        if external_key is None:
            return item
        new = dataclasses.replace(item, external_key=external_key)
        self.backend._docs[item.uid] = doc_of(new)
        return new


class LastWriterWinsStore(FakeProjectStore):
    """Ignores the quoted version: a stale update silently overwrites."""

    @staticmethod
    def _check_version(item: WorkItem, version):
        return None


class LossyFeedStore(FakeProjectStore):
    """Drops every second change from the feed."""

    def changes_since(self, cursor=None):
        cs = super().changes_since(cursor)
        if cursor is None:
            return cs
        return dataclasses.replace(cs, changes=cs.changes[::2])


class DanglingLinkStore(FakeProjectStore):
    """Links to any uid, resolvable or not."""

    def link(self, uid, target, relation, *, version=None):
        if relation in LINK_RELATIONS:
            known = self._records
            self._records = lambda: (*known(), target)
            try:
                return super().link(uid, target, relation, version=version)
            finally:
                self._records = known
        return super().link(uid, target, relation, version=version)


class ResultlessStore(FakeProjectStore):
    """Finishes an item without a result."""

    def close(self, uid=None, result=None, *, version=None):
        if uid is not None and not (result or "").strip():
            result = "-"
        return super().close(uid, result, version=version)


class BlockedFinishesStore(FakeProjectStore):
    """Lets an item finish while an unfinished item blocks it."""

    def _unblocked(self, items, item):
        return None
