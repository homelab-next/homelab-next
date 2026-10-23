# SPDX-License-Identifier: Apache-2.0
"""``records`` fake: the real ``homelabnext.records`` library over a temporary directory."""

from __future__ import annotations

import shutil
import tempfile
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from homelabnext.records.agent import Records, RecordsReader
from homelabnext.records.decider import Decider, init_tree

FIXED = datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC)


class FakeRecordsTarget:
    features = frozenset()

    def __init__(self) -> None:
        self._dir = Path(tempfile.mkdtemp(prefix="hnx-conform-records-"))
        init_tree(self._dir)
        self._agent = Records(self._dir, lambda: FIXED)
        self._reader = RecordsReader(self._dir)
        self._decider = Decider(self._dir, decided_by="operator", clock=lambda: FIXED)

    def close(self) -> None:
        shutil.rmtree(self._dir, ignore_errors=True)

    def propose(self, note: Mapping[str, Any], body: str = "") -> str:
        return self._agent.submit(note, body=body).name

    def completion_request(self, related: Sequence[str], body: str, *, agent: str) -> str:
        return self._agent.completion_request(related, body, agent=agent).name

    def list(self, lane: str) -> list[str]:
        return self._reader.list(lane)

    def read(self, lane: str, name: str):
        note = self._reader.read(lane, name)
        return dict(note.frontmatter), note.body

    def approve(self, name: str) -> None:
        self._decider.approve(name)

    def deny(self, name: str, reason: str | None = None) -> None:
        self._decider.deny(name, reason)

    def complete(self, name: str) -> None:
        self._decider.complete(name)


class OverwritingRecordsTarget(FakeRecordsTarget):
    """Defect: proposing an existing name silently replaces the earlier note."""

    def propose(self, note: Mapping[str, Any], body: str = "") -> str:
        try:
            return super().propose(note, body)
        except FileExistsError:
            for p in (self._dir / "inbox").glob("*.md"):
                p.unlink()
            return super().propose(note, body)


class InboxCompletingRecordsTarget(FakeRecordsTarget):
    """Defect: a completion request for a note still in the inbox approves it first."""

    def completion_request(self, related: Sequence[str], body: str, *, agent: str) -> str:
        for r in related:
            if r in self.list("inbox"):
                self._decider.approve(r)
        return super().completion_request(related, body, agent=agent)


class DeniedCompletingRecordsTarget(FakeRecordsTarget):
    """Defect: a denied note can be named in a completion request (and so completed)."""

    def completion_request(self, related: Sequence[str], body: str, *, agent: str) -> str:
        for r in related:
            if r in self.list("decided/denied"):
                (self._dir / "decided/denied" / r).rename(self._dir / "decided/approved" / r)
        return super().completion_request(related, body, agent=agent)


class PartialCompleteRecordsTarget(FakeRecordsTarget):
    """Defect: complete() moves related notes one by one, with no preflight."""

    def complete(self, name: str) -> None:
        from homelabnext.records.notes import read_note

        req = read_note(self._dir / "inbox" / name, "inbox")
        for rel in req.frontmatter.get("related", []):
            src = self._dir / rel
            if not src.is_file():
                raise FileNotFoundError(rel)
            src.rename(self._dir / "decided/completed" / src.name)
        self._decider._move(req, "decided/completed", "completed", None)


class TraversingRecordsTarget(FakeRecordsTarget):
    """Defect: deny/complete join the given name onto the inbox without refusing '../'."""

    def _resolve(self, name: str) -> str:
        path = (self._dir / "inbox" / name).resolve()
        if path.parent != (self._dir / "inbox").resolve():
            path.rename(self._dir / "inbox" / path.name)  # "fetch" the note it points at
        return path.name

    def deny(self, name: str, reason: str | None = None) -> None:
        super().deny(self._resolve(name), reason)

    def complete(self, name: str) -> None:
        super().complete(self._resolve(name))


class UnconfinedReadRecordsTarget(FakeRecordsTarget):
    """Defect: read() opens ``<lane>/<name>`` as given, so '../' reaches other lanes."""

    def read(self, lane: str, name: str):
        from homelabnext.records.notes import read_note

        self.list(lane)  # the lane name itself is still checked
        note = read_note(self._dir / lane / name, lane)
        return dict(note.frontmatter), note.body


class ReapprovingRecordsTarget(FakeRecordsTarget):
    """Defect: ``approve`` also accepts a note already in ``decided/denied`` and moves it to
    approved, so an operator's denial is overturned."""

    def approve(self, name: str) -> None:
        if name in self.list("decided/denied"):
            src = self._dir / "decided/denied" / name
            src.rename(self._dir / "decided/approved" / name)
            return
        super().approve(name)


class RedenyingRecordsTarget(FakeRecordsTarget):
    """Defect: ``deny`` of a note already in ``decided/approved`` moves it to denied, so an
    approval is quietly withdrawn."""

    def deny(self, name: str, reason: str | None = None) -> None:
        if name in self.list("decided/approved"):
            src = self._dir / "decided/approved" / name
            src.rename(self._dir / "decided/denied" / name)
            return
        super().deny(name, reason)
