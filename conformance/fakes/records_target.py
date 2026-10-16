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
