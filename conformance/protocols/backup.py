# SPDX-License-Identifier: Apache-2.0
"""Contract for ``backup`` (extended suite): immutable snapshots, verified restores, retention.

A *source* is a named dataset (``{path: bytes}``).  ``snapshot`` freezes it; later changes to the
source never alter an existing snapshot; ``restore`` returns exactly the frozen content;
``verify`` re-checks the stored bytes against the checksum recorded at snapshot time.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

__all__ = ["BackupError", "BackupStore", "NoSuchSnapshot", "Snapshot"]


class BackupError(Exception):
    pass


class NoSuchSnapshot(BackupError):
    pass


@dataclass(frozen=True)
class Snapshot:
    id: str
    source: str
    seq: int  # 1, 2, 3 ... per source
    files: int
    checksum: str


@runtime_checkable
class BackupStore(Protocol):
    def snapshot(self, source: str, data: Mapping[str, bytes]) -> Snapshot: ...

    def restore(self, snapshot_id: str) -> dict[str, bytes]:
        """Raises NoSuchSnapshot."""

    def verify(self, snapshot_id: str) -> bool:
        """True if the stored bytes still match the recorded checksum.  Raises NoSuchSnapshot."""

    def list(self, source: str) -> Sequence[Snapshot]:
        """Newest first."""

    def prune(self, source: str, keep_last: int) -> Sequence[str]:
        """Delete all but the newest ``keep_last`` snapshots; returns the deleted ids."""
