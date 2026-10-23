# SPDX-License-Identifier: Apache-2.0
"""Commit-then-checkpoint ingestion.

The incident this encodes: a log writer committed a batch to the table, crashed before it saved
its read offset, and on restart re-read the (by then rotated) log tail from the stale offset.
Every row of the tail was written a second time.

The design has three parts, so no single one is load-bearing:

* **Order.** The lake commit happens first; the checkpoint is saved after. A crash can therefore
  only leave the checkpoint *behind* the lake, never ahead of it. Data is never lost; at worst the
  tail is read again.
* **The checkpoint records what was committed**, not only where the reader got to: the position
  (high-water mark), the batch id and the snapshot id of the last committed batch. The same
  ``batch_id`` and ``high_water`` are stored inside the lake commit itself, so after a crash
  :meth:`Ingestor.start` finds the lake's mark, sees it is ahead of the checkpoint, and
  fast-forwards instead of re-reading.
* **Replay is idempotent by content key.** If the tail is read again anyway (checkpoint file lost,
  snapshots expired, different batching), the lake skips rows whose key columns already exist.
  ``write_batch`` reports how many it skipped.

Assumption: one writer per ``(table, source)`` at a time.
"""

from __future__ import annotations

import os
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from ..state import StateError, StateStore
from .errors import CheckpointError
from .protocol import LakeClient, WriteResult


@dataclass(frozen=True)
class SourceState:
    position: str | None  # opaque high-water mark of the reader
    batch_id: str  # last batch committed to the lake for this source
    snapshot_id: str | None  # lake snapshot that holds it


class Checkpoint:
    """Per-source checkpoint in a :class:`~homelabnext.state.StateStore` (atomic, locked, versioned).

    The file is the shared state-file format (``{"schema_version": 1, "data": {source: state}}``),
    so it gets the library's atomic replace, ``flock`` and ``0600`` mode.  A checkpoint written
    before the move (``{"version": 1, "sources": {...}}``) is still read, and is rewritten in the
    new format on the next save.  An unusable file raises :class:`CheckpointError` rather than
    being quarantined: start-up stops and says so, it does not silently re-read from the lake mark.
    """

    VERSION = 1  # the pre-StateStore file format, still read

    def __init__(self, path: str | os.PathLike):
        self.path = Path(path)
        self._store = StateStore(self.path, quarantine=False, legacy=self._legacy)

    @classmethod
    def _legacy(cls, doc: dict[str, Any]) -> dict[str, Any] | None:
        if doc.get("version") == cls.VERSION and isinstance(doc.get("sources"), dict):
            return doc["sources"]
        return None

    def get(self, source: str) -> SourceState | None:
        try:
            raw = self._store.get(source)
        except StateError as e:
            raise CheckpointError(f"checkpoint {self.path}: {e}") from e
        return None if raw is None else SourceState(**raw)

    def save(self, source: str, state: SourceState) -> None:
        try:
            self._store.put(source, asdict(state))
        except StateError as e:
            raise CheckpointError(f"checkpoint {self.path}: {e}") from e


class Ingestor:
    """Writes batches for one ``(table, source)`` with commit-then-checkpoint semantics."""

    def __init__(
        self,
        client: LakeClient,
        checkpoint: Checkpoint,
        *,
        table: str,
        source: str,
        before_checkpoint: Callable[[], None] | None = None,
    ):
        self.client = client
        self.checkpoint = checkpoint
        self.table = table
        self.source = source
        self._hook = before_checkpoint  # test seam: raise here to simulate a crash

    def start(self) -> str | None:
        """Reconcile the checkpoint with the lake and return the position to resume from.

        If the lake holds a committed batch for this source that the checkpoint does not know
        about (the crash window), the checkpoint is fast-forwarded to the lake's mark.  A
        checkpoint that already records the mark's snapshot is not behind it, even when it names
        a later batch: a batch with nothing new commits nothing, so the lake's mark stays put
        while the checkpoint's position moves on, and fast-forwarding would rewind the reader.
        """
        state = self.checkpoint.get(self.source)
        mark = self.client.describe(self.table).committed.get(self.source)
        if mark is not None and (state is None or not _knows(state, mark)):
            state = SourceState(mark.high_water, mark.batch_id, mark.snapshot_id)
            self.checkpoint.save(self.source, state)
        return None if state is None else state.position

    def ingest(
        self, rows: Sequence[Mapping[str, Any]], *, batch_id: str, position: str
    ) -> WriteResult:
        """Commit ``rows``, then checkpoint ``position``. ``position`` is the reader's mark
        *after* these rows."""
        res = self.client.write_batch(
            self.table, rows, idempotency_key=batch_id, source=self.source, high_water=position
        )
        if self._hook is not None:
            self._hook()
        prev = self.checkpoint.get(self.source)
        committed = res.snapshot_id is not None or res.replayed
        if not committed and prev is not None:
            # nothing new (an empty tail, or every row already present): the lake made no commit
            # and kept its mark, so the checkpoint keeps the last committed batch and snapshot and
            # only the reader's position moves on
            state = SourceState(position, prev.batch_id, prev.snapshot_id)
        else:
            snap = res.snapshot_id
            if snap is None and prev is not None:
                snap = prev.snapshot_id
            state = SourceState(position, batch_id, snap)
        self.checkpoint.save(self.source, state)
        return res


def _knows(state: SourceState, mark: Any) -> bool:
    """Whether ``state`` already covers the lake's ``mark`` (the same batch, or its snapshot)."""
    if state.batch_id == mark.batch_id:
        return True
    return state.snapshot_id is not None and state.snapshot_id == mark.snapshot_id
