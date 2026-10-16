# SPDX-License-Identifier: Apache-2.0
"""In-memory backup store (``backup`` fake) and its aliasing defect."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping

from conformance.protocols.backup import NoSuchSnapshot, Snapshot


def _sum(data: Mapping[str, bytes]) -> str:
    h = hashlib.sha256()
    for k in sorted(data):
        h.update(k.encode("utf-8") + b"\0" + data[k] + b"\0")
    return h.hexdigest()


class FakeBackupStore:
    features = frozenset({"fault-injection"})

    def __init__(self) -> None:
        self._snaps: dict[str, tuple[Snapshot, dict[str, bytes]]] = {}
        self._seq: dict[str, int] = {}

    def _store(self, data: Mapping[str, bytes]) -> dict[str, bytes]:
        return {k: bytes(v) for k, v in data.items()}  # deep copy: immutable snapshot

    def snapshot(self, source: str, data: Mapping[str, bytes]) -> Snapshot:
        if not source:
            raise ValueError("source is required")
        n = self._seq.get(source, 0) + 1
        self._seq[source] = n
        snap = Snapshot(f"{source}@{n}", source, n, len(data), _sum(data))
        self._snaps[snap.id] = (snap, self._store(data))
        return snap

    def _get(self, snapshot_id: str):
        try:
            return self._snaps[snapshot_id]
        except KeyError:
            raise NoSuchSnapshot(snapshot_id) from None

    def restore(self, snapshot_id: str) -> dict[str, bytes]:
        return dict(self._get(snapshot_id)[1])

    def verify(self, snapshot_id: str) -> bool:
        snap, data = self._get(snapshot_id)
        return _sum(data) == snap.checksum

    def list(self, source: str) -> list[Snapshot]:
        found = [s for s, _ in self._snaps.values() if s.source == source]
        return sorted(found, key=lambda s: -s.seq)

    def prune(self, source: str, keep_last: int) -> list[str]:
        if keep_last < 1:
            raise ValueError("keep_last must be >= 1")
        doomed = [s.id for s in self.list(source)[keep_last:]]
        for sid in doomed:
            del self._snaps[sid]
        return doomed

    def corrupt(self, snapshot_id: str) -> None:
        """Test hook (feature ``fault-injection``): flip a byte in the stored data."""
        _, data = self._get(snapshot_id)
        k = next(iter(data))
        data[k] = bytes([data[k][0] ^ 0xFF]) + data[k][1:] if data[k] else b"\xff"


class AliasingBackupStore(FakeBackupStore):
    """Defect: snapshots keep a reference to the caller's data, so later edits change them."""

    def _store(self, data):
        return data  # type: ignore[return-value]
