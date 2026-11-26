# SPDX-License-Identifier: Apache-2.0
"""In-memory backup store (``backup`` fake), its aliasing defect, and an Object-Lock stand-in.

:class:`ObjectLockBackupStore` plays the part of a restic repository on an S3 bucket with Object
Lock turned on in compliance mode: the automation's credential can push a new copy and read it
back, but cannot delete it, shorten its retention window or disable versioning.  The "attempt"
methods are not operator-facing actions; they are the shapes the suite calls so the subject
proves what its credential cannot do, which is the entire point of an off-site immutable copy.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping

from conformance.protocols.backup import (
    NoSuchOffsiteCopy,
    NoSuchSnapshot,
    OffsiteCopy,
    OffsiteImmutable,
    Snapshot,
)


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


# ---- Object-Lock stand-in --------------------------------------------------------------------


#: a week in seconds, the default retention window for a new off-site copy (chosen so a test
#: ``now`` of 0 leaves every fixture copy inside its lock)
_DEFAULT_RETENTION_S = 7 * 24 * 60 * 60


class ObjectLockBackupStore(FakeBackupStore):
    """A backup store with an off-site immutable lane modelled on S3 Object Lock in compliance
    mode: the automation can push new copies and read them back, but its credential cannot
    delete, shorten the retention window or disable versioning.

    The remote has its own wall clock (``now``); a copy's ``retain_until`` is ``now`` plus the
    configured retention window at the moment of the copy.  The suite's probes stay inside the
    window: this fake never says "it's past the lock, you may delete now", because what the
    suite is proving is what the credential CANNOT do.

    Features: ``fault-injection`` (inherited; a snapshot can be corrupted, and so can a remote
    copy via :meth:`corrupt_offsite`) plus ``offsite-immutable``, the new lane.
    """

    features = frozenset({"fault-injection", "offsite-immutable"})

    def __init__(self, *, retention_s: float = _DEFAULT_RETENTION_S) -> None:
        super().__init__()
        self._retention_s = float(retention_s)
        self._now = 0.0  # a frozen test clock; tests never read the wall clock
        self._copies: dict[str, tuple[OffsiteCopy, dict[str, bytes]]] = {}
        self._by_snapshot: dict[str, str] = {}
        self._versioning = True
        self._next_offsite_seq = 0

    # ---- the off-site lane --------------------------------------------------------------
    def copy_offsite(self, snapshot_id: str) -> OffsiteCopy:
        snap, data = self._get(snapshot_id)
        if snapshot_id in self._by_snapshot:
            return self._copies[self._by_snapshot[snapshot_id]][0]
        self._next_offsite_seq += 1
        oid = f"offsite:{snap.source}@{snap.seq}#{self._next_offsite_seq}"
        copy = OffsiteCopy(
            id=oid,
            snapshot_id=snapshot_id,
            source=snap.source,
            files=snap.files,
            checksum=snap.checksum,
            retain_until=self._now + self._retention_s,
        )
        # the remote stores a byte-for-byte clone of the snapshot's content
        self._copies[oid] = (copy, {k: bytes(v) for k, v in data.items()})
        self._by_snapshot[snapshot_id] = oid
        return copy

    def _get_copy(self, offsite_id: str):
        try:
            return self._copies[offsite_id]
        except KeyError:
            raise NoSuchOffsiteCopy(offsite_id) from None

    def verify_offsite(self, offsite_id: str) -> bool:
        copy, data = self._get_copy(offsite_id)
        return _sum(data) == copy.checksum

    def restore_from_offsite(self, offsite_id: str) -> dict[str, bytes]:
        return dict(self._get_copy(offsite_id)[1])

    def delete_offsite_attempt(self, offsite_id: str) -> None:
        copy, _ = self._get_copy(offsite_id)
        if self._now < copy.retain_until:
            raise OffsiteImmutable(
                f"{offsite_id}: inside retention window "
                f"(until {copy.retain_until}, now {self._now})"
            )
        # outside the window, an Object-Lock compliance mode still forbids delete to an
        # automation credential without a governance override; this fake deliberately never
        # concedes, so a defective subject cannot pass by claiming "my lock expired"
        raise OffsiteImmutable(f"{offsite_id}: delete refused by the lock policy")

    def shorten_retention_attempt(self, offsite_id: str, retain_until: float) -> None:
        copy, _ = self._get_copy(offsite_id)
        if retain_until < copy.retain_until:
            raise OffsiteImmutable(
                f"{offsite_id}: cannot shorten retention "
                f"(asked {retain_until}, locked {copy.retain_until})"
            )
        # lengthening is allowed, but is not what the probe is for; the suite only passes a
        # shorter value, so this branch never runs from a conforming check
        self._copies[offsite_id] = (
            OffsiteCopy(
                id=copy.id,
                snapshot_id=copy.snapshot_id,
                source=copy.source,
                files=copy.files,
                checksum=copy.checksum,
                retain_until=float(retain_until),
            ),
            self._copies[offsite_id][1],
        )

    def disable_versioning_attempt(self) -> None:
        raise OffsiteImmutable("the bucket is in compliance mode: versioning cannot be disabled")

    # ---- test hooks ---------------------------------------------------------------------
    def tick(self, seconds: float) -> None:
        """Advance the fake remote's clock (for a check that lengthens a window, say)."""
        self._now += float(seconds)

    def corrupt_offsite(self, offsite_id: str) -> None:
        """Flip a byte on the remote (feature ``fault-injection``): what a silent ``verify``
        implementation would fail to notice."""
        _, data = self._get_copy(offsite_id)
        k = next(iter(data))
        data[k] = bytes([data[k][0] ^ 0xFF]) + data[k][1:] if data[k] else b"\xff"


# ---- mutants of the Object-Lock lane ---------------------------------------------------------


class DeletableOffsiteStore(ObjectLockBackupStore):
    """Defect: the credential CAN delete an off-site copy.  ``delete-must-fail`` must catch it."""

    def delete_offsite_attempt(self, offsite_id: str) -> None:
        copy, _ = self._get_copy(offsite_id)
        del self._copies[offsite_id]
        self._by_snapshot.pop(copy.snapshot_id, None)


class ShortenableOffsiteStore(ObjectLockBackupStore):
    """Defect: the credential CAN shorten the retention window.  ``shorten-retention-must-fail``
    catches it (it would also let an attacker delete the copy early)."""

    def shorten_retention_attempt(self, offsite_id: str, retain_until: float) -> None:
        copy, data = self._get_copy(offsite_id)
        self._copies[offsite_id] = (
            OffsiteCopy(
                id=copy.id,
                snapshot_id=copy.snapshot_id,
                source=copy.source,
                files=copy.files,
                checksum=copy.checksum,
                retain_until=float(retain_until),
            ),
            data,
        )


class VersioningDisablableOffsiteStore(ObjectLockBackupStore):
    """Defect: the credential CAN disable versioning on the bucket.
    ``disable-versioning-must-fail`` catches it (a successful call lets an attacker overwrite
    every prior copy)."""

    def disable_versioning_attempt(self) -> None:
        self._versioning = False


class SilentOffsiteVerifyStore(ObjectLockBackupStore):
    """Defect: verify_offsite returns True unconditionally (no checksum re-read).  The
    ``verify-offsite`` check corrupts the remote bytes and asks for a verdict; this fake would
    answer True, and the check fails it."""

    def verify_offsite(self, offsite_id: str) -> bool:
        self._get_copy(offsite_id)
        return True


class LossyOffsiteRestoreStore(ObjectLockBackupStore):
    """Defect: restore_from_offsite drops the first file (silent data loss).  The
    ``copy-offsite-roundtrip`` and ``restore-from-offsite`` checks both catch it."""

    def restore_from_offsite(self, offsite_id: str) -> dict[str, bytes]:
        data = super().restore_from_offsite(offsite_id)
        if data:
            k = next(iter(sorted(data)))
            data.pop(k)
        return data
