# SPDX-License-Identifier: Apache-2.0
"""Contract for ``backup`` (extended suite): immutable snapshots, verified restores, retention.

A *source* is a named dataset (``{path: bytes}``).  ``snapshot`` freezes it; later changes to the
source never alter an existing snapshot; ``restore`` returns exactly the frozen content;
``verify`` re-checks the stored bytes against the checksum recorded at snapshot time.

Beyond the on-site contract, a store that declares the ``offsite-immutable`` product feature
also carries a second lane: a copy of a local snapshot pushed to a remote object store whose
retention window **cannot be shortened** and whose versioning **cannot be disabled** by the
credential the automation holds.  The six operations of that lane (``copy_offsite``,
``verify_offsite``, ``restore_from_offsite``, and the three attempts ``delete_offsite_attempt``,
``shorten_retention_attempt``, ``disable_versioning_attempt`` that MUST all raise
:class:`OffsiteImmutable`) are what the checks named in the suite probe.  The three "attempts"
are not actions an operator wants to succeed: they are the way the suite asks the subject to
prove that the remote refuses them, which is the whole point of an off-site immutable copy
(ADR-0042 F-09, the "1" of 3-2-1).
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

__all__ = [
    "BackupError",
    "BackupStore",
    "NoSuchOffsiteCopy",
    "NoSuchSnapshot",
    "OffsiteCopy",
    "OffsiteImmutable",
    "Snapshot",
]


class BackupError(Exception):
    pass


class NoSuchSnapshot(BackupError):
    pass


class NoSuchOffsiteCopy(BackupError):
    pass


class OffsiteImmutable(BackupError):
    """Raised when the remote refuses an action the credential has no authority for.

    The three operations the automation MUST NOT be able to complete - delete an offsite copy,
    shorten its retention window, disable versioning on the bucket - raise this.  A subject that
    lets any of them succeed is one credential compromise away from losing the last copy.
    """


@dataclass(frozen=True)
class Snapshot:
    id: str
    source: str
    seq: int  # 1, 2, 3 ... per source
    files: int
    checksum: str


@dataclass(frozen=True)
class OffsiteCopy:
    """An off-site copy of one snapshot.  ``retain_until`` is the remote's locked window
    (seconds since the Unix epoch, 0 for an unlocked copy used only by fixtures).  ``checksum``
    is the snapshot's checksum, re-recorded on the remote so a reader can verify the local
    snapshot and the remote agree without a restore."""

    id: str
    snapshot_id: str
    source: str
    files: int
    checksum: str
    retain_until: float


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

    # ---- off-site immutable lane (feature ``offsite-immutable``) -------------------------
    # Subjects that declare the ``offsite-immutable`` product feature implement these too; the
    # suite checks that need them require that feature and are skipped on a subject without.
    def copy_offsite(self, snapshot_id: str) -> OffsiteCopy:
        """Push the snapshot to the remote under a locked retention window; idempotent for the
        same ``snapshot_id`` (a second call returns the first copy).  Raises NoSuchSnapshot."""

    def verify_offsite(self, offsite_id: str) -> bool:
        """True if the remote still holds the bytes under the checksum this copy recorded.
        Raises NoSuchOffsiteCopy."""

    def restore_from_offsite(self, offsite_id: str) -> dict[str, bytes]:
        """Pull the copy back and return its content.  Raises NoSuchOffsiteCopy."""

    def delete_offsite_attempt(self, offsite_id: str) -> None:
        """MUST raise :class:`OffsiteImmutable` while the copy is inside its retention window.

        This is not an action the automation wants to succeed: it is the suite's way of asking
        the subject to prove that the credential it holds cannot delete the remote copy."""

    def shorten_retention_attempt(self, offsite_id: str, retain_until: float) -> None:
        """MUST raise :class:`OffsiteImmutable` when ``retain_until`` is earlier than the lock
        currently records.  Lengthening is allowed, but is not what this probe is for."""

    def disable_versioning_attempt(self) -> None:
        """MUST raise :class:`OffsiteImmutable`: the bucket's versioning cannot be turned off by
        the automation's credential.  A remote that lets this succeed is one API call away from
        a destructive overwrite of every prior copy."""
