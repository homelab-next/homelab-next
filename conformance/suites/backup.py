# SPDX-License-Identifier: Apache-2.0
"""``backup`` (extended): snapshots are immutable, restores exact, verification honest.

The on-site contract is nine checks: a restore returns exactly what was snapshotted, a snapshot
cannot be mutated through its source, verify catches corruption, list is newest-first with
increasing sequence numbers, prune keeps the newest N, sources are independent, an empty dataset
survives the round trip, and a missing snapshot id fails every reader.

A target that declares the ``offsite-immutable`` product feature also passes six further checks
that probe the off-site lane (ADR-0042 F-09; audit B5; the 2026-11-24 options note, Option A):
one round trip, one honest verify, one restore, and three "must fail" probes that ask the
subject to prove its credential CANNOT delete an off-site copy, shorten its retention window or
disable versioning on the bucket.  The "must fail" probes are not actions an operator wants to
succeed - they are the control for the "immutable" word in "off-site immutable", because without
them the off-site copy is one credential compromise away from being deleted with every prior
one.  Each has its own mutant (DeletableOffsiteStore, ShortenableOffsiteStore,
VersioningDisablableOffsiteStore, SilentOffsiteVerifyStore, LossyOffsiteRestoreStore) in
:mod:`conformance.fakes.backup_store`; every mutant is caught by its named check.

The default fake (``make_fake()``) is :class:`ObjectLockBackupStore`, so the suite runs all
fifteen checks against it; a target without the off-site lane (the plain :class:`FakeBackupStore`
is one) still runs the nine on-site checks and skips the six.
"""

from __future__ import annotations

from conformance.fakes.backup_store import (
    AliasingBackupStore,
    DeletableOffsiteStore,
    FakeBackupStore,
    LossyOffsiteRestoreStore,
    ObjectLockBackupStore,
    ShortenableOffsiteStore,
    SilentOffsiteVerifyStore,
    VersioningDisablableOffsiteStore,
)
from conformance.protocols.backup import (
    NoSuchOffsiteCopy,
    NoSuchSnapshot,
    OffsiteImmutable,
)
from homelabnext.conform.core import Mutant, Suite

from ._util import raises, uniq

SUITE = Suite(
    "backup",
    "immutable snapshots, exact restores, checksum verification, retention, "
    "and an off-site immutable copy whose credential cannot delete, shorten or unversion",
    "conformance.protocols.backup:BackupStore",
    tier="extended",
)

#: the feature a subject declares to have its off-site lane probed (``offsite-immutable``, a
#: product feature, not a test hook); the six off-site checks ``require`` it and skip on a
#: subject that does not declare it
OFFSITE = "offsite-immutable"


def _src():
    return uniq("src")


# ---- the on-site contract (nine checks) ------------------------------------------------------


@SUITE.check("snapshot-restore-roundtrip", "a restore returns exactly the snapshotted files")
def _(b):
    data = {"etc/app.conf": b"a=1\n", "var/blob.bin": bytes(range(256))}
    snap = b.snapshot(_src(), data)
    assert b.restore(snap.id) == data and snap.files == 2


@SUITE.check(
    "snapshot-is-immutable", "editing the source dataset afterwards does not change the snapshot"
)
def _(b):
    data = {"k": b"original"}
    snap = b.snapshot(_src(), data)
    data["k"] = b"changed"
    data["new"] = b"x"
    assert b.restore(snap.id) == {"k": b"original"}, "snapshot followed the live data"


@SUITE.check("list-is-newest-first", "snapshots list newest first with increasing sequence numbers")
def _(b):
    s = _src()
    ids = [b.snapshot(s, {"k": bytes([i])}).id for i in range(3)]
    listed = [x.id for x in b.list(s)]
    assert listed == ids[::-1], f"listed {listed}"


@SUITE.check(
    "restore-unknown-raises", "restoring or verifying a missing snapshot raises NoSuchSnapshot"
)
def _(b):
    raises(lambda: b.restore(uniq("ghost")), "restore ghost", NoSuchSnapshot)
    raises(lambda: b.verify(uniq("ghost")), "verify ghost", NoSuchSnapshot)


@SUITE.check("verify-true-for-intact", "an untouched snapshot verifies")
def _(b):
    assert b.verify(b.snapshot(_src(), {"k": b"v"}).id) is True


@SUITE.check(
    "verify-detects-corruption",
    "a snapshot whose bytes changed fails verification",
    requires=["fault-injection"],
)
def _(b):
    snap = b.snapshot(_src(), {"k": b"value"})
    b.corrupt(snap.id)
    assert b.verify(snap.id) is False, "corruption went unnoticed"


@SUITE.check("prune-keeps-newest", "prune keeps the newest N and deletes the rest")
def _(b):
    s = _src()
    ids = [b.snapshot(s, {"k": bytes([i])}).id for i in range(4)]
    gone = b.prune(s, 2)
    assert set(gone) == set(ids[:2]), f"pruned {gone}"
    assert [x.id for x in b.list(s)] == [ids[3], ids[2]], "wrong snapshots survived"
    raises(lambda: b.restore(ids[0]), "restore pruned", NoSuchSnapshot)


@SUITE.check("sources-are-independent", "pruning or snapshotting one source never touches another")
def _(b):
    a, c = _src(), _src()
    sa = b.snapshot(a, {"k": b"a"})
    for i in range(3):
        b.snapshot(c, {"k": bytes([i])})
    b.prune(c, 1)
    assert b.restore(sa.id) == {"k": b"a"}


@SUITE.check("empty-dataset-allowed", "an empty source can be snapshotted and restored")
def _(b):
    snap = b.snapshot(_src(), {})
    assert b.restore(snap.id) == {} and snap.files == 0


# ---- the off-site immutable lane (six checks; feature ``offsite-immutable``) -----------------
# Each probes one property of the off-site copy that makes it worth having: a round trip,
# an honest verify, a working restore, and three "attempts" that MUST raise (delete, shorten,
# disable versioning).  A pass without these would mean the credential can erase the copy, which
# is the whole thing the off-site immutable tier exists to prevent (ADR-0042 F-09).


@SUITE.check(
    "copy-offsite-roundtrip",
    "a snapshot copied off-site reads back byte-for-byte",
    requires=[OFFSITE],
)
def _(b):
    data = {"etc/app.conf": b"a=1\n", "var/blob.bin": bytes(range(256))}
    snap = b.snapshot(_src(), data)
    copy = b.copy_offsite(snap.id)
    assert copy.snapshot_id == snap.id and copy.files == snap.files, (
        f"copy {copy!r} does not refer to the snapshot it was made from"
    )
    assert copy.checksum == snap.checksum, "the copy's checksum does not equal the snapshot's"
    assert copy.retain_until > 0, "a copy with no retention window is not immutable"
    assert b.restore_from_offsite(copy.id) == data, "off-site restore returned different content"


@SUITE.check(
    "verify-offsite",
    "a copy whose remote bytes changed fails verify_offsite",
    requires=[OFFSITE, "fault-injection"],
)
def _(b):
    snap = b.snapshot(_src(), {"k": b"value"})
    copy = b.copy_offsite(snap.id)
    assert b.verify_offsite(copy.id) is True, "an untouched off-site copy did not verify"
    b.corrupt_offsite(copy.id)
    assert b.verify_offsite(copy.id) is False, "off-site corruption went unnoticed"


@SUITE.check(
    "delete-must-fail",
    "the automation credential cannot delete an off-site copy inside its retention window",
    requires=[OFFSITE],
)
def _(b):
    snap = b.snapshot(_src(), {"k": b"v"})
    copy = b.copy_offsite(snap.id)
    raises(
        lambda: b.delete_offsite_attempt(copy.id),
        f"delete_offsite_attempt {copy.id}",
        OffsiteImmutable,
    )
    # the copy must still be there after the refused attempt
    assert b.verify_offsite(copy.id) is True, "the copy was gone after a refused delete"
    assert b.restore_from_offsite(copy.id) == {"k": b"v"}, (
        "the copy lost content after a refused delete"
    )


@SUITE.check(
    "shorten-retention-must-fail",
    "the automation credential cannot shorten a copy's retention window",
    requires=[OFFSITE],
)
def _(b):
    snap = b.snapshot(_src(), {"k": b"v"})
    copy = b.copy_offsite(snap.id)
    # ask for a window one second shorter than what the copy currently records
    raises(
        lambda: b.shorten_retention_attempt(copy.id, copy.retain_until - 1.0),
        f"shorten_retention_attempt {copy.id}",
        OffsiteImmutable,
    )


@SUITE.check(
    "disable-versioning-must-fail",
    "the automation credential cannot turn off versioning on the bucket",
    requires=[OFFSITE],
)
def _(b):
    raises(
        lambda: b.disable_versioning_attempt(),
        "disable_versioning_attempt",
        OffsiteImmutable,
    )


@SUITE.check(
    "restore-from-offsite",
    "a full restore from the off-site copy returns exactly the content of its snapshot",
    requires=[OFFSITE],
)
def _(b):
    data = {"etc/app.conf": b"tenant=1\n", "var/blob.bin": bytes(reversed(range(256)))}
    snap = b.snapshot(_src(), data)
    copy = b.copy_offsite(snap.id)
    assert b.restore_from_offsite(copy.id) == data, "off-site restore lost content"
    # a restore of a missing offsite id must raise, so a typo cannot read as "empty"
    raises(
        lambda: b.restore_from_offsite(uniq("ghost")),
        "restore_from_offsite ghost",
        NoSuchOffsiteCopy,
    )


# ---- fakes and mutants ----------------------------------------------------------------------


def make_fake():
    """The default target carries the off-site lane; the on-site-only fake stays available for
    tests that want to prove the lane really is skipped on a subject that does not declare it."""
    return ObjectLockBackupStore()


def make_on_site_only_fake():
    """The on-site contract alone, used by tests that assert the off-site checks skip when the
    ``offsite-immutable`` feature is not declared."""
    return FakeBackupStore()


MUTANTS = {
    "snapshot-aliases-live-data": Mutant(
        AliasingBackupStore,
        "snapshot-is-immutable",
        "the snapshot keeps a reference to the live data",
    ),
    "offsite-delete-succeeds": Mutant(
        DeletableOffsiteStore,
        "delete-must-fail",
        "the automation credential can delete an off-site copy",
        features=frozenset({OFFSITE, "fault-injection"}),
    ),
    "offsite-retention-shortenable": Mutant(
        ShortenableOffsiteStore,
        "shorten-retention-must-fail",
        "the automation credential can shorten a copy's retention window",
        features=frozenset({OFFSITE, "fault-injection"}),
    ),
    "offsite-versioning-disablable": Mutant(
        VersioningDisablableOffsiteStore,
        "disable-versioning-must-fail",
        "the automation credential can disable versioning on the bucket",
        features=frozenset({OFFSITE, "fault-injection"}),
    ),
    "offsite-verify-silent": Mutant(
        SilentOffsiteVerifyStore,
        "verify-offsite",
        "verify_offsite returns True unconditionally (no checksum re-read)",
        features=frozenset({OFFSITE, "fault-injection"}),
    ),
    "offsite-restore-lossy": Mutant(
        LossyOffsiteRestoreStore,
        "copy-offsite-roundtrip",
        "restore_from_offsite silently drops files",
        features=frozenset({OFFSITE, "fault-injection"}),
    ),
}
