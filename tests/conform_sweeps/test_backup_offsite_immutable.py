# SPDX-License-Identifier: Apache-2.0
"""The backup suite's off-site immutable lane (ADR-0042 F-09; audit B5; 2026-11-24 options note).

Six checks probe one new property of the backup capability: a copy exists on a remote whose
retention window CANNOT be shortened and whose versioning CANNOT be disabled by the credential
the automation holds.  Three of them (``delete-must-fail``, ``shorten-retention-must-fail``,
``disable-versioning-must-fail``) are "must-fail" probes - they are not actions an operator wants
to succeed, they are the way the suite asks the subject to prove that its credential cannot
perform them.  Each has its own mutant; every mutant is caught by its named check.

This file is deliberately targeted at the lane: ``tests/conform/test_conform_suites.py`` runs
the whole suite shape and fake coverage against every capability, and
``tests/conform_sweeps/test_conform_mutants.py`` runs every mutant through its suite.  The
properties below are what the lane PROMISES - the guarantees a caller can rely on and a reviewer
should look for when the fake is replaced by a real restic repository.
"""

from __future__ import annotations

import pytest

from conformance.fakes.backup_store import (
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
from conformance.suites.backup import SUITE
from homelabnext.conform.core import run_checks
from homelabnext.conform.registry import load_module

OFFSITE_CHECKS = {
    "copy-offsite-roundtrip",
    "verify-offsite",
    "delete-must-fail",
    "shorten-retention-must-fail",
    "disable-versioning-must-fail",
    "restore-from-offsite",
}


# ---- the lane's own promises ----------------------------------------------------------------


def test_default_fake_declares_the_offsite_immutable_feature():
    """The six off-site checks ``require`` the ``offsite-immutable`` feature; a default fake
    that did not declare it would silently skip them all."""
    assert "offsite-immutable" in ObjectLockBackupStore().features


def test_on_site_only_fake_skips_the_offsite_lane():
    """A subject that does not declare ``offsite-immutable`` runs the nine on-site checks and
    skips the six off-site ones: a plain FakeBackupStore still conforms to the on-site contract.
    """
    results = run_checks(SUITE, FakeBackupStore)
    by_id = {r.check: r for r in results}
    for cid in OFFSITE_CHECKS:
        assert by_id[cid].status == "skip", by_id[cid]
    assert all(r.status == "pass" for cid, r in by_id.items() if cid not in OFFSITE_CHECKS)


def test_copy_offsite_preserves_bytes_and_locks_the_copy():
    b = ObjectLockBackupStore()
    data = {"etc/app.conf": b"a=1\n", "var/blob.bin": bytes(range(256))}
    snap = b.snapshot("src", data)
    copy = b.copy_offsite(snap.id)
    assert copy.snapshot_id == snap.id
    assert copy.checksum == snap.checksum
    assert copy.retain_until > 0, "a copy with no retention window is not immutable"
    assert b.restore_from_offsite(copy.id) == data


def test_copy_offsite_is_idempotent_for_the_same_snapshot():
    """A real restic repository, pointed at the same snapshot twice, uploads once and dedups;
    the fake's ``copy_offsite`` returns the first copy on a second call so a weekly timer that
    runs twice does not write the bucket twice."""
    b = ObjectLockBackupStore()
    snap = b.snapshot("src", {"k": b"v"})
    one = b.copy_offsite(snap.id)
    two = b.copy_offsite(snap.id)
    assert one == two


def test_copy_offsite_raises_for_an_unknown_snapshot():
    b = ObjectLockBackupStore()
    with pytest.raises(NoSuchSnapshot):
        b.copy_offsite("src@999")


def test_verify_offsite_catches_remote_corruption():
    b = ObjectLockBackupStore()
    snap = b.snapshot("src", {"k": b"value"})
    copy = b.copy_offsite(snap.id)
    assert b.verify_offsite(copy.id) is True
    b.corrupt_offsite(copy.id)
    assert b.verify_offsite(copy.id) is False


def test_verify_offsite_raises_for_an_unknown_copy():
    b = ObjectLockBackupStore()
    with pytest.raises(NoSuchOffsiteCopy):
        b.verify_offsite("offsite:does-not-exist")


def test_delete_offsite_attempt_refuses_inside_the_window():
    b = ObjectLockBackupStore()
    snap = b.snapshot("src", {"k": b"v"})
    copy = b.copy_offsite(snap.id)
    with pytest.raises(OffsiteImmutable):
        b.delete_offsite_attempt(copy.id)
    assert b.verify_offsite(copy.id) is True


def test_shorten_retention_attempt_refuses_a_shorter_window():
    b = ObjectLockBackupStore()
    snap = b.snapshot("src", {"k": b"v"})
    copy = b.copy_offsite(snap.id)
    with pytest.raises(OffsiteImmutable):
        b.shorten_retention_attempt(copy.id, copy.retain_until - 1.0)


def test_disable_versioning_attempt_always_refuses():
    b = ObjectLockBackupStore()
    with pytest.raises(OffsiteImmutable):
        b.disable_versioning_attempt()


def test_restore_from_offsite_matches_the_snapshot():
    b = ObjectLockBackupStore()
    data = {"etc/app.conf": b"tenant=1\n"}
    snap = b.snapshot("src", data)
    copy = b.copy_offsite(snap.id)
    assert b.restore_from_offsite(copy.id) == data


def test_restore_from_offsite_raises_for_an_unknown_copy():
    b = ObjectLockBackupStore()
    with pytest.raises(NoSuchOffsiteCopy):
        b.restore_from_offsite("offsite:does-not-exist")


# ---- the mutants and the checks that name them ---------------------------------------------


@pytest.mark.parametrize(
    ("factory", "fails"),
    [
        (DeletableOffsiteStore, "delete-must-fail"),
        (ShortenableOffsiteStore, "shorten-retention-must-fail"),
        (VersioningDisablableOffsiteStore, "disable-versioning-must-fail"),
        (SilentOffsiteVerifyStore, "verify-offsite"),
        (LossyOffsiteRestoreStore, "copy-offsite-roundtrip"),
    ],
)
def test_each_offsite_mutant_is_caught_by_its_named_check(factory, fails):
    """Every mutant has the features its subject declares, so a check never fails merely for a
    missing feature; the named check fails, and the suite as a whole reads as not-ok."""
    results = run_checks(SUITE, factory, features=factory().features)
    failed = [r.check for r in results if not r.ok]
    assert fails in failed, f"{factory.__name__}: expected {fails!r} in {failed}"
    # the check named must be a MUST, so the mutant actually fails the capability
    spec = next(s for s in SUITE.specs if s.id == fails)
    assert spec.severity == "must"


def test_every_offsite_mutant_is_in_the_suite_MUTANTS_table():
    """A mutant without an entry in ``MUTANTS`` cannot be run by ``hnx conform mutants``; this is
    the single table that keeps the ``test_conform_mutants`` sweep honest."""
    mutants = load_module("backup").MUTANTS
    factories = {m.factory for m in mutants.values()}
    for broken in (
        DeletableOffsiteStore,
        ShortenableOffsiteStore,
        VersioningDisablableOffsiteStore,
        SilentOffsiteVerifyStore,
        LossyOffsiteRestoreStore,
    ):
        assert broken in factories, f"{broken.__name__} is not in MUTANTS"
