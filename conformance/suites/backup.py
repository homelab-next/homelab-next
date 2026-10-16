# SPDX-License-Identifier: Apache-2.0
"""``backup`` (extended): snapshots are immutable, restores exact, verification honest."""

from __future__ import annotations

from conformance.fakes.backup_store import AliasingBackupStore, FakeBackupStore
from conformance.protocols.backup import NoSuchSnapshot
from homelabnext.conform.core import Mutant, Suite

from ._util import raises, uniq

SUITE = Suite(
    "backup",
    "immutable snapshots, exact restores, checksum verification and retention",
    "conformance.protocols.backup:BackupStore",
    tier="extended",
)


def _src():
    return uniq("src")


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


def make_fake():
    return FakeBackupStore()


MUTANTS = {
    "snapshot-aliases-live-data": Mutant(
        AliasingBackupStore,
        "snapshot-is-immutable",
        "the snapshot keeps a reference to the live data",
    ),
}
