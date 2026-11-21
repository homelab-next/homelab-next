# SPDX-License-Identifier: Apache-2.0
"""The graph-store role's backup tool (files/synapse_cortex_backup.py): seal, check, stage and prune.

A sealed backup passes the check; a changed byte, an extra or a missing file, a link, a hard link, an
unsealed directory, counts that differ or are empty and a directory that is not a service directory are
each refused by name; stage copies exactly the listed files into a new directory and refuses a shallow,
existing, nested or linked destination, and never deletes; prune removes only the oldest sealed backups
by their own names and refuses what is not a direct child, a bad keep and a link."""

from __future__ import annotations

import importlib.util
import io
import json
import os
from pathlib import Path

import pytest

from tests.modules.graph_store_module import TOOL

spec = importlib.util.spec_from_file_location("backup_tool", TOOL)
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)

COUNTS = {"inet:fqdn": 3, "inet:ipv4": 5}


def make_backup(parent: Path, name: str = "hnx-20261121T000000Z") -> Path:
    d = parent / name
    (d / "slabs" / "cell.lmdb").mkdir(parents=True)
    (d / "cell.guid").write_text("guid-1")
    (d / "slabs" / "cell.lmdb" / "data.mdb").write_bytes(b"slab" * 1000)
    (d / "layers" / "l1").mkdir(parents=True)
    (d / "layers" / "l1" / "data.mdb").write_bytes(b"layer" * 500)
    return d


def seal(d: Path, before=COUNTS, after=None) -> None:
    manifest = {
        "version": "v2.247.0",
        "counts_before": before,
        "counts_after": COUNTS if after is None else after,
    }
    tool_stdin = io.StringIO(json.dumps(manifest))
    import sys

    old = sys.stdin
    sys.stdin = tool_stdin
    try:
        tool.seal(str(d))
    finally:
        sys.stdin = old


def refused(fn, *a) -> str:
    with pytest.raises(SystemExit) as e:
        fn(*a)
    assert "backup refused" in str(e.value)
    return str(e.value)


def test_a_sealed_backup_passes_the_check_and_is_listed_exactly(tmp_path):
    d = make_backup(tmp_path / "var" / "lib" / "x")
    seal(d)
    m = tool.check(str(d))
    assert m["format"] == tool.FORMAT and m["counts_after"] == COUNTS
    rows = [json.loads(x) for x in (d / tool.LISTING).read_text().splitlines()]
    assert [r["key"] for r in rows] == [
        "cell.guid",
        "layers/l1/data.mdb",
        "slabs/cell.lmdb/data.mdb",
    ]
    assert oct((d / tool.MANIFEST).stat().st_mode & 0o777) == "0o600"


def test_sealing_twice_is_refused(tmp_path):
    d = make_backup(tmp_path / "var" / "lib" / "x")
    seal(d)
    assert "sealed once" in refused(seal, d)


def test_a_backup_whose_counts_differ_is_refused_by_the_seal_and_by_the_check(tmp_path):
    d = make_backup(tmp_path / "var" / "lib" / "x")
    assert "changed while the backup was taken" in refused(
        seal, d, COUNTS, {**COUNTS, "inet:ipv4": 6}
    )
    assert "changed while the backup was taken" in refused(tool.check, str(d))


@pytest.mark.parametrize(
    "counts", [{}, {"inet:ipv4": 0}, None, {"inet:ipv4": -1}, {"inet:ipv4": True}]
)
def test_an_empty_or_malformed_graph_is_never_a_backup_to_restore(tmp_path, counts):
    d = make_backup(tmp_path / "var" / "lib" / "x")
    with pytest.raises(SystemExit) as e:
        seal(d, counts, counts)
    assert "refused" in str(e.value)


def test_a_changed_byte_an_extra_a_missing_file_and_an_unsealed_directory_are_refused(tmp_path):
    base = tmp_path / "var" / "lib" / "x"
    d = make_backup(base)
    seal(d)
    (d / "slabs" / "cell.lmdb" / "data.mdb").write_bytes(b"slab" * 999 + b"xxxx")
    assert "not exactly what its listing says" in refused(tool.check, str(d))
    d2 = make_backup(base, "hnx-20261121T000001Z")
    seal(d2)
    (d2 / "extra.bin").write_text("x")
    assert "extra" in refused(tool.check, str(d2))
    d3 = make_backup(base, "hnx-20261121T000002Z")
    seal(d3)
    (d3 / "layers" / "l1" / "data.mdb").unlink()
    assert "missing" in refused(tool.check, str(d3))
    d4 = make_backup(base, "hnx-20261121T000003Z")
    assert "never sealed" in refused(tool.check, str(d4))


def test_a_link_a_hard_link_and_a_special_file_are_refused(tmp_path):
    base = tmp_path / "var" / "lib" / "x"
    d = make_backup(base)
    seal(d)
    os.symlink("/etc/hostname", d / "link")
    assert "link" in refused(tool.check, str(d))
    os.unlink(d / "link")
    os.link(d / "cell.guid", d / "again")
    assert "single-link" in refused(tool.check, str(d))
    os.unlink(d / "again")
    os.mkfifo(d / "fifo")
    assert "plain" in refused(tool.check, str(d))


def test_a_directory_that_is_not_a_service_directory_is_refused(tmp_path):
    d = tmp_path / "var" / "lib" / "x" / "hnx-20261121T000000Z"
    d.mkdir(parents=True)
    (d / "notes.txt").write_text("hello")
    assert "not a service directory" in refused(seal, d)


@pytest.mark.parametrize("path", ["relative/dir", "/tmp", "/var/lib/x/../y", "/var/lib//x"])
def test_a_shallow_relative_or_non_canonical_path_is_refused(path):
    refused(tool.check, path)


def test_stage_copies_exactly_the_listed_files_and_not_the_manifest(tmp_path):
    base = tmp_path / "var" / "lib" / "x"
    d = make_backup(base)
    seal(d)
    out = base / "storage.restoring"
    m = tool.stage(str(d), str(out))
    assert m["counts_after"] == COUNTS
    got = sorted(str(p.relative_to(out)) for p in out.rglob("*") if p.is_file())
    assert got == ["cell.guid", "layers/l1/data.mdb", "slabs/cell.lmdb/data.mdb"]
    assert (out / "cell.guid").read_text() == "guid-1"
    assert oct(out.stat().st_mode & 0o777) == "0o700"
    assert (d / "cell.guid").exists()  # the source is untouched


def test_stage_refuses_an_unchecked_source_and_never_writes(tmp_path):
    base = tmp_path / "var" / "lib" / "x"
    d = make_backup(base)
    seal(d)
    (d / "cell.guid").write_text("tampered")
    out = base / "storage.restoring"
    refused(tool.stage, str(d), str(out))
    assert not out.exists()


def test_stage_refuses_an_existing_nested_or_linked_destination(tmp_path):
    base = tmp_path / "var" / "lib" / "x"
    d = make_backup(base)
    seal(d)
    (base / "there").mkdir()
    assert "exists" in refused(tool.stage, str(d), str(base / "there"))
    assert "nested" in refused(tool.stage, str(d), str(d / "inside"))
    real = base / "real"
    real.mkdir()
    (base / "alias").symlink_to(real)
    refused(tool.stage, str(d), str(base / "alias" / "child"))
    assert not (real / "child").exists()
    refused(tool.stage, str(d), "/tmp/new")  # a shallow destination's parent


def test_prune_removes_the_oldest_sealed_beyond_keep_and_nothing_else(tmp_path):
    base = tmp_path / "var" / "lib" / "backups"
    names = [f"hnx-2026112{i}T000000Z" for i in range(1, 5)]
    for n in names:
        seal(make_backup(base, n))
    unsealed = make_backup(base, "hnx-20261130T000000Z")  # an interrupted one: never touched
    other = base / "keep-me"
    other.mkdir()
    (other / "f").write_text("x")
    assert tool.prune(str(base), 2) == names[:2]
    assert sorted(p.name for p in base.iterdir()) == sorted([*names[2:], unsealed.name, "keep-me"])
    assert tool.prune(str(base), 2) == []  # nothing more to remove


def test_prune_refuses_a_bad_keep_a_linked_directory_and_a_shallow_one(tmp_path):
    base = tmp_path / "var" / "lib" / "backups"
    seal(make_backup(base, "hnx-20261121T000000Z"))
    assert "at least one" in refused(tool.prune, str(base), 0)
    outside = tmp_path / "var" / "lib" / "outside"
    outside.mkdir()
    (outside / "important").write_text("x")
    link = tmp_path / "var" / "lib" / "linked"
    link.symlink_to(base)
    refused(tool.prune, str(link), 1)
    refused(tool.prune, "/var", 1)
    assert (outside / "important").exists()


def test_a_symlinked_backup_name_is_not_followed_by_prune(tmp_path):
    base = tmp_path / "var" / "lib" / "backups"
    base.mkdir(parents=True)
    victim = tmp_path / "var" / "lib" / "victim"
    seal(make_backup(tmp_path / "var" / "lib", "victim"))
    (base / "hnx-20261121T000000Z").symlink_to(victim)
    seal(make_backup(base, "hnx-20261121T000001Z"))
    seal(make_backup(base, "hnx-20261121T000002Z"))
    assert tool.prune(str(base), 1) == ["hnx-20261121T000001Z"]
    assert (victim / "cell.guid").exists()
    assert (base / "hnx-20261121T000000Z").is_symlink()  # skipped, not removed


def test_the_command_line_usage_error_is_two(tmp_path):
    assert tool.main(["tool"]) == 2


def test_discard_removes_an_unsealed_or_inconsistent_directory_and_never_a_sealed_one(tmp_path):
    base = tmp_path / "var" / "lib" / "backups"
    unsealed = make_backup(base, "hnx-20261121T000001Z")
    assert tool.discard(str(base), unsealed.name) is True and not unsealed.exists()
    moved = make_backup(base, "hnx-20261121T000002Z")
    refused(seal, moved, COUNTS, {**COUNTS, "inet:ipv4": 6})  # sealed but inconsistent
    assert tool.discard(str(base), moved.name) is True and not moved.exists()
    good = make_backup(base, "hnx-20261121T000003Z")
    seal(good)
    assert "sealed backup" in refused(tool.discard, str(base), good.name)
    assert good.exists()
    assert tool.discard(str(base), "hnx-20261121T000009Z") is False  # nothing there


def test_discard_refuses_foreign_names_and_links(tmp_path):
    base = tmp_path / "var" / "lib" / "backups"
    base.mkdir(parents=True)
    keep = base / "operators-notes"
    keep.mkdir()
    refused(tool.discard, str(base), "operators-notes")
    refused(tool.discard, str(base), "../x")
    victim = make_backup(tmp_path / "var" / "lib", "victim")
    (base / "hnx-20261121T000004Z").symlink_to(victim)
    refused(tool.discard, str(base), "hnx-20261121T000004Z")
    assert keep.exists() and (victim / "cell.guid").exists()
