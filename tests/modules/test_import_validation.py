# SPDX-License-Identifier: Apache-2.0
"""Import validation (ADR-0027 follow-up 7): the library's refusals one by one, the race between
the check and the read, the draft export manifest schema, and the ``migration`` suite run once
per stateful slot of the slot registry."""

from __future__ import annotations

import hashlib
import json
import os
import socket
import sys
from pathlib import Path

import pytest
import yaml

from conformance.fakes.migration_store import FakeMigratable
from homelabnext.conform.core import run_checks
from homelabnext.conform.registry import load_module
from homelabnext.modules import importcheck as ic

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT / "tools") not in sys.path:
    sys.path.insert(0, str(ROOT / "tools"))
import schema_check as sc

SLOTS = yaml.safe_load((ROOT / "examples/modules/slots.yml").read_text())["slots"]
STATEFUL = sorted(k for k, v in SLOTS.items() if v.get("stateful"))
SCHEMA = json.loads((ROOT / "schemas/platform/export_manifest.schema.json").read_text())
REGISTRY = sc.build_registry(ROOT)


def _entry(path: str, body: bytes) -> dict:
    return {"path": path, "size": len(body), "sha256": hashlib.sha256(body).hexdigest()}


def _manifest(entries: list[dict], slot: str = "records", fmt: str = "markdown-tree") -> dict:
    return {
        "schema_version": "1.0",
        "slot": slot,
        "format": fmt,
        "files": entries,
        "totals": {"files": len(entries), "bytes": sum(e["size"] for e in entries)},
    }


def _tree(root: Path, files: dict[str, bytes]) -> dict:
    for rel, body in files.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_bytes(body)
    return _manifest([_entry(k, v) for k, v in files.items()])


FILES = {"a.txt": b"alpha\n", "d/b.txt": b"bravo\n"}


def test_a_clean_tree_reads_back_exactly(tmp_path):
    m = _tree(tmp_path, FILES)
    assert ic.check_tree(tmp_path, m) == []
    assert ic.read_tree(tmp_path, m) == FILES


def test_build_manifest_matches_the_schema_and_reads_back(tmp_path):
    _tree(tmp_path, FILES)
    m = ic.build_manifest(tmp_path, "records", "markdown-tree")
    assert sc.errors_for(SCHEMA, m, REGISTRY) == []
    assert [f["path"] for f in m["files"]] == ["a.txt", "d/b.txt"]
    assert ic.read_tree(tmp_path, m, slot="records", formats=["markdown-tree"]) == FILES


def test_build_manifest_refuses_what_an_import_would(tmp_path):
    _tree(tmp_path, FILES)
    os.symlink(tmp_path / "a.txt", tmp_path / "link")
    with pytest.raises(ic.ImportRefused, match="symbolic link"):
        ic.build_manifest(tmp_path, "records", "markdown-tree")


@pytest.mark.parametrize(
    ("path", "why"),
    [
        ("../x", "'..'"),
        ("/etc/x", "absolute"),
        ("a//b", "empty"),
        ("a/./b", "'.'"),
        ("a\\b", "backslash"),
        ("a\nb", "control"),
        ("é.txt", "NFC"),
        ("x/" * 40 + "f", "deeper"),
        ("y" * 1100, "longer"),
    ],
)
def test_a_bad_path_is_refused_by_the_library_and_the_schema(tmp_path, path, why):
    m = _manifest([_entry(path, b"z")])
    assert any(why in p for p in ic.check_manifest(m)), ic.check_manifest(m)
    if why not in ("NFC", "deeper"):  # rules a pattern cannot state
        assert sc.errors_for(SCHEMA, m, REGISTRY), f"the schema accepted {path!r}"


def test_paths_compare_case_insensitively_and_a_file_is_not_a_directory():
    m = _manifest([_entry("A.txt", b"1"), _entry("a.txt", b"2")])
    assert any("case-insensitively" in p for p in ic.check_manifest(m))
    m = _manifest([_entry("a", b"1"), _entry("a/b", b"2")])
    assert any("which is a file" in p for p in ic.check_manifest(m))


def test_totals_must_be_the_sums():
    m = _manifest([_entry("a", b"12")])
    m["totals"] = {"files": 2, "bytes": 99}
    problems = ic.check_manifest(m)
    assert any("totals.files" in p for p in problems) and any("totals.bytes" in p for p in problems)


def test_slot_and_format_are_checked_when_given():
    m = _manifest([], slot="cases", fmt="jsonl")
    assert ic.check_manifest(m, slot="cases", formats=["jsonl"]) == []
    assert any("slot" in p for p in ic.check_manifest(m, slot="records"))
    assert any("format" in p for p in ic.check_manifest(m, formats=["markdown-tree"]))


@pytest.mark.parametrize(
    "bad",
    [
        None,
        [],
        {"schema_version": "1.0"},
        {"files": "x"},
        {**_manifest([]), "files": [{"path": "a"}]},
    ],
)
def test_a_malformed_manifest_is_refused_not_crashed(tmp_path, bad):
    assert ic.check_tree(tmp_path, bad)


def test_limits_are_ceilings(tmp_path):
    m = _tree(tmp_path, {f"f{i}": b"0123456789" for i in range(5)})
    assert any(
        "more than the limit of 4" in p for p in ic.check_tree(tmp_path, m, ic.Limits(max_files=4))
    )
    assert any(
        "over the limit" in p for p in ic.check_tree(tmp_path, m, ic.Limits(max_file_bytes=9))
    )
    assert any(
        "bytes is more than" in p for p in ic.check_tree(tmp_path, m, ic.Limits(max_bytes=49))
    )
    assert ic.check_tree(tmp_path, m, ic.Limits(max_files=5, max_bytes=50, max_file_bytes=10)) == []


def test_a_symlinked_root_is_refused(tmp_path):
    m = _tree(tmp_path / "real", FILES)
    os.symlink(tmp_path / "real", tmp_path / "root")
    assert any("symbolic link" in p for p in ic.check_tree(tmp_path / "root", m))
    with pytest.raises(ic.ImportRefused):
        ic.read_tree(tmp_path / "root", m)


def test_special_files_and_hard_links_are_named(tmp_path):
    m = _tree(tmp_path / "t", FILES)
    os.mkfifo(tmp_path / "t" / "fifo")
    s = socket.socket(socket.AF_UNIX)
    try:
        s.bind(str(tmp_path / "t" / "sock"))
        os.link(tmp_path / "t" / "a.txt", tmp_path / "hard")
        problems = ic.check_tree(tmp_path / "t", m)
    finally:
        s.close()
    assert "'fifo' is a special file" in problems
    assert "'sock' is a special file" in problems
    assert "'a.txt' has 2 hard links" in problems


def test_every_problem_is_reported_at_once(tmp_path):
    m = _tree(tmp_path, FILES)
    (tmp_path / "stray").write_bytes(b"s")
    (tmp_path / "a.txt").write_bytes(b"longer than it was\n")
    m["files"].append(_entry("gone", b"g"))
    m["totals"] = {"files": 3, "bytes": m["totals"]["bytes"] + 1}
    with pytest.raises(ic.ImportRefused) as exc:
        ic.read_tree(tmp_path, m)
    assert len(exc.value.problems) == 3, exc.value.problems


def test_a_file_swapped_for_a_link_after_the_check_is_not_followed(tmp_path, monkeypatch):
    m = _tree(tmp_path / "t", FILES)
    (tmp_path / "secret").write_bytes(b"bravo\n")  # same size and digest as the real file
    real = ic._check_fd

    def check_then_swap(*a, **k):
        out = real(*a, **k)
        (tmp_path / "t" / "d" / "b.txt").unlink()
        os.symlink(tmp_path / "secret", tmp_path / "t" / "d" / "b.txt")
        return out

    monkeypatch.setattr(ic, "_check_fd", check_then_swap)
    with pytest.raises(ic.ImportRefused, match="without following a link"):
        ic.read_tree(tmp_path / "t", m)


def test_a_directory_swapped_for_a_link_after_the_check_is_not_followed(tmp_path, monkeypatch):
    m = _tree(tmp_path / "t", FILES)
    _tree(tmp_path / "elsewhere", {"b.txt": b"bravo\n"})
    real = ic._check_fd

    def check_then_swap(*a, **k):
        out = real(*a, **k)
        (tmp_path / "t" / "d").rename(tmp_path / "old-d")
        os.symlink(tmp_path / "elsewhere", tmp_path / "t" / "d", target_is_directory=True)
        return out

    monkeypatch.setattr(ic, "_check_fd", check_then_swap)
    with pytest.raises(ic.ImportRefused, match="without following a link"):
        ic.read_tree(tmp_path / "t", m)


def test_content_changed_after_the_check_is_caught_by_the_digest(tmp_path, monkeypatch):
    m = _tree(tmp_path, FILES)
    real = ic._check_fd

    def check_then_edit(*a, **k):
        out = real(*a, **k)
        (tmp_path / "a.txt").write_bytes(b"ALPHA\n")
        return out

    monkeypatch.setattr(ic, "_check_fd", check_then_edit)
    with pytest.raises(ic.ImportRefused, match="sha256"):
        ic.read_tree(tmp_path, m)


def test_a_refusal_never_carries_content(tmp_path):
    m = _tree(tmp_path, {"a.txt": b"hunter2-secret\n"})
    m["files"][0]["sha256"] = "0" * 64
    with pytest.raises(ic.ImportRefused) as exc:
        ic.read_tree(tmp_path, m)
    assert "hunter2" not in str(exc.value)


def test_the_schema_negatives_are_refused_by_the_library_too():
    for f in sc.instances_for(ROOT / "schemas/platform/export_manifest.schema.json", "negative"):
        assert ic.check_manifest(json.loads(f.read_text())), f.name


# -- the stateful slots ----------------------------------------------------------------------

#: every stateful slot and what proves its import MUST.  ``reference`` means only the reference
#: importer runs as this slot (the harness self-check below): no provider's ``export``/``import_``
#: exists yet, because no slot protocol has them (rule 3).  When one does, its entry names the
#: adapter whose migration suite run proves it.  A stateful slot missing here fails the test, so a
#: new one cannot arrive without a decision about its migration proof.
MIGRATION_PROOF = {
    "backup": "reference: the backup protocol has no export/import_ yet",
    "broker": "reference: the broker protocol has no export/import_ yet",
    "cases": "reference: the cases protocol has no export/import_ yet",
    "detections": "reference: the detections protocol has no export/import_ yet",
    "dns": "reference: the dns protocol has no export/import_ yet",
    "events": "reference: the events protocol has no export/import_ yet",
    "hot-index": "reference: the slot is provisional (no contract), so nothing can add export/import_",
    "idp": "reference: the idp protocol has no export/import_ yet",
    "lake-catalog": "reference: the lake protocol has no export/import_ yet",
    "object-store": "reference: the object_store protocol has no export/import_ yet",
    "orchestration": "reference: the orchestration protocol has no export/import_ yet",
    "records": "reference: the records protocol has no export/import_ yet",
    "secrets": "reference: the secrets protocol has no export/import_ yet",
}


def test_every_stateful_slot_declares_export_formats_and_a_migration_proof():
    assert STATEFUL, "the slot registry has no stateful slot"
    for slot in STATEFUL:
        assert SLOTS[slot].get("export_formats"), slot
    assert sorted(MIGRATION_PROOF) == STATEFUL, "every stateful slot needs a MIGRATION_PROOF entry"


@pytest.mark.parametrize("slot", STATEFUL)
def test_the_harness_self_check_runs_the_reference_importer_as_each_stateful_slot(slot):
    """The reference importer, labelled with this slot and its export formats, meets the MUST:
    this proves the suite and the library over the registry's names and formats, not any
    provider (see MIGRATION_PROOF)."""
    suite = load_module("migration").SUITE
    fmts = tuple(SLOTS[slot]["export_formats"])
    results = run_checks(suite, lambda: FakeMigratable(slot, fmts))
    failed = [(r.check, r.evidence) for r in results if not r.ok]
    assert failed == [], failed
    assert {r.check for r in results if r.status == "pass"} == set(suite.ids())


def test_a_symlinked_root_named_with_a_trailing_slash_is_refused(tmp_path):
    """Linux ignores O_NOFOLLOW on a path ending in '/': the slash is stripped first."""
    m = _tree(tmp_path / "outside", {"f": b"x"})
    os.symlink(tmp_path / "outside", tmp_path / "t", target_is_directory=True)
    assert ic.check_tree(str(tmp_path / "t") + "/", m)
    with pytest.raises(ic.ImportRefused):
        ic.read_tree(str(tmp_path / "t") + "/", m)


def test_a_root_swapped_for_a_link_between_check_and_open_is_not_followed(tmp_path, monkeypatch):
    m = _tree(tmp_path / "t", {"f": b"x"})
    _tree(tmp_path / "outside", {"f": b"x"})
    real = ic._open_root
    swapped = []

    def swap_then_open(root):
        if not swapped:  # once: the root iter_tree opens is the one it then walks and reads
            (tmp_path / "t").rename(tmp_path / "t.old")
            os.symlink(tmp_path / "outside", tmp_path / "t", target_is_directory=True)
            swapped.append(True)
        return real(root)

    monkeypatch.setattr(ic, "_open_root", swap_then_open)
    with pytest.raises(ic.ImportRefused, match="without following a link"):
        ic.read_tree(str(tmp_path / "t") + "/", m)


def test_a_mount_point_inside_the_tree_is_refused(tmp_path, monkeypatch):
    m = _tree(tmp_path / "t", FILES)
    real = os.path.realpath(tmp_path / "t")
    info = tmp_path / "mountinfo"
    esc = real.replace(" ", "\\040")
    info.write_text(
        f"36 35 98:0 / / rw - ext4 /dev/root rw\n"
        f"40 36 98:0 /x {esc}/d rw - ext4 /dev/root rw\n"
        f"41 36 98:0 /x {esc}x/elsewhere rw - ext4 /dev/root rw\n"
    )
    monkeypatch.setattr(ic, "MOUNTINFO", str(info))
    problems = ic.check_tree(tmp_path / "t", m)
    assert problems == ["'d' is a mount point inside the tree"], problems


def test_an_unreadable_mount_table_refuses(tmp_path, monkeypatch):
    m = _tree(tmp_path / "t", FILES)
    monkeypatch.setattr(ic, "MOUNTINFO", str(tmp_path / "missing"))
    assert any("mount table" in p for p in ic.check_tree(tmp_path / "t", m))


def test_mount_paths_decode_only_mountinfo_escapes(tmp_path, monkeypatch):
    base = tmp_path / "t é"
    m = _tree(base, FILES)
    real = os.fsencode(os.path.realpath(base)).replace(b" ", b"\\040")
    info = tmp_path / "mountinfo"
    info.write_bytes(b"40 36 98:0 /x " + real + b"/d\\134x rw - ext4 /dev/root rw\n")
    monkeypatch.setattr(ic, "MOUNTINFO", str(info))
    assert ic.check_tree(base, m) == ["'d\\\\x' is a mount point inside the tree"]


def test_a_hostile_manifest_is_refused_never_raised():
    for bad in (
        _manifest([_entry("\ud800", b"z")]),
        _manifest([{"path": "a", "size": 10**5000, "sha256": "0" * 64}]),
        {**_manifest([]), "totals": {"files": 10**5000, "bytes": True}},
    ):
        problems = ic.check_manifest(bad)
        assert problems and all(len(p) < 400 for p in problems), problems
    m = _manifest([_entry("a", b"1")])
    m["totals"] = {"files": True, "bytes": 1.0}
    assert any("non-negative integers" in p for p in ic.check_manifest(m))


def test_an_oversize_path_is_refused_first_and_briefly():
    m = _manifest([_entry("a/" * 5_000_000 + "b", b"z")])
    problems = ic.check_manifest(m)
    assert len(problems) == 1 and "longer than" in problems[0] and len(problems[0]) < 200


def test_a_refusal_names_at_most_max_problems(tmp_path):
    m = _manifest([])
    for i in range(ic.MAX_PROBLEMS + 50):
        (tmp_path / f"s{i:04d}").write_bytes(b"s")
    problems = ic.check_tree(tmp_path, m)
    assert len(problems) == ic.MAX_PROBLEMS + 1 and problems[-1] == "... and 50 more"


def test_copy_tree_streams_a_verified_tree_into_place(tmp_path):
    m = _tree(tmp_path / "t", FILES)
    assert ic.copy_tree(tmp_path / "t", m, tmp_path / "dest") == 2
    assert (tmp_path / "dest" / "d" / "b.txt").read_bytes() == b"bravo\n"
    assert oct((tmp_path / "dest" / "a.txt").stat().st_mode & 0o777) == "0o600"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["dest", "t"]


def test_copy_tree_leaves_nothing_on_a_late_refusal_and_never_overwrites(tmp_path):
    m = _tree(tmp_path / "t", FILES)
    m["files"][-1]["sha256"] = hashlib.sha256(b"BRAVO\n").hexdigest()
    with pytest.raises(ic.ImportRefused, match="sha256"):
        ic.copy_tree(tmp_path / "t", m, tmp_path / "dest")
    assert sorted(p.name for p in tmp_path.iterdir()) == ["t"]
    (tmp_path / "dest").mkdir()
    with pytest.raises(ic.ImportRefused, match="already exists"):
        ic.copy_tree(tmp_path / "t", _tree(tmp_path / "t2", FILES), tmp_path / "dest")


def test_a_file_that_grows_after_the_check_is_refused(tmp_path, monkeypatch):
    m = _tree(tmp_path, FILES)
    real = ic._check_fd

    def check_then_grow(*a, **k):
        out = real(*a, **k)
        with open(tmp_path / "a.txt", "ab") as fh:
            fh.write(b"more")
        return out

    monkeypatch.setattr(ic, "_check_fd", check_then_grow)
    with pytest.raises(ic.ImportRefused, match="changed size"):
        ic.read_tree(tmp_path, m)


def test_the_schema_example_is_a_manifest_the_library_accepts():
    for f in sc.instances_for(ROOT / "schemas/platform/export_manifest.schema.json", "examples"):
        assert ic.check_manifest(json.loads(f.read_text())) == [], f.name


def test_limits_are_validated_and_only_tighten():
    for bad in ({"max_files": -1}, {"max_depth": ic.MAX_DEPTH + 1}, {"max_bytes": True}):
        with pytest.raises(ValueError):
            ic.Limits(**bad)
    own = ic.Limits(max_files=10, max_bytes=100)
    t = own.tighten(ic.Limits(max_files=5, max_bytes=1000))
    assert (t.max_files, t.max_bytes) == (5, 100)
    assert own.tighten(None) is own


def test_an_invalid_path_is_not_also_reported_missing(tmp_path):
    m = _tree(tmp_path, FILES)
    m["files"].append(_entry("../x", b"z"))
    problems = ic.check_tree(tmp_path, m)
    assert not any("not in the tree" in p for p in problems), problems


def test_a_file_and_a_directory_differing_in_case_collide():
    m = _manifest([_entry("A", b"1"), _entry("a/b", b"2")])
    assert any("which is a file" in p for p in ic.check_manifest(m))


def test_a_bytes_root_is_accepted(tmp_path):
    m = _tree(tmp_path, FILES)
    assert ic.check_tree(os.fsencode(tmp_path), m) == []


def test_build_manifest_sorts_by_path_and_its_digest_is_stable(tmp_path):
    _tree(tmp_path, {"z.txt": b"z", "a/b.txt": b"b", "m.txt": b"m"})
    m = ic.build_manifest(tmp_path, "records", "markdown-tree")
    assert [f["path"] for f in m["files"]] == ["a/b.txt", "m.txt", "z.txt"]
    shuffled = {**m, "files": list(reversed(m["files"]))}
    assert ic.manifest_sha256(m) == ic.manifest_sha256(shuffled)
    assert ic.manifest_sha256(m) != ic.manifest_sha256({**m, "slot": "cases"})


def test_copy_tree_writes_every_byte_through_short_writes(tmp_path, monkeypatch):
    m = _tree(tmp_path / "t", {"big.bin": bytes(range(256)) * 64})
    real = os.write
    monkeypatch.setattr(ic.os, "write", lambda fd, data: real(fd, bytes(data)[:7]))
    ic.copy_tree(tmp_path / "t", m, tmp_path / "dest")
    assert (tmp_path / "dest/big.bin").read_bytes() == bytes(range(256)) * 64


def test_copy_tree_refuses_a_missing_parent(tmp_path):
    m = _tree(tmp_path / "t", FILES)
    with pytest.raises(ic.ImportRefused, match="parent"):
        ic.copy_tree(tmp_path / "t", m, tmp_path / "no" / "dest")
