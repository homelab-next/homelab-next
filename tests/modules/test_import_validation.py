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


# -- one migration suite run per stateful slot ----------------------------------------------


def test_every_stateful_slot_declares_export_formats():
    assert STATEFUL, "the slot registry has no stateful slot"
    for slot in STATEFUL:
        assert SLOTS[slot].get("export_formats"), slot


@pytest.mark.parametrize("slot", STATEFUL)
def test_the_migration_suite_passes_for_each_stateful_slot(slot):
    """The reference importer, configured as this slot with its export formats, meets the MUST.
    A real provider proves the same once its slot protocol gains export and import_ (rule 3)."""
    suite = load_module("migration").SUITE
    fmts = tuple(SLOTS[slot]["export_formats"])
    results = run_checks(suite, lambda: FakeMigratable(slot, fmts))
    failed = [(r.check, r.evidence) for r in results if not r.ok]
    assert failed == [], failed
    assert {r.check for r in results if r.status == "pass"} == set(suite.ids())


def test_a_root_with_a_trailing_slash_swapped_for_a_link_is_not_followed(tmp_path, monkeypatch):
    m = _tree(tmp_path / "t", {"f": b"x"})
    _tree(tmp_path / "outside", {"f": b"x"})
    real = ic.check_tree

    def check_then_swap(*a, **k):
        out = real(*a, **k)
        (tmp_path / "t").rename(tmp_path / "t.old")
        os.symlink(tmp_path / "outside", tmp_path / "t", target_is_directory=True)
        return out

    assert ic.check_tree(str(tmp_path / "t") + "/", m) == []
    monkeypatch.setattr(ic, "check_tree", check_then_swap)
    check_then_swap(str(tmp_path / "t") + "/", m)
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


def test_an_oversize_path_is_cheap_and_its_refusal_short():
    import time

    m = _manifest([_entry("a/" * 5_000_000 + "b", b"z")])
    t0 = time.monotonic()
    problems = ic.check_manifest(m)
    assert time.monotonic() - t0 < 1.0
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
