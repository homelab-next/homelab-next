# SPDX-License-Identifier: Apache-2.0
"""The adversary-emulation module's export script, ``modules/caldera/roles/caldera/files``.

Export writes a staged snapshot of the dataset roots only (never the generated configuration),
check and restore refuse an unsafe or inconsistent snapshot before changing anything, and an empty
snapshot is an honest export and a refused restore.
"""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "modules" / "caldera" / "roles" / "caldera" / "files" / "caldera_tree.py"
spec = importlib.util.spec_from_file_location("caldera_tree_under_test", SCRIPT)
tree = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tree)


def make_source(base: Path) -> Path:
    src = base / "var" / "src"
    for rel, body in {
        "data/object_store": b"store-bytes",
        "data/adversaries/a1.yml": b"id: a1\n",
        "data/abilities/x/y.yml": b"id: y\n",
        "data/results/r1": b"result",
        "data/payloads/p.bin": b"payload",
        "data/payloads/.gitkeep": b"",
        "conf/agents.yml": b"sleep: 1\n",
        "conf/local.yml": b"generated: configuration\n",
        "data/backup/b.tar.gz": b"not exported",
    }.items():
        p = src / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(body)
    return src


@pytest.fixture
def work(tmp_path):
    src = make_source(tmp_path)
    exp = tmp_path / "var" / "export"
    exp.mkdir()
    return src, exp


def keys(snapshot: Path) -> dict[str, str]:
    rows = [json.loads(ln) for ln in (snapshot / "listing.jsonl").read_text().splitlines()]
    return {r["key"]: r["dataset"] for r in rows}


def test_export_lists_only_the_dataset_roots_and_never_the_generated_configuration(work):
    src, exp = work
    out = tree.export(str(src), str(exp))
    snap = Path(out["snapshot"])
    got = keys(snap)
    assert got == {
        "data/object_store": "operations",
        "data/results/r1": "operations",
        "data/adversaries/a1.yml": "adversaries",
        "data/abilities/x/y.yml": "adversaries",
        "conf/agents.yml": "agents",
        "data/payloads/p.bin": "artifacts",
    }
    assert not (snap / "files" / "conf" / "local.yml").exists()
    assert out["files"] == 6 and out["empty"] is False
    assert tree.check(str(snap))["files"] == 6
    assert not [p for p in exp.iterdir() if p.name.startswith(".")]  # no staging left


def test_export_skips_links_and_counts_them(work):
    src, exp = work
    (src / "data" / "results" / "ln").symlink_to("/etc/hostname")
    (src / "data" / "payloads" / "dirln").symlink_to(src / "data" / "abilities")
    out = tree.export(str(src), str(exp))
    assert out["skipped"] == 2
    assert "data/results/ln" not in keys(Path(out["snapshot"]))


def test_an_empty_source_exports_honestly_and_restore_refuses_it(tmp_path):
    src = tmp_path / "var" / "src"
    (src / "data").mkdir(parents=True)
    exp = tmp_path / "var" / "export"
    exp.mkdir()
    out = tree.export(str(src), str(exp))
    assert out["empty"] is True and out["files"] == 0
    with pytest.raises(tree.Refused, match="empty"):
        tree.check(out["snapshot"])


def test_restore_round_trips_into_a_fresh_tree(work, tmp_path):
    src, exp = work
    snap = tree.export(str(src), str(exp))["snapshot"]
    fresh = tmp_path / "fresh" / "tree" / "src"
    fresh.mkdir(parents=True)
    out = tree.restore(snap, str(fresh))
    assert out["restored"] == 6
    assert (fresh / "data" / "abilities" / "x" / "y.yml").read_bytes() == b"id: y\n"
    assert not list(fresh.rglob("*.hnx-restore.tmp"))


@pytest.mark.parametrize(
    "mutate, message",
    [
        (lambda s: (s / "files" / "data" / "object_store").write_bytes(b"tampered!!"), "differs"),
        (
            lambda s: (s / "files" / "data" / "results" / "extra").write_bytes(b"x"),
            "not in its listing",
        ),
        (lambda s: (s / "files" / "data" / "results" / "r1").unlink(), "missing"),
        (lambda s: (s / "files" / "data" / "results" / "ln").symlink_to("/etc/hostname"), "link"),
        (
            lambda s: os.link(
                s / "files" / "data" / "results" / "r1", s / "files" / "data" / "twin"
            ),
            "hard link",
        ),
    ],
)
def test_check_and_restore_refuse_an_unsafe_snapshot_before_writing(
    work, tmp_path, mutate, message
):
    src, exp = work
    snap = Path(tree.export(str(src), str(exp))["snapshot"])
    mutate(snap)
    with pytest.raises(tree.Refused, match=message):
        tree.check(str(snap))
    fresh = tmp_path / "fresh" / "tree" / "src"
    fresh.mkdir(parents=True)
    with pytest.raises(tree.Refused):
        tree.restore(str(snap), str(fresh))
    assert not any(fresh.rglob("*"))


@pytest.mark.parametrize(
    "key",
    [
        "../etc/passwd",
        "/abs",
        "data//x",
        "data/./x",
        "data\\x",
        "conf/local.yml",
        "data/backup/x",
        "data/ab\x01",
    ],
)
def test_a_listing_key_that_traverses_or_leaves_the_dataset_roots_is_refused(work, key):
    src, exp = work
    snap = Path(tree.export(str(src), str(exp))["snapshot"])
    row = {"key": key, "size": 0, "sha256": "0" * 64, "dataset": "artifacts"}
    with open(snap / "listing.jsonl", "a", encoding="utf-8") as f:
        f.write(json.dumps(row) + "\n")
    with pytest.raises(tree.Refused):
        tree.check(str(snap))


def test_a_duplicate_key_compared_case_insensitively_is_refused(work):
    src, exp = work
    snap = Path(tree.export(str(src), str(exp))["snapshot"])
    row = {"key": "data/results/R1", "size": 0, "sha256": "0" * 64, "dataset": "operations"}
    with open(snap / "listing.jsonl", "a", encoding="utf-8") as f:
        f.write(json.dumps(row) + "\n")
    with pytest.raises(tree.Refused, match="repeats"):
        tree.check(str(snap))


def test_restore_refuses_a_link_in_the_target_path_and_a_non_regular_target(work, tmp_path):
    src, exp = work
    snap = tree.export(str(src), str(exp))["snapshot"]
    fresh = tmp_path / "fresh" / "tree" / "src"
    (fresh / "data").mkdir(parents=True)
    (fresh / "data" / "adversaries").symlink_to(tmp_path)
    with pytest.raises(tree.Refused, match="link"):
        tree.restore(snap, str(fresh))
    assert not list(tmp_path.glob("a1.yml"))


def test_shallow_or_non_canonical_paths_are_refused(tmp_path):
    with pytest.raises(tree.Refused, match="three or more"):
        tree.export("/", "/")
    with pytest.raises(tree.Refused, match="canonical"):
        tree.check(str(tmp_path / "a" / ".." / "a"))


def test_the_command_line_exits_zero_on_success_and_two_on_a_refusal(work, tmp_path):
    src, exp = work
    ok = subprocess.run(
        [sys.executable, "-I", str(SCRIPT), "export", str(src), str(exp)],
        capture_output=True, text=True,
    )  # fmt: skip
    assert ok.returncode == 0 and json.loads(ok.stdout)["files"] == 6
    bad = subprocess.run(
        [sys.executable, "-I", str(SCRIPT), "check", str(tmp_path / "nowhere" / "x" / "y")],
        capture_output=True, text=True,
    )  # fmt: skip
    assert bad.returncode == 2 and bad.stderr.startswith("refused:")
    usage = subprocess.run([sys.executable, "-I", str(SCRIPT)], capture_output=True, text=True)
    assert usage.returncode == 2
