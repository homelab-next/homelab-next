# SPDX-License-Identifier: Apache-2.0
import os
import pathlib
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor

import pytest

from homelabnext.registers import ids

REPO = pathlib.Path(__file__).resolve().parents[2]
TOOL = REPO / "tools" / "register_ids.py"

ENTRY = """\
- id: {id}
  title: entry {id}
  note: this entry cites {id} in its own body
"""


def git(cwd, *args):
    subprocess.run(
        [
            "git",
            "-c",
            "user.email=t@example.org",
            "-c",
            "user.name=t",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "init.defaultBranch=main",
            *args,
        ],
        cwd=cwd,
        check=True,
        capture_output=True,
    )


@pytest.fixture
def repo(tmp_path):
    r = tmp_path / "repo"
    r.mkdir()
    git(r, "init")
    (r / "lessons.yml").write_text(
        "# header comment\nlessons:\n" + ENTRY.format(id="LL-001") + ENTRY.format(id="LL-002")
    )
    git(r, "add", "-A")
    git(r, "commit", "-m", "seed")
    return r


def run_tool(repo, *args, env=None):
    e = {**os.environ, **(env or {})}
    return subprocess.run(
        [sys.executable, str(TOOL), *args], cwd=repo, capture_output=True, text=True, env=e
    )


def test_alloc_continues_after_highest(repo):
    assert ids.allocate(repo, "lessons.yml", "LL", 2) == ["LL-003", "LL-004"]
    assert ids.allocate(repo, "lessons.yml", "LL") == ["LL-005"]  # hwm remembers uncommitted claims


def test_alloc_rejects_unknown_register_and_prefix(repo):
    with pytest.raises(ids.IdError):
        ids.allocate(repo, "notes.yml", "LL")
    with pytest.raises(ids.IdError):
        ids.allocate(repo, "lessons.yml", "RB")


def test_concurrent_allocation_gives_n_and_n_plus_one(repo, tmp_path):
    env = {"HOMELABNEXT_IDS_STATE": str(tmp_path / "shared-state")}

    def one(_):
        r = run_tool(repo, "alloc", "lessons.yml", env=env)
        assert r.returncode == 0, r.stderr
        return r.stdout.strip()

    with ThreadPoolExecutor(8) as ex:
        got = list(ex.map(one, range(8)))
    assert sorted(got) == [f"LL-{n:03d}" for n in range(3, 11)]  # no duplicates, no gaps


def test_resolve_two_authors_get_distinct_ids_and_self_citations_follow(repo, tmp_path):
    env = {"HOMELABNEXT_IDS_STATE": str(tmp_path / "s2")}
    wt_b = tmp_path / "wt-b"
    git(repo, "worktree", "add", "-b", "b", str(wt_b))
    for r in (repo, wt_b):
        with open(r / "lessons.yml", "a") as f:
            f.write(ENTRY.format(id="LL-NEW"))
    out_a = run_tool(repo, "resolve", "lessons.yml", env=env)
    out_b = run_tool(wt_b, "resolve", "lessons.yml", env=env)
    assert out_a.returncode == out_b.returncode == 3  # 3 = rewrote something
    ta = (repo / "lessons.yml").read_text()
    tb = (wt_b / "lessons.yml").read_text()
    assert "LL-NEW" not in ta + tb
    a_new = ids.ids_in(ta, ids.SPECS["lessons"])[-1]
    b_new = ids.ids_in(tb, ids.SPECS["lessons"])[-1]
    assert {a_new, b_new} == {"LL-003", "LL-004"}
    assert f"this entry cites {a_new} in its own body" in ta  # self-citation rewritten
    assert ta.startswith("# header comment")  # comments preserved
    assert run_tool(repo, "resolve", "lessons.yml", env=env).returncode == 0  # idempotent


def test_resolve_never_renumbers_existing(repo):
    before = (repo / "lessons.yml").read_text()
    assert ids.resolve_file(repo, "lessons.yml") == []
    assert (repo / "lessons.yml").read_text() == before


def test_check_lost_clean_and_dropped(repo):
    assert run_tool(repo, "check-lost", "lessons.yml").returncode == 0
    text = (repo / "lessons.yml").read_text()
    (repo / "lessons.yml").write_text(text.replace(ENTRY.format(id="LL-002"), ""))
    r = run_tool(repo, "check-lost", "lessons.yml")
    assert r.returncode == 1 and "LL-002" in r.stderr
    r = run_tool(repo, "check-lost", "lessons.yml", env={"REGISTER_IDS_ALLOW_DROP": "LL-002"})
    assert r.returncode == 0  # deliberate consolidation


def test_check_lost_detects_entry_lost_in_merge_resolution(repo):
    git(repo, "checkout", "-b", "third")
    with open(repo / "lessons.yml", "a") as f:
        f.write(ENTRY.format(id="LL-005"))
    git(repo, "commit", "-am", "third adds LL-005")
    git(repo, "checkout", "main")
    with open(repo / "lessons.yml", "a") as f:
        f.write(ENTRY.format(id="LL-006"))
    git(repo, "commit", "-am", "main adds LL-006")
    merge = subprocess.run(
        ["git", "-c", "user.email=t@example.org", "-c", "user.name=t", "merge", "third"],
        cwd=repo,
        capture_output=True,
    )
    assert merge.returncode != 0 and (repo / ".git" / "MERGE_HEAD").exists()  # a real conflict, not an ident error
    # Botched hand resolution: keep our side, silently drop the other side's entry.
    (repo / "lessons.yml").write_text(
        (repo / "lessons.yml").read_text().split("<<<<<<<")[0] + ENTRY.format(id="LL-006")
    )
    assert ids.check_lost(repo, "lessons.yml") == ["LL-005"]  # visible only via MERGE_HEAD
    assert run_tool(repo, "check-lost", "lessons.yml").returncode == 1


def test_unprotected_register_may_delete(tmp_path):
    r = tmp_path / "q"
    r.mkdir()
    git(r, "init")
    (r / "queue.yml").write_text(ENTRY.format(id="PRJ-001") + ENTRY.format(id="PRJ-001.1"))
    git(r, "add", "-A")
    git(r, "commit", "-m", "x")
    (r / "queue.yml").write_text(ENTRY.format(id="PRJ-001"))
    assert ids.check_lost(r, "queue.yml") == []


def test_alloc_cli_needs_prefix_for_multi_prefix_register(tmp_path):
    r = tmp_path / "inv"
    r.mkdir()
    git(r, "init")
    (r / "invariants.yml").write_text("criteria:\n" + ENTRY.format(id="X-01"))
    git(r, "add", "-A")
    git(r, "commit", "-m", "x")
    assert run_tool(r, "alloc", "invariants.yml").returncode == 1
    out = run_tool(r, "alloc", "invariants.yml", "--prefix", "X")
    assert out.stdout.strip() == "X-02"
