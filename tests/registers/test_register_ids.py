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
    assert (
        merge.returncode != 0 and (repo / ".git" / "MERGE_HEAD").exists()
    )  # a real conflict, not an ident error
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


# --- lock state: per repository, private, no symlinks; floor from the upstream default branch ----


def test_state_lives_in_the_git_common_dir_and_is_shared_by_worktrees(repo, tmp_path, monkeypatch):
    monkeypatch.delenv("HOMELABNEXT_IDS_STATE", raising=False)
    wt_b = tmp_path / "wt-b"
    git(repo, "worktree", "add", "-b", "b", str(wt_b))
    assert ids.allocate(repo, "lessons.yml", "LL") == ["LL-003"]
    assert ids.allocate(wt_b, "lessons.yml", "LL") == ["LL-004"]  # the other worktree sees it
    sd = repo / ".git" / "homelabnext" / "register_ids"
    assert ids.state_dir(wt_b) == sd.resolve()
    assert (sd / "lessons.yml.LL.hwm").read_text().strip() == "4"
    assert oct(sd.stat().st_mode & 0o777) == "0o700"
    assert not list(sd.glob("*.tmp"))  # the mark is replaced atomically, no temp file is left


def test_a_different_repository_has_its_own_state(repo, tmp_path, monkeypatch):
    monkeypatch.delenv("HOMELABNEXT_IDS_STATE", raising=False)
    other = tmp_path / "other"
    other.mkdir()
    git(other, "init")
    (other / "lessons.yml").write_text("lessons:\n" + ENTRY.format(id="LL-001"))
    assert ids.allocate(repo, "lessons.yml", "LL") == ["LL-003"]
    assert ids.allocate(other, "lessons.yml", "LL") == ["LL-002"]  # not LL-004


def test_state_dir_open_to_others_is_refused(repo, tmp_path, monkeypatch):
    sd = tmp_path / "open-state"
    sd.mkdir(mode=0o755)
    sd.chmod(0o755)
    monkeypatch.setenv("HOMELABNEXT_IDS_STATE", str(sd))
    with pytest.raises(ids.IdError, match="0700"):
        ids.allocate(repo, "lessons.yml", "LL")


def test_state_dir_symlink_is_refused(repo, tmp_path, monkeypatch):
    real = tmp_path / "real-state"
    real.mkdir(mode=0o700)
    link = tmp_path / "link-state"
    link.symlink_to(real)
    monkeypatch.setenv("HOMELABNEXT_IDS_STATE", str(link))
    with pytest.raises(ids.IdError, match="not a directory"):
        ids.allocate(repo, "lessons.yml", "LL")


@pytest.mark.parametrize("which", ["lock", "hwm"])
def test_symlinked_lock_or_mark_is_refused(repo, tmp_path, monkeypatch, which):
    sd = tmp_path / "st"
    sd.mkdir(mode=0o700)
    monkeypatch.setenv("HOMELABNEXT_IDS_STATE", str(sd))
    victim = tmp_path / "victim.txt"
    victim.write_text("do not touch\n")
    (sd / f"lessons.yml.LL.{which}").symlink_to(victim)
    with pytest.raises(ids.IdError):
        ids.allocate(repo, "lessons.yml", "LL")
    assert victim.read_text() == "do not touch\n"


def _remote_with(tmp_path, name, ident, branch="main"):
    up = tmp_path / name
    up.mkdir()
    git(up, "init")
    git(up, "checkout", "-b", branch)
    (up / "lessons.yml").write_text("lessons:\n" + ENTRY.format(id=ident))
    git(up, "add", "-A")
    git(up, "commit", "-m", "x")
    return up


def test_floor_prefers_upstream_main_in_a_fork(repo, tmp_path):
    up = _remote_with(tmp_path, "project", "LL-040")
    fork = _remote_with(tmp_path, "fork", "LL-007")
    git(repo, "remote", "add", "upstream", str(up))
    git(repo, "remote", "add", "origin", str(fork))
    git(repo, "fetch", "-q", "upstream")
    git(repo, "fetch", "-q", "origin")
    assert ids.upstream_refs(repo)[0] == "upstream/main"
    assert ids.allocate(repo, "lessons.yml", "LL") == ["LL-041"]


def test_floor_uses_origins_default_branch_whatever_its_name(repo, tmp_path):
    origin = _remote_with(tmp_path, "origin-src", "LL-020", branch="trunk")
    git(repo, "remote", "add", "origin", str(origin))
    git(repo, "fetch", "-q", "origin")
    git(repo, "remote", "set-head", "origin", "trunk")
    assert ids.upstream_refs(repo) == ["origin/trunk"]
    assert ids.allocate(repo, "lessons.yml", "LL") == ["LL-021"]


# --- XX-NEW is a valid committed state; CI checks against the PR base -------------------------


def test_new_placeholders_may_be_committed_and_repeat(repo):
    with open(repo / "lessons.yml", "a") as f:
        f.write(ENTRY.format(id="LL-NEW") + ENTRY.format(id="LL-NEW"))
    git(repo, "commit", "-qam", "two contributions")
    assert run_tool(repo, "check-dupes", "lessons.yml").returncode == 0
    assert run_tool(repo, "check-lost", "lessons.yml").returncode == 0
    from homelabnext.registers.schema import _dupes

    problems: list[str] = []
    _dupes(["LL-001", "LL-NEW", "LL-NEW"], problems)
    assert problems == []


def test_check_dupes_fails_on_a_repeated_allocated_id(repo):
    with open(repo / "lessons.yml", "a") as f:
        f.write(ENTRY.format(id="LL-002"))
    r = run_tool(repo, "check-dupes", "lessons.yml")
    assert r.returncode == 1 and "LL-002" in r.stderr


def test_check_lost_against_a_pr_base(repo):
    base = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=repo, capture_output=True, text=True, check=True
    ).stdout.strip()
    text = (repo / "lessons.yml").read_text()
    (repo / "lessons.yml").write_text(text.replace(ENTRY.format(id="LL-001"), ""))
    git(repo, "commit", "-qam", "drop LL-001")
    # against HEAD the drop is already committed, so only the base comparison sees it
    assert run_tool(repo, "check-lost", "lessons.yml").returncode == 0
    r = run_tool(repo, "check-lost", "--base", base, "lessons.yml")
    assert r.returncode == 1 and "LL-001" in r.stderr
    assert run_tool(repo, "check-lost", "--base", "nope", "lessons.yml").returncode == 1


# --- retiring an id: a tombstone keeps it accounted for, and keeps it from being reused ----------

TOMB = """\
retired:
  # a comment inside the block
  {id}:
    replaced_by: X-02
    reason: "collided with another register's meaning"
"""


def _inv_repo(tmp_path):
    r = tmp_path / "inv"
    r.mkdir()
    git(r, "init")
    (r / "invariants.yml").write_text(
        "criteria:\n" + ENTRY.format(id="F-01") + ENTRY.format(id="X-02")
    )
    git(r, "add", "-A")
    git(r, "commit", "-m", "base")
    base = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=r, capture_output=True, text=True, check=True
    ).stdout.strip()
    return r, base


def test_retired_in_reads_only_the_top_level_block():
    spec = ids.SPECS["invariants"]
    text = (
        "pillars:\n- letter: F\n"
        + TOMB.format(id="F-01")
        + "  F-NEW:\n    reason: placeholders are never tombstones\n"
        + "  not-an-id:\n    reason: ignored here, reported by the schema\n"
        + "criteria:\n"
        + ENTRY.format(id="X-02")
        + "  F-09: nested, not a tombstone\n"
    )
    assert ids.retired_in(text, spec) == ["F-01"]
    assert ids.retired_in("criteria:\n" + ENTRY.format(id="X-02"), spec) == []


def test_retiring_an_id_passes_check_lost_and_deleting_the_tombstone_fails(tmp_path):
    r, base = _inv_repo(tmp_path)
    path = r / "invariants.yml"
    # deleting F-01 outright is a loss, against HEAD and against the PR base
    path.write_text("criteria:\n" + ENTRY.format(id="X-02"))
    assert run_tool(r, "check-lost", "invariants.yml").returncode == 1
    # retiring it is not
    path.write_text(TOMB.format(id="F-01") + "criteria:\n" + ENTRY.format(id="X-02"))
    assert run_tool(r, "check-lost", "invariants.yml").returncode == 0
    git(r, "commit", "-qam", "retire F-01")
    assert run_tool(r, "check-lost", "--base", base, "invariants.yml").returncode == 0
    # the tombstone is append-only too: dropping it later loses F-01 again
    path.write_text("criteria:\n" + ENTRY.format(id="X-02"))
    out = run_tool(r, "check-lost", "invariants.yml")
    assert out.returncode == 1 and "F-01" in out.stderr and "retired:" in out.stderr


def test_a_live_entry_may_not_reuse_a_retired_id(tmp_path):
    r, _ = _inv_repo(tmp_path)
    live = ENTRY.format(id="F-01") + ENTRY.format(id="X-02")
    (r / "invariants.yml").write_text(TOMB.format(id="F-01") + "criteria:\n" + live)
    out = run_tool(r, "check-dupes", "invariants.yml")
    assert out.returncode == 1 and "F-01 retired" in out.stderr
    # reuse on purpose = delete the tombstone in the same change; nothing is lost then
    (r / "invariants.yml").write_text("criteria:\n" + live)
    assert run_tool(r, "check-dupes", "invariants.yml").returncode == 0
    assert run_tool(r, "check-lost", "invariants.yml").returncode == 0


def test_allocation_never_hands_out_a_retired_number(tmp_path):
    r, _ = _inv_repo(tmp_path)
    (r / "invariants.yml").write_text(
        TOMB.format(id="F-07") + "criteria:\n" + ENTRY.format(id="F-01")
    )
    assert ids.allocate(r, "invariants.yml", "F") == ["F-08"]
