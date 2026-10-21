# SPDX-License-Identifier: Apache-2.0
"""Loss and duplicate detection (homelabnext.registers.ids): single-file registers keyed by uid
(a joined lessons.yml) or by checklist id (invariants.yml).  Nothing is allocated (ADR-0019)."""

import os
import pathlib
import subprocess
import sys

import pytest

from homelabnext.registers import ids

REPO = pathlib.Path(__file__).resolve().parents[2]
TOOL = REPO / "tools" / "register_ids.py"
L1 = "01a15e4e-0000-7000-8000-000000000001"
L2 = "01a15e4e-0000-7000-8000-000000000002"
L5 = "01a15e4e-0000-7000-8000-000000000005"
L6 = "01a15e4e-0000-7000-8000-000000000006"

ENTRY = """\
- uid: {id}
  title: entry {id}
  note: this entry cites {id} in its own body
"""
CRIT = """\
- id: {id}
  title: entry {id}
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
        "# header comment\nlessons:\n" + ENTRY.format(id=L1) + ENTRY.format(id=L2)
    )
    git(r, "add", "-A")
    git(r, "commit", "-m", "seed")
    return r


def run_tool(repo, *args, env=None):
    e = {**os.environ, **(env or {})}
    return subprocess.run(
        [sys.executable, str(TOOL), *args], cwd=repo, capture_output=True, text=True, env=e
    )


def test_check_lost_clean_and_dropped(repo):
    assert run_tool(repo, "check-lost", "lessons.yml").returncode == 0
    text = (repo / "lessons.yml").read_text()
    (repo / "lessons.yml").write_text(text.replace(ENTRY.format(id=L2), ""))
    r = run_tool(repo, "check-lost", "lessons.yml")
    assert r.returncode == 1 and L2 in r.stderr
    r = run_tool(repo, "check-lost", "lessons.yml", env={"REGISTER_IDS_ALLOW_DROP": L2})
    assert r.returncode == 0  # deliberate consolidation


def test_check_lost_detects_entry_lost_in_merge_resolution(repo):
    git(repo, "checkout", "-b", "third")
    with open(repo / "lessons.yml", "a") as f:
        f.write(ENTRY.format(id=L5))
    git(repo, "commit", "-am", "third adds one")
    git(repo, "checkout", "main")
    with open(repo / "lessons.yml", "a") as f:
        f.write(ENTRY.format(id=L6))
    git(repo, "commit", "-am", "main adds another")
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
        (repo / "lessons.yml").read_text().split("<<<<<<<")[0] + ENTRY.format(id=L6)
    )
    assert ids.check_lost(repo, "lessons.yml") == [L5]  # visible only via MERGE_HEAD
    assert run_tool(repo, "check-lost", "lessons.yml").returncode == 1


def test_check_dupes_fails_on_a_repeated_allocated_id(repo):
    with open(repo / "lessons.yml", "a") as f:
        f.write(ENTRY.format(id=L2))
    r = run_tool(repo, "check-dupes", "lessons.yml")
    assert r.returncode == 1 and L2 in r.stderr


def test_check_lost_against_a_pr_base(repo):
    base = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=repo, capture_output=True, text=True, check=True
    ).stdout.strip()
    text = (repo / "lessons.yml").read_text()
    (repo / "lessons.yml").write_text(text.replace(ENTRY.format(id=L1), ""))
    git(repo, "commit", "-qam", "drop one")
    # against HEAD the drop is already committed, so only the base comparison sees it
    assert run_tool(repo, "check-lost", "lessons.yml").returncode == 0
    r = run_tool(repo, "check-lost", "--base", base, "lessons.yml")
    assert r.returncode == 1 and L1 in r.stderr
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
        "criteria:\n" + CRIT.format(id="F-01") + CRIT.format(id="X-02")
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
        + "  F-NEW:\n    reason: not a criterion id\n"
        + "  not-an-id:\n    reason: ignored here, reported by the schema\n"
        + "criteria:\n"
        + CRIT.format(id="X-02")
        + "  F-09: nested, not a tombstone\n"
    )
    assert ids.retired_in(text, spec) == ["F-01"]
    assert ids.retired_in("criteria:\n" + CRIT.format(id="X-02"), spec) == []


def test_retiring_an_id_passes_check_lost_and_deleting_the_tombstone_fails(tmp_path):
    r, base = _inv_repo(tmp_path)
    path = r / "invariants.yml"
    # deleting F-01 outright is a loss, against HEAD and against the PR base
    path.write_text("criteria:\n" + CRIT.format(id="X-02"))
    assert run_tool(r, "check-lost", "invariants.yml").returncode == 1
    # retiring it is not
    path.write_text(TOMB.format(id="F-01") + "criteria:\n" + CRIT.format(id="X-02"))
    assert run_tool(r, "check-lost", "invariants.yml").returncode == 0
    git(r, "commit", "-qam", "retire F-01")
    assert run_tool(r, "check-lost", "--base", base, "invariants.yml").returncode == 0
    # the tombstone is append-only too: dropping it later loses F-01 again
    path.write_text("criteria:\n" + CRIT.format(id="X-02"))
    out = run_tool(r, "check-lost", "invariants.yml")
    assert out.returncode == 1 and "F-01" in out.stderr and "retired:" in out.stderr


def test_a_live_entry_may_not_reuse_a_retired_id(tmp_path):
    r, _ = _inv_repo(tmp_path)
    live = CRIT.format(id="F-01") + CRIT.format(id="X-02")
    (r / "invariants.yml").write_text(TOMB.format(id="F-01") + "criteria:\n" + live)
    out = run_tool(r, "check-dupes", "invariants.yml")
    assert out.returncode == 1 and "F-01 retired" in out.stderr
    # reuse on purpose = delete the tombstone in the same change; nothing is lost then
    (r / "invariants.yml").write_text("criteria:\n" + live)
    assert run_tool(r, "check-dupes", "invariants.yml").returncode == 0
    assert run_tool(r, "check-lost", "invariants.yml").returncode == 0


def test_a_queue_or_any_unknown_file_is_not_a_register():
    """Allocation is retired, so a work queue (queue.yml) is not a register this tool keys."""
    assert ids.spec_for("queue.yml") is None and ids.spec_for("notes.yml") is None
    assert ids.spec_for("lessons/") == ids.SPECS["lessons"] and ids.SPECS["lessons"].key == "uid"
    assert ids.SPECS["invariants"].key == "id"


def test_every_example_record_carries_its_uid(examples):
    """M-16 holds on the examples: no record is keyed by a number or a placeholder."""
    found = 0
    for d in [examples / "lessons", examples / "runbooks"] + [
        examples.parent / "strategy" / k for k in ("objectives", "measures", "requirements", "rfis")
    ]:
        spec = ids.spec_for(d.name)
        texts = {p.name: p.read_text() for p in d.glob("*.md")}
        assert texts and ids.missing_uids(texts, spec) == [] and ids.dir_problems(texts, spec) == []
        found += len(texts)
    assert found >= 25


def test_a_numbered_record_has_no_uid():
    spec = ids.SPECS["lessons"]
    texts = {
        "LL-001.md": "---\nid: LL-001\ntitle: x\n---\n",
        f"{L1}.md": f"---\nuid: {L1}\ntype: lesson\n---\n",
        "bad.md": "---\nuid: 0f6b1c2e-3d4a-4b5c-8d6e-7f8091a2b3c4\n---\n",  # a v4 uuid
    }
    assert ids.missing_uids(texts, spec) == [
        "LL-001.md: no uid (still numbered LL-001)",
        "bad.md: no uid",
    ]
