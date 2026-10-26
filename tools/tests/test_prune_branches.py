# SPDX-License-Identifier: Apache-2.0
"""tools/prune_branches.py: only a branch whose pull request is finished, at that pull request's
head, is deleted; every other branch is kept with its reason."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))

import prune_branches as pb

REPO = "owner/lab"


def branch(name, sha, protected=False):
    return {"name": name, "commit": {"sha": sha}, "protected": protected}


def pull(ref, sha, state, repo=REPO, base="main"):
    return {
        "state": state,
        "head": {"ref": ref, "sha": sha, "repo": {"full_name": repo}},
        "base": {"ref": base},
    }


BRANCHES = [
    branch("main", "m1", protected=True),
    branch("merged-work", "a1"),
    branch("closed-work", "b1"),
    branch("in-review", "c2"),
    branch("pushed-after-close", "d2"),
    branch("never-a-pr", "e1"),
    branch("release", "f1", protected=True),
    branch("fork-named-alike", "g1"),
]
PULLS = [
    pull("merged-work", "a1", "closed"),
    pull("closed-work", "b1", "closed"),
    pull("in-review", "c1", "closed"),  # an old, closed one
    pull("in-review", "c2", "open"),  # and the open one wins
    pull("pushed-after-close", "d1", "closed"),
    pull("release", "f1", "closed"),
    pull("fork-named-alike", "g1", "closed", repo="someone/fork"),
]


def test_only_finished_branches_at_their_pull_request_s_head_are_deleted():
    delete, kept = pb.decide(BRANCHES, PULLS, default="main", repo=REPO)
    assert delete == ["closed-work", "merged-work"]
    assert kept == {
        "fork-named-alike": "no pull request",
        "in-review": "an open pull request",
        "main": "the default branch",
        "never-a-pr": "no pull request",
        "pushed-after-close": "commits after its pull request closed",
        "release": "protected",
    }


def test_the_default_branch_is_kept_even_unprotected_and_at_a_closed_head():
    delete, kept = pb.decide(
        [branch("trunk", "t1")], [pull("trunk", "t1", "closed")], default="trunk"
    )
    assert delete == [] and kept == {"trunk": "the default branch"}


def test_the_command_reads_slurped_pages_and_writes_the_kept_list(tmp_path, capsys):
    b, p, k = tmp_path / "b.json", tmp_path / "p.json", tmp_path / "kept.tsv"
    b.write_text(json.dumps([BRANCHES[:4], BRANCHES[4:]]))  # two pages
    p.write_text(json.dumps([PULLS]))
    assert pb.main([str(b), str(p), "--default", "main", "--repo", REPO, "--keep", str(k)]) == 0
    assert capsys.readouterr().out == "closed-work\nmerged-work\n"
    assert "never-a-pr\tno pull request\n" in k.read_text()


def test_bad_input_deletes_nothing(tmp_path, capsys):
    b, p = tmp_path / "b.json", tmp_path / "p.json"
    b.write_text('{"message": "Bad credentials"}')  # an API error, not a list
    p.write_text("[]")
    assert pb.main([str(b), str(p), "--default", "main"]) == 2
    assert capsys.readouterr().out == ""


def test_the_base_of_an_open_stacked_pull_request_is_kept():
    """Deleting a branch another open pull request targets would close that pull request."""
    branches = [branch("main", "m1"), branch("step-1", "s1"), branch("step-2", "s2")]
    pulls = [pull("step-1", "s1", "closed"), pull("step-2", "s2", "open", base="step-1")]
    delete, kept = pb.decide(branches, pulls, default="main", repo=REPO)
    assert delete == [] and kept["step-1"] == "the base of an open pull request"


def test_an_empty_default_branch_deletes_nothing(tmp_path, capsys):
    b, p = tmp_path / "b.json", tmp_path / "p.json"
    b.write_text(json.dumps([branch("main", "m1")]))
    p.write_text(json.dumps([pull("main", "m1", "closed")]))  # main's tip is a closed head
    assert pb.main([str(b), str(p), "--default", ""]) == 2
    assert capsys.readouterr().out == ""
