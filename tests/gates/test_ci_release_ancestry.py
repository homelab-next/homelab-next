# SPDX-License-Identifier: Apache-2.0
"""The release workflow signs only a commit the default branch already holds: its first step after
the checkout (full history) fails unless the tagged commit is an ancestor of the default branch."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
RELEASE = yaml.safe_load((ROOT / ".github" / "workflows" / "release.yml").read_text())
STEPS = RELEASE["jobs"]["build"]["steps"]
NAME = "the tagged commit is on the default branch"


def _step() -> dict:
    (step,) = [s for s in STEPS if s.get("name") == NAME]
    return step


def test_the_ancestry_check_runs_first_after_a_full_history_checkout():
    checkout = STEPS[0]
    assert checkout["uses"].startswith("actions/checkout@")
    assert checkout["with"]["fetch-depth"] == 0
    assert STEPS[1] is _step()  # before any action or script of the tagged tree
    assert _step()["env"] == {"DEFAULT_BRANCH": "${{ github.event.repository.default_branch }}"}


def _git(root: Path, *args: str) -> str:
    env = {
        **os.environ,
        "GIT_AUTHOR_NAME": "t",
        "GIT_AUTHOR_EMAIL": "t@example.invalid",
        "GIT_COMMITTER_NAME": "t",
        "GIT_COMMITTER_EMAIL": "t@example.invalid",
    }
    return subprocess.run(
        ["git", "-C", str(root), *args], check=True, capture_output=True, text=True, env=env
    ).stdout.strip()


@pytest.mark.requires_tool("git", "bash")
def test_the_check_passes_a_commit_of_the_default_branch_and_refuses_any_other(tmp_path):
    root = tmp_path / "r"
    root.mkdir()
    _git(root, "init", "-q", "-b", "main")
    _git(root, "commit", "-q", "--allow-empty", "-m", "a")
    on_main = _git(root, "rev-parse", "HEAD")
    _git(root, "update-ref", "refs/remotes/origin/main", on_main)
    _git(root, "checkout", "-q", "-b", "side")
    _git(root, "commit", "-q", "--allow-empty", "-m", "b")
    off_main = _git(root, "rev-parse", "HEAD")

    def run(sha: str, branch: str = "main") -> int:
        env = {**os.environ, "GITHUB_SHA": sha, "DEFAULT_BRANCH": branch}
        return subprocess.run(
            ["bash", "-c", _step()["run"]], cwd=root, env=env, capture_output=True
        ).returncode

    assert run(on_main) == 0
    assert run(off_main) == 1
    assert run(on_main, "") == 1
