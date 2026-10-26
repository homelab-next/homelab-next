# SPDX-License-Identifier: Apache-2.0
"""The CI dco job's sign-off step, run as written in ci.yml against a scratch repository: every
commit needs a Signed-off-by for its author, and only Dependabot's own commits in a pull request
GitHub says Dependabot opened are exempt (a commit's author email is self-asserted)."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
CI = ROOT / ".github" / "workflows" / "ci.yml"
DEPENDABOT = "49699333+dependabot[bot]@users.noreply.github.com"
HUMAN = "dev@example.org"

pytestmark = pytest.mark.skipif(
    shutil.which("git") is None or shutil.which("bash") is None, reason="git or bash not installed"
)


def dco_step() -> dict:
    jobs = yaml.safe_load(CI.read_text())["jobs"]
    (step,) = [s for s in jobs["dco"]["steps"] if s.get("name") == "sign-off on every commit"]
    return step


def _git(repo: Path, *args: str, email: str = HUMAN) -> str:
    env = {
        "PATH": "/usr/bin:/bin",
        "GIT_AUTHOR_NAME": "a",
        "GIT_AUTHOR_EMAIL": email,
        "GIT_COMMITTER_NAME": "a",
        "GIT_COMMITTER_EMAIL": email,
        "GIT_CONFIG_NOSYSTEM": "1",
        "HOME": str(repo.parent),
    }
    return subprocess.run(
        ["git", "-c", "commit.gpgsign=false", *args],
        cwd=repo, env=env, capture_output=True, text=True, check=True,
    ).stdout.strip()  # fmt: skip


def scratch(tmp_path: Path, commits: list[tuple[str, bool]]) -> tuple[Path, str, str]:
    """A repository with a base commit and then one commit per (author email, signed off)."""
    repo = tmp_path / "repo"
    repo.mkdir(parents=True)
    _git(repo, "init", "-q", "-b", "main")
    (repo / "f.txt").write_text("0\n")
    _git(repo, "add", "f.txt")
    _git(repo, "commit", "-q", "-m", "base")
    base = _git(repo, "rev-parse", "HEAD")
    for i, (email, signed) in enumerate(commits, 1):
        (repo / "f.txt").write_text(f"{i}\n")
        msg = f"chore: change {i}" + (f"\n\nSigned-off-by: a <{email}>" if signed else "")
        _git(repo, "commit", "-q", "-am", msg, email=email)
    return repo, base, _git(repo, "rev-parse", "HEAD")


def run_dco(repo: Path, base: str, head: str, login: str, user_type: str):
    step = dco_step()
    env = {
        "PATH": "/usr/bin:/bin",
        "HOME": str(repo.parent),
        "GIT_CONFIG_NOSYSTEM": "1",
        "BASE": base,
        "HEAD_SHA": head,
        "PR_USER_LOGIN": login,
        "PR_USER_TYPE": user_type,
    }
    assert set(step["env"]) == {"BASE", "HEAD_SHA", "PR_USER_LOGIN", "PR_USER_TYPE"}
    return subprocess.run(
        [shutil.which("bash"), "-c", step["run"]],
        cwd=repo, env=env, capture_output=True, text=True, check=False,
    )  # fmt: skip


def test_the_step_takes_the_pull_request_author_from_the_event():
    env = dco_step()["env"]
    assert env["PR_USER_LOGIN"] == "${{ github.event.pull_request.user.login }}"
    assert env["PR_USER_TYPE"] == "${{ github.event.pull_request.user.type }}"


def test_signed_off_commits_pass(tmp_path):
    repo, base, head = scratch(tmp_path, [(HUMAN, True), (HUMAN, True)])
    assert run_dco(repo, base, head, "someone", "User").returncode == 0


def test_an_unsigned_commit_fails(tmp_path):
    repo, base, head = scratch(tmp_path, [(HUMAN, True), (HUMAN, False)])
    r = run_dco(repo, base, head, "someone", "User")
    assert r.returncode == 1 and "has no Signed-off-by" in r.stdout


@pytest.mark.parametrize(
    "email",
    [DEPENDABOT, "1+renovate[bot]@users.noreply.github.com", "2+github-actions[bot]@users.noreply.github.com"],
)  # fmt: skip
def test_a_bot_email_in_a_contributors_pull_request_is_not_exempt(tmp_path, email):
    # anyone can set GIT_AUTHOR_EMAIL to a bot's noreply address
    repo, base, head = scratch(tmp_path, [(email, False)])
    r = run_dco(repo, base, head, "someone", "User")
    assert r.returncode == 1, r.stdout + r.stderr


def test_dependabots_own_pull_request_is_exempt_for_its_commits_only(tmp_path):
    repo, base, head = scratch(tmp_path, [(DEPENDABOT, False)])
    assert run_dco(repo, base, head, "dependabot[bot]", "Bot").returncode == 0
    # a person's unsigned commit pushed onto the Dependabot branch still needs its sign-off
    repo, base, head = scratch(tmp_path / "2", [(DEPENDABOT, False), (HUMAN, False)])
    assert run_dco(repo, base, head, "dependabot[bot]", "Bot").returncode == 1
    # a user account that calls itself dependabot[bot] is not the bot
    repo, base, head = scratch(tmp_path / "3", [(DEPENDABOT, False)])
    assert run_dco(repo, base, head, "dependabot[bot]", "User").returncode == 1
