# SPDX-License-Identifier: Apache-2.0
"""One base rule for every CI job that compares with a base: ``homelabnext/gitbase.py``.

The schemas, register-ids, regression-tests and trusted-gates jobs each wrote the push / pull
request / force-push rule out in shell, and the copies disagreed: trusted-gates refused a root
commit while the other two ran with no base.  Now the rule has one copy; ``python -m
homelabnext.gitbase`` prints the base, ``--allow-root`` is the explicit choice of the jobs that run
without one, and trusted-gates reads the file from the commit it trusts, not from the checkout.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from homelabnext import gitbase

ROOT = Path(__file__).resolve().parents[2]
CI = yaml.safe_load((ROOT / ".github" / "workflows" / "ci.yml").read_text())
JOBS = CI["jobs"]
ZERO = "0" * 40


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@example.invalid", *args],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _repo(path: Path, commits: int) -> Path:
    path.mkdir()
    _git(path, "init", "-q")
    for n in range(commits):
        (path / "a").write_text(str(n))
        _git(path, "add", "a")
        _git(path, "commit", "-qm", f"c{n}")
    return path


def _cli(repo: Path, event: str, *, pr_base="", before="", extra=()) -> subprocess.CompletedProcess:
    env = {
        **os.environ,
        "GITHUB_EVENT_NAME": event,
        "HNX_PR_BASE": pr_base,
        "HNX_PUSH_BEFORE": before,
    }
    return subprocess.run(
        [sys.executable, "-m", "homelabnext.gitbase", "--root", str(repo), *extra],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


def test_the_cli_prints_the_push_and_pull_request_bases(tmp_path):
    repo = _repo(tmp_path / "r", 3)
    head, parent, first = (_git(repo, "rev-parse", f"HEAD~{n}") for n in range(3))
    r = _cli(repo, "push", before=first)
    assert (r.returncode, r.stdout.strip()) == (0, first), r.stderr
    assert "previous tip" in r.stderr
    # a new branch (zero) and a force-push (an unreadable old tip) fall back to HEAD^
    for before in (ZERO, "f" * 40, ""):
        r = _cli(repo, "push", before=before)
        assert (r.returncode, r.stdout.strip()) == (0, parent), (before, r.stderr)
    r = _cli(repo, "pull_request", pr_base=first)
    assert (r.returncode, r.stdout.strip()) == (0, first)
    assert head != parent


@pytest.mark.parametrize(
    ("event", "pr_base"),
    [("pull_request", ""), ("pull_request", "e" * 40), ("workflow_dispatch", ""), ("", "")],
)
def test_the_cli_fails_without_a_rule_or_a_readable_base(tmp_path, event, pr_base):
    repo = _repo(tmp_path / "r", 2)
    for extra in ((), ("--allow-root",)):
        r = _cli(repo, event, pr_base=pr_base, extra=extra)
        assert r.returncode == 1 and r.stdout == "", (event, extra, r.stdout)
        assert "gitbase:" in r.stderr


def test_a_root_commit_is_an_error_unless_allowed(tmp_path):
    repo = _repo(tmp_path / "r", 1)
    r = _cli(repo, "push", before=ZERO)
    assert r.returncode == 1 and r.stdout == ""
    assert "a root commit" in r.stderr
    r = _cli(repo, "push", before=ZERO, extra=("--allow-root",))
    assert (r.returncode, r.stdout) == (0, "")
    assert "a root commit" in r.stderr


def test_a_shallow_checkout_is_an_error_even_when_a_root_is_allowed(tmp_path):
    src = _repo(tmp_path / "src", 2)
    shallow = tmp_path / "shallow"
    subprocess.run(
        ["git", "clone", "-q", "--depth", "1", f"file://{src}", str(shallow)],
        check=True,
        capture_output=True,
    )
    r = _cli(shallow, "push", before=ZERO, extra=("--allow-root",))
    assert r.returncode == 1 and "shallow" in r.stderr


def test_main_agrees_with_the_function(tmp_path, monkeypatch, capsys):
    repo = _repo(tmp_path / "r", 2)
    monkeypatch.setenv("GITHUB_EVENT_NAME", "push")
    monkeypatch.setenv("HNX_PUSH_BEFORE", ZERO)
    monkeypatch.delenv("HNX_PR_BASE", raising=False)
    assert gitbase.main(["--root", str(repo)]) == 0
    assert capsys.readouterr().out.strip() == gitbase.ci_base_from_env(repo)[0]


# --- the workflow calls the one copy ---------------------------------------------------------


def _step(job: str, needle: str) -> dict:
    (step,) = [s for s in JOBS[job]["steps"] if needle in str(s.get("run", ""))]
    return step


@pytest.mark.parametrize(
    ("job", "needle"), [("register-ids", "ids-check"), ("regression-tests", "fix_has_test")]
)
def test_the_jobs_that_run_without_a_base_on_a_root_commit_say_so_and_call_the_rule(job, needle):
    step = _step(job, needle)
    assert "base=$(python -m homelabnext.gitbase --allow-root)" in step["run"]
    assert step["env"]["HNX_PR_BASE"] == "${{ github.event.pull_request.base.sha }}"
    assert step["env"]["HNX_PUSH_BEFORE"] == "${{ github.event.before }}"


@pytest.mark.parametrize("job", ["register-ids", "regression-tests", "trusted-gates", "schemas"])
def test_no_job_writes_the_rule_out_again(job):
    runs = "\n".join(str(s.get("run", "")) for s in JOBS[job]["steps"])
    for copy in (ZERO, "HEAD^^{commit}", "HEAD^)", "rev-parse --verify --quiet"):
        assert copy not in runs, (job, copy)


def _trusted_base_script() -> str:
    """The trusted-gates base step up to the checker worktree, then the base it picked."""
    (step,) = [s for s in JOBS["trusted-gates"]["steps"] if s.get("id") == "base"]
    run = step["run"]
    assert step["env"]["TRUSTED"] == "${{ github.event.pull_request.base.sha || github.sha }}"
    assert 'git show "$TRUSTED:homelabnext/gitbase.py"' in run
    return run[: run.index("git worktree add")] + 'echo "BASE=$base"\n'


def _trusted(repo: Path, tmp_path: Path, event: str, trusted: str, *, pr_base="", before=""):
    env = {
        **os.environ,
        "GITHUB_EVENT_NAME": event,
        "TRUSTED": trusted,
        "HNX_PR_BASE": pr_base,
        "HNX_PUSH_BEFORE": before,
        "PY": sys.executable,
        "GITHUB_WORKSPACE": str(repo),
        "RUNNER_TEMP": str(tmp_path),
    }
    return subprocess.run(
        ["bash", "-c", _trusted_base_script()],
        cwd=repo,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


def _with_gitbase(path: Path, commits: int) -> Path:
    """A repository whose every commit carries this checkout's gitbase.py."""
    path.mkdir()
    _git(path, "init", "-q")
    (path / "homelabnext").mkdir()
    for n in range(commits):
        (path / "homelabnext" / "gitbase.py").write_text(
            (ROOT / "homelabnext" / "gitbase.py").read_text()
        )
        (path / "a").write_text(str(n))
        _git(path, "add", "-A")
        _git(path, "commit", "-qm", f"c{n}")
    return path


def test_trusted_gates_takes_the_base_by_the_trusted_copy_of_the_rule(tmp_path):
    repo = _with_gitbase(tmp_path / "r", 3)
    head, parent, first = (_git(repo, "rev-parse", f"HEAD~{n}") for n in range(3))
    r = _trusted(repo, tmp_path, "pull_request", first, pr_base=first)
    assert r.returncode == 0 and f"BASE={first}" in r.stdout, r.stderr
    r = _trusted(repo, tmp_path, "push", head, before=ZERO)
    assert r.returncode == 0 and f"BASE={parent}" in r.stdout, r.stderr


def test_trusted_gates_refuses_a_root_commit_and_an_unreadable_trusted_commit(tmp_path):
    repo = _with_gitbase(tmp_path / "r", 1)
    head = _git(repo, "rev-parse", "HEAD")
    r = _trusted(repo, tmp_path, "push", head, before=ZERO)
    assert r.returncode != 0 and "BASE=" not in r.stdout
    assert "a root commit" in r.stderr
    r = _trusted(repo, tmp_path, "pull_request", "e" * 40, pr_base="e" * 40)
    assert r.returncode != 0 and "BASE=" not in r.stdout
