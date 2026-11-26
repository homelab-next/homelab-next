# SPDX-License-Identifier: Apache-2.0
"""One base rule for every CI job that compares with a base: ``homelabnext/gitbase.py``.

The schemas, register-ids, regression-tests and trusted-gates jobs each wrote the push / pull
request / force-push rule out in shell, and the copies disagreed.  Now the rule has one copy;
``python -m homelabnext.gitbase`` prints the base, and ``--allow-root`` is the explicit choice of
the callers that run without one: the precheck job (``tools/precheck.sh``, which runs the ratchets
and the register-ids check against it) and regression-tests.
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


PRECHECK = ROOT / "tools" / "precheck.sh"


@pytest.mark.parametrize(
    ("job", "needle", "text"),
    [
        ("precheck", "make precheck", lambda: PRECHECK.read_text()),
        ("regression-tests", "fix_has_test", None),
    ],
)
def test_the_callers_that_run_without_a_base_on_a_root_commit_say_so_and_call_the_rule(
    job, needle, text
):
    step = _step(job, needle)
    run = text() if text else step["run"]
    assert "-m homelabnext.gitbase --allow-root)" in run
    assert step["env"]["HNX_PR_BASE"] == "${{ github.event.pull_request.base.sha }}"
    assert step["env"]["HNX_PUSH_BEFORE"] == "${{ github.event.before }}"


@pytest.mark.parametrize("job", ["precheck", "regression-tests"])
def test_no_job_writes_the_rule_out_again(job):
    runs = "\n".join(str(s.get("run", "")) for s in JOBS[job]["steps"])
    if job == "precheck":
        runs += PRECHECK.read_text()
    for copy in (ZERO, "HEAD^^{commit}", "HEAD^)", "rev-parse --verify --quiet"):
        assert copy not in runs, (job, copy)


def test_precheck_takes_the_ci_base_from_the_rule(tmp_path):
    """tools/precheck.sh's base selection, run as written up to the make call."""
    repo = _repo(tmp_path / "r", 3)
    head, parent, first = (_git(repo, "rev-parse", f"HEAD~{n}") for n in range(3))
    script = PRECHECK.read_text()
    script = script[: script.index("log=$(mktemp)")] + 'echo "BASE=$base"\n'
    script = script.replace('repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)', f"repo={repo}")
    env = {**os.environ, "PY": sys.executable, "PYTHONPATH": str(ROOT), "GITHUB_EVENT_NAME": ""}
    env.pop("BASE", None)
    for event, extra, want in (
        ("pull_request", {"HNX_PR_BASE": first}, first),
        ("push", {"HNX_PUSH_BEFORE": ZERO}, parent),
    ):
        r = subprocess.run(
            ["bash", "-c", script],
            env={**env, "GITHUB_EVENT_NAME": event, **extra},
            capture_output=True,
            text=True,
            check=False,
        )
        assert r.returncode == 0 and f"BASE={want}" in r.stdout, r.stdout + r.stderr
    assert head != parent
