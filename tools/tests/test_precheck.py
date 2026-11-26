# SPDX-License-Identifier: Apache-2.0
"""``make precheck`` (tools/precheck.sh), the pre-push hook that runs it, tools/hygiene.py, and
the ``static``/``perf`` markers that split the suite between precheck, the test shards and the
nightly workflow."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
PRECHECK = ROOT / "tools" / "precheck.sh"
HOOK = ROOT / "tools" / "install-prepush-hook.sh"
HYGIENE = ROOT / "tools" / "hygiene.py"
CI = ROOT / ".github" / "workflows" / "ci.yml"
NIGHTLY = ROOT / ".github" / "workflows" / "nightly.yml"


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@example.invalid", *args],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _repo(path: Path) -> Path:
    path.mkdir()
    _git(path, "init", "-q")
    return path


# --- tools/precheck.sh -------------------------------------------------------------------------


def _precheck_repo(tmp_path: Path, makefile: str) -> Path:
    repo = _repo(tmp_path / "r")
    (repo / "tools").mkdir()
    shutil.copy(PRECHECK, repo / "tools" / "precheck.sh")
    (repo / "Makefile").write_text(makefile)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "c")
    return repo


def _run_precheck(repo: Path, **env: str) -> subprocess.CompletedProcess:
    clean = {k: v for k, v in os.environ.items() if k not in ("BASE", "HNX_PR_BASE")}
    clean.pop("HNX_PUSH_BEFORE", None)
    return subprocess.run(
        ["bash", str(repo / "tools" / "precheck.sh")],
        cwd=repo,
        env={**clean, "PRECHECK_JOBS": "2", **env},
        capture_output=True,
        text=True,
        check=False,
    )


FAKE = """\
precheck-run: good bad also
good:
\t@echo good ran
bad:
\t@echo bad ran; exit 3
also:
\t@echo "also ran with BASE=[$(BASE)]"
"""


def test_precheck_runs_every_target_and_names_the_failed_ones(tmp_path):
    repo = _precheck_repo(tmp_path, FAKE)
    r = _run_precheck(repo)
    assert r.returncode == 1, r.stdout + r.stderr
    # -k: a failure does not stop the other targets
    assert "good ran" in r.stdout and "bad ran" in r.stdout and "also ran" in r.stdout
    assert re.search(r"precheck: FAILED in \d+s: bad\s*$", r.stdout, re.M), r.stdout
    # no origin/main and no CI event: the ratchets get no base, and it says so
    assert "no base (no origin/main)" in r.stdout and "BASE=[]" in r.stdout


def test_precheck_passes_when_every_target_passes_and_hands_make_the_base(tmp_path):
    repo = _precheck_repo(tmp_path, FAKE.replace("good bad also", "good also"))
    head = _git(repo, "rev-parse", "HEAD")
    r = _run_precheck(repo, BASE=head)
    assert r.returncode == 0, r.stdout + r.stderr
    assert re.search(r"^precheck: OK in \d+s$", r.stdout, re.M)
    assert f"BASE=[{head}]" in r.stdout and f"precheck: base {head}" in r.stdout


def test_precheck_takes_the_merge_base_with_origin_main(tmp_path):
    repo = _precheck_repo(tmp_path, FAKE.replace("good bad also", "also"))
    first = _git(repo, "rev-parse", "HEAD")
    _git(repo, "update-ref", "refs/remotes/origin/main", first)
    (repo / "x").write_text("x")
    _git(repo, "add", "x")
    _git(repo, "commit", "-qm", "d")
    r = _run_precheck(repo)
    assert r.returncode == 0 and f"BASE=[{first}]" in r.stdout, r.stdout + r.stderr


@pytest.mark.static
def test_make_precheck_runs_the_script_and_every_static_gate_of_check():
    """precheck-run holds every gate `make check` runs but the suite, the coverage floor and the
    fix check (which CI's regression-tests job reports as a warning)."""
    from test_experimental import make_rules

    prereqs, recipes = make_rules((ROOT / "Makefile").read_text())
    assert recipes["precheck"] == ['PY="python3" tools/precheck.sh']
    left_out = {"test", "coverage", "fix-check"}
    assert set(prereqs["check"]) - set(prereqs["precheck-run"]) == left_out
    assert {"hygiene", "invariants", "ratchets", "static-tests"} <= set(prereqs["precheck-run"])


@pytest.mark.static
def test_ci_starts_with_precheck_and_every_other_job_waits_for_it():
    jobs = yaml.safe_load(CI.read_text())["jobs"]
    runs = [s.get("run", "") for s in jobs["precheck"]["steps"]]
    assert "make precheck PY=python" in runs
    assert "needs" not in jobs["precheck"] and "if" not in jobs["precheck"]

    def waits(name, seen=()):
        needs = jobs[name].get("needs") or []
        needs = [needs] if isinstance(needs, str) else needs
        return "precheck" in needs or any(waits(n, (*seen, name)) for n in needs if n not in seen)

    assert [n for n in jobs if n != "precheck" and not waits(n)] == []
    for gone in ("lint", "schemas", "trusted-gates", "invariants", "register-ids", "hygiene"):
        assert gone not in jobs, gone
    for gone in ("dco", "markdown-links"):
        assert gone not in jobs, gone


# --- tools/install-prepush-hook.sh ---------------------------------------------------------------


def test_the_hook_runs_make_precheck_and_keeps_a_foreign_hook(tmp_path):
    repo = _repo(tmp_path / "r")
    hooks = repo / ".git" / "hooks"
    hooks.mkdir(exist_ok=True)
    (hooks / "pre-push").write_text("#!/bin/sh\necho mine\n")
    run = subprocess.run(["bash", str(HOOK)], cwd=repo, capture_output=True, text=True, check=False)
    assert run.returncode == 0, run.stderr
    hook = hooks / "pre-push"
    assert os.access(hook, os.X_OK)
    text = hook.read_text()
    assert "exec make precheck" in text and 'pre-push.saved" "$@"' in text
    assert (hooks / "pre-push.saved").read_text() == "#!/bin/sh\necho mine\n"
    # a second install refreshes its own hook and leaves the kept one alone
    again = subprocess.run(
        ["bash", str(HOOK)], cwd=repo, capture_output=True, text=True, check=False
    )
    assert again.returncode == 0 and hook.read_text() == text
    assert (hooks / "pre-push.saved").read_text() == "#!/bin/sh\necho mine\n"


def test_the_hook_installer_refuses_outside_a_work_tree(tmp_path):
    run = subprocess.run(
        ["bash", str(HOOK)],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
        env={**os.environ, "GIT_CEILING_DIRECTORIES": str(tmp_path.parent)},
    )
    assert run.returncode == 1 and "not inside a git work tree" in run.stdout


# --- tools/hygiene.py --------------------------------------------------------------------------


def _hygiene(repo: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["python3", str(HYGIENE), str(repo)], capture_output=True, text=True, check=False
    )


def test_hygiene_is_clean_on_a_clean_tree_and_names_each_problem(tmp_path):
    repo = _repo(tmp_path / "r")
    (repo / "ok.yml").write_text("a: !vault |\n  x\n")  # a tag is data: only syntax counts
    (repo / "ok.json").write_text("{}")
    _git(repo, "add", "-A")
    r = _hygiene(repo)
    assert (r.returncode, r.stdout.strip()) == (0, "hygiene: clean"), r.stdout + r.stderr
    (repo / "bad.yml").write_text("a: [\n")
    (repo / "bad.json").write_text("{")
    (repo / "conflict.txt").write_text("x\n" + "<" * 7 + " ours\ny\n")
    (repo / "big.txt").write_text("x" * (512 * 1024 + 1))
    (repo / "key.txt").write_text("-----BEGIN " + "OPENSSH PRIVATE KEY-----\n")
    (repo / "link").symlink_to("ok.yml")
    _git(repo, "add", "-A")
    r = _hygiene(repo)
    assert r.returncode == 1
    assert sorted(r.stdout.splitlines()) == [
        "bad.json: does not parse (JSONDecodeError)",
        "bad.yml: does not parse (ParserError)",
        "big.txt: larger than 512 KB",
        "conflict.txt: merge-conflict marker",
        "key.txt: private key block",
        "link: symbolic link (packaging refuses them)",
    ]


# --- the markers -------------------------------------------------------------------------------


def _marked(marker: str) -> set[str]:
    out = subprocess.run(
        ["git", "grep", "-l", "-e", rf"mark\.{marker}\b", "--", "tests/*.py", "tools/tests/*.py"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    ).stdout.split()
    return {f for f in out if f != "tools/tests/test_precheck.py"}


@pytest.mark.static
def test_the_static_rules_the_operator_named_are_marked():
    static = _marked("static")
    for f in (
        "tests/roles/test_now_epoch.py",
        "tests/roles/test_last_run.py",
        "tests/modules/test_core_units.py",
        "tools/tests/test_pin_freshness.py",
        "tools/tests/test_make_matches_ci.py",
        "tools/tests/test_ci_runs_tests.py",
    ):
        assert f in static, f
    assert len(static) > 200


@pytest.mark.static
def test_the_shards_leave_static_to_precheck_and_perf_to_the_nightly():
    ci = CI.read_text()
    assert '-m "not live and not experimental and not static and not perf"' in ci
    make = (ROOT / "Makefile").read_text()
    assert '-m "static and not live and not experimental"' in make
    nightly = yaml.safe_load(NIGHTLY.read_text())
    runs = "\n".join(s.get("run", "") for j in nightly["jobs"].values() for s in j["steps"])
    assert '-m "perf and not live and not experimental"' in runs
    assert '-m "not live and not experimental and not perf"' in runs
    (floor,) = [
        s["with"]["python-version"]
        for s in nightly["jobs"]["test-floor"]["steps"]
        if "python-version" in s.get("with", {})
    ]
    assert floor == "3.11"
    assert "tests/context/test_levels.py" in _marked("perf")
