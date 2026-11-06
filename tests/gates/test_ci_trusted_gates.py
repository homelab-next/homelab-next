# SPDX-License-Identifier: Apache-2.0
"""CI's trusted-gates job runs the base commit's checker in an interpreter nothing of the change
set up: no composite action from the checkout, Python called by the absolute path setup-python
reports, pip and the checker's dependencies from the base's own constraints, and no fallback to
the change's own code when the base cannot run a gate.  Every ratchet (a gate that holds the change
to the base) runs there, from the base's worktree; the other jobs' copies are quick feedback that a
change can edit, so a ratchet added to them must be added here too."""

from __future__ import annotations

import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
CI = yaml.safe_load((ROOT / ".github" / "workflows" / "ci.yml").read_text())
JOB = CI["jobs"]["trusted-gates"]
STEPS = JOB["steps"]
PY = "${{ steps.python.outputs.python-path }}"
#: an interpreter or pip named as a command, found through PATH
#: the forms in which the change's checkout may appear: an argument the base's code reads as data
DATA_ARGS = ('--root "$GITHUB_WORKSPACE"', '"$RUNNER_TEMP/gitbase.py" "$GITHUB_WORKSPACE"')
#: a base tool run as a script with -I: neither the working directory nor the environment adds a
#: path, so it may run in, or name, the change's checkout as data
ISOLATED = re.compile(r'"\$PY" -I "\$RUNNER_TEMP/base/tools/(\w+)\.py"')
#: each ratchet's tool and how trusted-gates runs it against the base the job picked
RATCHETS = {
    "schema_check": '--strict --root "$GITHUB_WORKSPACE" --base "$BASE"',
    "product_name_lint": '--base "$BASE" "$GITHUB_WORKSPACE"',
    "dup_check": '--base "$BASE" "$GITHUB_WORKSPACE"',
    "register_ids": 'check-lost --base "$BASE"',
}
BARE = re.compile(r"(?:^|[\s;|&(])(?:python3?|pip3?)(?:\s|$)")


def _runs() -> list[dict]:
    return [s for s in STEPS if "run" in s]


def test_no_action_from_the_changes_checkout_runs():
    local = [s["uses"] for s in STEPS if s.get("uses", "").startswith(".")]
    assert local == []


def test_python_comes_from_a_pinned_setup_python_and_is_called_by_its_path():
    (setup,) = [s for s in STEPS if s.get("uses", "").startswith("actions/setup-python@")]
    assert setup["id"] == "python" and "cache" not in (setup.get("with") or {})
    assert STEPS.index(setup) < STEPS.index(_runs()[0])
    for step in _runs():
        assert step["env"]["PY"] == PY, step["name"]
        for line in step["run"].splitlines():
            # "$PY" -m pip is the interpreter by path; a bare python or pip is a PATH lookup
            assert not BARE.search(line.replace("-m pip", "")), (step["name"], line)


def test_the_checker_installs_from_the_bases_constraints():
    (base,) = [s for s in STEPS if s.get("id") == "base"]
    run = base["run"]
    cd = run.index('cd "$RUNNER_TEMP/base"')
    for needle in ("-r constraints/bootstrap.txt", "-c constraints/ci.txt", '"pyproject.toml"'):
        assert run.index(needle) > cd, needle  # read in the base's worktree, not the checkout
    assert "--require-hashes" in run


def test_a_base_that_cannot_run_a_gate_fails_rather_than_running_the_change():
    for step in _runs():
        run = step["run"]
        for data in DATA_ARGS:  # the change's tree passed as data, never run
            run = run.replace(data, "")
        if ISOLATED.search(run) and len(ISOLATED.findall(run)) == run.count('"$PY"'):
            run = run.replace('cd "$GITHUB_WORKSPACE"', "").replace(' "$GITHUB_WORKSPACE"', "")
        assert "GITHUB_WORKSPACE" not in run, step["name"]
        assert "::notice::" not in step["run"]
    gates = [s for s in _runs() if "homelabnext.cli modules" in s["run"]]
    assert len(gates) == 2
    for step in gates:
        assert 'cd "$RUNNER_TEMP/base"' in step["run"]


def test_every_ratchet_runs_from_the_bases_worktree_against_the_jobs_base():
    found = {}
    for step in _runs():
        for line in step["run"].splitlines():
            m = ISOLATED.search(line)
            if m:
                found[m[1]] = line[m.end() :].strip().rstrip("'")
                assert step["env"]["BASE"] == "${{ steps.base.outputs.sha }}", step["name"]
    assert found == RATCHETS


def _ratchets_elsewhere() -> set[str]:
    """The tools another job runs against a base: ``--ci-base`` or ``--base``, and
    ``make ids-check`` with ``BASE=`` (``register_ids.py check-lost``)."""
    out = set()
    for name, job in CI["jobs"].items():
        if name == "trusted-gates":
            continue
        for step in job.get("steps") or []:
            for line in str(step.get("run", "")).splitlines():
                if re.search(r"--(?:ci-)?base\b", line):
                    out.update(re.findall(r"tools/(\w+)\.py", line))
                if re.search(r"make ids-check\b.*\bBASE=", line):
                    out.add("register_ids")
    return out


def test_a_ratchet_another_job_runs_also_runs_here():
    # fix_has_test proves the change's own tests, which trusted-gates never runs: its job runs
    # the base's copy of the judge instead (below)
    assert _ratchets_elsewhere() - {"fix_has_test"} <= set(RATCHETS)
    assert set(RATCHETS) <= _ratchets_elsewhere()  # the quick-feedback copies are still there


def test_the_fix_judge_is_the_bases_copy():
    (step,) = [
        s for s in CI["jobs"]["regression-tests"]["steps"] if "fix_has_test" in s.get("run", "")
    ]
    run = step["run"]
    assert 'git worktree add --detach "$RUNNER_TEMP/judge" "$base"' in run
    assert 'python -I "$RUNNER_TEMP/judge/tools/fix_has_test.py" --repo "$GITHUB_WORKSPACE"' in run
    assert "python tools/fix_has_test.py" not in run


def test_every_interpreter_call_keeps_the_checkout_off_the_path():
    for step in _runs():
        for line in step["run"].splitlines():
            for m in re.finditer(r'"\$PY" (-\S+)', line):
                assert m[1] in ("-I", "-P", "-m"), (step["name"], line)
