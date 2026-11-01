# SPDX-License-Identifier: Apache-2.0
"""CI's trusted-gates job runs the base commit's checker in an interpreter nothing of the change
set up: no composite action from the checkout, Python called by the absolute path setup-python
reports, pip and the checker's dependencies from the base's own constraints, and no fallback to
the change's own code when the base cannot run a gate."""

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
        assert "GITHUB_WORKSPACE" not in step["run"].replace('--root "$GITHUB_WORKSPACE"', ""), (
            step["name"]
        )
        assert "::notice::" not in step["run"]
    gates = [s for s in _runs() if "homelabnext.cli modules" in s["run"]]
    assert len(gates) == 2
    for step in gates:
        assert 'cd "$RUNNER_TEMP/base"' in step["run"]
