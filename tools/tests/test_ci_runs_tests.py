# SPDX-License-Identifier: Apache-2.0
"""Q-01 and F-08's checkout half: CI runs the tests, lint and secret scan on every change.

Every push to main and every pull request starts ci.yml, whose jobs run the unit and contract
tests over the whole tree, ruff, and both secret scans. Whether main is green, and whether a red
run blocks a merge, live on the forge, not in the checkout (F-08 is a manual criterion).
"""

from __future__ import annotations

import shlex
import tomllib
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]


def _ci():
    doc = yaml.safe_load((ROOT / ".github" / "workflows" / "ci.yml").read_text())
    # PyYAML reads the bare key `on` as True
    return doc, doc.get("on", doc.get(True))


def _runs(job):
    return [s.get("run", "") for s in _ci()[0]["jobs"][job]["steps"]]


def test_ci_starts_on_every_push_to_main_and_every_pull_request():
    _, on = _ci()
    assert on["push"]["branches"] == ["main"]
    assert "pull_request" in on and not (on["pull_request"] or {}).get("branches")
    assert not (on["pull_request"] or {}).get("paths"), "a paths filter would skip some changes"


def test_the_test_job_runs_every_suite_with_no_path_selection():
    (run,) = [r for r in _runs("test") if "pytest" in r]
    words = shlex.split(run)[3:]  # after `python -m pytest`
    takes_value = {"-m", "--deselect", "-k"}
    positional = [
        w for i, w in enumerate(words) if not w.startswith("-") and words[i - 1] not in takes_value
    ]
    assert positional == [], positional  # pytest's testpaths then decide, so every suite runs
    assert "-k" not in words
    with (ROOT / "pyproject.toml").open("rb") as f:
        testpaths = tomllib.load(f)["tool"]["pytest"]["ini_options"]["testpaths"]
    assert set(testpaths) == {"tests", "tools/tests", "conformance"}


def test_lint_and_both_secret_scans_run():
    lint = _runs("lint")
    assert "python -m ruff check ." in lint
    jobs = _ci()[0]["jobs"]
    scans = " ".join(s.get("run", "") for j in jobs.values() for s in j.get("steps", []))
    assert "tools/leak_scan.py" in scans and "gitleaks git" in scans
