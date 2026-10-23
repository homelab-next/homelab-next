# SPDX-License-Identifier: Apache-2.0
"""`make test` selects what CI's test job selects, and `make check` runs the coverage floor.

A local gate that is red on a green tree (the floor test re-running the whole suite under
coverage inside tools/tests' time budget) trains people to ignore red; one that selects less
than CI lets a red CI surprise a contributor whose `make check` passed.
"""

import re
import shlex
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]


def _make_vars(text):
    return {m[1]: m[2].strip() for m in re.finditer(r"^([A-Z_]+) :?= (.*)$", text, re.M)}


def _recipe(text, target):
    m = re.search(rf"^{re.escape(target)}:\n((?:\t.*\n)+)", text, re.M)
    assert m, f"no recipe for {target}"
    return [line.strip() for line in m[1].splitlines()]


def _expand(line, variables):
    return re.sub(r"\$\((\w+)\)", lambda m: variables.get(m[1], m[0]), line)


def makefile_problems(text):
    """What the simple parser above cannot model, refused outright: an appended or conditional
    assignment (``+=``, ``?=``, ``!=``) of a variable the recipe uses, a second ``test:`` rule,
    and ``PYTEST_ADDOPTS`` anywhere (make exports it to pytest)."""
    out = []
    # PY (`PY ?= python3`) only names the interpreter; every other variable selects tests
    used = set(re.findall(r"\$\((\w+)\)", " ".join(_recipe(text, "test")))) - {"PY"}
    for m in re.finditer(r"^(?:override\s+|export\s+)?([A-Z_]+)\s*([+?!]|::?)?=", text, re.M):
        if m[1] in used and m[2] in ("+", "?", "!"):
            out.append(f"{m[1]} {m[2]}= changes what the test recipe runs")
    if len(re.findall(r"^test:", text, re.M)) != 1:
        out.append("more than one `test:` rule")
    if "PYTEST_ADDOPTS" in text:
        out.append("PYTEST_ADDOPTS changes pytest's selection")
    return out


def make_pytest_args():
    text = (ROOT / "Makefile").read_text()
    assert makefile_problems(text) == []
    (line,) = _recipe(text, "test")
    words = shlex.split(_expand(line, _make_vars(text)))
    assert words[:3] == ["$(PY)", "-m", "pytest"], words
    return words[3:]


def ci_pytest_args():
    ci = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
    runs = [s["run"] for s in ci["jobs"]["test"]["steps"] if "pytest" in s.get("run", "")]
    assert len(runs) == 1, runs
    words = shlex.split(runs[0])
    assert words[:3] == ["python", "-m", "pytest"], words
    return words[3:]


def test_make_test_selects_what_the_ci_test_job_selects():
    assert make_pytest_args() == ci_pytest_args()


def test_make_test_leaves_the_floor_to_the_coverage_target():
    args = make_pytest_args()
    assert "tools/tests/test_coverage_floor.py::test_this_repo_meets_the_floor" in args
    assert args[args.index("-m") + 1] == "not live"


def test_make_check_runs_the_coverage_floor_like_ci():
    text = (ROOT / "Makefile").read_text()
    prereqs = {w for m in re.finditer(r"^check:(.*)$", text, re.M) for w in m[1].split()}
    assert {"test", "coverage"} <= prereqs
    assert _recipe(text, "coverage") == ["$(PY) tools/coverage_floor.py"]
    ci = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
    assert any(
        s.get("run") == "python tools/coverage_floor.py" for s in ci["jobs"]["coverage"]["steps"]
    )


@pytest.mark.parametrize(
    "extra",
    [
        "PYTEST_ARGS += --ignore=tests/broker\n",
        "PYTEST_ARGS ?= -q\n",
        "override PYTEST_ARGS += -k x\n",
        "export PYTEST_ADDOPTS = --ignore=tests/broker\n",
        "test:\n\t$(PY) -m pytest tests/cli\n",
    ],
)
def test_a_makefile_that_the_parser_would_misread_is_refused(extra):
    text = (ROOT / "Makefile").read_text()
    assert makefile_problems(text) == []
    assert makefile_problems(text + "\n" + extra), extra
