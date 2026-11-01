# SPDX-License-Identifier: Apache-2.0
"""`make test` selects what CI's test job selects, `make check` runs the coverage floor, and every
command `make check` runs also runs in a required CI job.

A local gate that is red on a green tree (the floor test re-running the whole suite under
coverage inside tools/tests' time budget) trains people to ignore red; one that selects less
than CI lets a red CI surprise a contributor whose `make check` passed.
"""

import re
import shlex
from pathlib import Path

import pytest
import yaml
from test_experimental import make_target_lines

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
    # the full run: a `python -m pytest` step selecting "not live ..." (one that only installs a
    # plugin, or runs a subset beside it, is not what make test mirrors)
    runs = [shlex.split(s.get("run", "")) for s in ci["jobs"]["test"]["steps"]]
    runs = [
        w for w in runs if w[:3] == ["python", "-m", "pytest"] and any("not live" in x for x in w)
    ]
    assert len(runs) == 1, runs
    # less the shard flags: each CI job runs a shard of what make test runs whole
    words = runs[0][3:]
    for flag in ("--shard", "--shard-report"):
        if flag in words:
            del words[words.index(flag) : words.index(flag) + 2]
    return words


def test_make_test_selects_what_the_ci_test_job_selects():
    assert make_pytest_args() == ci_pytest_args()


def test_make_test_leaves_the_floor_to_the_coverage_target():
    args = make_pytest_args()
    assert "tools/tests/test_coverage_floor.py::test_this_repo_meets_the_floor" in args
    # the tests of tools/experimental.yml run in `make experimental`, never here
    assert args[args.index("-m") + 1] == "not live and not experimental"


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


# --- every gate of `make check` runs in CI -------------------------------------------------------

#: the `make check` commands no CI job runs as written, each with the reason
NOT_IN_CI = {
    # CI's regression-tests job runs the same tool on the event's range with --prove
    "python tools/fix_has_test.py --range origin/main..HEAD --allow-missing-base": "regression-tests",
}


def _commands(lines) -> set[str]:
    """The ``python ...`` commands of some shell lines: continuations joined, split at ``;``,
    ``&&`` and ``||``, loop keywords and ``exit 1`` dropped, ``$$`` as the shell sees it, make's
    ``$(if ...)`` (an opt-in, such as BASE) and an unset ``$(VAR)`` removed, ``$(wildcard X)``
    as the glob ``X`` and ``python3`` as ``python``."""
    text = "\n".join(lines).replace("\\\n", " ")
    text = re.sub(r"\$\(wildcard ([^)]*)\)", r"\1", text)
    text = re.sub(r"\$\(dir ([^)]*/)[^/)]*\)", r"\1", text)
    text = re.sub(r"\$\(or \$\(\w+\),([^)]*)\)", r"\1", text)
    text = re.sub(r"\$\(if [^()]*(?:\([^()]*\)[^()]*)*\)", "", text)
    text = re.sub(r"\$\([A-Z_]+\)", "", text).replace("$$", "$")
    out = set()
    for part in re.split(r"\n|;|&&|\|\|", text):
        words = part.strip().lstrip("@").split()
        while words and words[0] in ("do", "then"):
            words = words[1:]
        if words and words[0] in ("python", "python3"):
            out.add(" ".join(["python", *words[1:]]))
    return out


def _as_make_runs_it(cmd: str) -> str:
    """A CI command less what only CI adds: the base it compares with (``--ci-base``,
    ``--base REV``) and the test shard (``--shard``, ``--shard-report``)."""
    cmd = re.sub(r" --ci-base\b", "", cmd)
    return re.sub(r' --(?:base|shard|shard-report) (?:"[^"]*"|\S+)', "", cmd)


def _ci_commands(ci) -> set[str]:
    """Every ``python ...`` command a required CI job runs, and those of each ``make <target>``
    it calls (the `experimental` job blocks nothing and is left out)."""
    text = (ROOT / "Makefile").read_text()
    out: set[str] = set()
    for name, job in ci["jobs"].items():
        if name == "experimental":
            continue
        for step in job.get("steps") or []:
            run = str(step.get("run", ""))
            # the `hnx` entry point is the CLI module
            run = re.sub(r"^(\s*)hnx ", r"\1python -m homelabnext.cli ", run, flags=re.M)
            out |= {_as_make_runs_it(c) for c in _commands(run.splitlines())}
            for target in re.findall(r"^\s*make ([a-z][\w-]*)", run, re.M):
                rules = make_target_lines(text, target).values()
                out |= _commands(line for lines in rules for line in lines)
    return out


def check_parity_problems(make_text: str, ci: dict) -> list[str]:
    ci_cmds = _ci_commands(ci)
    out = []
    for target, lines in sorted(make_target_lines(make_text, "check").items()):
        for cmd in sorted(_commands(lines)):
            if cmd not in ci_cmds and cmd not in NOT_IN_CI:
                out.append(f"make {target}: CI never runs `{cmd}`")
    return out


def test_every_command_make_check_runs_also_runs_in_a_required_ci_job():
    ci = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
    assert check_parity_problems((ROOT / "Makefile").read_text(), ci) == []


def test_a_gate_only_make_check_runs_is_caught():
    text = (ROOT / "Makefile").read_text()
    ci = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
    added = text.replace(
        "\t$(PY) -m homelabnext.cli graph check\n",
        "\t$(PY) -m homelabnext.cli graph check\n\t$(PY) -m homelabnext.cli graph check --strict\n",
    )
    assert added != text
    assert check_parity_problems(added, ci) == [
        "make gates: CI never runs `python -m homelabnext.cli graph check --strict`"
    ]
    for step in ci["jobs"]["schemas"]["steps"]:
        if "graph check" in str(step.get("run", "")):
            step["run"] = "true"
    assert "make gates: CI never runs `python -m homelabnext.cli graph check`" in (
        check_parity_problems(text, ci)
    )
