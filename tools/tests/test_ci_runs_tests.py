# SPDX-License-Identifier: Apache-2.0
"""Q-01 and F-08's checkout half: CI runs the tests, lint and secret scan on every change.

Every push to main and every pull request starts ci.yml, whose jobs run the unit and contract
tests over the whole tree, ruff, and both secret scans. Whether main is green, and whether a red
run blocks a merge, live on the forge, not in the checkout (F-08, a SERVER row with a manual
criterion).

Each rule is a function over the parsed workflow that returns its problems, so the negative
self-tests below can feed it a workflow edited the ways a selection quietly shrinks (an
``--ignore``, a different ``-m``, a path filter on either trigger, a job-level ``if:``,
``PYTEST_ADDOPTS``, a shard that no job runs or no merge counts) and prove each one is caught.

The test job runs the suite in shards (``--shard "$SHARD/N"``, one job per shard of the matrix),
which is a selection only in each job: :func:`shard_problems` holds that the matrix runs shards
1..N and that the ``test-ok`` job merges their reports (``tests/shard_report.py``), proving they
ran every test exactly once, and fails unless every shard passed.
"""

from __future__ import annotations

import copy
import re
import shlex
import tomllib
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
#: the one deselection CI makes: the floor test re-runs the suite under coverage (the coverage job)
FLOOR_TEST = "tools/tests/test_coverage_floor.py::test_this_repo_meets_the_floor"
#: the jobs that carry Q-01: tests, lint and the two secret scans
GUARDED_JOBS = ("test", "lint", "leak-scan", "secret-scan")
#: what a guarded step runs; such a step must not be conditional
GUARDED_COMMANDS = ("pytest", "ruff check", "tools/leak_scan.py", "gitleaks")
#: trigger keys that run the workflow on only some changes
NARROWING = ("paths", "paths-ignore", "branches-ignore", "types")
#: GitHub's default pull_request activity types: a `types:` list holding all of them narrows nothing
PR_DEFAULT_TYPES = {"opened", "synchronize", "reopened"}
#: the flag-value pairs of CI's pytest selection
PAIRS = {("-m", "not live"), ("--deselect", FLOOR_TEST)}
#: the shard flags: which shard (the job's own, of N) and where its report goes
SHARD = re.compile(r"^\$SHARD/([1-9][0-9]*)$")


def _ci():
    doc = yaml.safe_load((ROOT / ".github" / "workflows" / "ci.yml").read_text())
    return doc


def _on(doc):
    return doc.get("on", doc.get(True))  # PyYAML reads the bare key `on` as True


def trigger_problems(doc) -> list[str]:
    on = _on(doc) or {}
    out = []
    branches = (on.get("push") or {}).get("branches") or []
    # more branches than main widen the trigger; a negated pattern can take main back out
    if "main" not in branches or any(str(b).startswith("!") for b in branches):
        out.append("push: must start on every push to main")
    if "pull_request" not in on:
        out.append("pull_request: must start on every pull request")
    elif (on["pull_request"] or {}).get("branches"):
        out.append("pull_request: a branches filter skips some pull requests")
    for event in ("push", "pull_request"):
        for key in NARROWING:
            value = (on.get(event) or {}).get(key)
            if value is None:
                continue
            if event == "pull_request" and key == "types" and set(value) >= PR_DEFAULT_TYPES:
                continue  # e.g. adding ready_for_review: every default type still starts it
            out.append(f"{event}: {key} would skip some changes")
    return out


def pytest_problems(run: str) -> list[str]:
    """The test job's pytest is ``python -m pytest -q -m "not live" --deselect FLOOR_TEST``,
    in any order, with optionally ``--shard "$SHARD/N" --shard-report FILE`` (checked against
    the job by :func:`shard_problems`): an allowlist, so any other flag, value or word
    (``--ignore``, ``-k``, ``-p no:...``, a path, ``|| true``) is a problem."""
    words = shlex.split(run)
    if words[:3] != ["python", "-m", "pytest"]:
        return [f"the test step is not `python -m pytest ...`: {run!r}"]
    out, rest = [], words[3:]
    i = 0
    while i < len(rest):
        w = rest[i]
        if w == "-q":
            i += 1
        elif (
            (w, *rest[i + 1 : i + 2]) in PAIRS
            or (w == "--shard" and SHARD.match(" ".join(rest[i + 1 : i + 2])))
            or (w == "--shard-report" and len(rest) > i + 1)
        ):
            i += 2
        else:
            out.append(f"pytest argument {w!r} is not part of CI's selection")
            i += 1
    if rest.count("-m") != 1:
        out.append('pytest must select exactly -m "not live"')
    if rest.count("--shard") > 1 or rest.count("--shard-report") != rest.count("--shard"):
        out.append("pytest takes --shard and --shard-report once each, or neither")
    return out


def shard_problems(doc, run: str) -> list[str]:
    """A sharded run: the matrix runs shards 1..N, each job its own, and test-ok merges them."""
    words = shlex.split(run)
    if "--shard" not in words:
        return []
    n = int(SHARD.match(words[words.index("--shard") + 1])[1])
    jobs = doc.get("jobs") or {}
    test = jobs.get("test") or {}
    out = []
    if (test.get("strategy") or {}).get("matrix", {}).get("shard") != list(range(1, n + 1)):
        out.append(f"test: the matrix must run shards 1..{n}, the N of --shard")
    (step,) = [s for s in test.get("steps") or [] if s.get("run") == run]
    if (step.get("env") or {}).get("SHARD") != "${{ matrix.shard }}":
        out.append("test: SHARD must be the job's own ${{ matrix.shard }}")
    ok = jobs.get("test-ok") or {}
    needs = ok.get("needs")
    if "test" not in ([needs] if isinstance(needs, str) else needs or []):
        out.append("test-ok: must need the test job, so it waits for every shard")
    if ok.get("if") != "always()" or "continue-on-error" in ok:
        out.append("test-ok: must run whatever the shards did (if: always()), and fail with them")
    runs = [(s.get("run", ""), s.get("env") or {}) for s in ok.get("steps") or []]
    if not any(
        "python3 -m tests.shard_report" in r
        and '[ "$TEST" = success ]' in r
        and env.get("TEST") == "${{ needs.test.result }}"
        for r, env in runs
    ):
        out.append("test-ok: must merge the shard reports and fail unless every shard passed")
    return out


def _env_names(*scopes) -> set[str]:
    return {k for s in scopes for k in (s or {}).get("env", {}) or {}}


def job_problems(doc) -> list[str]:
    out = []
    jobs = doc.get("jobs") or {}
    if "PYTEST_ADDOPTS" in _env_names(doc):
        out.append("workflow env: PYTEST_ADDOPTS changes every pytest's selection")
    for name, job in jobs.items():
        steps = job.get("steps") or []
        if "PYTEST_ADDOPTS" in _env_names(job, *steps):
            out.append(f"{name}: PYTEST_ADDOPTS changes pytest's selection")
    for name in GUARDED_JOBS:
        job = jobs.get(name)
        if job is None:
            out.append(f"{name}: job is missing")
            continue
        for key in ("if", "continue-on-error"):
            if key in job:
                out.append(f"{name}: job-level {key}: lets it skip or pass while red")
        for step in job.get("steps") or []:
            run = step.get("run", "")
            if any(c in run for c in GUARDED_COMMANDS):
                for key in ("if", "continue-on-error"):
                    if key in step:
                        out.append(f"{name}: step-level {key}: on {run.split()[:3]}")
    return out


def _pytest_runs(doc) -> list[str]:
    """Every test-job step that runs pytest.  A step that only names it (installing a plugin,
    printing a version) is not one, and an extra pytest run cannot shrink the full one."""
    runs = [s.get("run", "") for s in doc["jobs"]["test"]["steps"]]
    return [r for r in runs if shlex.split(r)[:3] == ["python", "-m", "pytest"]]


def selection_problems(doc) -> list[str]:
    runs = _pytest_runs(doc)
    if not runs:
        return ["the test job has no `python -m pytest` step"]
    found = [pytest_problems(r) or shard_problems(doc, r) for r in runs]
    return [] if [] in found else [p for f in found for p in f]


def test_ci_starts_on_every_push_to_main_and_every_pull_request():
    assert trigger_problems(_ci()) == []


def test_the_test_job_runs_every_suite_with_no_selection_but_ci_s_own():
    assert selection_problems(_ci()) == []
    with (ROOT / "pyproject.toml").open("rb") as f:
        ini = tomllib.load(f)["tool"]["pytest"]["ini_options"]
    # no positional path: pytest's testpaths decide, so every suite runs
    assert set(ini["testpaths"]) == {"tests", "tools/tests", "conformance"}
    # and addopts only reports and tightens; it never selects
    assert set(shlex.split(ini.get("addopts", ""))) <= {"-ra", "--strict-markers"}


def test_no_guarded_job_is_conditional_or_carries_pytest_addopts():
    assert job_problems(_ci()) == []


def test_lint_and_both_secret_scans_run():
    jobs = _ci()["jobs"]
    lint = [s.get("run", "") for s in jobs["lint"]["steps"]]
    assert "python -m ruff check ." in lint
    scans = " ".join(s.get("run", "") for j in GUARDED_JOBS for s in jobs[j].get("steps", []))
    assert "tools/leak_scan.py" in scans and "gitleaks git" in scans


# --- negative self-tests: each edit that narrows what CI runs is caught --------------------------

BASE_RUN = f'python -m pytest -q -m "not live" --deselect {FLOOR_TEST}'


@pytest.mark.parametrize(
    "run",
    [
        BASE_RUN + " --ignore=tests/broker",
        BASE_RUN + " --ignore tests/broker",
        BASE_RUN + " --ignore-glob=tests/a*",
        BASE_RUN + " --deselect tests/broker/test_x.py::test_y",
        BASE_RUN + " -p no:randomly",
        BASE_RUN + " -k broker",
        BASE_RUN + " tests/broker",
        BASE_RUN + " || true",
        'python -m pytest -q -m "not live and not slow"',
        "python -m pytest -q -m live",
        "python -m pytest -q",
        BASE_RUN + ' -m "not live"',
        f'python -m pytest -q -m="not live" --deselect {FLOOR_TEST}',
        BASE_RUN.replace("python -m pytest", "pytest"),
        BASE_RUN + ' --shard "1/4" --shard-report r.json',  # a fixed shard, not the job's own
        BASE_RUN + ' --shard "$SHARD/4"',  # no report: nothing can count it
        BASE_RUN + ' --shard "$SHARD/4" --shard "$SHARD/2" --shard-report r.json',
    ],
)
def test_a_narrowed_pytest_line_is_caught(run):
    assert pytest_problems(run), run


def test_ci_s_own_line_passes_in_any_order():
    assert pytest_problems(f'python -m pytest --deselect {FLOOR_TEST} -m "not live" -q') == []


def _edited(edit):
    doc = copy.deepcopy(_ci())
    edit(doc)
    return doc


@pytest.mark.parametrize("event", ["push", "pull_request"])
@pytest.mark.parametrize("key", NARROWING)
def test_a_narrowing_trigger_filter_is_caught(event, key):
    def edit(doc):
        on = _on(doc)
        on[event] = dict(on[event] or {}, **{key: ["homelabnext/broker/**"]})

    assert trigger_problems(_edited(edit))


def test_a_branch_filter_on_pull_requests_or_another_push_branch_is_caught():
    assert trigger_problems(_edited(lambda d: _on(d).update(pull_request={"branches": ["x"]})))
    assert trigger_problems(_edited(lambda d: _on(d).update(push={"branches": ["release"]})))
    assert trigger_problems(_edited(lambda d: _on(d).update(push={"branches": ["main", "!main"]})))
    assert trigger_problems(_edited(lambda d: _on(d).pop("pull_request")))
    narrow = {"types": ["opened", "reopened"]}  # no synchronize: a pushed fix is never tested
    assert trigger_problems(_edited(lambda d: _on(d).update(pull_request=narrow)))


# --- legitimate edits that widen or leave CI's selection alone pass ----------------------------


def test_widening_the_triggers_is_not_a_problem():
    wide = {"types": ["opened", "synchronize", "reopened", "ready_for_review"]}
    assert trigger_problems(_edited(lambda d: _on(d).update(pull_request=wide))) == []
    more = {"branches": ["main", "release/**"]}
    assert trigger_problems(_edited(lambda d: _on(d).update(push=more))) == []


def test_another_step_naming_or_running_pytest_is_not_a_problem():
    def edit(doc):
        steps = doc["jobs"]["test"]["steps"]
        steps.insert(-1, {"run": "python -m pip install pytest-timeout"})
        steps.append({"run": "python -m pytest -q tests/cli -p no:randomly"})

    doc = _edited(edit)
    assert selection_problems(doc) == [] and job_problems(doc) == []


def test_a_test_job_whose_only_pytest_is_narrowed_is_still_caught():
    def edit(doc):
        for s in doc["jobs"]["test"]["steps"]:
            if s.get("run", "").startswith("python -m pytest"):
                s["run"] += " --ignore=tests/broker"

    assert selection_problems(_edited(edit))


@pytest.mark.parametrize("job", GUARDED_JOBS)
@pytest.mark.parametrize("key", ["if", "continue-on-error"])
def test_a_conditional_guarded_job_is_caught(job, key):
    assert job_problems(_edited(lambda d: d["jobs"][job].update({key: "false"})))


@pytest.mark.parametrize("key", ["if", "continue-on-error"])
def test_a_conditional_pytest_step_is_caught(key):
    def edit(doc):
        for s in doc["jobs"]["test"]["steps"]:
            if s.get("run", "").startswith("python -m pytest"):
                s[key] = "github.event_name == 'push'"

    assert job_problems(_edited(edit))


@pytest.mark.parametrize("scope", ["workflow", "job", "step"])
def test_pytest_addopts_in_any_env_is_caught(scope):
    def edit(doc):
        target = {
            "workflow": doc,
            "job": doc["jobs"]["test"],
            "step": next(
                s for s in doc["jobs"]["test"]["steps"] if s.get("run", "").startswith("python -m")
            ),
        }[scope]
        target.setdefault("env", {})["PYTEST_ADDOPTS"] = "--ignore=tests/broker"

    assert job_problems(_edited(edit))


def _sharded_step(doc):
    (step,) = [s for s in doc["jobs"]["test"]["steps"] if "--shard" in s.get("run", "")]
    return step


@pytest.mark.parametrize(
    "edit",
    [
        lambda d: d["jobs"]["test"]["strategy"]["matrix"].update(shard=[1, 2, 3]),
        lambda d: d["jobs"]["test"]["strategy"]["matrix"].update(shard=[1, 2, 3, 4, 5]),
        lambda d: d["jobs"]["test"]["strategy"]["matrix"].pop("shard"),
        lambda d: _sharded_step(d)["env"].update(SHARD="1"),
        lambda d: d["jobs"].pop("test-ok"),
        lambda d: d["jobs"]["test-ok"].update(needs=["lint"]),
        lambda d: d["jobs"]["test-ok"].pop("if"),
        lambda d: d["jobs"]["test-ok"].update({"continue-on-error": True}),
        lambda d: d["jobs"]["test-ok"]["steps"][-1].update(run="echo ok"),
        lambda d: d["jobs"]["test-ok"]["steps"][-1]["env"].update(TEST="success"),
    ],
)
def test_a_shard_no_job_runs_or_no_merge_counts_is_caught(edit):
    assert selection_problems(_edited(edit))
