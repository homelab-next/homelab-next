# SPDX-License-Identifier: Apache-2.0
"""``tools/experimental.yml`` is the one list of what is out of the blocking set, and it holds.

The operator's v0 cuts (2026-10-31) took the playbook engine, Code Mode, the strategy stack and the
home-built projects store out of what blocks a merge without deleting them: their gates and tests
still run, in ``make experimental`` and CI's ``experimental`` job.  These tests hold the Makefile,
CI, the invariants register and the test marker to the list, so a gate cannot drift back into
``make check`` or a required CI job unreviewed, a listed component cannot quietly stop running,
and nothing marks a test ``experimental`` except the list.
"""

from __future__ import annotations

import datetime as dt
import io
import re
import shlex
import subprocess
import sys
from pathlib import Path

import pytest
import yaml
from test_ci_runs_tests import without_network

from tests.experimental_marker import experimental as ex

ROOT = Path(__file__).resolve().parents[2]
MAKEFILE = ROOT / "Makefile"
CI = ROOT / ".github" / "workflows" / "ci.yml"
INVARIANTS = ROOT / "examples" / "registers" / "invariants.yml"
JOB = "experimental"


def _gate_tail(gate: str) -> str:
    """A gate without its interpreter: what a Makefile (``$(PY) -m ...``) or CI line contains."""
    return " ".join(shlex.split(gate)[1:])


def _expand(line: str, variables: dict[str, str]) -> str:
    for _ in range(5):  # nested variables, a few levels deep
        line = re.sub(r"\$\((\w+)\)", lambda m: variables.get(m[1], m[0]), line)
    return line.replace("$(PY)", "python")


def make_rules(text: str) -> tuple[dict[str, list[str]], dict[str, list[str]]]:
    """Each target's prerequisites and recipe lines (``check:`` may be given more than once; the
    lists are merged, as make merges them), with simple variables expanded."""
    variables = {m[1]: m[2].strip() for m in re.finditer(r"^([A-Z_]+) [:?]?= (.*)$", text, re.M)}
    prereqs: dict[str, list[str]] = {}
    recipes: dict[str, list[str]] = {}
    current = None
    for line in text.splitlines():
        m = re.match(r"^([A-Za-z0-9_.-]+):(?!=)(.*)$", line)
        if m and not line.startswith("\t"):
            current = None if m[1].startswith(".") else m[1]
            if current:
                prereqs.setdefault(current, []).extend(m[2].split("#")[0].split())
            continue
        if line.startswith("\t") and current:
            recipes.setdefault(current, []).append(_expand(line.strip(), variables))
        elif not line.startswith("\t"):
            current = None
    return prereqs, recipes


def make_target_lines(text: str, target: str) -> dict[str, list[str]]:
    """The recipe lines `make <target>` runs, per target: ``target``'s and its prerequisites',
    transitively, ``$(MAKE) <target>`` calls included."""
    prereqs, recipes = make_rules(text)
    seen: dict[str, list[str]] = {}
    todo = [target]
    while todo:
        t = todo.pop()
        if t in seen:
            continue
        seen[t] = recipes.get(t, [])
        todo += prereqs.get(t, [])
        for line in seen[t]:
            todo += re.findall(r"\$\(MAKE\)\s+([A-Za-z0-9_.-]+)", line)
    return seen


def make_check_lines(text: str) -> list[str]:
    """Every recipe line `make check` runs: the recipes of ``check`` and of its prerequisites,
    transitively, ``$(MAKE) <target>`` calls included, with simple variables expanded."""
    return [line for lines in make_target_lines(text, "check").values() for line in lines]


def ci_lines(doc: dict, *, skip: tuple[str, ...] = (JOB,)) -> list[str]:
    """Every ``run:`` line of every CI job except ``skip``."""
    return [
        line.strip()
        for name, job in (doc.get("jobs") or {}).items()
        if name not in skip
        for step in job.get("steps") or []
        for line in str(step.get("run", "")).splitlines()
    ]


def blocking_problems(components, make_text: str, ci_doc: dict) -> list[str]:
    out = []
    make_lines = make_check_lines(make_text)
    runs = ci_lines(ci_doc)
    for c in components:
        for gate in c.gates:
            tail = _gate_tail(gate)
            if any(tail in line for line in make_lines):
                out.append(f"{c.name}: `make check` still runs {tail!r}")
            if any(tail in line for line in runs):
                out.append(f"{c.name}: a CI job other than {JOB} still runs {tail!r}")
    return out


def job_problems(ci_doc: dict) -> list[str]:
    jobs = ci_doc.get("jobs") or {}
    job = jobs.get(JOB)
    if job is None:
        return [f"CI has no {JOB} job: the listed components would stop running"]
    out = []
    if job.get("continue-on-error") is not True:
        out.append(f"{JOB}: must be continue-on-error: true (it blocks no merge)")
    if "if" in job:
        out.append(f"{JOB}: a job-level if: lets it stop running")
    runs = [str(s.get("run", "")).strip() for s in job.get("steps") or []]
    if "make experimental PY=python" not in runs:
        out.append(f"{JOB}: must run `make experimental PY=python`")
    for name, other in jobs.items():
        needs = other.get("needs") or []
        if JOB in ([needs] if isinstance(needs, str) else needs):
            out.append(f"{name}: needs {JOB}, which would make it block")
    return out


# --- the list itself -------------------------------------------------------------------------


def test_the_list_is_valid_and_names_the_operator_s_cuts():
    components = {c.name: c for c in ex.load()}
    assert {"code-mode", "strategy", "projects-store"} <= set(components)
    # the playbook engine is the one experimental (built on) entry, the rest are frozen
    assert sorted(c.status for c in components.values()).count("experimental") == 1
    assert components["code-mode"].status == "frozen"


def test_every_listed_page_says_so():
    for c in ex.load():
        for page in c.docs:
            text = (ROOT / page).read_text(encoding="utf-8")
            assert "tools/experimental.yml" in text, f"{page} does not name tools/experimental.yml"
            assert c.status in text.lower(), f"{page} does not say {c.name} is {c.status}"


GOOD = {
    "status": "frozen",
    "decided": dt.date(2026, 10, 31),
    "why": "x",
    "until": "y",
    "docs": ["docs/strategy.md"],
    "tests": ["tests/strategy"],
    "gates": ["python -m homelabnext.strategy check examples/strategy"],
}


def test_the_minimal_entry_parses():
    (c,) = ex.parse({"components": {"c": GOOD}})
    assert (c.name, c.tests, c.invariants) == ("c", ("tests/strategy",), ())


@pytest.mark.parametrize(
    "entry, words",
    [
        ({"status": "paused"}, "status: must be one of"),
        ({"decided": "soon"}, "decided: must be a YYYY-MM-DD date"),
        ({"tests": ["tests/no-such-dir"]}, "is not a path in the repository"),
        ({"tests": ["homelabnext/cli.py"]}, "is not under tests/"),
        ({"tests": []}, "tests: must not be empty"),
        ({"gates": ["make strategy"]}, "must be `python -m <module> ...`"),
        ({"invariants": ["P8"]}, "is not a criterion id"),
        ({"owner": "x"}, "owner: unknown key"),
        ({"conform": ["projects"]}, "no gate runs `hnx conform report --capability projects`"),
        ({"code": ["tests/strategy/conftest.py"]}, "is not a Python module outside the tests"),
        ({"code": ["docs/strategy.md"]}, "is not a Python module outside the tests"),
        ({"code": ["homelabnext/no_such_module.py"]}, "is not a path in the repository"),
    ],
)
def test_a_bad_entry_is_refused(entry, words):
    with pytest.raises(ex.ListError) as err:
        ex.parse({"components": {"c": {**GOOD, **entry}}})
    assert any(words in p for p in err.value.problems), err.value.problems


def test_a_test_path_claimed_twice_is_refused():
    with pytest.raises(ex.ListError, match="listed by both a and b"):
        ex.parse({"components": {"a": GOOD, "b": GOOD}})


def test_path_matching_is_by_whole_path_segments():
    paths = ("tests/strategy", "tests/projects/test_projects_store.py")
    assert ex.is_experimental("tests/strategy/test_strategy_links.py", paths)
    assert ex.is_experimental("tests/projects/test_projects_store.py", paths)
    assert not ex.is_experimental("tests/strategy_other/test_x.py", paths)
    assert not ex.is_experimental("tests/projects/test_projects_product.py", paths)


# --- out of the blocking set, still running --------------------------------------------------


def test_no_listed_gate_blocks_a_merge():
    ci = yaml.safe_load(CI.read_text(encoding="utf-8"))
    assert blocking_problems(ex.load(), MAKEFILE.read_text(encoding="utf-8"), ci) == []


def test_a_gate_put_back_into_make_check_or_a_required_job_is_caught():
    components = ex.load()
    make = MAKEFILE.read_text(encoding="utf-8")
    ci = yaml.safe_load(CI.read_text(encoding="utf-8"))
    assert blocking_problems(components, make + "\ncheck: strategy\n", ci)
    gate = next(g for c in components for g in c.gates if "workflows" in g)
    put_back = make.replace(
        "\t$(PY) -m homelabnext.cli workflows validate\n",
        "\t$(PY) -m homelabnext.cli workflows validate\n\t$(PY) " + gate.split(" ", 1)[1] + "\n",
    )
    assert put_back != make and blocking_problems(components, put_back, ci)
    ci["jobs"]["schemas"]["steps"].append({"run": "python -m homelabnext.cli codemode gen --check"})
    assert blocking_problems(components, make, ci)


def test_ci_runs_the_listed_components_in_a_job_that_blocks_nothing():
    ci = yaml.safe_load(CI.read_text(encoding="utf-8"))
    assert job_problems(ci) == []
    blocking = yaml.safe_load(CI.read_text(encoding="utf-8"))
    blocking["jobs"][JOB].pop("continue-on-error")
    assert job_problems(blocking)
    needed = yaml.safe_load(CI.read_text(encoding="utf-8"))
    needed["jobs"]["test-ok"]["needs"] = ["test", JOB]
    assert job_problems(needed)
    gone = yaml.safe_load(CI.read_text(encoding="utf-8"))
    del gone["jobs"][JOB]
    assert job_problems(gone)


def test_make_experimental_runs_the_list():
    text = MAKEFILE.read_text(encoding="utf-8")
    m = re.search(r"^experimental:\n((?:\t.*\n)+)", text, re.M)
    assert m and m[1].strip() == "$(PY) tools/experimental.py run"


def test_the_blocking_runs_deselect_exactly_the_marker():
    assert ex.BLOCKING_SELECT == "not live and not experimental"
    assert ex.SELECT == "experimental and not live"
    assert f'-m "{ex.BLOCKING_SELECT}"' in MAKEFILE.read_text(encoding="utf-8")


def test_the_conformance_harness_leaves_out_exactly_the_listed_capabilities():
    from homelabnext.conform.registry import CAPABILITIES, EXPERIMENTAL

    listed = ex.experimental_capabilities(ex.load())
    assert sorted(EXPERIMENTAL) == sorted(listed)
    assert set(listed) <= set(CAPABILITIES)
    # the frozen components own them: Code Mode its two suites. The projects suite stays blocking
    # although the home-built store is frozen, since it also checks the OpenProject adapter
    owner = {cap: c.name for c in ex.load() for cap in c.conform}
    assert owner == {
        "codemode-executor": "code-mode",
        "codemode-runner": "code-mode",
    }
    assert "projects" not in listed


def test_make_invariants_skips_exactly_the_listed_criteria():
    text = MAKEFILE.read_text(encoding="utf-8")
    m = re.search(r"^EXPERIMENTAL_INVARIANTS := (.*)$", text, re.M)
    assert m, "the Makefile has no EXPERIMENTAL_INVARIANTS"
    listed = sorted(i for c in ex.load() for i in c.invariants)
    assert sorted(m[1].strip().split(",")) == listed
    target = re.search(r"^invariants:\n\t(.+)$", text, re.M)
    assert target and "--skip $(EXPERIMENTAL_INVARIANTS)" in target[1]
    # each is a real criterion, still in the register (the row stays PUBLIC-NOW and runnable)
    doc = yaml.safe_load(INVARIANTS.read_text(encoding="utf-8"))
    ids = {c["id"] for c in doc["criteria"]}
    assert set(listed) <= ids


def test_no_test_is_marked_experimental_by_hand():
    hand = re.compile(r"mark\.experimental\b")
    offenders = [
        p.relative_to(ROOT).as_posix()
        for top in ("tests", "tools/tests", "conformance")
        for p in (ROOT / top).rglob("*.py")
        if p.name != "experimental_marker.py" and hand.search(p.read_text(encoding="utf-8"))
    ]
    assert offenders == [], f"the marker comes from tools/experimental.yml only: {offenders}"


def test_the_listed_tests_are_marked_and_others_are_not():
    # the plugin's own decision, on real node paths: a listed file is marked, its neighbour is not
    paths = ex.marked_paths(ex.load())
    engine = next(p for p in paths if p.startswith("tests/workflows/"))
    assert ex.is_experimental(engine, paths)
    assert not ex.is_experimental("tests/workflows/test_workflows_validate.py", paths)
    assert ex.is_experimental("tests/codemode/test_runner.py", paths)
    assert not ex.is_experimental("tests/mcp/test_mcp_launch.py", paths)


def blocking_selection_problems(ci_doc: dict, paths) -> list[str]:
    """A ``pytest`` run in a job that blocks must deselect the marker, or name only test paths
    none of which is, or holds, an experimental one."""
    out = []
    for line in ci_lines(ci_doc):
        words = shlex.split(without_network(line)) if "pytest" in line else []
        if words[:3] != ["python", "-m", "pytest"]:
            continue
        if "-m" in words and words[words.index("-m") + 1] == ex.BLOCKING_SELECT:
            continue
        named = [w for w in words[3:] if w.startswith(("tests/", "tools/tests/", "conformance/"))]
        inside = [p for w in named for p in paths if p.startswith(w.rstrip("/") + "/")]
        if not named or inside or any(ex.is_experimental(w, paths) for w in named):
            out.append(f"a blocking job's pytest selects experimental tests: {line}")
    return out


def test_no_blocking_job_selects_an_experimental_test():
    ci = yaml.safe_load(CI.read_text(encoding="utf-8"))
    paths = ex.marked_paths(ex.load())
    assert blocking_selection_problems(ci, paths) == []
    ci["jobs"]["schemas"]["steps"].append({"run": "python -m pytest -q tests/workflows"})
    assert blocking_selection_problems(ci, paths)


def test_the_coverage_gate_selects_its_tests_like_the_blocking_jobs(tmp_path, monkeypatch):
    # the coverage job runs tools/coverage_floor.py, which starts a pytest of its own per unit
    sys.path.insert(0, str(ROOT / "tools"))
    import coverage_floor

    cmds = []

    def fake_run(cmd, **_):
        cmds.append(cmd)
        return type("Done", (), {"returncode": 0})()

    monkeypatch.setattr(coverage_floor.subprocess, "run", fake_run)
    coverage_floor.run_tests(tmp_path / "g.json", ("tests/workflows",), ["homelabnext/workflows"])
    (cmd,) = cmds
    assert cmd[cmd.index("-m", 3) + 1] == ex.BLOCKING_SELECT


# --- the ratchet: the list only shrinks against the base ------------------------------------

BASE_LIST = {
    "components": {
        "engine": {
            "status": "experimental",
            "decided": dt.date(2026, 10, 31),
            "why": "x",
            "until": "y",
            "docs": ["docs/engine.md"],
            "tests": ["tests/engine", "tests/other/test_engine.py"],
            "gates": ["python -m homelabnext.cli engine check"],
            "invariants": ["R-09"],
            "code": ["homelabnext/engine.py"],
        }
    }
}


def _git(root: Path, *args: str) -> str:
    env = {
        "GIT_AUTHOR_NAME": "t",
        "GIT_AUTHOR_EMAIL": "t@example.invalid",
        "GIT_COMMITTER_NAME": "t",
        "GIT_COMMITTER_EMAIL": "t@example.invalid",
        "GIT_CONFIG_NOSYSTEM": "1",
        "HOME": str(root),
        "PATH": "/usr/bin:/bin",
    }
    cmd = ["git", "-C", str(root), *args]
    return subprocess.run(cmd, capture_output=True, text=True, env=env, check=True).stdout.strip()


def _write(root: Path, doc: object) -> None:
    (root / "tools").mkdir(exist_ok=True)
    (root / "tools" / "experimental.yml").write_text(yaml.safe_dump(doc), encoding="utf-8")


@pytest.fixture
def repo(tmp_path):
    """A repository whose one commit (the base) holds BASE_LIST, with every path the tests name."""
    for rel in (
        "docs/engine.md",
        "tests/engine/test_a.py",
        "tests/other/test_engine.py",
        "tests/broker/test_broker.py",
        "homelabnext/engine.py",
        "homelabnext/broker.py",
    ):
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text("\n", encoding="utf-8")
    _write(tmp_path, BASE_LIST)
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "add", "-A")
    _git(tmp_path, "commit", "-q", "-m", "base")
    return tmp_path, _git(tmp_path, "rev-parse", "HEAD")


def _head(**changes) -> dict:
    doc = yaml.safe_load(yaml.safe_dump(BASE_LIST))
    doc["components"]["engine"].update(changes)
    return doc


def _ratchet(repo, doc: object, growth: str = "none") -> tuple[int, str]:
    root, base = repo
    _write(root, doc)
    out = io.StringIO()
    return ex.ratchet(root, base, {ex.GROWTH_ENV: growth}, out), out.getvalue()


def test_the_unchanged_list_passes_the_ratchet(repo):
    assert _ratchet(repo, BASE_LIST)[0] == 0


def test_a_new_frozen_component_fails_the_ratchet(repo):
    doc = yaml.safe_load(yaml.safe_dump(BASE_LIST))
    doc["components"]["broker"] = {
        **doc["components"]["engine"],
        "status": "frozen",
        "tests": ["tests/broker"],
        "invariants": [],
        "code": ["homelabnext/broker.py"],
    }
    rc, out = _ratchet(repo, doc)
    assert rc == 1, out
    assert "components.broker: a component the base does not list" in out
    assert "components.broker.tests: tests/broker is not out of the blocking set" in out
    assert "components.broker.code: homelabnext/broker.py is not out of the blocking set" in out


@pytest.mark.parametrize(
    "changes, words",
    [
        ({"tests": ["tests/engine", "tests/other/test_engine.py", "tests/broker"]}, "tests/broker"),
        ({"tests": ["tests/engine", "tests/other"]}, "tests/other is not"),
        ({"code": ["homelabnext/engine.py", "homelabnext/broker.py"]}, "homelabnext/broker.py"),
        ({"invariants": ["R-09", "B-01"]}, "B-01"),
        (
            {"gates": ["python -m homelabnext.cli engine check", "python -m homelabnext.cli x"]},
            "python -m homelabnext.cli x",
        ),
        ({"owner": "someone"}, "the base's rules refuse the list"),
    ],
)
def test_a_path_gate_or_criterion_added_fails_the_ratchet(repo, changes, words):
    rc, out = _ratchet(repo, _head(**changes))
    assert rc == 1 and words in out, out


@pytest.mark.parametrize(
    "changes",
    [
        {"tests": ["tests/engine"]},
        {"tests": ["tests/engine/test_a.py", "tests/other/test_engine.py"]},  # under a listed dir
        {"code": [], "invariants": []},
        {"status": "frozen", "why": "changed"},
    ],
)
def test_shrinking_or_editing_the_other_keys_passes_the_ratchet(repo, changes):
    rc, out = _ratchet(repo, _head(**changes))
    assert rc == 0, out


def test_removing_every_component_passes_the_ratchet(repo):
    assert _ratchet(repo, {"components": {}})[0] == 0


def test_only_the_operator_s_label_or_a_push_to_main_allows_growth(repo):
    grown = _head(invariants=["R-09", "B-01"])
    assert _ratchet(repo, grown, "label")[0] == 0
    assert _ratchet(repo, grown, "push")[0] == 0
    for value in ("none", "", "true", ex.GROWTH_LABEL, "LABEL"):
        assert _ratchet(repo, grown, value)[0] == 1, value


def test_an_unreadable_base_or_list_fails_closed(repo):
    root, _ = repo
    assert ex.ratchet(root, "0" * 40, {}, io.StringIO()) == 2
    assert ex.ratchet(root, " ", {}, io.StringIO()) == 2
    assert _ratchet(repo, {"components": {"engine": {"tests": "tests/broker"}}})[0] == 2
    assert _ratchet(repo, ["not", "a", "list"])[0] == 2


def test_the_ratchet_runs_from_the_command_line(repo, capsys):
    root, base = repo
    _write(root, _head(invariants=["R-09", "B-01"]))
    assert ex.main(["ratchet", "--base", base, str(root)]) == 1
    assert "B-01" in capsys.readouterr().out
    _write(root, BASE_LIST)
    assert ex.main(["ratchet", "--base", base, str(root)]) == 0


def test_ci_passes_the_operator_s_label_to_both_copies_of_the_ratchet():
    ci = yaml.safe_load(CI.read_text(encoding="utf-8"))
    on = ci.get("on") or ci.get(True)
    # the label is read from the event, which a re-run does not refresh: labelling runs CI again
    assert {"labeled", "unlabeled", "synchronize"} <= set(on["pull_request"]["types"])
    steps = [
        s
        for job in ci["jobs"].values()
        for s in job.get("steps") or []
        if 'tools/experimental.py" ratchet' in s.get("run", "")
        or "tools/experimental.py ratchet" in s.get("run", "")
    ]
    assert len(steps) == 2
    want = (
        "${{ github.event_name == 'push' && 'push' || (contains(github.event.pull_request.labels"
        f".*.name, '{ex.GROWTH_LABEL}') && 'label' || 'none') }}}}"
    )
    for step in steps:
        assert step["env"][ex.GROWTH_ENV] == want, step["name"]
