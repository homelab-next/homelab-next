# SPDX-License-Identifier: Apache-2.0
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import coverage_floor


def _file(stmts, covered):
    return {"summary": {"num_statements": stmts, "covered_lines": covered}}


def _report(**overrides):
    files = {
        "homelabnext/broker/__init__.py": _file(100, 95),
        "homelabnext/scope/guard.py": _file(50, 45),
        "homelabnext/scope/policy.py": _file(50, 45),
        "homelabnext/records/notes.py": _file(10, 9),
        "homelabnext/decide/cascade.py": _file(10, 10),
        "homelabnext/agent/compiler.py": _file(10, 9),
        "homelabnext/agent/readers.py": _file(10, 9),
        "homelabnext/agent/handoff.py": _file(10, 9),
        "homelabnext/agent/memory.py": _file(10, 9),
        "homelabnext/agent/screen.py": _file(10, 9),
        "homelabnext/workflows/runner.py": _file(10, 9),
        "homelabnext/registry/limits.py": _file(10, 9),
        "homelabnext/context/store.py": _file(10, 9),
        "homelabnext/mcp/catalog.py": _file(10, 9),
        "homelabnext/status/agents/auth.py": _file(10, 9),
        "homelabnext/status/agents/ingest.py": _file(10, 9),
        "homelabnext/status/approvals.py": _file(10, 9),
        "homelabnext/status/serve.py": _file(10, 9),
        "homelabnext/generators/safe.py": _file(10, 9),
        "homelabnext/tlp.py": _file(10, 9),
        "homelabnext/tlp_egress.py": _file(10, 9),
        "tools/leak_scan.py": _file(10, 9),
        "homelabnext/agent/pack.py": _file(10, 0),  # not a unit: never counted
    }
    files.update(overrides)
    return {"files": {k: v for k, v in files.items() if v is not None}}


def _write(tmp_path, report):
    p = tmp_path / "coverage.json"
    p.write_text(json.dumps(report))
    return p


def test_every_unit_above_the_floor_passes(tmp_path):
    assert coverage_floor.main(["--json", str(_write(tmp_path, _report()))]) == 0


def test_a_package_is_measured_as_a_whole_and_fails_below_the_floor(tmp_path, capsys):
    # guard.py alone is fine; the package averages (45 + 20) / 100 = 65%
    report = _report(**{"homelabnext/scope/policy.py": _file(50, 20)})
    assert coverage_floor.per_unit(report)["homelabnext/scope"] == pytest.approx(65.0)
    assert coverage_floor.main(["--json", str(_write(tmp_path, report))]) == 1
    assert (
        "homelabnext/scope: 65.0% line coverage is below the 80% floor" in capsys.readouterr().err
    )


def test_a_module_unit_ignores_its_siblings(tmp_path):
    report = _report(**{"homelabnext/agent/compiler.py": _file(10, 7)})
    assert coverage_floor.per_unit(report)["homelabnext/agent/compiler.py"] == pytest.approx(70.0)
    assert coverage_floor.main(["--json", str(_write(tmp_path, report))]) == 1


def test_an_unmeasured_unit_fails(tmp_path, capsys):
    report = _report(**{"homelabnext/decide/cascade.py": None})
    assert coverage_floor.main(["--json", str(_write(tmp_path, report))]) == 1
    assert "homelabnext/decide: not measured" in capsys.readouterr().err


def test_absolute_paths_are_matched_against_the_repo(tmp_path):
    root = coverage_floor.REPO_ROOT
    report = {"files": {str(root / k): v for k, v in _report()["files"].items()}}
    assert coverage_floor.below_floor(coverage_floor.per_unit(report)) == []


def test_unreadable_report_is_exit_2(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    assert coverage_floor.main(["--json", str(bad)]) == 2


def test_every_unit_names_existing_code_and_tests():
    for unit, tests in coverage_floor.UNITS.items():
        assert (coverage_floor.REPO_ROOT / unit).exists(), unit
        for t in tests:
            assert (coverage_floor.REPO_ROOT / t).exists(), t


def test_the_units_the_review_found_missing_are_measured():
    for unit in (
        "homelabnext/status/approvals.py",
        "homelabnext/status/serve.py",
        "homelabnext/generators/safe.py",
        "tools/leak_scan.py",
    ):
        assert unit in coverage_floor.UNITS, unit


def _captured_env(tmp_path, monkeypatch):
    seen = {}

    def fake_run(cmd, cwd, check, env):
        seen.update(env)
        return type("Done", (), {"returncode": 0})()

    monkeypatch.setattr(coverage_floor.subprocess, "run", fake_run)
    coverage_floor.run_tests(tmp_path / "report.json", ("tests/scope",), ["homelabnext/scope"])
    return seen


def _fake_pytest(monkeypatch, calls):
    """A pytest stand-in: each unit's files are fully covered only when the run is the unit's own
    tests, so a unit credited with another group's coverage shows up as 0%."""

    def fake_run(cmd, cwd, check, env):
        at = next(i for i, a in enumerate(cmd) if a.startswith("--cov-report=json:"))
        report, tests = cmd[at].split(":", 1)[1], tuple(cmd[at + 1 :])
        targets = {a.split("=", 1)[1] for a in cmd if a.startswith("--cov=")}
        calls.append((tests, targets))
        files = {}
        for unit, own in coverage_floor.UNITS.items():
            name = unit if unit.endswith(".py") else f"{unit}/__init__.py"
            files[name] = _file(10, 10 if tuple(own) == tests else 0)
        Path(report).write_text(json.dumps({"files": files}))
        return type("Done", (), {"returncode": 0})()

    monkeypatch.setattr(coverage_floor.subprocess, "run", fake_run)


def test_each_unit_is_measured_by_its_own_tests_only(tmp_path, monkeypatch, capsys):
    calls = []
    _fake_pytest(monkeypatch, calls)
    monkeypatch.setattr(coverage_floor, "REPORT_DIR", tmp_path)
    assert coverage_floor.main([]) == 0, capsys.readouterr().err
    # one run per distinct test set, each measuring only the units that name it
    assert sorted(t for t, _ in calls) == sorted(coverage_floor.groups())
    for tests, targets in calls:
        units = coverage_floor.groups()[tests]
        assert targets == {coverage_floor._cov_target(u) for u in units}


def test_subprocesses_the_tests_start_are_measured(tmp_path, monkeypatch):
    # tools/leak_scan.py's tests run it as a program; without this its main() reads as untested
    cmds = []

    def fake_run(cmd, cwd, check, env):
        cmds.append(cmd)
        return type("Done", (), {"returncode": 0})()

    monkeypatch.setattr(coverage_floor.subprocess, "run", fake_run)
    coverage_floor.run_tests(tmp_path / "g.json", ("tools/tests/x.py",), ["tools/leak_scan.py"])
    (rc,) = [a.split("=", 1)[1] for a in cmds[0] if a.startswith("--cov-config=")]
    assert "patch = subprocess" in Path(rc).read_text()
    assert "--cov=tools" in cmds[0]


def test_a_failing_group_is_exit_2(tmp_path, monkeypatch):
    def fail(cmd, cwd, check, env):
        return type("Done", (), {"returncode": 1})()

    monkeypatch.setattr(coverage_floor.subprocess, "run", fail)
    monkeypatch.setattr(coverage_floor, "REPORT_DIR", tmp_path)
    assert coverage_floor.main([]) == 2


def test_the_coverage_run_scales_the_suite_budgets(tmp_path, monkeypatch):
    monkeypatch.delenv("HNX_SUITE_BUDGET_SCALE", raising=False)
    env = _captured_env(tmp_path, monkeypatch)
    assert float(env["HNX_SUITE_BUDGET_SCALE"]) > 1


def test_an_explicit_budget_scale_is_kept(tmp_path, monkeypatch):
    monkeypatch.setenv("HNX_SUITE_BUDGET_SCALE", "5")
    assert _captured_env(tmp_path, monkeypatch)["HNX_SUITE_BUDGET_SCALE"] == "5"


@pytest.mark.slow
def test_this_repo_meets_the_floor(tmp_path, monkeypatch):
    pytest.importorskip("pytest_cov")
    monkeypatch.setattr(coverage_floor, "REPORT_DIR", tmp_path)
    assert coverage_floor.main([]) == 0


def test_the_test_and_dev_extras_pin_a_coverage_that_patches_subprocesses():
    """coverage_floor writes ``patch = subprocess`` (coverage >= 7.10); an older coverage ignores
    it, and leak_scan's floor then fails for a reason nobody would guess (59.8% without its
    subprocess runs).  pytest-cov alone does not pull a new enough coverage."""
    import re
    import tomllib

    with (Path(__file__).resolve().parents[2] / "pyproject.toml").open("rb") as f:
        extras = tomllib.load(f)["project"]["optional-dependencies"]
    for name in ("test", "dev"):
        pins = [re.fullmatch(r"coverage>=(\d+)\.(\d+)", d) for d in extras[name]]
        (m,) = [m for m in pins if m]
        assert (int(m[1]), int(m[2])) >= (7, 10), name
