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
            assert (coverage_floor.REPO_ROOT / t).is_dir(), t


def _captured_env(tmp_path, monkeypatch):
    seen = {}

    def fake_run(cmd, cwd, check, env):
        seen.update(env)
        return type("Done", (), {"returncode": 0})()

    monkeypatch.setattr(coverage_floor.subprocess, "run", fake_run)
    coverage_floor.run_tests(tmp_path / "report.json")
    return seen


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
    monkeypatch.setattr(coverage_floor, "REPORT", tmp_path / "coverage.json")
    assert coverage_floor.main([]) == 0
