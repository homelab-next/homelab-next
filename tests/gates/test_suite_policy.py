# SPDX-License-Identifier: Apache-2.0
"""Q-02: the suite policy plugin -- per-suite time budgets, no silent skips, bounded quarantine."""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap
from datetime import date
from pathlib import Path

import pytest

from tests import suite_policy as sp

ROOT = str(Path(__file__).resolve().parents[2])
TODAY = date(2026, 1, 1)


def test_parse_budgets():
    assert sp.parse_budgets(["tests/roles = 480", " tools/tests/ =2.5"]) == {
        "tests/roles": 480.0,
        "tools/tests": 2.5,
    }
    with pytest.raises(pytest.UsageError):
        sp.parse_budgets(["tests/roles 480"])


def test_suite_of(tmp_path):
    assert sp.suite_of(tmp_path / "tests" / "lake" / "x" / "test_a.py", tmp_path) == "tests/lake"
    assert sp.suite_of(tmp_path / "tools" / "tests" / "test_a.py", tmp_path) == "tools/tests"
    assert sp.suite_of(tmp_path / "tests" / "test_a.py", tmp_path) == "tests"
    assert sp.suite_of(tmp_path / "test_a.py", tmp_path) == "."


def test_skip_reasons():
    pats = ["^could not import '[A-Za-z0-9_.]+'", r"\bnot installed\b"]
    assert sp.skip_reason_allowed("could not import 'duckdb': No module named 'duckdb'", pats)
    assert sp.skip_reason_allowed("shellcheck not installed", pats)
    assert not sp.skip_reason_allowed("flaky, fix later", pats)
    assert not sp.skip_reason_allowed("", pats)
    assert not sp.skip_reason_allowed("unconditional skip", pats)


@pytest.mark.parametrize(
    "kwargs, problem",
    [
        ({"owner": "data-team", "until": "2026-02-01", "reason": "flaky"}, None),
        ({"owner": "data-team", "until": "2026-01-01", "reason": "flaky"}, None),  # last day
        ({"owner": "data-team", "until": "2025-12-31", "reason": "flaky"}, "expired on 2025-12-31"),
        ({"until": "2026-02-01", "reason": "flaky"}, "needs owner"),
        ({"owner": "data-team", "reason": "flaky"}, "needs until"),
        ({"owner": "data-team", "until": "2026-02-01"}, "needs reason"),
        ({"owner": "data-team", "until": "soon", "reason": "flaky"}, "not a YYYY-MM-DD"),
        ({"owner": "data-team", "until": "2026-06-01", "reason": "flaky"}, "more than 90 days"),
    ],
)
def test_check_quarantine(kwargs, problem):
    got = sp.check_quarantine(kwargs, TODAY, 90)
    assert (got is None) if problem is None else (problem in got), got


def _project(tmp_path, ini_budgets="", **files):
    (tmp_path / "pytest.ini").write_text(
        "[pytest]\n"
        "suite_budget_default = 60\n"
        f"suite_budgets =\n    {ini_budgets or 'unused = 1'}\n"
        "skip_reasons =\n    ^could not import '[A-Za-z0-9_.]+'\n    \\bnot installed\\b\n"
    )
    for rel, text in files.items():
        p = tmp_path / (rel.replace("__", "/") + ".py")
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(text))


def _pytest(tmp_path, *extra, env=None, plugin=True):
    argv = ["-p", "tests.suite_policy"] if plugin else []
    argv += ["-p", "no:cacheprovider", "-q", "-rA"]
    argv += ["-c", str(tmp_path / "pytest.ini"), "--rootdir", str(tmp_path), *extra]
    e = {
        "PYTHONPATH": ROOT,
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HNX_TODAY": "2026-01-01",
    }
    e.update(env or {})
    return subprocess.run(
        [sys.executable, "-m", "pytest", *argv, str(tmp_path)],
        capture_output=True, text=True, cwd=tmp_path, env=e, check=False,
    )  # fmt: skip


SKIPS = """
    import pytest

    def test_allowed_skip():
        pytest.skip("shellcheck not installed")

    def test_silent_skip():
        pytest.skip("flaky, fix later")

    @pytest.mark.skip
    def test_skip_without_reason():
        pass

    @pytest.mark.xfail(reason="known bug", strict=True)
    def test_xfail_is_not_a_skip():
        assert False

    @pytest.mark.quarantine(owner="data-team", until="2026-02-01", reason="flaky on slow disks")
    def test_quarantined_failure_does_not_break_the_build():
        assert False

    @pytest.mark.quarantine(owner="data-team", until="2025-12-01", reason="flaky")
    def test_expired_quarantine_fails():
        pass

    @pytest.mark.quarantine(until="2026-02-01", reason="flaky")
    def test_quarantine_without_owner_fails():
        pass
"""
MODULE_OK = """
    import pytest

    pytest.importorskip("hnx_fake_optional_extra")
"""
MODULE_SILENT = """
    import pytest

    pytest.skip("not ready", allow_module_level=True)
"""


def test_skips_and_quarantine_end_to_end(tmp_path):
    _project(
        tmp_path,
        a__test_skips=SKIPS,
        a__test_module_ok=MODULE_OK,
    )
    proc = _pytest(tmp_path)
    out = proc.stdout
    assert proc.returncode == 1, out
    assert "SKIPPED [1] a/test_skips.py" in out and "shellcheck not installed" in out
    assert "SKIPPED [1] a/test_module_ok.py" in out  # an absent optional extra
    assert "FAILED a/test_skips.py::test_silent_skip" in out
    assert "ERROR a/test_skips.py::test_skip_without_reason" in out  # refused at setup
    assert "XFAIL a/test_skips.py::test_xfail_is_not_a_skip" in out
    assert "XFAIL a/test_skips.py::test_quarantined_failure_does_not_break_the_build" in out
    assert "quarantined until 2026-02-01 by data-team" in out
    assert "ERROR a/test_skips.py::test_expired_quarantine_fails" in out  # refused at setup
    assert "quarantine expired on 2025-12-01 (owner data-team)" in out
    assert "ERROR a/test_skips.py::test_quarantine_without_owner_fails" in out  # refused at setup
    assert "quarantined tests" in out
    assert "1 failed, 2 skipped, 2 xfailed, 3 errors" in out


def test_without_the_plugin_the_same_suite_passes_silently(tmp_path):
    silent = "import pytest\n\ndef test_silent_skip():\n    pytest.skip('flaky, fix later')\n"
    _project(tmp_path, a__test_silent=silent)
    (tmp_path / "pytest.ini").write_text("[pytest]\n")
    proc = _pytest(tmp_path, plugin=False)
    assert proc.returncode == 0, proc.stdout  # the gap the plugin closes
    assert "1 skipped" in proc.stdout


def test_a_silent_module_level_skip_is_a_collection_error(tmp_path):
    _project(tmp_path, a__test_module_silent=MODULE_SILENT)
    proc = _pytest(tmp_path)
    assert proc.returncode == 2, proc.stdout  # collection errors interrupt the session
    assert "ERROR a/test_module_silent.py" in proc.stdout
    assert "silent skip: reason 'not ready'" in proc.stdout


def test_all_good_passes(tmp_path):
    _project(tmp_path, a__test_ok="def test_ok():\n    pass\n", a__test_module_ok=MODULE_OK)
    proc = _pytest(tmp_path, "--suite-times")
    assert proc.returncode == 0, proc.stdout
    assert "suite time budgets" in proc.stdout


SLOW = """
    import time

    def test_slow():
        time.sleep(0.3)
"""


def test_suite_over_budget_fails_the_session(tmp_path):
    _project(
        tmp_path,
        ini_budgets="slow = 0.1",
        slow__test_slow=SLOW,
        fast__test_ok="def test_ok():\n    pass\n",
    )
    proc = _pytest(tmp_path)
    assert proc.returncode == 1, proc.stdout
    assert "2 passed" in proc.stdout
    assert "suite time budget exceeded" in proc.stdout
    assert "slow: 0.3s > budget 0s" in proc.stdout
    assert "fast:" not in proc.stdout.split("suite time budget exceeded")[1]
    # a slow machine scales every budget instead of editing them
    ok = _pytest(tmp_path, env={"HNX_SUITE_BUDGET_SCALE": "100"})
    assert ok.returncode == 0, ok.stdout


def test_this_suite_is_configured():
    import tomllib

    cfg = tomllib.loads((Path(ROOT) / "pyproject.toml").read_text())["tool"]["pytest"]
    ini = cfg["ini_options"]
    assert float(ini["suite_budget_default"]) > 0
    assert sp.parse_budgets(ini["suite_budgets"])
    assert ini["skip_reasons"]
    assert (Path(ROOT) / "conftest.py").read_text().count("tests.suite_policy") == 1
