# SPDX-License-Identifier: Apache-2.0
"""Q-02: the suite policy plugin -- per-suite time budgets, no silent skips, bounded quarantine."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import textwrap
from datetime import date
from pathlib import Path

import pytest

from tests import shard_report
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


@pytest.mark.parametrize(
    ("env", "want"),
    [
        ({}, set()),
        ({"HNX_REQUIRE_TOOLS": " zizmor , nats-server ,"}, {"zizmor", "nats-server"}),
        ({"HNX_REQUIRE_GO": "1"}, {"go"}),  # the older switch still works
        ({"HNX_REQUIRE_GO": "0", "HNX_REQUIRE_TOOLS": "docker"}, {"docker"}),
        ({"HNX_REQUIRE_GO": "1", "HNX_REQUIRE_TOOLS": "go,actionlint"}, {"go", "actionlint"}),
    ],
)
def test_required_tools(env, want):
    assert sp.required_tools(env) == want


@pytest.mark.parametrize(
    ("env", "outcome", "why"),
    [
        ({}, pytest.skip.Exception, "hnx-fake-lint is not installed"),
        ({"HNX_REQUIRE_TOOLS": "other"}, pytest.skip.Exception, "hnx-fake-lint is not installed"),
        (
            {"HNX_REQUIRE_TOOLS": "hnx-fake-lint"},
            pytest.fail.Exception,
            "HNX_REQUIRE_TOOLS requires",
        ),
    ],
)
def test_require_tool_skips_or_fails(monkeypatch, tmp_path, env, outcome, why):
    monkeypatch.setenv("PATH", str(tmp_path))  # nothing here
    monkeypatch.delenv("HNX_REQUIRE_TOOLS", raising=False)
    monkeypatch.delenv("HNX_REQUIRE_GO", raising=False)
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    with pytest.raises(outcome, match=why):
        sp.require_tool("hnx-fake-lint")


def test_require_tool_returns_the_path_and_honours_its_availability_check(monkeypatch, tmp_path):
    tool = tmp_path / "hnx-fake-lint"
    tool.write_text("#!/bin/sh\n")
    tool.chmod(0o755)
    monkeypatch.setenv("PATH", str(tmp_path))
    monkeypatch.setenv("HNX_REQUIRE_TOOLS", "hnx-fake-lint")
    assert sp.require_tool("hnx-fake-lint") == str(tool)
    with pytest.raises(pytest.fail.Exception):  # on PATH but not usable (docker without compose)
        sp.require_tool("hnx-fake-lint", lambda: False)


def test_a_required_tools_skip_is_a_failure_end_to_end(tmp_path):
    _project(
        tmp_path,
        a__test_tools="""
            from tests.suite_policy import require_tool

            def test_needs_lint():
                require_tool("hnx-fake-lint")

            def test_needs_other():
                require_tool("hnx-fake-other")
        """,
    )
    proc = _pytest(tmp_path, env={"HNX_REQUIRE_TOOLS": "hnx-fake-lint"})
    assert proc.returncode == 1, proc.stdout
    assert "HNX_REQUIRE_TOOLS requires it" in proc.stdout
    assert "1 failed, 1 skipped" in proc.stdout
    assert _pytest(tmp_path).returncode == 0  # without the variable both are ordinary skips


CI_REQUIRED = ("actionlint", "zizmor", "nats-server", "docker", "go")


def test_the_tools_ci_requires_are_only_skipped_through_the_helper():
    """A skip that names one of these tools in its own words is outside the HNX_REQUIRE_TOOLS
    contract (CI could not turn it into a failure): it must go through require_tool."""
    tools = "|".join(map(re.escape, CI_REQUIRED))
    own = re.compile(
        rf"(?:pytest\.skip\(|reason=)\s*f?[\"'][^\"']*\b(?:{tools})\b[^\"']*\bnot "
        r"(?:installed|available)\b"
    )
    offenders = []
    for base in ("tests", "tools/tests", "conformance"):
        for f in sorted((Path(ROOT) / base).rglob("*.py")):
            if f.name == "suite_policy.py" or f.name == "test_suite_policy.py":
                continue
            for n, line in enumerate(f.read_text(encoding="utf-8").splitlines(), 1):
                if own.search(line):
                    offenders.append(f"{f.relative_to(ROOT)}:{n}: {line.strip()}")
    assert offenders == []


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


@pytest.mark.parametrize("text", ["0/3", "4/3", "1/0", "3", "a/b", "1/2/3", ""])
def test_parse_shard_refuses(text):
    with pytest.raises(ValueError):
        shard_report.parse_shard(text)


def test_select_spreads_the_tests_over_the_shards():
    ids = [f"t{k}" for k in range(7)]
    picks = [shard_report.select(ids, i, 3) for i in (1, 2, 3)]
    assert [sum(p) for p in picks] == [3, 2, 2]
    assert all(sum(col) == 1 for col in zip(*picks, strict=True))  # each test in exactly one
    assert shard_report.parse_shard("2/3") == (2, 3)
    assert shard_report.select(ids, 1, 1) == [True] * 7


SHARDED = {
    f"{suite}__test_{suite}_{name}": "".join(f"def test_{k}():\n    pass\n\n" for k in range(5))
    for suite in ("a", "b")
    for name in ("one", "two")
}


def _shards(tmp_path, count, *extra, **project):
    (tmp_path / "p").mkdir()
    _project(tmp_path / "p", **project)
    reports = tmp_path / "reports"
    reports.mkdir(exist_ok=True)
    procs = [
        _pytest(
            tmp_path / "p", f"--shard={i}/{count}", f"--shard-report={reports}/{i}.json", *extra
        )
        for i in range(1, count + 1)
    ]
    return procs, reports


def _merge(*argv):
    proc = subprocess.run(
        [sys.executable, "-m", "tests.shard_report", *map(str, argv)],
        capture_output=True, text=True, cwd=ROOT, check=False,
    )  # fmt: skip
    return proc.returncode, proc.stdout + proc.stderr


def test_shards_run_every_test_once_end_to_end(tmp_path):
    procs, reports = _shards(tmp_path, 3, "-k", "not test_4", **SHARDED)
    assert all(p.returncode == 0 for p in procs), [p.stdout for p in procs]
    ran = [re.findall(r"^PASSED (\S+)", p.stdout, re.M) for p in procs]
    assert sorted(n for r in ran for n in r) == sorted(
        f"{s}/test_{s}_{n}.py::test_{k}" for s in "ab" for n in ("one", "two") for k in range(4)
    )  # -k dropped test_4 before the split, and no test ran twice
    assert [len(r) for r in ran] == [6, 5, 5]
    rc, out = _merge(reports, "--groups", "{}.{}".format(*sys.version_info[:2]))
    assert rc == 0, out
    assert "3 shards" in out and "  a\n" in out
    rc, out = _merge(reports, "--groups", "3.11,3.12,3.13,3.14")
    assert rc == 1 and "expected" in out


def test_the_merge_refuses_shards_that_do_not_add_up(tmp_path):
    _, reports = _shards(tmp_path, 3, **SHARDED)
    data = {i: json.loads((reports / f"{i}.json").read_text()) for i in (1, 2, 3)}

    def merged(**changes):
        for i, change in changes.items():
            (reports / f"{i[1:]}.json").write_text(json.dumps({**data[int(i[1:])], **change}))
        try:
            return _merge(reports)
        finally:
            for i in (1, 2, 3):
                (reports / f"{i}.json").write_text(json.dumps(data[i]))

    assert _merge(reports)[0] == 0
    one = data[1]["selected"]
    cases = [
        ({"s2": {"selected": data[2]["selected"] + one[:1]}}, "not each of the 20"),
        ({"s2": {"selected": data[2]["selected"][1:]}}, "ran 19 tests"),
        ({"s3": {"shard": 2}}, "missing [3], reported twice [2]"),
        ({"s3": {"of": 4}}, "disagree on how many"),
        ({"s1": {"collected_sha256": "0" * 64}}, "did not collect the same tests"),
        ({"s1": {"exitstatus": 1}}, "shard 1/3 exited 1"),
        ({"s1": {"collected": None}}, "never finished collecting"),
        ({"s2": {"default_budget": 1.0}}, "different budgets"),
        ({"s1": {"times": {"a": 61.0}}}, "a: 6"),  # over 60s only once the shards are summed
        ({"s1": {"format": 0}}, "format 0"),
    ]
    for changes, problem in cases:
        rc, out = merged(**changes)
        assert rc == 1 and problem in out, (changes, out)
    (reports / "bad.json").write_text("{")
    assert _merge(reports)[0] == 2
    assert _merge(tmp_path / "nowhere")[0] == 2


def test_each_shard_keeps_the_budget_on_its_share_and_the_merge_on_the_sum(tmp_path):
    slow = "import time\n\n" + "".join(
        f"def test_{k}():\n    time.sleep(0.2)\n\n" for k in range(4)
    )
    procs, reports = _shards(tmp_path, 2, ini_budgets="slow = 0.6", slow__test_slow=slow)
    assert [p.returncode for p in procs] == [0, 0], [p.stdout for p in procs]  # 0.4s each
    rc, out = _merge(reports)
    assert rc == 1 and "slow: 0.8s over all shards > budget 1s" in out, out
