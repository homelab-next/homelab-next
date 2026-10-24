# SPDX-License-Identifier: Apache-2.0
"""Pytest plugin: test suites are trustworthy (checklist Q-02).

Loaded for the whole suite by the root ``conftest.py``, next to ``tests/network_guard.py``.
Configuration is in ``[tool.pytest.ini_options]`` of ``pyproject.toml``.

**Time budgets.**  A *suite* is a test file's first two directories (``tests/lake``,
``tools/tests``, ``conformance/idp``; a file directly under ``tests/`` is suite ``tests``).  The
setup, call and teardown time of every test is summed per suite; a suite over its budget fails the
session (exit 1) and the summary names it.  ``suite_budget_default`` (seconds) applies to every
suite, ``suite_budgets`` (``"<suite> = <seconds>"`` lines) overrides it per suite, and the
environment variable ``HNX_SUITE_BUDGET_SCALE`` multiplies every budget (a slow machine, a coverage
run).  ``--suite-times`` prints the table.

**No silent skips.**  A skip (``pytest.skip``, ``skipif``, ``importorskip``, at collection or at
run time) must give a reason matching one of the ``skip_reasons`` regular expressions (searched,
not anchored).  Each pattern names a legitimate, visible cause: an optional extra or external tool
is absent, the platform cannot run the test.  Any other skip -- including one with no reason -- is
turned into a failure.  ``xfail`` and ``-m`` deselection are not skips.

**Required tools.**  A test that needs an external tool asks for it through one helper,
:func:`require_tool` (``go_toolchain`` and the docker and linter checks use it): it returns the
tool's path, or skips with ``"<tool> is not installed"`` (a registered skip reason).  Where the
environment says the tool must be there, the helper fails the test instead of skipping, so a
broken install cannot pass as a skip.  ``HNX_REQUIRE_TOOLS`` names the required tools
(comma-separated, e.g. ``actionlint,zizmor,nats-server,docker,go``); ``HNX_REQUIRE_GO=1``, the
older switch for Go, still means ``go``.  The decision is made by the helper from the tool's
name, not by reading the wording of a skip afterwards: a test that skips for a tool on its own
(its own ``skipif``, an early return) is outside the contract, so every such test goes through
the helper (``tests/gates/test_suite_policy.py`` checks the tools CI requires).

**Quarantine.**  ``@pytest.mark.quarantine(owner="team-or-handle", until="YYYY-MM-DD",
reason="...")`` lets a known-flaky test keep running without breaking the build (it becomes a
non-strict ``xfail``) for a bounded time.  The owner, the date and the reason are required; a date
in the past fails the test ("quarantine expired"), and a date more than ``quarantine_max_days``
(default 90) ahead is refused, so a quarantine cannot be parked forever.  ``HNX_TODAY``
(``YYYY-MM-DD``) overrides today's date for the plugin's own tests.
"""

from __future__ import annotations

import os
import re
import shutil
from collections.abc import Callable, Iterable
from datetime import date
from pathlib import Path

import pytest

QUARANTINE = "quarantine"
_STATE = pytest.StashKey[dict]()


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addini("suite_budget_default", "default per-suite time budget, seconds", default="120")
    parser.addini(
        "suite_budgets", "per-suite budgets: '<suite> = <seconds>' lines", type="linelist"
    )
    parser.addini("skip_reasons", "regular expressions a skip reason must match", type="linelist")
    parser.addini("quarantine_max_days", "longest allowed quarantine, days", default="90")
    parser.addoption(
        "--suite-times", action="store_true", help="print the per-suite time against its budget"
    )


def _today() -> date:
    override = os.environ.get("HNX_TODAY")
    if override:
        return date.fromisoformat(override)
    return date.today()  # hermetic: allow quarantine expiry is relative to the real date


def parse_budgets(lines: Iterable[str]) -> dict[str, float]:
    out: dict[str, float] = {}
    for line in lines:
        suite, sep, secs = line.partition("=")
        if not sep or not suite.strip():
            raise pytest.UsageError(f"suite_budgets: expected '<suite> = <seconds>', got {line!r}")
        out[suite.strip().rstrip("/")] = float(secs)
    return out


def suite_of(path: Path, rootdir: Path) -> str:
    try:
        rel = Path(path).resolve().relative_to(Path(rootdir).resolve())
    except ValueError:
        rel = Path(path)
    parts = rel.parts[:-1]
    return "/".join(parts[:2]) if parts else "."


def skip_reason_allowed(reason: str, patterns: Iterable[str]) -> bool:
    reason = reason.strip()
    return bool(reason) and any(re.search(p, reason) for p in patterns)


def check_quarantine(kwargs: dict, today: date, max_days: int) -> str | None:
    """None when the quarantine is valid, else why it is not."""
    owner, until, reason = kwargs.get("owner"), kwargs.get("until"), kwargs.get("reason")
    missing = [k for k, v in (("owner", owner), ("until", until), ("reason", reason)) if not v]
    if missing:
        return f"quarantine needs {', '.join(missing)} (owner=, until='YYYY-MM-DD', reason=)"
    try:
        end = date.fromisoformat(str(until))
    except ValueError:
        return f"quarantine until={until!r} is not a YYYY-MM-DD date"
    if end < today:
        return f"quarantine expired on {end} (owner {owner}): fix the test or remove it"
    if (end - today).days > max_days:
        return f"quarantine until {end} is more than {max_days} days ahead; renew it in steps"
    return None


def _reason(longrepr: object) -> str:
    if isinstance(longrepr, tuple) and len(longrepr) == 3:
        text = str(longrepr[2])
    else:
        text = str(longrepr or "")
    return text.removeprefix("Skipped: ").removeprefix("Skipped")


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers",
        f"{QUARANTINE}(owner, until, reason): known-flaky test, runs as non-strict xfail until "
        "the date (tests/suite_policy.py)",
    )
    default = float(config.getini("suite_budget_default"))
    scale = float(os.environ.get("HNX_SUITE_BUDGET_SCALE", "1") or "1")
    config.stash[_STATE] = {
        "default": default,
        "budgets": parse_budgets(config.getini("suite_budgets")),
        "scale": scale,
        "skip_patterns": list(config.getini("skip_reasons")),
        "max_days": int(config.getini("quarantine_max_days")),
        "times": {},
        "over": [],
        "quarantined": [],
    }
    config.pluginmanager.register(_Timer(config), "hnx-suite-timer")


def _state(config: pytest.Config) -> dict:
    return config.stash[_STATE]


def required_tools(env: dict[str, str] | None = None) -> set[str]:
    """The tools the environment requires: ``HNX_REQUIRE_TOOLS`` (comma-separated), plus ``go``
    when ``HNX_REQUIRE_GO=1``."""
    env = os.environ if env is None else env
    tools = {t.strip() for t in env.get("HNX_REQUIRE_TOOLS", "").split(",") if t.strip()}
    if env.get("HNX_REQUIRE_GO") == "1":
        tools.add("go")
    return tools


def require_tool(name: str, available: Callable[[], bool] | None = None) -> str:
    """The path of the external tool ``name`` (or ``name`` when ``available`` decides instead of
    PATH).  Missing: skip with ``"<name> is not installed"``, or fail when the environment
    requires the tool (:func:`required_tools`)."""
    path = shutil.which(name)
    ok = (path is not None) if available is None else bool(path and available())
    if ok:
        return path or name
    if name in required_tools():
        switch = (
            "HNX_REQUIRE_GO=1"
            if name == "go" and os.environ.get("HNX_REQUIRE_GO") == "1"
            else "HNX_REQUIRE_TOOLS"
        )
        pytest.fail(
            f"{name} is not on PATH (or not usable), and {switch} requires it", pytrace=False
        )
    pytest.skip(f"{name} is not installed")


def _silent_skip(config: pytest.Config, rep) -> None:
    if not rep.skipped or hasattr(rep, "wasxfail"):
        return
    reason = _reason(rep.longrepr)
    if skip_reason_allowed(reason, _state(config)["skip_patterns"]):
        return
    rep.outcome = "failed"
    rep.longrepr = (
        f"silent skip: reason {reason.strip()!r} matches no pattern in skip_reasons "
        "([tool.pytest.ini_options] in pyproject.toml).  Give the skip a reason that names the "
        "missing extra or tool, or register a new legitimate cause there."
    )


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    _silent_skip(item.config, outcome.get_result())


@pytest.hookimpl(hookwrapper=True)
def pytest_make_collect_report(collector):
    outcome = yield
    _silent_skip(collector.config, outcome.get_result())


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    st = _state(config)
    today = _today()
    for item in items:
        m = item.get_closest_marker(QUARANTINE)
        if m is None:
            continue
        problem = check_quarantine(dict(m.kwargs), today, st["max_days"])
        if problem:
            item.stash[_STATE] = {"problem": problem}
            continue
        st["quarantined"].append(
            f"{item.nodeid} (owner {m.kwargs['owner']}, until {m.kwargs['until']})"
        )
        item.add_marker(
            pytest.mark.xfail(
                reason=f"quarantined until {m.kwargs['until']} by {m.kwargs['owner']}: "
                f"{m.kwargs['reason']}",
                strict=False,
            )
        )


def pytest_runtest_setup(item: pytest.Item) -> None:
    info = item.stash.get(_STATE, None)
    if info and info.get("problem"):
        pytest.fail(info["problem"], pytrace=False)


def _budget(st: dict, suite: str) -> float:
    return st["budgets"].get(suite, st["default"]) * st["scale"]


class _Timer:
    """Sums setup + call + teardown time per suite (a plugin object: the hook needs config)."""

    def __init__(self, config: pytest.Config):
        self.config = config

    def pytest_runtest_logreport(self, report) -> None:
        st = _state(self.config)
        suite = suite_of(Path(str(report.fspath)), self.config.rootpath)
        st["times"][suite] = st["times"].get(suite, 0.0) + float(report.duration or 0.0)


@pytest.hookimpl(tryfirst=True)
def pytest_sessionfinish(session: pytest.Session, exitstatus) -> None:
    st = _state(session.config)
    st["over"] = [
        (suite, secs, _budget(st, suite))
        for suite, secs in sorted(st["times"].items())
        if secs > _budget(st, suite)
    ]
    if st["over"] and session.exitstatus == 0:
        session.exitstatus = pytest.ExitCode.TESTS_FAILED


def pytest_terminal_summary(terminalreporter, exitstatus, config: pytest.Config) -> None:
    st = _state(config)
    tr = terminalreporter
    if config.getoption("suite_times"):
        tr.section("suite time budgets")
        for suite, secs in sorted(st["times"].items(), key=lambda kv: -kv[1]):
            tr.line(f"{secs:8.1f}s / {_budget(st, suite):6.0f}s  {suite}")
    if st["quarantined"]:
        tr.section("quarantined tests")
        for q in st["quarantined"]:
            tr.line(q)
    if st["over"]:
        tr.section("suite time budget exceeded", red=True)
        for suite, secs, budget in st["over"]:
            tr.line(
                f"{suite}: {secs:.1f}s > budget {budget:.0f}s (suite_budgets in pyproject.toml)",
                red=True,
            )
