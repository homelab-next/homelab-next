#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# hnx-script:
#   id: coverage-floor
#   kind: check
#   purpose: Fail when a security-critical unit drops below its line-coverage floor from its own tests.
#   owner: maintainers
#   trigger: [ci:ci/coverage, make:coverage]
#   invariant: [Q-07]
#   inputs: the units listed in this file and their tests (runs pytest with coverage)
#   outputs: a per-unit coverage table; --json FILE writes it as JSON
#   exit:
#     "0": every unit at or above the floor
#     "1": some unit below it or not measured
#     "2": coverage could not be run
"""Gate: the security-critical code keeps at least 80% line coverage from its own tests.

Each unit below is measured by the tests that exist for it (not by the whole suite, so a unit
cannot ride on coverage some unrelated test happens to give it) and must reach ``FLOOR`` percent
of its statements on its own; one aggregate number would let a well-covered package hide a
poorly covered one.  Raising a unit's coverage is always fine; lowering ``FLOOR`` or dropping a
unit is a reviewed change to this file.

* ``homelabnext/broker``  -- the broker decision evaluator (grants, tiers, approvals) and the
  reference service (lanes, pinned handlers, durable single-use approvals)
* ``homelabnext/scope``   -- the scope guard for writer tools
* ``homelabnext/records`` -- the approval lifecycle (inbox, decided lanes, completion)
* ``homelabnext/decide``  -- the decision cascade
* ``homelabnext/agent/compiler.py`` -- the agent-profile grant ceiling (privilege decisions)
* ``homelabnext/agent/readers.py``  -- the reader/actor split (who may see untrusted text)
* ``homelabnext/agent/handoff.py``  -- the reader->actor handoff (validated structured input)
* ``homelabnext/agent/memory.py``   -- the agent memory write path (untrusted text at rest)
* ``homelabnext/agent/screen.py``   -- the injection screen in front of the model
* ``homelabnext/workflows``         -- workflow runs: the broker executor and approval binding
* ``homelabnext/registry/limits.py`` -- the model rate/token/cost budget (throttle + alert)
* ``homelabnext/context``          -- context retrieval: scope enforcement and inactive records
* ``homelabnext/mcp``              -- the read-only MCP server: path refusal, scope intersection
* ``homelabnext/status/agents/auth.py``   -- the status hub's private-tier front door + access log
* ``homelabnext/status/agents/ingest.py`` -- the agent-activity push ingest (tokens, limits)

Usage: python tools/coverage_floor.py [--floor N] [--json FILE]
  --json FILE  evaluate an existing ``coverage json`` report instead of running the tests
Exit: 0 every unit at or above the floor, 1 some unit below it (or not measured at all),
2 the tests failed or the report could not be produced.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
FLOOR = 80.0
REPORT = REPO_ROOT / "build" / "coverage-security.json"

# unit (a package directory or one module) -> the tests that exercise it
UNITS: dict[str, tuple[str, ...]] = {
    "homelabnext/broker": ("tests/broker", "conformance/broker"),
    "homelabnext/scope": ("tests/scope",),
    "homelabnext/records": ("tests/records", "conformance/records"),
    "homelabnext/decide": ("tests/decide",),
    "homelabnext/agent/compiler.py": ("tests/agent",),
    "homelabnext/agent/readers.py": ("tests/agent",),
    "homelabnext/agent/handoff.py": ("tests/agent",),
    "homelabnext/agent/memory.py": ("tests/agent",),
    "homelabnext/agent/screen.py": ("tests/agent",),
    "homelabnext/workflows": ("tests/workflows",),
    "homelabnext/registry/limits.py": ("tests/models",),
    "homelabnext/context": ("tests/context", "conformance/context"),
    "homelabnext/mcp": ("tests/mcp",),
    "homelabnext/status/agents/auth.py": ("tests/status",),
    "homelabnext/status/agents/ingest.py": ("tests/status",),
}


def _module(unit: str) -> str:
    return unit.removesuffix(".py").replace("/", ".")


def per_unit(report: dict, units: dict[str, tuple[str, ...]] = UNITS) -> dict[str, float | None]:
    """Line coverage percent per unit from a ``coverage json`` report (None = no file measured)."""
    files = report.get("files", {})
    out: dict[str, float | None] = {}
    for unit in units:
        stmts = covered = 0
        seen = False
        for name, data in files.items():
            path = Path(name)
            if path.is_absolute() and path.is_relative_to(REPO_ROOT):
                path = path.relative_to(REPO_ROOT)
            path = path.as_posix()
            hit = path == unit if unit.endswith(".py") else path.startswith(unit.rstrip("/") + "/")
            if not hit:
                continue
            seen = True
            stmts += data["summary"]["num_statements"]
            covered += data["summary"]["covered_lines"]
        out[unit] = None if not seen else (100.0 if stmts == 0 else 100.0 * covered / stmts)
    return out


def below_floor(coverage: dict[str, float | None], floor: float = FLOOR) -> list[str]:
    problems = []
    for unit, pct in sorted(coverage.items()):
        if pct is None:
            problems.append(
                f"{unit}: not measured (moved or renamed? update tools/coverage_floor.py)"
            )
        elif pct < floor:
            problems.append(f"{unit}: {pct:.1f}% line coverage is below the {floor:.0f}% floor")
    return problems


COVERAGE_BUDGET_SCALE = "2"


def run_tests(report: Path) -> int:
    report.parent.mkdir(parents=True, exist_ok=True)
    paths = sorted({t for tests in UNITS.values() for t in tests})
    cmd = [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "-m", "not live"]
    cmd += [f"--cov={_module(u)}" for u in UNITS]
    cmd += ["--cov-report=", f"--cov-report=json:{report}", *paths]
    # the data file goes under build/ with the report, not into the working tree
    env = {**os.environ, "COVERAGE_FILE": str(report.parent / ".coverage-security")}
    # tracing slows every test, so the per-suite time budgets are scaled as tests/suite_policy.py
    # intends for a coverage run; an explicit HNX_SUITE_BUDGET_SCALE still wins
    env.setdefault("HNX_SUITE_BUDGET_SCALE", COVERAGE_BUDGET_SCALE)
    return subprocess.run(cmd, cwd=REPO_ROOT, check=False, env=env).returncode


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--floor", type=float, default=FLOOR)
    ap.add_argument("--json", type=Path, help="an existing coverage json report to evaluate")
    args = ap.parse_args(argv)
    report_path = args.json
    if report_path is None:
        report_path = REPORT
        if run_tests(report_path) != 0:
            print("coverage_floor: the tests failed; coverage not evaluated", file=sys.stderr)
            return 2
    try:
        report = json.loads(report_path.read_text())
    except (OSError, ValueError) as exc:
        print(f"coverage_floor: cannot read {report_path}: {exc}", file=sys.stderr)
        return 2
    coverage = per_unit(report)
    for unit, pct in sorted(coverage.items()):
        print(f"  {unit:<34} {'-' if pct is None else f'{pct:5.1f}%'}")
    problems = below_floor(coverage, args.floor)
    for p in problems:
        print(f"coverage_floor: {p}", file=sys.stderr)
    if problems:
        return 1
    print(f"coverage_floor: all {len(coverage)} security-critical units >= {args.floor:.0f}%")
    return 0


if __name__ == "__main__":
    sys.exit(main())
