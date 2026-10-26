#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# hnx-script:
#   id: conform-coverage
#   kind: check
#   purpose: Fail unless each of the eighteen capabilities has a passing conformance suite.
#   owner: maintainers
#   trigger: [ci:ci/schemas, make:conform-check]
#   inputs: the conformance suites and the target (--target, default fake)
#   outputs: build/conform-report.json and a summary on stdout
#   exit:
#     "0": all capabilities pass
#     "1": some capability lacks a passing test
#     "2": the report could not be produced
"""Gate: every one of the eighteen capabilities has a passing conformance test.

Runs ``hnx conform list`` and ``hnx conform report --json`` (the exporter behind invariant X-10)
and fails when any capability of ``homelabnext.conform.CAPABILITIES`` is missing from the report,
has no suite, or is not ``passing``.  The report is written to ``build/conform-report.json``.

Usage: python tools/conform_coverage.py [--root DIR] [--target fake]
Exit: 0 all pass, 1 some capability lacks a passing test, 2 the report could not be produced.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from homelabnext.conform import CAPABILITIES  # noqa: E402


def _hnx(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "homelabnext.cli", "conform", "--root", str(root), *args],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        check=False,
    )


def missing_passes(report: dict, expected: tuple[str, ...] = CAPABILITIES) -> list[str]:
    caps = report.get("capabilities", {})
    out = []
    for cap in expected:
        row = caps.get(cap)
        if row is None:
            out.append(f"{cap}: not in the report")
        elif not row.get("suite"):
            out.append(f"{cap}: no suite")
        elif not row.get("passing"):
            out.append(f"{cap}: suite does not pass (failed must: {row.get('failed_must')})")
    out += [
        f"{c}: listed without a passing test"
        for c in report.get("capabilities_without_passing_test", [])
    ]
    return sorted(set(out))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--root", type=Path, default=REPO_ROOT)
    ap.add_argument("--target", default="fake")
    args = ap.parse_args(argv)
    listing = _hnx(args.root, "list")
    sys.stdout.write(listing.stdout)
    if listing.returncode != 0:
        sys.stderr.write(listing.stderr)
        return 2
    rep = _hnx(args.root, "report", "--json", "--target", args.target)
    try:
        report = json.loads(rep.stdout)
    except ValueError:
        sys.stderr.write(f"conform_coverage: no JSON report (rc={rep.returncode})\n{rep.stderr}")
        return 2
    out = args.root / "build" / "conform-report.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    problems = missing_passes(report)
    for p in problems:
        sys.stderr.write(f"conform_coverage: {p}\n")
    if problems:
        return 1
    print(f"conform_coverage: all {len(CAPABILITIES)} capabilities have a passing conformance test")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
