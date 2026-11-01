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

Runs ``hnx conform list`` and ``hnx conform report --out build/conform-report.json`` (the
exporter behind invariant X-10) and fails when any capability of
``homelabnext.conform.CAPABILITIES`` is missing from the report, has no suite, or is not
``passing``.  Like X-10, the report is read from that file, never scraped from stdout (an
adapter imported during the run can print anything), and its verdicts must agree with the
exporter's exit code.

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
from homelabnext.conform.report import SCHEMA, exit_code  # noqa: E402


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
            out.append(
                f"{cap}: suite does not pass ({row.get('verdict', 'fail')}: "
                f"{row.get('reason', 'failed must: ' + str(row.get('failed_must')))})"
            )
    out += [
        f"{c}: listed without a passing test"
        for c in report.get("capabilities_without_passing_test", [])
    ]
    return sorted(set(out))


def read_report(path: Path) -> dict | None:
    """The report in ``path``, or None unless it is one well-formed report of this schema."""
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(doc, dict) or doc.get("schema") != SCHEMA:
        return None
    caps = doc.get("capabilities")
    if not isinstance(caps, dict) or not all(isinstance(e, dict) for e in caps.values()):
        return None
    return doc


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
    out = args.root / "build" / "conform-report.json"
    out.unlink(missing_ok=True)  # never judge a report left over from an earlier run
    rep = _hnx(args.root, "report", "--out", str(out), "--target", args.target)
    sys.stdout.write(rep.stdout)
    report = read_report(out)
    if report is None:
        sys.stderr.write(f"conform_coverage: no usable report in {out} (rc={rep.returncode})\n")
        sys.stderr.write(rep.stderr)
        return 2
    if exit_code(report) != rep.returncode:
        sys.stderr.write(
            f"conform_coverage: the report's verdicts mean exit {exit_code(report)}, "
            f"the exporter exited {rep.returncode}\n{rep.stderr}"
        )
        return 2
    problems = missing_passes(report)
    for p in problems:
        sys.stderr.write(f"conform_coverage: {p}\n")
    if problems:
        return 1
    print(f"conform_coverage: all {len(CAPABILITIES)} capabilities have a passing conformance test")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
