#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Gate: every seam has a passing publisher AND consumer contract test (checklist T-07, Q-05).

The seams are every event type with a schema (``schemas/events/<type>.schema.json``) and every
shared lake table with a schema (``schemas/ocsf/<table>.v<N>.json``).  The contract tests are
generated from those directories (``tests/events/test_contracts.py``,
``tests/lake/test_table_contracts.py``); this gate runs them and fails unless, for every seam,
``test_publisher_contract[<name>]`` and ``test_consumer_contract[<name>]`` both ran and passed.
A skip is not a pass.  So a new type or table without an example, a negative, or a schema the
publisher and consumer agree on fails here, by name.

Usage: python tools/contract_coverage.py [--junit FILE]   (``--junit`` reads an existing report
instead of running the tests)
Exit: 0 every seam covered, 1 some seam lacks a passing test, 2 the tests could not be run.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from homelabnext.events.contract import event_type_stems, table_names  # noqa: E402

# seam kind -> the generated test module (junit classname) that covers it
MODULES = {
    "event": "tests.events.test_contracts",
    "table": "tests.lake.test_table_contracts",
}
ROLES = ("publisher", "consumer")


def expected_seams() -> list[tuple[str, str]]:
    return [("event", s) for s in event_type_stems()] + [("table", t) for t in table_names()]


def parse_junit(path: Path) -> dict[tuple[str, str], str]:
    """``(classname, test name) -> passed | failed | skipped`` from a junit XML report."""
    out: dict[tuple[str, str], str] = {}
    for tc in ET.parse(path).getroot().iter("testcase"):
        if tc.find("failure") is not None or tc.find("error") is not None:
            outcome = "failed"
        elif tc.find("skipped") is not None:
            outcome = "skipped"
        else:
            outcome = "passed"
        out[(tc.get("classname", ""), tc.get("name", ""))] = outcome
    return out


def problems(seams: list[tuple[str, str]], results: dict[tuple[str, str], str]) -> list[str]:
    out = []
    for kind, name in seams:
        for role in ROLES:
            key = (MODULES[kind], f"test_{role}_contract[{name}]")
            got = results.get(key)
            if got is None:
                out.append(f"{kind} {name}: no {role} contract test ran")
            elif got != "passed":
                out.append(f"{kind} {name}: {role} contract test {got}")
    return out


def run_tests(junit: Path) -> int:
    files = [m.replace(".", "/") + ".py" for m in MODULES.values()]
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "-q",
            "-p",
            "no:cacheprovider",
            "--junitxml",
            str(junit),
            *files,
        ],
        cwd=REPO_ROOT,
        env=os.environ.copy(),
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode not in (0, 1):  # 1 = some test failed: reported per seam below
        sys.stderr.write(proc.stdout[-4000:] + proc.stderr[-4000:])
    return proc.returncode


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--junit", type=Path, help="read this junit XML instead of running the tests")
    args = ap.parse_args(argv)
    seams = expected_seams()
    with tempfile.TemporaryDirectory() as tmp:
        junit = args.junit or Path(tmp) / "contracts.xml"
        if args.junit is None:
            rc = run_tests(junit)
            if not junit.is_file():
                print(f"contract_coverage: the contract tests did not run (pytest exit {rc})")
                return 2
        probs = problems(seams, parse_junit(junit))
    for p in probs:
        print(f"MISSING {p}")
    n_ev = sum(k == "event" for k, _ in seams)
    print(
        f"contract_coverage: {n_ev} event types, {len(seams) - n_ev} tables, "
        f"{len(probs)} missing publisher/consumer passes"
    )
    return 1 if probs else 0


if __name__ == "__main__":
    sys.exit(main())
