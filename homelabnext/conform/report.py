# SPDX-License-Identifier: Apache-2.0
"""The exporter: which capabilities have no *passing* conformance test.

A capability has a passing test when its suite (a) exists, (b) runs at least ``MIN_CHECKS``
checks against the target, (c) has no failing MUST check, and (d) - for the built-in ``fake``
target - catches every one of its deliberately broken fakes.  Clause (d) is what stops a
vacuous suite from counting: a test that cannot fail proves nothing.

Every entry carries a ``verdict`` (``runner.VERDICTS``): ``pass``; ``fail`` (no suite, a failing
MUST check, too few checks executed, a mutant not caught or none to catch); ``unmeasured`` (the
subject could not be built, and nothing else failed); ``misconfigured`` (the binding or the
adapter's settings are wrong, and nothing else failed).  The exit code is a function of the
verdicts alone (:func:`exit_code`), so one capability's outage never hides another's failure.

The JSON form is the input of invariant X-10 (``homelabnext.conform.plugins.x10_conformance``).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from . import registry
from .registry import CAPABILITIES, EXTENDED, ConformError, find_root, load_suite
from .runner import MIN_CHECKS, VERDICTS, CapabilityRun, git_sha, mutation_runs, run_capability

__all__ = ["SCHEMA", "build_report", "declared_capabilities", "exit_code", "render_human"]

SCHEMA = "homelabnext.conform.report/1"


def declared_capabilities(root: Path) -> list[str]:
    """Capabilities the tree declares (``capabilities.yml``, validated by
    :func:`registry.declared_capabilities`), else the eighteen."""
    declared = registry.declared_capabilities(root)
    return list(CAPABILITIES) if declared is None else declared


def exit_code(rep: dict[str, Any]) -> int:
    """``hnx conform report``'s exit code, from the entries' verdicts alone.

    1 when any capability fails, else 2 when any is misconfigured, else 100 when any could not
    be measured, else 0.  A failure outranks an outage: "could not measure" is reported only
    when nothing that was measured failed.
    """
    verdicts = {e.get("verdict") for e in rep["capabilities"].values()}
    if "fail" in verdicts:
        return 1
    if "misconfigured" in verdicts:
        return 2
    if "unmeasured" in verdicts:
        return 100
    return 0


def build_report(
    root: str | Path | None = None,
    target: str = "fake",
    *,
    mutants: bool | None = None,
    capabilities: list[str] | None = None,
) -> dict[str, Any]:
    r = find_root(root)
    if not (r / "conformance" / "suites").is_dir():
        raise ConformError(
            f"no conformance/suites/ under {r}: hnx conform report needs a source checkout"
        )
    caps = list(capabilities) if capabilities is not None else declared_capabilities(r)
    if not caps:
        raise ConformError("no capabilities to report on: a report of nothing proves nothing")
    with_mutants = (target == "fake") if mutants is None else mutants
    entries: dict[str, Any] = {}
    errors = 0
    for cap in caps:
        if cap not in (*CAPABILITIES, *EXTENDED):
            entries[cap] = {
                "suite": False,
                "passing": False,
                "verdict": "fail",
                "reason": "no conformance suite",
            }
            continue
        try:
            load_suite(cap, r)
        except ConformError as exc:  # the suite itself is missing or broken: no test at all
            entries[cap] = {"suite": False, "passing": False, "verdict": "fail", "reason": str(exc)}
            continue
        try:
            run: CapabilityRun = run_capability(cap, target, r)
        except ConformError as exc:  # the suite exists; the target's binding for it is wrong
            errors += 1
            entries[cap] = {
                "suite": True,
                "passing": False,
                "verdict": "misconfigured",
                "error": str(exc),
                "reason": str(exc),
            }
            continue
        e: dict[str, Any] = {
            "suite": True,
            "executed": len(run.executed),
            "failed_must": [x.check for x in run.failed_must],
            "failed_should": [x.check for x in run.failed_should],
            "skipped": [x.check for x in run.results if x.status == "skip"],
            "untested": [x.check for x in run.results if x.status == "untested"],
            "error": run.error,
            "provenance": dict(run.meta),
        }
        reasons: list[str] = []
        failed = False  # a reason that is a real failure, not an outage
        if run.error:
            errors += 1
            reasons.append(run.error)
        if e["failed_must"]:
            failed = True
            reasons.append("failing MUST check(s): " + ", ".join(e["failed_must"]))
        if not run.error and len(run.executed) < MIN_CHECKS:
            failed = True
            reasons.append(f"only {len(run.executed)} check(s) executed")
        if with_mutants:
            ms = mutation_runs(cap, r)
            e["mutants"] = [
                {
                    "name": m.name,
                    "expected_check": m.expected,
                    "failed": m.failed,
                    "detected": m.detected,
                    "reason": m.reason,
                }
                for m in ms
            ]
            if not ms:
                failed = True
                reasons.append("no deliberately broken fake")
            for m in ms:
                if not m.detected:
                    failed = True
                    reasons.append(
                        f"mutant {m.name!r} not caught by check {m.expected!r}: {m.reason}"
                    )
        e["passing"] = not reasons
        e["verdict"] = "fail" if failed else (run.verdict if run.error else "pass")
        if reasons:
            e["reason"] = "; ".join(reasons)
        entries[cap] = e
    without = [c for c in caps if not entries[c]["passing"]]
    return {
        "schema": SCHEMA,
        "target": target,
        "git_sha": git_sha(r),
        "ok": not without,
        "measurement_errors": errors,
        "verdicts": {v: sum(e["verdict"] == v for e in entries.values()) for v in VERDICTS},
        "capabilities": entries,
        "capabilities_without_passing_test": without,
    }


def render_human(rep: dict[str, Any]) -> str:
    lines = [f"conformance report (target: {rep['target']})"]
    for cap, e in rep["capabilities"].items():
        if not e.get("suite"):
            lines.append(f"  NONE  {cap:<16} {e.get('reason', '')}")
            continue
        if "executed" not in e:  # misconfigured before anything ran
            lines.append(f"  MISCONFIGURED  {cap:<16} {e.get('reason', '')}")
            continue
        mark = {"pass": "PASS", "unmeasured": "COULD NOT MEASURE"}.get(
            e.get("verdict", ""), e.get("verdict", "fail").upper()
        )
        mut = ""
        if "mutants" in e:
            caught = sum(m["detected"] for m in e["mutants"])
            mut = f", mutants caught {caught}/{len(e['mutants'])}"
        lines.append(f"  {mark}  {cap:<16} {e['executed']} checks executed{mut}")
        if not e["passing"]:
            lines.append(f"        {e.get('reason', '')}")
    without = rep["capabilities_without_passing_test"]
    lines.append(
        "capabilities without a passing test: " + (", ".join(without) if without else "none")
    )
    return "\n".join(lines)
