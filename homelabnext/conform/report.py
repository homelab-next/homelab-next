# SPDX-License-Identifier: Apache-2.0
"""The exporter: which capabilities have no *passing* conformance test.

A capability has a passing test when its suite (a) exists, (b) runs at least ``MIN_CHECKS``
checks against the target, (c) has no failing MUST check, and (d) - for the built-in ``fake``
target - catches every one of its deliberately broken fakes.  Clause (d) is what stops a
vacuous suite from counting: a test that cannot fail proves nothing.

The JSON form is the input of invariant X-10 (``homelabnext.conform.plugins.x10_conformance``).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .registry import CAPABILITIES, EXTENDED, ConformError, find_root
from .runner import CapabilityRun, mutation_runs, run_capability

__all__ = ["SCHEMA", "build_report", "declared_capabilities", "render_human"]

SCHEMA = "homelabnext.conform.report/1"


def declared_capabilities(root: Path) -> list[str]:
    """Capabilities the tree declares (``capabilities.yml``), else the fourteen."""
    for cand in ("capabilities.yml", "registry/capabilities.yml"):
        p = root / cand
        if p.is_file():
            import yaml

            data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
            return [str(c) for c in data.get("capabilities", [])]
    return list(CAPABILITIES)


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
    caps = capabilities or declared_capabilities(r)
    with_mutants = (target == "fake") if mutants is None else mutants
    entries: dict[str, Any] = {}
    errors = 0
    for cap in caps:
        if cap not in (*CAPABILITIES, *EXTENDED):
            entries[cap] = {"suite": False, "passing": False, "reason": "no conformance suite"}
            continue
        try:
            run: CapabilityRun = run_capability(cap, target, r)
        except ConformError as exc:
            entries[cap] = {"suite": False, "passing": False, "reason": str(exc)}
            continue
        e: dict[str, Any] = {
            "suite": True,
            "executed": len(run.executed),
            "failed_must": [x.check for x in run.failed_must],
            "failed_should": [x.check for x in run.failed_should],
            "skipped": [x.check for x in run.results if x.status == "skip"],
            "error": run.error,
        }
        reasons: list[str] = []
        if run.error:
            errors += 1
            reasons.append(run.error)
        if e["failed_must"]:
            reasons.append("failing MUST check(s): " + ", ".join(e["failed_must"]))
        if not run.error and len(run.executed) < 6:
            reasons.append(f"only {len(run.executed)} check(s) executed")
        if with_mutants:
            ms = mutation_runs(cap, r)
            e["mutants"] = [
                {
                    "name": m.name,
                    "expected_check": m.expected,
                    "failed": m.failed,
                    "detected": m.detected,
                }
                for m in ms
            ]
            if not ms:
                reasons.append("no deliberately broken fake")
            for m in ms:
                if not m.detected:
                    reasons.append(f"mutant {m.name!r} not caught by check {m.expected!r}")
        e["passing"] = not reasons
        if reasons:
            e["reason"] = "; ".join(reasons)
        entries[cap] = e
    without = [c for c in caps if not entries[c]["passing"]]
    return {
        "schema": SCHEMA,
        "target": target,
        "ok": not without,
        "measurement_errors": errors,
        "capabilities": entries,
        "capabilities_without_passing_test": without,
    }


def render_human(rep: dict[str, Any]) -> str:
    lines = [f"conformance report (target: {rep['target']})"]
    for cap, e in rep["capabilities"].items():
        if not e.get("suite"):
            lines.append(f"  NONE  {cap:<16} {e.get('reason', '')}")
            continue
        mark = "PASS" if e["passing"] else "FAIL"
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
