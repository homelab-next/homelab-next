# SPDX-License-Identifier: Apache-2.0
"""ATT&CK coverage counted from passing fixtures only (checklist D-04).

A rule counts toward coverage only when it is deployed (its ``status`` is neither ``unsupported``
nor ``deprecated``) and the fixture runner proves it: it has at least one
``must_fire`` and one ``must_not_fire`` fixture and every one of them passes (each must_fire fires,
each must_not_fire stays silent).  A rule that misses a must_fire, or fires on benign input, is
listed under ``uncounted`` with the reason, and its techniques are covered only if another, passing
rule covers them.  Evasion fixtures never decide coverage; they are reported as known gaps.

Each backend that can evaluate its own artefact (:func:`runner.compiled_backends`) gets its own
count under ``backends``, from the same fixtures run through what it compiled
(:func:`runner.run_compiled`): a rule it cannot express, or whose compiled form misses a must_fire
or fires on a must_not_fire, is uncounted there, so the top-level numbers are never read as an
engine's coverage when its compiled rules would not fire.

The report is deterministic (sorted, no timestamps) so it is committed as a golden file
(``detections/attack_coverage.json``) and CI fails when it is not the one the current rules and
fixtures produce (``python -m homelabnext.detections coverage --check``).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .runner import BackendRun, RunReport, compiled_backends, run_all, run_compiled
from .sigma import Rule, load_rules

SCHEMA_ID = "homelabnext.detections.attack_coverage/v1"


def _why_not(rr) -> str | None:
    mf, mn = rr.of("must_fire"), rr.of("must_not_fire")
    if not mf:
        return "no must_fire fixture"
    if not mn:
        return "no must_not_fire fixture"
    missed = sorted(r.fixture.path.name for r in mf if not r.ok)
    if missed:
        return "must_fire missed: " + ", ".join(missed)
    fps = sorted(r.fixture.path.name for r in mn if not r.ok)
    if fps:
        return "must_not_fire fired: " + ", ".join(fps)
    return None


def _count(rules: list[Rule], run: RunReport, refused: dict[str, str]) -> dict[str, Any]:
    by_det = {rr.det_id: rr for rr in run.rules}
    techniques: dict[str, dict[str, Any]] = {}
    tactics: dict[str, set[str]] = {}
    counted: list[str] = []
    uncounted: list[dict[str, str]] = []
    gaps: list[dict[str, str]] = []
    for rule in sorted(rules, key=lambda r: r.det_id):
        rr = by_det.get(rule.det_id)
        if not rule.deployable:
            # an inert rule is tested, never counted: it cannot fire as shipped
            reason = f"status {rule.status}: not deployed, so not coverage"
        elif rule.det_id in refused:
            reason = refused[rule.det_id]
        else:
            reason = "not run" if rr is None else _why_not(rr)
        if reason:
            uncounted.append({"rule": rule.det_id, "reason": reason})
            continue
        counted.append(rule.det_id)
        for t in rule.attack_techniques:
            row = techniques.setdefault(t, {"rules": [], "tactics": set()})
            row["rules"].append(rule.det_id)
            row["tactics"].update(rule.attack_tactics)
        for tac in rule.attack_tactics:
            tactics.setdefault(tac, set()).update(rule.attack_techniques)
        gaps += [
            {"rule": rule.det_id, "evasion": r.fixture.path.name}
            for r in rr.evaded  # type: ignore[union-attr]
        ]
    return {
        "counted": counted,
        "uncounted": uncounted,
        "techniques": techniques,
        "tactics": tactics,
        "gaps": gaps,
    }


def _backend(rules: list[Rule], b: BackendRun) -> dict[str, Any]:
    refused = {d: f"not expressible in {b.backend}: {why}" for d, why in b.not_expressible.items()}
    c = _count(rules, b.report, refused)
    mf = [r for rr in b.report.rules for r in rr.of("must_fire")]
    return {
        "counted_from": "the same fixtures, run through the backend's compiled rules",
        "rules_counted": len(c["counted"]),
        "techniques_covered": len(c["techniques"]),
        "must_fire": {"fired": sum(r.fired for r in mf), "total": len(mf)},
        "uncounted": c["uncounted"],
    }


def coverage_report(
    rules: list[Rule], run: RunReport, backends: list[BackendRun] | None = None
) -> dict[str, Any]:
    c = _count(rules, run, {})
    techniques, tactics = c["techniques"], c["tactics"]
    out = {
        "schema": SCHEMA_ID,
        "counted_from": "rules whose must_fire and must_not_fire fixtures all pass",
        "summary": {
            "rules_total": len(rules),
            "rules_counted": len(c["counted"]),
            "techniques_covered": len(techniques),
            "tactics_covered": len(tactics),
        },
        "techniques": {
            t: {"rules": sorted(v["rules"]), "tactics": sorted(v["tactics"])}
            for t, v in sorted(techniques.items())
        },
        "tactics": {k: sorted(v) for k, v in sorted(tactics.items())},
        "uncounted": c["uncounted"],
        "evasion_gaps": sorted(c["gaps"], key=lambda g: (g["rule"], g["evasion"])),
    }
    if backends:
        ordered = sorted(backends, key=lambda b: b.backend)
        out["backends"] = {b.backend: _backend(rules, b) for b in ordered}
    return out


def report_for(root: Path) -> dict[str, Any]:
    """The report for the detections tree at ``root``, every compiled backend included."""
    run = run_all(root)
    backends = [run_compiled(root, name, run) for name in compiled_backends()]
    return coverage_report(load_rules(root), run, backends)


def dumps(report: dict[str, Any]) -> str:
    return json.dumps(report, indent=2, sort_keys=False) + "\n"


def check_golden(report: dict[str, Any], golden_text: str) -> list[str]:
    """Problems when the committed report is not the one the current rules produce."""
    try:
        old = json.loads(golden_text)
    except json.JSONDecodeError as exc:
        return [f"golden report is not JSON: {exc}"]
    if old == report:
        return []
    out = []
    was, now = set(old.get("techniques", {})), set(report["techniques"])
    out += [
        f"technique {t}: covered now, missing from the golden report" for t in sorted(now - was)
    ]
    out += [f"technique {t}: in the golden report, no passing rule covers it now" for t in sorted(was - now)]  # fmt: skip
    if not out:
        out.append("golden report differs from the current one")
    out.append(
        "regenerate: python -m homelabnext.detections coverage --out detections/attack_coverage.json"
    )
    return out
