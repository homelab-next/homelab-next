# SPDX-License-Identifier: Apache-2.0
"""The Sigma lane on the engine: engine fixtures, proved through the engine's own rule tester.

A Sigma rule's ``fixtures/`` are events in the generic shape: they prove the rule's logic (the
reference evaluator) and its compiled form (a backend's ``evaluate``). They cannot prove what only
the engine knows: that the rule's logsource binding chains from a base that the engine reaches for
that telemetry, that no lower-level sibling claims the event first, that the binding's field names
are the ones the engine's decoder sets. Those are proved by **engine fixtures**, raw engine input
in the native rules' shape, sent through the deployed engine's rule tester::

    engine_fixtures/<slug>/{must_fire,must_not_fire}/*.json
        {"event": "<the raw line>", "location": "/var/log/...", "format": "json",
         "provenance": "where the line came from (a lake row, a capture) and what was changed"}

The expected rule is the det map's number for ``det:<slug>``, never a number in the file
(ADR-0006 decision 2). ``run_engine`` fails on a missed must-fire, a fired must-not-fire, and on
a deployable rule with no engine fixture of either kind: a rule shipped to the engine and never
seen to fire there is coverage on paper only. A rule awaiting its source (``hnx_source:
awaiting-source``) is not in the bundle and needs none yet.
"""

from __future__ import annotations

import json
from pathlib import Path

from .native import FIXTURE_KINDS, Fixture, Tester
from .sigma import Rule

DIR = "engine_fixtures"


def load_engine_fixtures(root: Path, slug: str, rule_id: int) -> list[Fixture]:
    out = []
    for kind in FIXTURE_KINDS:
        d = Path(root) / DIR / slug / kind
        if not d.is_dir():
            continue
        for f in sorted(d.glob("*.json")):
            doc = json.loads(f.read_text(encoding="utf-8"))
            if not isinstance(doc, dict) or not isinstance(doc.get("event"), str):
                raise ValueError(
                    f"{f}: an engine fixture is an object with the raw line in 'event'"
                )
            if "rule_id" in doc:
                raise ValueError(f"{f}: the expected rule comes from the det map, not the fixture")
            if not isinstance(doc.get("provenance"), str) or not doc["provenance"].strip():
                raise ValueError(f"{f}: 'provenance' says where the line came from")
            out.append(
                Fixture(slug, kind, f, doc["event"], str(doc.get("location", "")),
                        str(doc.get("format", "syslog")), rule_id)
            )  # fmt: skip
    return out


def lint_engine_fixtures(root: Path, rules: list[Rule]) -> list[str]:
    """Orphan engine fixtures, unknown kinds and malformed files (the run needs the engine)."""
    base = Path(root) / DIR
    if not base.is_dir():
        return []
    slugs = {r.slug for r in rules}
    problems = []
    for d in sorted(p for p in base.iterdir() if p.is_dir()):
        if d.name not in slugs:
            problems.append(f"{DIR}/{d.name}: orphan engine fixtures, no rule det:{d.name}")
            continue
        for k in sorted(p.name for p in d.iterdir() if p.is_dir()):
            if k not in FIXTURE_KINDS:
                problems.append(f"{DIR}/{d.name}/{k}: unknown kind (allowed: {FIXTURE_KINDS})")
        try:
            load_engine_fixtures(root, d.name, 0)
        except (ValueError, json.JSONDecodeError) as exc:
            problems.append(f"{DIR}/{d.name}: {exc}")
    return problems


def run_engine(
    root: Path, rules: list[Rule], det_map: dict[str, int], tester: Tester
) -> tuple[list[str], int]:
    """Every deployable rule's engine fixtures through ``tester``; (problems, fixtures run)."""
    problems: list[str] = []
    ran = 0
    for rule in rules:
        if not rule.deployable:
            continue
        num = det_map.get(rule.det_id)
        if num is None:
            problems.append(f"{rule.det_id}: no engine number in the det map (regenerate)")
            continue
        fixtures = load_engine_fixtures(root, rule.slug, num)
        for need in FIXTURE_KINDS:
            if not any(f.kind == need for f in fixtures):
                problems.append(
                    f"{rule.det_id}: no {need} engine fixture (a deployed rule is proved on the engine)"
                )
        for fx in fixtures:
            ran += 1
            fired = tester(fx)
            label = f"{rule.det_id} {fx.kind}/{fx.path.name}"
            if fx.kind == "must_fire" and fired != num:
                problems.append(
                    f"{label}: expected the rule's own number, the engine matched {fired}"
                )
            if fx.kind == "must_not_fire" and fired == num:
                problems.append(f"{label}: the rule fired and must not")
    return problems, ran
