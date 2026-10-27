# SPDX-License-Identifier: Apache-2.0
"""Lints: (1) rule/fixture completeness, (2) no engine rule numbers in agent-facing files."""

from __future__ import annotations

import re
from pathlib import Path

from .fixtures import FixtureError, load_fixtures
from .sigma import ATTACK_TECH_RE, STATUSES, RuleError, load_rules

# Agent-facing file kinds: charters, profiles, decision specs, schedules.
AGENT_GLOBS = (
    "**/charters/**/*",
    "**/profiles/**/*",
    "**/decision_specs/**/*",
    "**/schedules/**/*",
    "**/*charter*",
)
# Never agent-facing: test fixtures (some are bad on purpose), build output, virtualenvs and
# hidden directories.  Paths are judged relative to the scanned root.
SKIP_DIRS = frozenset({"tests", "build", "dist", "node_modules", "venv"})
# A number is "an engine rule number" when it follows rule-ish words, or is in the det map.
RULE_NO_CONTEXT = re.compile(
    r"(?i)\b(?:rule|sid|rule[_ -]?id|signature|detection[_ -]?id)\b[^\n\d]{0,16}(\d{4,9})\b"
)


def lint_rules(root: Path) -> list[str]:
    """A rule without fixtures fails; so do bad tags, orphan fixtures and bad fixture files."""
    root = Path(root)
    problems: list[str] = []
    try:
        rules = load_rules(root)
    except RuleError as exc:
        return [str(exc)]
    slugs = {r.slug for r in rules}
    for r in rules:
        if r.status not in STATUSES:
            problems.append(f"{r.det_id}: status {r.status!r} is not one of {STATUSES}")
        techs = [t for t in r.tags if ATTACK_TECH_RE.match(t)]
        if not techs:
            problems.append(f"{r.det_id}: no ATT&CK technique tag (attack.tNNNN)")
        tactic_dir = r.path.parent.name
        if tactic_dir not in r.attack_tactics:
            problems.append(
                f"{r.det_id}: directory '{tactic_dir}' is not one of its tactic tags "
                f"{r.attack_tactics}"
            )
        try:
            fx = load_fixtures(root, r.slug)
        except FixtureError as exc:
            problems.append(f"{r.det_id}: {exc}")
            continue
        kinds = {f.kind for f in fx}
        for need in ("must_fire", "must_not_fire"):
            if need not in kinds:
                problems.append(f"{r.det_id}: no {need} fixture (a rule without fixtures fails)")
    fx_root = root / "fixtures"
    if fx_root.is_dir():
        for d in sorted(p for p in fx_root.iterdir() if p.is_dir()):
            if d.name not in slugs:
                problems.append(f"fixtures/{d.name}: orphan fixtures, no rule det:{d.name}")
    return problems


def lint_no_rule_numbers(paths: list[Path], det_map: dict | None = None) -> list[str]:
    """Fail when an engine rule number appears in an agent-charter-like file."""
    known: set[int] = set()
    if det_map:
        known = set(det_map.get("entries", {}).values()) | set(det_map.get("retired", []))
    problems = []
    for p in paths:
        if not p.is_file():
            continue
        for i, line in enumerate(p.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            hits = [m.group(1) for m in RULE_NO_CONTEXT.finditer(line)]
            hits += [t for t in re.findall(r"\b\d{4,9}\b", line) if int(t) in known]
            for h in sorted(set(hits)):
                problems.append(f"{p}:{i}: engine rule number {h} - reference a det:<slug> instead")
    return problems


def find_agent_files(root: Path) -> list[Path]:
    root = Path(root)
    seen: dict[Path, None] = {}
    for g in AGENT_GLOBS:
        for p in root.glob(g):
            parts = p.relative_to(root).parts[:-1]
            if any(d in SKIP_DIRS or d.startswith(".") for d in parts):
                continue
            if p.is_file():
                seen[p] = None
    return sorted(seen)
