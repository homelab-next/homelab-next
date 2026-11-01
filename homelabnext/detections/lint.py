# SPDX-License-Identifier: Apache-2.0
"""Lints: (1) rule/fixture completeness, (2) logical detection ids in agent-facing files.

(2) is the ONE implementation of ADR-0006's "no raw rule number in prose or a spec" rule:
``lint-ids`` (``make detections``, CI) and invariant X-06 both call ``lint_agent_ids`` over
``find_agent_files``, so the two gates cannot disagree about the same tree.
"""

from __future__ import annotations

import re
from pathlib import Path

from .fixtures import FixtureError, load_fixtures
from .sigma import ATTACK_TECH_RE, STATUSES, RuleError, load_rules

# Agent-facing file kinds: charters, profiles, decision specs, schedules. Decision specs live in
# decision packs (``workflows/decisions/``) and as ``decision_spec*`` files.
AGENT_GLOBS = (
    "**/charters/**/*",
    "**/profiles/**/*",
    "**/decisions/**/*",
    "**/decision_specs/**/*",
    "**/decision_spec*",
    "**/schedules/**/*",
    "**/*charter*",
)
# Never agent-facing: test fixtures (some are bad on purpose), build output, virtualenvs and
# hidden directories.  Paths are judged relative to the scanned root.
SKIP_DIRS = frozenset({"tests", "build", "dist", "node_modules", "venv"})
# A number is "an engine rule number" when it follows rule-ish words, or is in the det map. A
# date after the word ("rule revised 2026-10-15", "2026/10/15") is not one.
RULE_NO_CONTEXT = re.compile(
    r"(?i)\b(?:rule|sid|rule[_ -]?id|signature|detection[_ -]?id)\b[^\n\d]{0,16}(\d{4,9})\b"
    r"(?![-/]\d)"
)
# A logical detection id cited in an agent-facing file; it must resolve in the det map.
DET_REF = re.compile(r"\bdet:([a-z0-9_.\-]+[a-z0-9])")
# Where a rule file may live: sigma/<tactic>/<slug>.yml (``load_rules`` reads nothing else).
RULE_PATH_RE = re.compile(r"^[a-z0-9-]+/[a-z0-9]+(-[a-z0-9]+)*\.yml$")


def lint_rules(root: Path) -> list[str]:
    """A rule without fixtures fails; so do bad tags, orphan fixtures and bad fixture files."""
    root = Path(root)
    problems: list[str] = []
    try:
        rules = load_rules(root)
    except RuleError as exc:
        return [str(exc)]
    slugs = {r.slug for r in rules}
    sigma_dir = root / "sigma"
    if sigma_dir.is_dir():
        for f in sorted(p for p in sigma_dir.rglob("*") if p.is_file()):
            rel = f.relative_to(sigma_dir).as_posix()
            if not RULE_PATH_RE.match(rel):
                problems.append(
                    f"sigma/{rel}: not sigma/<tactic>/<slug>.yml, so no gate loads it "
                    "(move or rename it)"
                )
    for r in rules:
        problems += [f"{r.det_id}: {p}" for p in r.attack_tag_problems()]
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


def lint_det_refs(paths: list[Path], det_map: dict, map_label: str = "the det map") -> list[str]:
    """Fail when a ``det:<slug>`` cited in an agent-facing file is not a live map entry."""
    known = {str(k).removeprefix("det:") for k in det_map.get("entries", {})}
    problems = []
    for p in paths:
        if not p.is_file():
            continue
        for i, line in enumerate(p.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            for m in DET_REF.finditer(line):
                if m.group(1) not in known:
                    problems.append(f"{p}:{i}: det:{m.group(1)} is not in {map_label}")
    return problems


def lint_agent_ids(
    paths: list[Path], det_map: dict | None = None, map_label: str = "the det map"
) -> list[str]:
    """The whole agent-facing id rule: no engine rule numbers and, when a det map is given,
    every cited ``det:`` id resolves in it. ``lint-ids`` and invariant X-06 both run this."""
    problems = lint_no_rule_numbers(paths, det_map)
    if det_map is not None:
        problems += lint_det_refs(paths, det_map, map_label)
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
