# SPDX-License-Identifier: Apache-2.0
"""Fixture runner. The engine is an interface so any backend can be driven."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from .fixtures import Fixture, load_fixtures
from .sigma import Rule, load_mapping, load_rules, rule_matches


class Engine(Protocol):
    def matches(self, rule: Rule, event: dict) -> bool: ...


class FakeGenericEngine:
    """In-process reference engine: the Sigma-subset evaluator plus a field map."""

    def __init__(self, mapping: dict[str, str] | None = None):
        self.mapping = mapping or {}

    def matches(self, rule: Rule, event: dict) -> bool:
        return rule_matches(rule, event, self.mapping)


@dataclass
class FixtureResult:
    fixture: Fixture
    fired: bool

    @property
    def ok(self) -> bool:
        if self.fixture.kind == "must_fire":
            return self.fired
        if self.fixture.kind == "must_not_fire":
            return not self.fired
        return True  # evasion never fails

    @property
    def label(self) -> str:
        k = self.fixture.kind
        if k == "evasion":
            return "caught" if self.fired else "EVADED"
        return "ok" if self.ok else ("MISSED" if k == "must_fire" else "FALSE-POSITIVE")


@dataclass
class RuleReport:
    det_id: str
    results: list[FixtureResult] = field(default_factory=list)

    def of(self, kind: str) -> list[FixtureResult]:
        return [r for r in self.results if r.fixture.kind == kind]

    @property
    def ok(self) -> bool:
        return (
            all(r.ok for r in self.results)
            and bool(self.of("must_fire"))
            and bool(self.of("must_not_fire"))
        )

    @property
    def evaded(self) -> list[FixtureResult]:
        return [r for r in self.of("evasion") if not r.fired]


@dataclass
class RunReport:
    rules: list[RuleReport]

    @property
    def ok(self) -> bool:
        return all(r.ok for r in self.rules)

    def render(self) -> str:
        lines = []
        for rr in self.rules:
            mf, mn, ev = rr.of("must_fire"), rr.of("must_not_fire"), rr.of("evasion")
            lines.append(
                f"{'PASS' if rr.ok else 'FAIL'} {rr.det_id}: "
                f"must_fire {sum(r.fired for r in mf)}/{len(mf)} fired, "
                f"must_not_fire {sum(not r.fired for r in mn)}/{len(mn)} silent, "
                f"evasion {sum(r.fired for r in ev)}/{len(ev)} caught"
            )
            for r in rr.results:
                if not r.ok or r.fixture.kind == "evasion":
                    lines.append(
                        f"    [{r.label}] {r.fixture.kind}/{r.fixture.path.name}"
                        + (f" - {r.fixture.note}" if r.fixture.note else "")
                    )
        lines.append("RESULT: " + ("ok" if self.ok else "FAILED"))
        return "\n".join(lines)


def run_rule(rule: Rule, root: Path, engine: Engine) -> RuleReport:
    rep = RuleReport(rule.det_id)
    for fx in load_fixtures(root, rule.slug):
        rep.results.append(FixtureResult(fx, engine.matches(rule, fx.event)))
    return rep


def run_all(
    root: Path, mapping_path: Path | None = None, engine: Engine | None = None
) -> RunReport:
    root = Path(root)
    if engine is None:
        mp = mapping_path if mapping_path is not None else root / "mappings" / "generic.yml"
        engine = FakeGenericEngine(load_mapping(mp if Path(mp).exists() else None))
    return RunReport([run_rule(r, root, engine) for r in load_rules(root)])
