# SPDX-License-Identifier: Apache-2.0
"""Fixture runner. The engine is an interface so any backend can be driven.

:func:`run_all` drives the reference evaluator (:class:`FakeGenericEngine`). A backend that can
evaluate its own artefact (an ``evaluate(artifact, event)`` method, as the Wazuh stub has) is
also driven through what it compiled, by :func:`run_compiled`: a must_fire or must_not_fire
fixture whose compiled result differs from the reference one is a failure, since a rule that
fires in the evaluator and not in the engine's form is coverage on paper only (ADR-0006).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from .adapters import Artifact, Target, UnsupportedConstruct, get_backend, registered
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


def _fixture_mapping(root: Path, mapping_path: Path | None) -> dict[str, str]:
    """The field map of the fixtures' event shape (``mappings/generic.yml``)."""
    mp = mapping_path if mapping_path is not None else root / "mappings" / "generic.yml"
    return load_mapping(mp if Path(mp).exists() else None)


def run_all(
    root: Path, mapping_path: Path | None = None, engine: Engine | None = None
) -> RunReport:
    root = Path(root)
    if engine is None:
        engine = FakeGenericEngine(_fixture_mapping(root, mapping_path))
    return RunReport([run_rule(r, root, engine) for r in load_rules(root)])


class CompiledEngine:
    """A backend's compiled artefact as the engine: each rule is compiled once, with the
    fixtures' field map (so the artefact names the fields the fixture events carry) and a
    placeholder engine number (the artefact is evaluated here, never shipped)."""

    def __init__(self, backend, mapping: dict[str, str]):
        self.backend = backend
        self.mapping = mapping
        self._arts: dict[str, Artifact] = {}

    def compile(self, rule: Rule) -> Artifact:
        if rule.det_id not in self._arts:
            tgt = Target(self.backend.name, self.mapping, {rule.det_id: 0})
            self._arts[rule.det_id] = self.backend.compile(rule, tgt)
        return self._arts[rule.det_id]

    def matches(self, rule: Rule, event: dict) -> bool:
        return self.backend.evaluate(self.compile(rule), event)


@dataclass
class BackendRun:
    """The fixtures through one backend's compiled artefacts, beside the reference run."""

    backend: str
    report: RunReport
    #: det id -> why the backend cannot express it (left out of its bundle, never counted)
    not_expressible: dict[str, str] = field(default_factory=dict)
    #: fixtures whose compiled result is not the reference one
    divergent: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.divergent

    def render(self) -> str:
        n = sum(len(rr.results) for rr in self.report.rules)
        lines = [
            f"{'PASS' if self.ok else 'FAIL'} {self.backend} (compiled): "
            f"{len(self.report.rules)} rule(s), {n} fixture(s), {len(self.divergent)} divergent"
        ]
        lines += [f"    [DIVERGES] {d}" for d in self.divergent]
        lines += [
            f"    [not expressible] {d}: {why}" for d, why in sorted(self.not_expressible.items())
        ]
        return "\n".join(lines)


def compiled_backends() -> list[str]:
    """The registered backends that can evaluate their own artefact."""
    get_backend("generic")  # registers the built-ins
    return sorted(n for n, be in registered().items() if callable(getattr(be, "evaluate", None)))


def run_compiled(
    root: Path, backend: str, reference: RunReport, mapping_path: Path | None = None
) -> BackendRun:
    """Every deployable rule's fixtures through ``backend``'s compiled artefact, compared with
    ``reference`` (the :func:`run_all` report) fixture by fixture."""
    root = Path(root)
    engine = CompiledEngine(get_backend(backend), _fixture_mapping(root, mapping_path))
    ref = {(rr.det_id, r.fixture.path): r.fired for rr in reference.rules for r in rr.results}
    out = BackendRun(backend, RunReport([]))
    for rule in load_rules(root):
        if not rule.deployable:
            continue
        try:
            engine.compile(rule)
        except UnsupportedConstruct as exc:
            out.not_expressible[rule.det_id] = str(exc)
            continue
        rr = run_rule(rule, root, engine)
        out.report.rules.append(rr)
        for r in rr.results:
            want = ref.get((rule.det_id, r.fixture.path))
            if r.fixture.kind != "evasion" and want is not None and want != r.fired:
                out.divergent.append(
                    f"{rule.det_id} {r.fixture.kind}/{r.fixture.path.name}: "
                    f"{'fires' if want else 'silent'} in the reference evaluator, "
                    f"{'fires' if r.fired else 'silent'} compiled"
                )
    return out
