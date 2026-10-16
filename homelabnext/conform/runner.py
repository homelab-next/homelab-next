# SPDX-License-Identifier: Apache-2.0
"""Run a capability's suite against a target and summarise the outcome."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .core import CheckResult, Suite, run_checks
from .registry import ConformError, load_module, load_suite
from .target import Target, binding_from_mapping, load_target, make_factory

__all__ = [
    "MIN_CHECKS",
    "CapabilityRun",
    "MutantRun",
    "mutation_runs",
    "run",
    "run_capability",
]

#: a suite with fewer executed checks than this is not a conformance test
MIN_CHECKS = 6


@dataclass
class CapabilityRun:
    capability: str
    target: str
    results: list[CheckResult] = field(default_factory=list)
    error: str | None = None  # the run could not be measured (factory failed, ...)
    meta: dict[str, Any] = field(default_factory=dict)

    @property
    def executed(self) -> list[CheckResult]:
        return [r for r in self.results if r.status in ("pass", "fail")]

    @property
    def failed_must(self) -> list[CheckResult]:
        return [r for r in self.results if r.severity == "must" and not r.ok]

    @property
    def failed_should(self) -> list[CheckResult]:
        return [r for r in self.results if r.severity == "should" and not r.ok]

    @property
    def ok(self) -> bool:
        return self.error is None and not self.failed_must

    def ok_strict(self) -> bool:
        return self.ok and not self.failed_should

    @property
    def passing(self) -> bool:
        """A *passing test*: measured, no MUST failure, and enough checks really executed."""
        return self.ok and len(self.executed) >= MIN_CHECKS

    def to_dict(self) -> dict[str, Any]:
        return {
            "capability": self.capability,
            "target": self.target,
            "ok": self.ok,
            "passing": self.passing,
            "error": self.error,
            "counts": {
                "executed": len(self.executed),
                "passed": sum(r.counts_as_pass for r in self.results),
                "failed_must": len(self.failed_must),
                "failed_should": len(self.failed_should),
                "skipped": sum(r.status == "skip" for r in self.results),
                "waived": sum(r.status == "waived" for r in self.results),
            },
            "results": [r.to_dict() for r in self.results],
        }


def run_capability(
    capability: str,
    target: Target | str,
    root: str | Path | None = None,
    *,
    only: list[str] | None = None,
) -> CapabilityRun:
    tgt = load_target(target, root) if isinstance(target, str) else target
    run_obj = CapabilityRun(capability, tgt.name)
    try:
        suite = load_suite(capability, root)
        binding = tgt.binding(capability)
        factory = make_factory(binding, suite, root)
        run_obj.results = run_checks(
            suite, factory, features=binding.features, waive=binding.waive, only=only
        )
    except ConformError:
        raise
    except ValueError as exc:  # bad waiver / selection: misconfiguration
        raise ConformError(str(exc)) from exc
    except Exception as exc:  # the subject could not even be built: could not measure
        run_obj.error = f"could not build subject: {type(exc).__name__}: {exc}"
    return run_obj


def run(
    capability: str, target: Mapping[str, Any], root: str | Path | None = None
) -> list[CheckResult]:
    """The ``docs/interfaces.md`` entry point: run ``capability`` against a binding mapping.

    ``target`` is ``{"fake": True}`` or ``{"adapter": "pkg.mod:factory", "config": {...},
    "features": [...], "waive": {...}}``.  Raises on misconfiguration or when the subject cannot
    be built (that is not a pass and not a failure).
    """
    binding = binding_from_mapping(capability, target)
    suite = load_suite(capability, root)
    factory = make_factory(binding, suite, root)
    return run_checks(suite, factory, features=binding.features, waive=binding.waive)


@dataclass
class MutantRun:
    capability: str
    name: str
    description: str
    expected: str
    failed: list[str]
    detected: bool  # the suite failed the expected check (and only a MUST failure counts)


def mutation_runs(capability: str, root: str | Path | None = None) -> list[MutantRun]:
    """Run every deliberately broken fake of ``capability`` through its suite."""
    mod = load_module(capability, root)
    suite: Suite = mod.SUITE
    out: list[MutantRun] = []
    for name, m in mod.MUTANTS.items():
        res = run_checks(suite, m.factory)
        failed = [r.check for r in res if not r.ok]
        out.append(MutantRun(capability, name, m.description, m.fails, failed, m.fails in failed))
    return out
