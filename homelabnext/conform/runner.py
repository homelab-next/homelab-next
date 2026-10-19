# SPDX-License-Identifier: Apache-2.0
"""Run a capability's suite against a target and summarise the outcome."""

from __future__ import annotations

import hashlib
import subprocess
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .core import CheckResult, Suite, run_checks
from .registry import ConformError, find_root, load_module, load_suite
from .target import Binding, Target, adapter_origin, binding_from_mapping, load_target, make_factory

__all__ = [
    "MIN_CHECKS",
    "CapabilityRun",
    "MutantRun",
    "git_sha",
    "mutation_runs",
    "run",
    "run_capability",
    "suite_digest",
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
    only: list[str] | None = None  # the --check selection, if any

    @property
    def executed(self) -> list[CheckResult]:
        return [r for r in self.results if r.status in ("pass", "fail")]

    @property
    def too_few(self) -> str | None:
        """Why the run executed too little to mean anything, else None.

        A full run needs ``MIN_CHECKS`` executed checks; a ``--check`` selection needs at least
        one.  Skips do not count, so a subject that skips everything cannot pass.
        """
        if self.error is not None:
            return None
        need = MIN_CHECKS if self.only is None else 1
        n = len(self.executed)
        if n < need:
            return f"only {n} check(s) executed; at least {need} required"
        return None

    @property
    def failed_must(self) -> list[CheckResult]:
        return [r for r in self.results if r.severity == "must" and not r.ok]

    @property
    def failed_should(self) -> list[CheckResult]:
        return [r for r in self.results if r.severity == "should" and not r.ok]

    @property
    def ok(self) -> bool:
        return self.error is None and not self.failed_must and self.too_few is None

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
            "too_few": self.too_few,
            "provenance": dict(self.meta),
            "counts": {
                "executed": len(self.executed),
                "passed": sum(r.counts_as_pass for r in self.results),
                "failed_must": len(self.failed_must),
                "failed_should": len(self.failed_should),
                "skipped": sum(r.status == "skip" for r in self.results),
                "waived": sum(r.status == "waived" for r in self.results),
                "untested": sum(r.status == "untested" for r in self.results),
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
    run_obj = CapabilityRun(capability, tgt.name, only=list(only) if only is not None else None)
    try:
        suite = load_suite(capability, root)
        binding = tgt.binding(capability)
        run_obj.meta = provenance(capability, binding, root)
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


def suite_digest(capability: str, root: str | Path | None = None) -> str | None:
    """sha256 of the suite module file, so a report says exactly which checks produced it."""
    path = getattr(load_module(capability, root), "__file__", None)
    if not path:
        return None
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def git_sha(root: str | Path | None = None) -> str | None:
    """HEAD of the checkout holding the suites, or None (not a git tree, no git)."""
    try:
        p = subprocess.run(
            ["git", "-C", str(find_root(root)), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    out = p.stdout.strip()
    return out if p.returncode == 0 and out else None


def provenance(capability: str, binding: Binding, root: str | Path | None = None) -> dict[str, Any]:
    """What a result was measured with: suite file hash, checkout SHA, adapter and its file."""
    meta: dict[str, Any] = {
        "suite_sha256": suite_digest(capability, root),
        "git_sha": git_sha(root),
    }
    if binding.builtin:
        meta["adapter"] = f"builtin:{binding.builtin}"
    else:
        meta["adapter"] = binding.adapter
        meta["adapter_file"] = adapter_origin(binding.adapter or "", root)
    return meta


@dataclass
class MutantRun:
    capability: str
    name: str
    description: str
    expected: str
    failed: list[str]
    detected: bool  # the suite failed the expected check, a MUST that cannot skip
    reason: str = ""  # why it does not count as detected, when it does not


def mutation_runs(capability: str, root: str | Path | None = None) -> list[MutantRun]:
    """Run every deliberately broken fake of ``capability`` through its suite."""
    mod = load_module(capability, root)
    suite: Suite = mod.SUITE
    out: list[MutantRun] = []
    specs = {s.id: s for s in suite.specs}
    for name, m in mod.MUTANTS.items():
        res = run_checks(suite, m.factory)
        failed = [r.check for r in res if not r.ok]
        status = {r.check: r.status for r in res}
        spec = specs.get(m.fails)
        reason = ""
        if spec is None:
            reason = f"no check {m.fails!r} in the suite"
        elif spec.severity != "must":
            reason = f"check {m.fails!r} is a SHOULD; only a MUST failure fails a capability"
        elif spec.can_skip:
            reason = f"check {m.fails!r} can skip (requires/skippable), so it proves nothing"
        elif status.get(m.fails) != "fail":
            reason = f"check {m.fails!r} did not fail (status {status.get(m.fails)})"
        out.append(MutantRun(capability, name, m.description, m.fails, failed, not reason, reason))
    return out
