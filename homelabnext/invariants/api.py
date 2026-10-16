# SPDX-License-Identifier: Apache-2.0
"""Check plugin API.

A plugin is a function ``fn(ctx) -> CheckResult`` registered under a criterion id. Three ways
to provide one:

1. Built in: ``homelabnext.invariants.plugins.pillar_x`` (loaded by ``default_registry``).
2. Entry points, group ``homelabnext.invariants.checks``. Each entry point resolves to either
   a ``Check``, an iterable of ``Check``, or a callable ``register(registry)``.
3. A directory of ``*.py`` modules (``--plugins-dir``). A module exposes ``CHECKS`` (iterable of
   ``Check``) and/or ``register(registry)``.

Statuses: ``pass``, ``fail``, ``error`` (could not measure), ``skip`` (not applicable here,
with a reason; never counts as a pass of anything that matters). An exception inside a plugin
is ``error``, never ``fail`` and never ``pass``: "could not measure" is its own verdict.
"""

from __future__ import annotations

import importlib.util
import pathlib
import subprocess
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from importlib import metadata

__all__ = [
    "ENTRY_POINT_GROUP",
    "ERROR",
    "FAIL",
    "PASS",
    "SKIP",
    "Check",
    "CheckResult",
    "Context",
    "Registry",
    "default_registry",
    "load_directory",
    "load_entry_points",
]

ENTRY_POINT_GROUP = "homelabnext.invariants.checks"
PASS, FAIL, ERROR, SKIP = "pass", "fail", "error", "skip"


@dataclass(frozen=True)
class CheckResult:
    status: str
    evidence: str = ""

    def __post_init__(self):
        if self.status not in (PASS, FAIL, ERROR, SKIP):
            raise ValueError(f"bad status {self.status!r}")


def passed(evidence=""):
    return CheckResult(PASS, evidence)


def failed(evidence=""):
    return CheckResult(FAIL, evidence)


def skipped(reason):
    return CheckResult(SKIP, reason)


@dataclass
class Context:
    """What a check may touch. ``run`` is injectable so tests never spawn real tools."""

    root: pathlib.Path
    run: Callable[..., tuple[int, str]] = None  # (argv, timeout) -> (returncode, combined output)

    def __post_init__(self):
        self.root = pathlib.Path(self.root)
        if self.run is None:
            self.run = self._run

    def _run(self, argv, timeout=120):
        p = subprocess.run(
            list(argv), cwd=self.root, capture_output=True, text=True, timeout=timeout
        )
        return p.returncode, ((p.stdout or "") + (p.stderr or "")).strip()


@dataclass(frozen=True)
class Check:
    id: str
    statement: str
    fn: Callable[[Context], CheckResult]
    slow: bool = False


@dataclass
class Registry:
    checks: dict[str, Check] = field(default_factory=dict)

    def register(self, check: Check) -> Check:
        if check.id in self.checks:
            raise ValueError(f"duplicate check id {check.id}")
        self.checks[check.id] = check
        return check

    def check(self, id: str, statement: str, slow: bool = False):
        """Decorator form: ``@registry.check("X-09", "statement")``."""

        def deco(fn):
            self.register(Check(id, statement, fn, slow))
            return fn

        return deco

    def get(self, id: str) -> Check | None:
        return self.checks.get(id)

    def _absorb(self, obj) -> None:
        if isinstance(obj, Check):
            self.register(obj)
        elif callable(obj):
            obj(self)
        else:
            for c in obj:
                self.register(c)


def load_entry_points(registry: Registry, entry_points: Iterable | None = None) -> list[str]:
    """Load ``homelabnext.invariants.checks`` entry points; returns names loaded."""
    eps = (
        entry_points if entry_points is not None else metadata.entry_points(group=ENTRY_POINT_GROUP)
    )
    names = []
    for ep in eps:
        registry._absorb(ep.load())
        names.append(ep.name)
    return names


def load_directory(registry: Registry, directory) -> list[str]:
    """Import every ``*.py`` in ``directory`` (sorted, skipping ``_*``) as a check module."""
    names = []
    for p in sorted(pathlib.Path(directory).glob("*.py")):
        if p.name.startswith("_"):
            continue
        spec = importlib.util.spec_from_file_location(f"hnx_checks_{p.stem}", p)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        if hasattr(mod, "register"):
            mod.register(registry)
        if hasattr(mod, "CHECKS"):
            for c in mod.CHECKS:
                registry.register(c)
        names.append(p.stem)
    return names


def default_registry() -> Registry:
    from .plugins import pillar_x

    reg = Registry()
    pillar_x.register(reg)
    return reg
