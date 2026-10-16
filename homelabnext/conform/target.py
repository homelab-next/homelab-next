# SPDX-License-Identifier: Apache-2.0
"""Targets: which implementation of a capability a suite runs against.

A *target* maps capability names to *bindings*.  A binding says how to build a subject:

* ``fake`` (built in): the capability's in-memory fake from ``conformance/suites/<cap>.py``;
* ``broken`` / ``broken:<mutant>`` (built in): a deliberately defective fake; the suite must fail;
* ``adapter: "package.module:factory"`` (a target file): ``factory(**config)`` returns the
  subject, an object implementing the capability's Protocol in ``conformance/protocols/``.

Target file (YAML or JSON), looked up as a path, then ``conformance/targets/NAME.yml`` under the
root, then ``$HNX_CONFORM_TARGETS``::

    name: staging
    capabilities:
      object-store:
        adapter: my_adapters.s3:make_store      # callable(**config) -> subject
        config: {namespace: conformance}        # keyword arguments; never a raw URL
        features: [clock-control]               # optional features the subject supports
        waive: {list-unicode-keys: "backend rewrites keys"}   # SHOULD checks only, with a reason

Endpoints come from the registry resolver inside the adapter, never from this file
(``docs/conformance.md``).
"""

from __future__ import annotations

import importlib
import os
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .core import Suite
from .registry import ConformError, find_root, load_module

__all__ = ["Binding", "Target", "binding_from_mapping", "load_target", "make_factory"]


@dataclass(frozen=True)
class Binding:
    capability: str
    builtin: str | None = None  # "fake" | "broken" | "broken:<mutant>"
    adapter: str | None = None
    config: Mapping[str, Any] = field(default_factory=dict)
    features: tuple[str, ...] = ()
    waive: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class Target:
    name: str
    bindings: Mapping[str, Binding]
    builtin: str | None = None

    def binding(self, capability: str) -> Binding:
        if self.builtin:
            return Binding(capability, builtin=self.builtin)
        try:
            return self.bindings[capability]
        except KeyError:
            raise ConformError(
                f"target {self.name!r} has no binding for capability {capability!r}"
            ) from None


def binding_from_mapping(capability: str, m: Mapping[str, Any]) -> Binding:
    """Build a binding from the mapping form used by ``homelabnext.conform.run``."""
    if m.get("fake") or m.get("builtin"):
        return Binding(capability, builtin=str(m.get("builtin") or "fake"))
    adapter = m.get("adapter")
    if not isinstance(adapter, str) or ":" not in adapter:
        raise ConformError(f"{capability}: 'adapter' must look like 'package.module:factory'")
    cfg = m.get("config")
    cfg = {} if cfg is None else cfg
    if not isinstance(cfg, Mapping):
        raise ConformError(f"{capability}: 'config' must be a mapping")
    feats = m.get("features")
    feats = [] if feats is None else feats
    if isinstance(feats, str) or not isinstance(feats, list | tuple):
        raise ConformError(f"{capability}: 'features' must be a list of names")
    waive = m.get("waive")
    waive = {} if waive is None else waive
    if not isinstance(waive, Mapping):
        raise ConformError(f"{capability}: 'waive' must map check id to reason")
    return Binding(capability, None, adapter, dict(cfg), tuple(str(f) for f in feats), dict(waive))


def _read(path: Path) -> Mapping[str, Any]:
    text = path.read_text(encoding="utf-8")
    if path.suffix == ".json":
        import json

        doc = json.loads(text)
    else:
        import yaml

        doc = yaml.safe_load(text)
    if not isinstance(doc, Mapping):
        raise ConformError(f"{path}: target file must be a mapping")
    return doc


def load_target(spec: str, root: str | Path | None = None) -> Target:
    """Resolve ``fake``, ``broken[:mutant]``, a file path, or a named target file."""
    if spec == "fake":
        return Target("fake", {}, "fake")
    if spec == "broken" or spec.startswith("broken:"):
        return Target(spec, {}, spec)
    r = find_root(root)
    candidates = [Path(spec)]
    for ext in (".yml", ".yaml", ".json"):
        candidates.append(r / "conformance" / "targets" / f"{spec}{ext}")
        env = os.environ.get("HNX_CONFORM_TARGETS")
        if env:
            candidates.append(Path(env) / f"{spec}{ext}")
    path = next((c for c in candidates if c.is_file()), None)
    if path is None:
        raise ConformError(
            f"unknown target {spec!r}: not 'fake', 'broken', a file, or a named target in "
            f"{r / 'conformance' / 'targets'}"
        )
    doc = _read(path)
    caps = doc.get("capabilities")
    if not isinstance(caps, Mapping) or not caps:
        raise ConformError(f"{path}: needs a non-empty 'capabilities' mapping")
    bindings = {c: binding_from_mapping(c, b or {}) for c, b in caps.items()}
    return Target(str(doc.get("name", path.stem)), bindings)


def _import_attr(dotted: str) -> Callable[..., Any]:
    mod, _, attr = dotted.partition(":")
    try:
        obj: Any = importlib.import_module(mod)
        for part in attr.split("."):
            obj = getattr(obj, part)
    except (ImportError, AttributeError) as exc:
        raise ConformError(f"adapter {dotted!r} cannot be imported: {exc}") from exc
    if not callable(obj):
        raise ConformError(f"adapter {dotted!r} is not callable")
    return obj


def make_factory(
    binding: Binding, suite: Suite | None = None, root: str | Path | None = None
) -> Callable[[], Any]:
    """Return a zero-argument factory building a fresh subject for this binding."""
    cap = binding.capability
    if binding.builtin:
        mod = load_module(cap, root)
        if binding.builtin == "fake":
            return mod.make_fake
        _, _, mutant = binding.builtin.partition(":")
        mutants = mod.MUTANTS
        if not mutants:
            raise ConformError(f"{cap} defines no mutants")
        name = mutant or next(iter(mutants))
        if name not in mutants:
            raise ConformError(f"{cap} has no mutant {name!r}; known: {', '.join(mutants)}")
        return mutants[name].factory
    assert binding.adapter
    r = find_root(root)
    import sys

    if str(r) not in sys.path:
        sys.path.insert(0, str(r))
    fn = _import_attr(binding.adapter)
    cfg = dict(binding.config)
    return lambda: fn(**cfg)
