# SPDX-License-Identifier: Apache-2.0
"""Engine adapter interface: ``compile(rule, target) -> Artifact``.

An adapter turns a Sigma-subset rule into something a specific engine can
load. Adapters are pure functions of (rule, target): no network, no deploy.

Optionally, an adapter also advertises what ATT&CK ids its target engine KNOWS, so a rule can
be checked against the engine's bundled ATT&CK database before it ships. Advertising is through
either (a) a ``known_technique_ids()`` method returning a set/frozenset of ids, OR (b) a
``known_ids_snapshot`` path on the backend pointing at a snapshot file for ``attack.load_snapshot``.
The ``KnownTechniques`` protocol is informational: nothing enforces that a backend provides
it, and ``validate-techniques`` loads ``known_ids_snapshot`` itself when the method is absent.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from .sigma import Rule


class UnsupportedConstruct(Exception):
    """The rule cannot be expressed in this engine; author native rules instead."""


class MissingEngineId(Exception):
    """The target has no engine id for this det: (run the det map generator)."""


class BindingError(ValueError):
    """A logsource binding in ``mappings/<backend>.yml`` is malformed."""


#: the Sigma logsource keys a binding may match on
LOGSOURCE_KEYS = ("product", "category", "service")
_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,62}\Z")


@dataclass(frozen=True)
class Binding:
    """Where one Sigma logsource lands in an engine: the rules for it chain from ``parent`` (the
    engine's own base for that telemetry, backend-specific) and read ``fields`` (Sigma field ->
    the engine's name for it). A rule whose logsource matches a binding is compiled ONLY with that
    binding's fields: a Sigma field it does not name is refused, never passed through under its
    Sigma name (a field the engine never sets loads clean and never fires)."""

    name: str
    match: dict[str, str]
    parent: dict[str, Any]
    fields: dict[str, str]

    def matches(self, logsource: dict[str, Any]) -> bool:
        have = {k: str(v).lower() for k, v in logsource.items()}
        return all(have.get(k) == v for k, v in self.match.items())


def load_bindings(doc: dict | None) -> tuple[Binding, ...]:
    """The ``logsources:`` list of a backend mapping document (``mappings/<backend>.yml``)."""
    out: list[Binding] = []
    seen: set[str] = set()
    for i, b in enumerate((doc or {}).get("logsources") or []):
        where = f"logsources[{i}]"
        if not isinstance(b, dict) or set(b) - {"name", "match", "parent", "fields"}:
            raise BindingError(f"{where}: a mapping of name, match, parent and fields")
        name = b.get("name")
        if not isinstance(name, str) or not _NAME_RE.match(name) or name in seen:
            raise BindingError(f"{where}: name must be a unique lower-case word")
        seen.add(name)
        match = b.get("match")
        if (
            not isinstance(match, dict)
            or not match
            or set(match) - set(LOGSOURCE_KEYS)
            or not all(isinstance(v, str) and v for v in match.values())
        ):
            raise BindingError(f"{name}: match is a non-empty map of {', '.join(LOGSOURCE_KEYS)}")
        parent = b.get("parent")
        if not isinstance(parent, dict) or len(parent) != 1:
            raise BindingError(f"{name}: parent names exactly one engine base")
        fields = b.get("fields")
        if (
            not isinstance(fields, dict)
            or not fields
            or not all(isinstance(k, str) and isinstance(v, str) and v for k, v in fields.items())
        ):
            raise BindingError(f"{name}: fields is a non-empty map of Sigma field -> engine name")
        out.append(
            Binding(name, {k: v.lower() for k, v in match.items()}, dict(parent), dict(fields))
        )
    return tuple(out)


def select_binding(bindings: tuple[Binding, ...], logsource: dict[str, Any]) -> Binding | None:
    """The most specific binding (most matched keys, then file order) for ``logsource``."""
    hits = [b for b in bindings if b.matches(logsource)]
    return max(hits, key=lambda b: len(b.match)) if hits else None


@dataclass(frozen=True)
class Target:
    name: str
    field_mapping: dict[str, str] = field(default_factory=dict)
    det_map: dict[str, int] = field(default_factory=dict)  # det:<slug> -> engine number
    options: dict[str, str] = field(default_factory=dict)
    #: per-logsource engine bindings; when any are given, a rule must match one to compile
    logsources: tuple[Binding, ...] = ()


@dataclass(frozen=True)
class Artifact:
    det_id: str
    backend: str
    media_type: str
    content: str


class Backend(Protocol):
    name: str

    def compile(self, rule: Rule, target: Target) -> Artifact: ...


@runtime_checkable
class KnownTechniques(Protocol):
    """Optional capability on a backend: it can list the ATT&CK ids its engine knows about.

    ``known_technique_ids()`` returns a (frozen)set of canonical uppercase technique ids. Many
    engines ship their ATT&CK database behind a plain data file, so a backend that implements
    this protocol typically loads a snapshot from ``known_ids_snapshot`` (a path relative to
    the detections root or absolute) and returns its ``technique_ids`` set.
    """

    known_ids_snapshot: Path | str | None

    def known_technique_ids(self) -> frozenset[str]: ...


_REGISTRY: dict[str, Backend] = {}


def register(backend: Backend) -> Backend:
    _REGISTRY[backend.name] = backend
    return backend


def registered() -> dict[str, Backend]:
    """Every registered backend by name (built-ins once :func:`get_backend` has run)."""
    return dict(_REGISTRY)


def get_backend(name: str) -> Backend:
    from . import backends  # noqa: F401  (registers built-ins)

    try:
        return _REGISTRY[name]
    except KeyError:
        raise KeyError(f"unknown backend {name!r}; known: {sorted(_REGISTRY)}") from None
