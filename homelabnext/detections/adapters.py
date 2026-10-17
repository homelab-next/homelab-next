# SPDX-License-Identifier: Apache-2.0
"""Engine adapter interface: ``compile(rule, target) -> Artifact``.

An adapter turns a Sigma-subset rule into something a specific engine can
load. Adapters are pure functions of (rule, target): no network, no deploy.

Optionally, an adapter also advertises what ATT&CK ids its target engine KNOWS, so a rule can
be checked against the engine's bundled ATT&CK database before it ships. Advertising is through
either (a) a ``known_technique_ids()`` method returning a set/frozenset of ids, OR (b) a
``known_ids_snapshot`` path on the backend pointing at a snapshot file for ``attack.load_snapshot``.
The ``KnownTechniques`` protocol is informational: nothing enforces that a backend provides
it, and the validator falls back to the loaded-file path when the method is absent.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol, runtime_checkable

from .sigma import Rule


class UnsupportedConstruct(Exception):
    """The rule cannot be expressed in this engine; author native rules instead."""


class MissingEngineId(Exception):
    """The target has no engine id for this det: (run the det map generator)."""


@dataclass(frozen=True)
class Target:
    name: str
    field_mapping: dict[str, str] = field(default_factory=dict)
    det_map: dict[str, int] = field(default_factory=dict)  # det:<slug> -> engine number
    options: dict[str, str] = field(default_factory=dict)


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


def get_backend(name: str) -> Backend:
    from . import backends  # noqa: F401  (registers built-ins)

    try:
        return _REGISTRY[name]
    except KeyError:
        raise KeyError(f"unknown backend {name!r}; known: {sorted(_REGISTRY)}") from None
