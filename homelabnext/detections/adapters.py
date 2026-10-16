# SPDX-License-Identifier: Apache-2.0
"""Engine adapter interface: ``compile(rule, target) -> Artifact``.

An adapter turns a Sigma-subset rule into something a specific engine can
load. Adapters are pure functions of (rule, target): no network, no deploy.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

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
