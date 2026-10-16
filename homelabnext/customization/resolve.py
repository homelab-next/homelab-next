# SPDX-License-Identifier: Apache-2.0
"""Scope resolution, activation and conflict detection."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from .model import Customization, extension_points, scopes_overlap, sort_key
from .universe import Universe

__all__ = ["Conflict", "active", "detect_conflicts", "resolve_hosts"]


@dataclass(frozen=True)
class Conflict:
    extension_point: str
    ids: tuple[str, ...]

    def __str__(self) -> str:
        return f"{self.extension_point} is claimed by {', '.join(self.ids)}"


def active(items: list[Customization], enabled: dict[str, list[str]]) -> list[Customization]:
    """Everything not optional, plus optional ones a deployment enabled; deterministic order."""
    return sorted((c for c in items if not c.optional or c.id in enabled), key=sort_key)


def resolve_hosts(c: Customization, u: Universe, enabled: dict[str, list[str]]) -> set[str]:
    """Registry hosts a customization applies to. Empty = could not expand (role or capability
    scope with no registry); callers treat empty as "broad"."""
    narrowed = enabled.get(c.id) if c.optional else None
    if narrowed:
        return set(narrowed)
    scope = c.scope
    hosts = set(scope.get("hosts", []))
    for s in scope.get("services", []):
        h = u.service_host(s.split(":", 1)[1])
        if h:
            hosts.add(h)
    for cap in scope.get("capabilities", []):
        hosts |= u.capability_hosts(cap)
    return hosts


def detect_conflicts(
    items: list[Customization], u: Universe, enabled: dict[str, list[str]]
) -> list[Conflict]:
    """Two active customizations touching the same extension point on overlapping scope."""
    by_point: dict[str, list[Customization]] = defaultdict(list)
    for c in items:
        for ep in extension_points(c):
            by_point[ep].append(c)
    out = []
    for ep in sorted(by_point):
        group = by_point[ep]
        clashing: set[str] = set()
        for i, a in enumerate(group):
            for b in group[i + 1 :]:
                if a.id != b.id and scopes_overlap(
                    resolve_hosts(a, u, enabled), resolve_hosts(b, u, enabled)
                ):
                    clashing |= {a.id, b.id}
        if clashing:
            out.append(Conflict(ep, tuple(sorted(clashing))))
    return out
