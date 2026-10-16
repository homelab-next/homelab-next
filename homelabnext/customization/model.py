# SPDX-License-Identifier: Apache-2.0
"""Customization data model and the table of sanctioned extension points.

A customization is a plain mapping validated by ``schemas/platform/customization.schema.json``.
This module holds the few derived notions everything else shares: the extension point(s) a
customization touches, scope overlap, deterministic ordering and the expiry arithmetic.
Nothing here touches the filesystem.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, timedelta
from pathlib import Path
from typing import Any

__all__ = [
    "ENTRY_POINTS",
    "EXPIRY_WARN_DAYS",
    "KIND_ORDER",
    "MAX_HORIZON_DAYS",
    "Customization",
    "Finding",
    "days_left",
    "extension_points",
    "parse_date",
    "scopes_overlap",
    "sort_key",
]

#: the entry points of docs/role-interface.md; the only places a hook may attach
ENTRY_POINTS = ("main", "health", "readiness", "backup", "restore", "upgrade", "export")

#: deterministic application order: registry first (everything else reads it), then variables,
#: template overlays, role hooks and finally opt-in host profiles
KIND_ORDER = ("registry-patch", "override", "patch-overlay", "hook", "profile")

#: a review date further out than this from ``created`` is "never expires" in disguise
MAX_HORIZON_DAYS = 366
EXPIRY_WARN_DAYS = 14


@dataclass
class Customization:
    """One loaded customization file."""

    doc: dict[str, Any]
    path: Path
    origin: str  # "public" (shipped profile) or "local" (private overlay)
    schema_errors: list[str] = field(default_factory=list)

    @property
    def base(self) -> Path:
        return self.path.parent

    @property
    def id(self) -> str:
        return str(self.doc.get("id", f"<unnamed:{self.path.name}>"))

    @property
    def kind(self) -> str:
        return str(self.doc.get("kind", ""))

    @property
    def action(self) -> dict[str, Any]:
        a = self.doc.get("action")
        return a if isinstance(a, dict) else {}

    @property
    def scope(self) -> dict[str, Any]:
        s = self.doc.get("scope")
        return s if isinstance(s, dict) else {}

    @property
    def optional(self) -> bool:
        return bool(self.doc.get("optional", False))


@dataclass(frozen=True)
class Finding:
    code: str
    severity: str  # "error" | "warning"
    customization: str
    message: str

    def __str__(self) -> str:
        return f"{self.severity.upper():7s} {self.code} {self.customization}: {self.message}"

    def as_dict(self) -> dict[str, str]:
        return {
            "code": self.code,
            "severity": self.severity,
            "customization": self.customization,
            "message": self.message,
        }


def parse_date(text: Any) -> date | None:
    try:
        return date.fromisoformat(str(text))
    except ValueError:
        return None


def days_left(c: Customization, today: date) -> int | None:
    rb = parse_date(c.doc.get("review_by"))
    return None if rb is None else (rb - today).days


def extension_points(c: Customization) -> list[str]:
    """The extension point strings this customization claims, sorted.

    ``var:<role>.<name>``, ``hook:<role>.<entry>.<phase>``, ``template:<role>/<name>``,
    ``registry:<service>.<field>``, ``profile:<name>``.
    """
    a, k = c.action, c.kind
    if k == "override":
        return sorted(f"var:{a.get('role')}.{v}" for v in (a.get("vars") or {}))
    if k == "hook":
        return [f"hook:{a.get('role')}.{a.get('entry_point')}.{a.get('phase')}"]
    if k == "patch-overlay":
        return [f"template:{a.get('role')}/{a.get('template')}"]
    if k == "registry-patch":
        return sorted(f"registry:{a.get('service')}.{f}" for f in (a.get("set") or {}))
    if k == "profile":
        return [f"profile:{a.get('profile')}"]
    return []


def scopes_overlap(a_hosts: set[str] | None, b_hosts: set[str] | None) -> bool:
    """Two scopes overlap if their resolved host sets intersect; a scope with no resolved host
    set (it names roles or capabilities the deployment has not expanded) overlaps everything,
    because the safe reading of "I cannot tell" is "yes"."""
    if not a_hosts or not b_hosts:
        return True
    return bool(a_hosts & b_hosts)


def sort_key(c: Customization) -> tuple[int, str]:
    rank = KIND_ORDER.index(c.kind) if c.kind in KIND_ORDER else len(KIND_ORDER)
    return rank, c.id


def horizon_limit(created: date) -> date:
    return created + timedelta(days=MAX_HORIZON_DAYS)
