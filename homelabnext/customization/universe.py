# SPDX-License-Identifier: Apache-2.0
"""What scope selectors, roles and contracts are checked against.

A :class:`Universe` is a read-only snapshot of the deployment's names: registry hosts and
services, capabilities, role defaults, schema ids and ADR slugs. Any member left ``None`` means
"not provided" and the matching checks are skipped rather than guessed.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

__all__ = ["Universe", "discover"]


@dataclass
class Universe:
    registry: dict[str, Any] | None = None
    capabilities: set[str] | None = None  # "cap:<name>"
    roles: dict[str, set[str]] | None = None  # role -> variable names defined in its defaults
    role_templates: dict[str, set[str]] = field(default_factory=dict)
    schema_ids: set[str] | None = None
    adr_slugs: set[str] | None = None
    #: directories core files live in; a customization may never point into them
    core_roots: list[Path] = field(default_factory=list)

    @property
    def hosts(self) -> set[str] | None:
        return None if self.registry is None else set(self.registry.get("hosts", {}))

    @property
    def services(self) -> set[str] | None:
        return None if self.registry is None else set(self.registry.get("services", {}))

    def service_host(self, service: str) -> str | None:
        if self.registry is None:
            return None
        return (self.registry.get("services", {}).get(service) or {}).get("host")

    def capability_hosts(self, cap: str) -> set[str]:
        """Registry hosts of services providing ``cap:<name>`` (empty if unknown)."""
        if self.registry is None:
            return set()
        name = cap.split(":", 1)[1]
        return {
            s["host"]
            for s in self.registry.get("services", {}).values()
            if s.get("capability") == name and "host" in s
        }


def _role_info(roles_dir: Path) -> tuple[dict[str, set[str]], dict[str, set[str]]]:
    roles: dict[str, set[str]] = {}
    templates: dict[str, set[str]] = {}
    for r in sorted(p for p in roles_dir.iterdir() if p.is_dir()):
        d = r / "defaults" / "main.yml"
        doc = yaml.safe_load(d.read_text(encoding="utf-8")) if d.is_file() else None
        roles[r.name] = set(doc) if isinstance(doc, dict) else set()
        t = r / "templates"
        templates[r.name] = {f.name for f in t.iterdir() if f.is_file()} if t.is_dir() else set()
    return roles, templates


def discover(
    root: Path,
    registry: Path | None = None,
    roles_dir: Path | None = None,
    inventory: Path | None = None,
) -> Universe:
    """Build a universe from a repository-shaped tree; every source is optional."""
    root = Path(root)
    u = Universe()
    reg = registry or root / "examples" / "services.yml"
    if reg.is_file():
        u.registry = yaml.safe_load(reg.read_text(encoding="utf-8"))
    caps: set[str] | None = None
    if u.registry:
        caps = {
            f"cap:{s['capability']}"
            for s in u.registry.get("services", {}).values()
            if "capability" in s
        }
    inv = inventory or root / "ansible" / "inventory" / "example" / "hosts.yml"
    if inv.is_file():
        groups = (yaml.safe_load(inv.read_text(encoding="utf-8")) or {}).get("all", {})
        names = {g[4:] for g in groups.get("children", {}) if g.startswith("cap_")}
        caps = (caps or set()) | {f"cap:{n.replace('_', '-')}" for n in names}
    u.capabilities = caps
    rd = roles_dir or root / "ansible" / "roles"
    if rd.is_dir():
        u.roles, u.role_templates = _role_info(rd)
        u.core_roots.append(rd.resolve())
    sd = root / "schemas"
    if sd.is_dir():
        ids = set()
        for p in sd.rglob("*.json"):
            if "_frozen" in p.parts:
                continue
            try:
                doc = json.loads(p.read_text(encoding="utf-8"))
            except ValueError:
                continue
            if isinstance(doc, dict) and "$id" in doc:
                ids.add(doc["$id"])
        u.schema_ids = ids
        u.core_roots.append(sd.resolve())
    ad = root / "docs" / "adr"
    if ad.is_dir():
        u.adr_slugs = {
            p.stem.split("-", 1)[1] for p in ad.glob("[0-9][0-9][0-9][0-9]-*.md") if "-" in p.stem
        }
    return u
