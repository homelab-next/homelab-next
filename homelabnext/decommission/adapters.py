# SPDX-License-Identifier: Apache-2.0
"""Adapters: how planes talk to the world.

Every probe reads through one of these, never through ``subprocess`` or a socket, so the whole
audit runs offline against fakes.  The shipped implementations are snapshot-backed (a JSON file
an operator's own exporter writes); a live adapter implements the same small methods.  A method
that cannot answer raises :class:`Unreachable`; a plane with no adapter at all is SKIP.
Adapters are read-only by construction: no method mutates anything, and ``secret_names`` returns
NAMES only, so a value can never reach the audit.
"""

from __future__ import annotations

import json
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from homelabnext.swap.decommission import MAX_BYTES, SKIP_DIRS

from .model import Unreachable


class Tree(Protocol):
    def files(self) -> Iterator[tuple[str, str]]:
        """Yield ``(relative posix path, text)`` for every readable text file."""


class DirTree:
    """Read-only walk of real directories."""

    def __init__(self, *roots: str | Path) -> None:
        self.roots = [Path(r) for r in roots]
        for r in self.roots:
            if not r.exists():
                raise FileNotFoundError(f"scan root {r} does not exist")

    def files(self) -> Iterator[tuple[str, str]]:
        for root in self.roots:
            paths = [root] if root.is_file() else sorted(root.rglob("*"))
            for p in paths:
                rel_parts = p.relative_to(root).parts if root.is_dir() else ()
                if any(part in SKIP_DIRS for part in rel_parts):
                    continue
                if not p.is_file() or p.is_symlink():
                    continue
                try:
                    if p.stat().st_size > MAX_BYTES:
                        continue
                    text = p.read_text(encoding="utf-8")
                except (OSError, UnicodeDecodeError):
                    continue
                yield (p.relative_to(root).as_posix() if root.is_dir() else p.name), text


class MemTree:
    """In-memory tree for tests."""

    def __init__(self, files: Mapping[str, str]) -> None:
        self._files = files  # by reference: tests may edit the tree after wiring

    def files(self) -> Iterator[tuple[str, str]]:
        yield from sorted(self._files.items())


class Hypervisor(Protocol):
    def guest_config(self, vmid: int) -> str | None: ...
    def firewall_files(self, vmid: int) -> list[str]: ...
    def volumes(self, vmid: int) -> list[str]: ...
    def backup_jobs(self) -> list[dict[str, Any]]: ...  # {"id": str, "vmids": [int]}
    def ha_resources(self) -> list[str]: ...  # e.g. "vm:180"


class _Section:
    """Base for snapshot sections: ``{"unreachable": "why"}`` makes every call raise."""

    def __init__(self, data: Mapping[str, Any]) -> None:
        self.data = data

    def _get(self, key: str) -> Any:
        if "unreachable" in self.data:
            raise Unreachable(str(self.data["unreachable"]))
        return self.data.get(key, [])


class SnapshotHypervisor(_Section):
    def guest_config(self, vmid: int) -> str | None:
        cfgs = self._get("guest_configs")
        return cfgs.get(str(vmid)) if isinstance(cfgs, dict) else None

    def firewall_files(self, vmid: int) -> list[str]:
        return [f for f in self._get("firewall_files") if Path(f).stem == str(vmid)]

    def volumes(self, vmid: int) -> list[str]:
        tag = f"vm-{vmid}-"
        return [v for v in self._get("volumes") if tag in v or f"subvol-{vmid}-" in v]

    def backup_jobs(self) -> list[dict[str, Any]]:
        return list(self._get("backup_jobs"))

    def ha_resources(self) -> list[str]:
        return list(self._get("ha"))


class SnapshotList(_Section):
    """A flat list of records or strings under one key."""

    def __init__(self, data: Mapping[str, Any], key: str) -> None:
        super().__init__(data)
        self.key = key

    def entries(self) -> list[Any]:
        return list(self._get(self.key))


@dataclass
class Adapters:
    """Everything a probe may ask the outside world.  ``None`` = not configured = SKIP."""

    tree: Tree | None = None
    hypervisor: Hypervisor | None = None
    siem: SnapshotList | None = None  # agent roster
    monitoring: SnapshotList | None = None  # scrape/probe targets
    secrets: SnapshotList | None = None  # secret NAMES
    dns: SnapshotList | None = None
    proxy: SnapshotList | None = None
    dhcp: SnapshotList | None = None
    claimed: set[str] = field(default_factory=set)  # paths already reported by a dedicated plane

    @classmethod
    def from_snapshot(cls, doc: Mapping[str, Any], tree: Tree | None = None) -> Adapters:
        def lst(sec: str, key: str) -> SnapshotList | None:
            return SnapshotList(doc[sec], key) if sec in doc else None

        return cls(
            tree=tree,
            hypervisor=SnapshotHypervisor(doc["hypervisor"]) if "hypervisor" in doc else None,
            siem=lst("siem", "agents"),
            monitoring=lst("monitoring", "targets"),
            secrets=lst("secrets", "names"),
            dns=lst("dns", "records"),
            proxy=lst("proxy", "routes"),
            dhcp=lst("dhcp", "reservations"),
        )

    @classmethod
    def from_file(cls, path: str | Path, tree: Tree | None = None) -> Adapters:
        return cls.from_snapshot(json.loads(Path(path).read_text("utf-8")), tree)
