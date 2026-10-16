# SPDX-License-Identifier: Apache-2.0
"""Plan output: a deterministic diff between a previous render and the current one."""

from __future__ import annotations

import difflib
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Plan:
    added: tuple[str, ...]
    removed: tuple[str, ...]
    changed: tuple[str, ...]
    diff: str

    @property
    def empty(self) -> bool:
        return not (self.added or self.removed or self.changed)

    def summary(self) -> str:
        return f"{len(self.added)} to add, {len(self.changed)} to change, {len(self.removed)} to remove"


def plan(old: Mapping[str, str], new: Mapping[str, str]) -> Plan:
    added = tuple(sorted(set(new) - set(old)))
    removed = tuple(sorted(set(old) - set(new)))
    changed = tuple(sorted(k for k in set(old) & set(new) if old[k] != new[k]))
    parts: list[str] = []
    for k in sorted(set(old) | set(new)):
        a = old.get(k, "")
        b = new.get(k, "")
        if a == b:
            continue
        parts += difflib.unified_diff(
            a.splitlines(keepends=True),
            b.splitlines(keepends=True),
            fromfile=f"a/{k}" if k in old else "/dev/null",
            tofile=f"b/{k}" if k in new else "/dev/null",
        )
        if parts and not parts[-1].endswith("\n"):
            parts.append("\n")
    return Plan(added, removed, changed, "".join(parts))


def read_tree(directory: str | Path) -> dict[str, str]:
    d = Path(directory)
    if not d.is_dir():
        return {}
    return {
        p.relative_to(d).as_posix(): p.read_text(encoding="utf-8")
        for p in sorted(d.rglob("*"))
        if p.is_file()
    }


def write_tree(directory: str | Path, files: Mapping[str, str]) -> None:
    d = Path(directory)
    for rel, text in files.items():
        dest = d / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(text, encoding="utf-8")
