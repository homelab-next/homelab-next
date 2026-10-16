# SPDX-License-Identifier: Apache-2.0
"""Decommission check: find every remaining reference to a retired service.

Decommissioning is "touch every reference" (ADR-0005 step 8). This scanner is the proof: it walks
a tree, a registry and inventory files and reports each stale alias, registry row, environment
variable, systemd unit and documentation mention. A clean scan is the gate for the swap's
``decommission-check`` step; any finding is a non-zero exit.

Matching is word-bounded (``lake-core`` does not match ``lake-core-2``), case-insensitive for
names and aliases, case-sensitive for environment variables. History that legitimately names the
retired product (changelog, ADRs, swap records) is excluded with allow globs, never silently.
"""

from __future__ import annotations

import fnmatch
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

MAX_BYTES = 1_000_000
SKIP_DIRS = {
    ".git",
    "__pycache__",
    "node_modules",
    ".venv",
    "venv",
    "build",
    "dist",
    ".pytest_cache",
}
DEFAULT_ALLOW = ("*.swap.json", "*.evidence/*")
UNIT_SUFFIXES = (".service", ".timer", ".socket", ".path", ".mount")
DOC_SUFFIXES = (".md", ".rst", ".txt", ".adoc")


@dataclass(frozen=True)
class Retired:
    name: str
    hosts: tuple[str, ...] = ()
    impls: tuple[str, ...] = ()
    aliases: tuple[str, ...] = ()
    env_vars: tuple[str, ...] = ()
    units: tuple[str, ...] = ()
    words: tuple[str, ...] = ()

    def terms(self) -> list[tuple[str, str, bool]]:
        """(kind, term, case_sensitive)."""
        out: list[tuple[str, str, bool]] = []
        out += [("host", t, False) for t in self.hosts]
        out += [("impl", t, False) for t in self.impls]
        out += [("alias", t, False) for t in self.aliases]
        out += [("env-var", t, True) for t in self.env_vars]
        out += [("unit", re.sub(r"\.service$", "", t), False) for t in self.units]
        out += [("word", t, False) for t in self.words]
        return [t for t in out if t[1]]


@dataclass(frozen=True)
class Finding:
    kind: str  # registry-host | registry-impl | registry-env-var | unit-file | systemd-unit | env-var | alias | doc | host | impl | word | reference
    path: str
    line: int
    text: str
    term: str

    def __str__(self) -> str:
        return f"{self.path}:{self.line}: [{self.kind}] {self.term!r}: {self.text.strip()[:120]}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "path": self.path,
            "line": self.line,
            "term": self.term,
            "text": self.text.strip()[:200],
        }


def _pattern(term: str, case_sensitive: bool) -> re.Pattern[str]:
    return re.compile(
        r"(?<![\w.-])" + re.escape(term) + r"(?![\w-])", 0 if case_sensitive else re.IGNORECASE
    )


def _file_kind(path: Path, base_kind: str) -> str:
    n = path.name
    if n.endswith(UNIT_SUFFIXES):
        return "systemd-unit"
    if base_kind in ("env-var", "alias", "host", "impl", "unit"):
        if n.endswith(DOC_SUFFIXES):
            return "doc"
        return {"unit": "systemd-unit"}.get(base_kind, base_kind)
    return "doc" if n.endswith(DOC_SUFFIXES) else "reference"


def _allowed(rel: str, allow: Sequence[str]) -> bool:
    return any(fnmatch.fnmatch(rel, g) or fnmatch.fnmatch(Path(rel).name, g) for g in allow)


def load_allow(path: str | Path) -> list[str]:
    out = []
    for raw in Path(path).read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if line:
            out.append(line)
    return out


def _iter_files(root: Path) -> Iterable[Path]:
    if root.is_file():
        yield root
        return
    for p in sorted(root.rglob("*")):
        if any(part in SKIP_DIRS for part in p.relative_to(root).parts):
            continue
        if p.is_file() and not p.is_symlink():
            yield p


def _scan_file(
    path: Path, rel: str, retired: Retired, base_kind: str | None = None
) -> list[Finding]:
    try:
        if path.stat().st_size > MAX_BYTES:
            return []
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return []
    pats = [(k, t, _pattern(t, cs)) for k, t, cs in retired.terms()]
    found: list[Finding] = []
    for no, line in enumerate(text.splitlines(), 1):
        for kind, term, pat in pats:
            if pat.search(line):
                fk = base_kind or _file_kind(path, kind)
                found.append(Finding(fk, rel, no, line, term))
    return found


def _unit_files(root: Path, retired: Retired, allow: Sequence[str]) -> list[Finding]:
    names = {re.sub(r"\.(service|timer|socket|path|mount)$", "", u) for u in retired.units}
    out = []
    for p in _iter_files(root):
        rel = p.relative_to(root).as_posix() if root.is_dir() else p.name
        if p.name.endswith(UNIT_SUFFIXES) and p.stem in names and not _allowed(rel, allow):
            out.append(Finding("unit-file", rel, 0, p.name, p.stem))
    return out


def registry_findings(
    doc: Mapping[str, Any], retired: Retired, rel: str = "registry"
) -> list[Finding]:
    out: list[Finding] = []
    hosts = {h.lower() for h in retired.hosts}
    impls = {i.lower() for i in retired.impls}
    envs = set(retired.env_vars)
    for h in doc.get("hosts", {}) or {}:
        if h.lower() in hosts:
            out.append(Finding("registry-host", rel, 0, f"hosts.{h}", h))
    for name, s in (doc.get("services", {}) or {}).items():
        if str(s.get("host", "")).lower() in hosts:
            out.append(
                Finding("registry-host", rel, 0, f"services.{name}.host={s['host']}", s["host"])
            )
        if str(s.get("impl", "")).lower() in impls:
            out.append(
                Finding("registry-impl", rel, 0, f"services.{name}.impl={s['impl']}", s["impl"])
            )
        if s.get("env_var") in envs:
            out.append(
                Finding("registry-env-var", rel, 0, f"services.{name}.env_var", s["env_var"])
            )
    return out


def scan(
    roots: Sequence[str | Path],
    retired: Retired,
    *,
    registry: str | Path | None = None,
    inventory: Sequence[str | Path] = (),
    allow: Sequence[str] = (),
) -> list[Finding]:
    """All remaining references to ``retired`` under ``roots`` (+ registry + inventory files)."""
    allow = [*DEFAULT_ALLOW, *allow]
    findings: list[Finding] = []
    for r in roots:
        root = Path(r)
        if not root.exists():
            raise FileNotFoundError(f"scan root {root} does not exist")
        findings += _unit_files(root, retired, allow)
        for p in _iter_files(root):
            rel = p.relative_to(root).as_posix() if root.is_dir() else p.name
            if _allowed(rel, allow):
                continue
            findings += _scan_file(p, rel, retired)
    if registry is not None:
        reg = Path(registry)
        doc = yaml.safe_load(reg.read_text(encoding="utf-8")) or {}
        findings += registry_findings(doc, retired, reg.name)
    for inv in inventory:
        ip = Path(inv)
        findings += _scan_file(ip, ip.name, retired, base_kind="inventory")
    seen: set[tuple] = set()
    uniq = []
    for f in findings:
        k = (f.kind, f.path, f.line, f.term)
        if k not in seen:
            seen.add(k)
            uniq.append(f)
    return uniq


def retired_from_record(doc: Mapping[str, Any]) -> Retired:
    """Derive what is retired from a swap record: the old adapter and the implementation the flip
    replaced. Hosts are *not* derived: a host usually carries other services, so retiring one is
    an explicit decision (``--host``). A name the flip kept is not retired.
    """
    route = doc.get("route", {})
    before, after = route.get("before", {}), route.get("after", {})
    impls = (
        (before["impl"],) if before.get("impl") and before.get("impl") != after.get("impl") else ()
    )
    return Retired(name=doc["from_adapter"], impls=impls)
