# SPDX-License-Identifier: Apache-2.0
"""What counts as a script, and the catalog built from their headers (checklist M-01).

A **script** is a file that is executed as a program rather than imported.  In a tree that means:

* every ``*.py``, ``*.sh`` or ``*.bash`` file, every ``*.py.j2``/``*.sh.j2`` template (a script a
  role or profile installs), and every file starting with a ``#!`` line, **except**
* the classes in :data:`EXCLUDED`, each with the reason it is not a script; and
* **plus** any file, in any class, that carries a header: a fake under ``conformance/`` that a
  compose service runs is a script there, so it gets a header (``hnx scripts reality`` reports a
  run file that has none).

The tracked files are ``git ls-files`` when the root is a git checkout, else every file below it
(skipping :data:`SKIP_DIRS`).

The catalog is ``docs/scripts/catalog.json`` plus ``docs/scripts/catalog.md``, both generated from
the headers and committed; ``hnx scripts catalog --check`` fails when a script has no valid
header, two scripts share an id, or either file differs from what the headers produce now.
"""

from __future__ import annotations

import json
import pathlib
import subprocess
from dataclasses import dataclass, field
from typing import Any

from .header import HeaderError, find_header, validate

__all__ = [
    "CATALOG_JSON",
    "CATALOG_MD",
    "CATALOG_SCHEMA",
    "EXCLUDED",
    "Catalog",
    "build",
    "check_current",
    "is_candidate",
    "render_json",
    "render_md",
    "tracked_files",
    "write",
]

CATALOG_JSON = "docs/scripts/catalog.json"
CATALOG_MD = "docs/scripts/catalog.md"
CATALOG_SCHEMA = "homelabnext.scripts.catalog/1"
SCRIPT_SUFFIXES = (".py", ".sh", ".bash", ".py.j2", ".sh.j2")
SKIP_DIRS = {".git", "build", "dist", "node_modules", "__pycache__", ".venv", "venv", ".tox"}

#: (path prefix, or file name when it has no slash) -> why files there are not scripts
EXCLUDED: dict[str, str] = {
    "homelabnext/": "package modules: run through `hnx` or `python -m`, never as files",
    "tests/": "test code: pytest imports it",
    "tools/tests/": "test code: pytest imports it",
    "conformance/": "conformance suites, protocols and fakes that the suites import",
    "ansible/plugins/": "Ansible plugins: Ansible loads them, nothing executes them",
    "workflows/stackstorm/": "rendered StackStorm action shims: its python runner imports them "
    "(`hnx workflows st2 render`)",
    "examples/codemode/": "generated Code Mode outputs (`hnx codemode gen`): a profile's runtime "
    "prelude is source the executor runs inside a program's sandbox, never a file run",
    "conftest.py": "pytest configuration",
    "setup.py": "the build backend's hook, run by setuptools",
}
#: never scanned for headers either (test code builds headers in strings)
_NO_HEADER_SCAN = ("tests/", "tools/tests/")


def tracked_files(root: pathlib.Path) -> list[str]:
    """Repository-relative posix paths of the files that make up the tree."""
    root = pathlib.Path(root)
    try:
        p = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-z"],
            capture_output=True,
            check=True,
        )
        top = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "--show-toplevel"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        if pathlib.Path(top).resolve() == root.resolve():
            return sorted(f for f in p.stdout.decode().split("\0") if f)
    except (OSError, subprocess.CalledProcessError):
        pass
    out = []
    for f in root.rglob("*"):
        rel = f.relative_to(root)
        if f.is_file() and not SKIP_DIRS.intersection(rel.parts):
            out.append(rel.as_posix())
    return sorted(out)


def _excluded(rel: str) -> str | None:
    for key, why in EXCLUDED.items():
        if (key.endswith("/") and rel.startswith(key)) or (
            "/" not in key and rel.split("/")[-1] == key
        ):
            return why
    return None


def _head(path: pathlib.Path, n: int = 4096) -> str:
    try:
        with path.open("rb") as fh:
            return fh.read(n).decode("utf-8", errors="replace")
    except OSError:
        return ""


def is_candidate(root: pathlib.Path, rel: str) -> bool:
    """True when ``rel`` is a script by the rule above (before headers pull others in)."""
    if _excluded(rel):
        return False
    return rel.endswith(SCRIPT_SUFFIXES) or _head(pathlib.Path(root) / rel, 2) == "#!"


@dataclass
class Catalog:
    entries: list[dict[str, Any]] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)

    def by_id(self) -> dict[str, dict[str, Any]]:
        return {e["id"]: e for e in self.entries}

    def by_path(self) -> dict[str, dict[str, Any]]:
        return {e["path"]: e for e in self.entries}


def _language(rel: str, text: str) -> str:
    first = text.split("\n", 1)[0]
    if rel.endswith((".py", ".py.j2")) or "python" in first:
        return "python"
    return "shell"


def build(root: pathlib.Path, files: list[str] | None = None) -> Catalog:
    """Read every candidate's header (and every other header) into a catalog."""
    root = pathlib.Path(root)
    files = tracked_files(root) if files is None else files
    cat = Catalog()
    seen: dict[str, str] = {}
    for rel in files:
        candidate = is_candidate(root, rel)
        if not candidate and (rel.startswith(_NO_HEADER_SCAN) or not rel.endswith(SCRIPT_SUFFIXES)):
            continue
        text = _head(root / rel, 16384)
        try:
            head = find_header(text)
        except HeaderError as exc:
            cat.problems.append(f"{rel}: {exc}")
            continue
        if head is None:
            if candidate:
                cat.problems.append(f"{rel}: no '# hnx-script:' header (docs/scripts.md)")
            continue
        errs = validate(head)
        if errs:
            cat.problems += [f"{rel}: header {e}" for e in errs]
            continue
        if head["id"] in seen:
            cat.problems.append(
                f"{rel}: duplicate script id {head['id']!r} (also {seen[head['id']]})"
            )
            continue
        seen[head["id"]] = rel
        entry = {"path": rel, "language": _language(rel, text), **head}
        entry.setdefault("status", "active")
        cat.entries.append(entry)
    cat.entries.sort(key=lambda e: e["id"])
    return cat


def render_json(cat: Catalog) -> str:
    doc = {"schema": CATALOG_SCHEMA, "scripts": cat.entries}
    return json.dumps(doc, indent=2, sort_keys=True) + "\n"


def _cell(value: Any) -> str:
    if isinstance(value, list):
        value = "; ".join(str(v) for v in value)
    return str(value).replace("|", "\\|").replace("\n", " ")


def render_md(cat: Catalog) -> str:
    kinds: dict[str, int] = {}
    for e in cat.entries:
        kinds[e["kind"]] = kinds.get(e["kind"], 0) + 1
    lines = [
        "<!-- Generated by `hnx scripts catalog` from the script headers. Do not edit. -->",
        "",
        "# Script catalog",
        "",
        "Every script in the tree, read from its `# hnx-script:` header. What counts as a script,",
        "the header fields and the checks that keep this page honest: [docs/scripts.md](../scripts.md).",
        "",
        f"{len(cat.entries)} scripts: "
        + ", ".join(f"{n} {k}" for k, n in sorted(kinds.items()))
        + ".",
        "",
        "| id | path | kind | owner | purpose | triggers | invariant | exit codes |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for e in cat.entries:
        kind = (
            e["kind"] if e.get("status", "active") == "active" else f"{e['kind']} ({e['status']})"
        )
        exits = "; ".join(
            f"{k} {v}" for k, v in sorted(e["exit"].items(), key=lambda kv: int(kv[0]))
        )
        lines.append(
            "| "
            + " | ".join(
                [
                    f"`{e['id']}`",
                    f"[`{e['path']}`](../../{e['path']})",
                    kind,
                    _cell(e["owner"]),
                    _cell(e["purpose"]),
                    _cell([f"`{t}`" for t in e["trigger"]]),
                    _cell(e.get("invariant", [])) or "-",
                    _cell(exits),
                ]
            )
            + " |"
        )
    return "\n".join(lines) + "\n"


def write(root: pathlib.Path, cat: Catalog) -> list[pathlib.Path]:
    out = []
    for rel, text in ((CATALOG_JSON, render_json(cat)), (CATALOG_MD, render_md(cat))):
        p = pathlib.Path(root) / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
        out.append(p)
    return out


def check_current(root: pathlib.Path, cat: Catalog) -> list[str]:
    """Problems that make the committed catalog stale (empty = current)."""
    out = []
    for rel, want in ((CATALOG_JSON, render_json(cat)), (CATALOG_MD, render_md(cat))):
        p = pathlib.Path(root) / rel
        if not p.is_file():
            out.append(f"{rel}: missing; run `hnx scripts catalog` and commit it")
        elif p.read_text(encoding="utf-8") != want:
            out.append(f"{rel}: stale; run `hnx scripts catalog` and commit the result")
    return out
