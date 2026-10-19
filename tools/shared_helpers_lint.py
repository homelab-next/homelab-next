#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Gate (checklist M-03): helpers are shared, not copied.

Three seams have one shared library each, with a fake (ADR-0003). Code outside the library that
re-implements the seam is a private helper: it drifts, it has no fake, and its failure modes are
not the ones the library was tested for. This lint walks the AST of every runtime Python file and
reports:

  notify  a private notification sender: ``smtplib`` anywhere, or a function (or module body)
          that both performs an HTTP send and names ntfy (a non-docstring string mentioning
          ``ntfy``, or the ntfy header keys ``Title``/``Priority``/``Tags``)
          -> use ``homelabnext.notify`` (``Notifier`` + a ``Sender``)
  state   an ad-hoc JSON state file: a function that serialises JSON to a file (``json.dump``,
          or ``write_text``/``write`` of ``json.dumps(...)``) and either replaces it atomically
          (``os.replace``/``os.rename``) or names it state (the written or opened path is an
          identifier or string such as ``state``, ``state_file``, ``run.state.json``)
          -> use ``homelabnext.state`` (``StateStore`` / ``KeyedState``)
  lake    a raw lake-query client: importing ``trino``, ``duckdb``, ``pyiceberg`` or ``sqlite3``,
          or a string naming the Trino REST endpoint ``/v1/statement``
          -> use ``homelabnext.lake`` (``LakeClient`` and its adapters)

The shared libraries own their seam (``homelabnext/notify``, ``homelabnext/state``,
``homelabnext/lake``). Test code is out of scope (tests exercise the seams on purpose). Every other
exemption is an entry in ``tools/shared_helpers.allow.yml`` naming the path, the rule and the
reason, so the list is reviewed in one place; an entry that no longer matches anything is
reported as stale.

Usage: python tools/shared_helpers_lint.py [ROOT] [--allowlist FILE] [--json]
Exit: 0 clean, 1 private helpers (or a stale allowlist entry), 2 usage / bad allowlist.
"""

from __future__ import annotations

import argparse
import ast
import fnmatch
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path

import yaml

DEFAULT_ALLOWLIST = "tools/shared_helpers.allow.yml"
RULES = {
    "notify": "private notification sender; use homelabnext.notify (Notifier + Sender)",
    "state": "ad-hoc JSON state file; use homelabnext.state (StateStore / KeyedState)",
    "lake": "raw lake-query client; use homelabnext.lake (LakeClient and its adapters)",
}
OWNERS = {
    "notify": ("homelabnext/notify/",),
    "state": ("homelabnext/state/",),
    "lake": ("homelabnext/lake/",),
}
SKIP_DIRS = {
    ".git",
    "node_modules",
    "__pycache__",
    ".venv",
    "venv",
    "build",
    "dist",
    ".pytest_cache",
    ".ruff_cache",
}

HTTP_SEND = {
    "urllib.request.urlopen",
    "urllib.request.Request",
    "http.client.HTTPConnection",
    "http.client.HTTPSConnection",
    "requests.post",
    "requests.put",
    "requests.request",
    "requests.Session",
    "httpx.post",
    "httpx.put",
    "httpx.request",
    "httpx.Client",
}
NTFY_HEADERS = {"title", "priority", "tags", "x-title", "x-priority", "x-tags"}
LAKE_MODULES = ("trino", "duckdb", "pyiceberg", "sqlite3")
ATOMIC = {"os.replace", "os.rename"}
STATE_WORD = re.compile(r"(?i)(?:^|[^a-z])state(?:s|_file|_path|_dir)?(?:[^a-z]|$)")


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    rule: str
    detail: str

    def as_dict(self) -> dict:
        return {"path": self.path, "line": self.line, "rule": self.rule, "detail": self.detail}


class AllowlistError(ValueError):
    pass


def _dotted(node: ast.AST, aliases: dict[str, str]) -> str:
    """``a.b.c`` for a Name/Attribute chain, with the head resolved through import aliases."""
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return ""
    parts.append(aliases.get(node.id, node.id))
    return ".".join(reversed(parts))


def _aliases(tree: ast.AST) -> dict[str, str]:
    out: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                out[a.asname or a.name.split(".")[0]] = a.name if a.asname else a.name.split(".")[0]
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            for a in node.names:
                out[a.asname or a.name] = f"{node.module}.{a.name}"
    return out


def _docstrings(tree: ast.AST) -> set[int]:
    ids: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Module | ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            body = node.body
            if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
                ids.add(id(body[0].value))
    return ids


def _scopes(tree: ast.Module):
    """The module body (minus nested defs) and every function, each as (node, inner nodes)."""

    def inner(root: ast.AST):
        stack = list(ast.iter_child_nodes(root))
        while stack:
            n = stack.pop()
            yield n
            if not isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda):
                stack.extend(ast.iter_child_nodes(n))

    yield tree, list(inner(tree))
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            yield node, list(inner(node))


def _is_json_write(call: ast.Call, aliases: dict[str, str]) -> bool:
    name = _dotted(call.func, aliases)
    if name == "json.dump":
        return True
    if isinstance(call.func, ast.Attribute) and call.func.attr in ("write_text", "write"):
        for arg in call.args:
            for sub in ast.walk(arg):
                if isinstance(sub, ast.Call) and _dotted(sub.func, aliases) == "json.dumps":
                    return True
    return False


def _names_state(node: ast.AST, docs: set[int]) -> bool:
    for n in ast.walk(node):
        text = (
            n.id
            if isinstance(n, ast.Name)
            else n.attr
            if isinstance(n, ast.Attribute)
            else n.value
            if isinstance(n, ast.Constant) and isinstance(n.value, str) and id(n) not in docs
            else None
        )
        if text and STATE_WORD.search(text):
            return True
    return False


def lint_source(source: str, rel: str = "<string>") -> list[Finding]:
    tree = ast.parse(source, filename=rel)
    aliases = _aliases(tree)
    docs = _docstrings(tree)
    found: list[Finding] = []

    for node in ast.walk(tree):
        mods: list[str] = []
        if isinstance(node, ast.Import):
            mods = [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            mods = [node.module]
        for m in mods:
            top = m.split(".")[0]
            if top == "smtplib":
                found.append(Finding(rel, node.lineno, "notify", "imports smtplib"))
            if top in LAKE_MODULES:
                found.append(Finding(rel, node.lineno, "lake", f"imports {top}"))
        if (
            isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and id(node) not in docs
            and "/v1/statement" in node.value
        ):
            found.append(Finding(rel, node.lineno, "lake", "names the Trino REST endpoint"))

    for scope, nodes in _scopes(tree):
        calls = [n for n in nodes if isinstance(n, ast.Call)]
        sends = [c for c in calls if _dotted(c.func, aliases) in HTTP_SEND]
        ntfy = any(
            isinstance(n, ast.Constant)
            and isinstance(n.value, str)
            and id(n) not in docs
            and "ntfy" in n.value.lower()
            for n in nodes
        ) or any(
            isinstance(n, ast.Dict)
            and any(
                isinstance(k, ast.Constant)
                and isinstance(k.value, str)
                and k.value.lower() in NTFY_HEADERS
                for k in n.keys
            )
            for n in nodes
        )
        if sends and ntfy:
            where = getattr(scope, "name", "module body")
            found.append(
                Finding(rel, sends[0].lineno, "notify", f"{where}: HTTP send to an ntfy target")
            )

        if scope is tree:
            continue  # state files are written by functions; module-level writes are scripts
        writes = [c for c in calls if _is_json_write(c, aliases)]
        if not writes:
            continue
        atomic = any(_dotted(c.func, aliases) in ATOMIC for c in calls)
        # "names a state file": the write's target, or a file the function opens, says state
        targets: list[ast.AST] = []
        for c in writes:
            if isinstance(c.func, ast.Attribute) and c.func.attr in ("write_text", "write"):
                targets.append(c.func.value)
            else:
                targets.extend(c.args[1:])
        targets += [
            a
            for c in calls
            if _dotted(c.func, aliases) in ("open", "io.open", "pathlib.Path", "os.open")
            for a in c.args
        ]
        named = any(_names_state(t, docs) for t in targets)
        if atomic or named:
            why = "atomic replace" if atomic else "names a state file"
            found.append(
                Finding(rel, writes[0].lineno, "state", f"{scope.name}: JSON file write + {why}")
            )
    return sorted(set(found), key=lambda f: (f.line, f.rule, f.detail))


def load_allowlist(path: Path | None) -> list[tuple[str, str, str]]:
    """``[(path glob, rule, reason)]``; every entry needs all three."""
    if path is None or not path.is_file():
        return []
    doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    entries = doc.get("allow", [])
    if not isinstance(entries, list):
        raise AllowlistError(f"{path}: 'allow' must be a list")
    out = []
    for i, e in enumerate(entries):
        if not isinstance(e, dict) or not str(e.get("path", "")).strip():
            raise AllowlistError(f"{path}: entry {i} needs a 'path' glob")
        if e.get("rule") not in RULES:
            raise AllowlistError(f"{path}: entry {i} ({e['path']}) needs a rule from {list(RULES)}")
        if not str(e.get("reason", "")).strip():
            raise AllowlistError(f"{path}: entry {i} ({e['path']}) has no 'reason'")
        out.append((str(e["path"]), e["rule"], str(e["reason"]).strip()))
    return out


def _in_scope(rel: str) -> bool:
    parts = rel.split("/")
    name = parts[-1]
    if any(p in SKIP_DIRS or p.endswith(".egg-info") for p in parts):
        return False
    if parts[0] == "tests" or "tests" in parts[:-1]:
        return False  # test code exercises the seams on purpose
    return not (name.startswith("test_") or name == "conftest.py")


def iter_python(root: Path):
    for p in sorted(root.rglob("*.py")):
        rel = p.relative_to(root).as_posix()
        if p.is_file() and not p.is_symlink() and _in_scope(rel):
            yield p, rel


def scan(root: Path, allow: list[tuple[str, str, str]]) -> tuple[list[Finding], list[str], int]:
    """(unallowed findings, stale allowlist entries, files scanned)."""
    findings: list[Finding] = []
    used: set[int] = set()
    n = 0
    for p, rel in iter_python(root):
        n += 1
        try:
            found = lint_source(p.read_text(encoding="utf-8"), rel)
        except (SyntaxError, UnicodeDecodeError) as exc:
            findings.append(Finding(rel, 0, "parse", f"cannot parse: {exc.__class__.__name__}"))
            continue
        for f in found:
            if rel.startswith(OWNERS[f.rule]):
                continue
            hit = [
                i
                for i, (g, rule, _) in enumerate(allow)
                if rule == f.rule and fnmatch.fnmatchcase(rel, g)
            ]
            if hit:
                used.update(hit)
                continue
            findings.append(f)
    stale = [f"{g} ({rule})" for i, (g, rule, _) in enumerate(allow) if i not in used]
    return findings, stale, n


def main(argv: list[str] | None = None, out=None, err=None) -> int:
    out = out or sys.stdout
    err = err or sys.stderr
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    ap.add_argument("root", nargs="?", default=".")
    ap.add_argument("--allowlist", help=f"default: <root>/{DEFAULT_ALLOWLIST}")
    ap.add_argument("--json", action="store_true")
    try:
        args = ap.parse_args(argv)
    except SystemExit as exc:
        return 2 if exc.code else 0
    root = Path(args.root).resolve()
    al = Path(args.allowlist) if args.allowlist else root / DEFAULT_ALLOWLIST
    if args.allowlist and not al.is_file():
        print(f"shared_helpers_lint: allowlist {al} not found", file=err)
        return 2
    try:
        allow = load_allowlist(al)
    except (AllowlistError, yaml.YAMLError) as exc:
        print(f"shared_helpers_lint: bad allowlist: {exc}", file=err)
        return 2
    findings, stale, n = scan(root, allow)
    if args.json:
        doc = {"scanned_files": n, "findings": [f.as_dict() for f in findings], "stale": stale}
        print(json.dumps(doc, indent=2), file=out)
    else:
        for f in findings:
            print(f"{f.path}:{f.line}: [{f.rule}] {f.detail}: {RULES.get(f.rule, '')}", file=err)
        for s in stale:
            print(f"shared_helpers_lint: stale allowlist entry {s}: matches nothing", file=err)
        print(
            f"shared_helpers_lint: {len(findings)} private helper(s), {len(stale)} stale "
            f"allowlist entr{'y' if len(stale) == 1 else 'ies'}, {n} files scanned",
            file=out,
        )
    return 1 if findings or stale else 0


if __name__ == "__main__":
    raise SystemExit(main())
