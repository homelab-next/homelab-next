#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Gate (checklist F-07): no client turns TLS certificate verification off.

Role-lint RL013 covers Ansible tasks and role variables. This covers the rest of the tree:

Python (AST)
  verify-false        a call with ``verify=False`` (requests, httpx, ...) or ``verify=0``
  unverified-context  ``ssl._create_unverified_context`` (called, referenced or assigned as the
                      default ``ssl._create_default_https_context``)
  cert-none           ``ssl.CERT_NONE`` anywhere (``verify_mode = CERT_NONE``, ``cert_reqs=``)
  no-hostname-check   ``<ctx>.check_hostname = False`` or ``check_hostname=False``
  warnings-silenced   ``urllib3.disable_warnings(...)`` (only ever done to hide unverified TLS)
Config (YAML and JSON, every document, every nesting level)
  config-verify-off   a key that turns verification off: ``validate_certs``/``verify_ssl``/
                      ``ssl_verify``/``sslverify``/``tls_verify``/``verify_certs``/``verify``/
                      ``check_hostname`` set to false, or ``insecure_skip_verify``/
                      ``insecure``/``skip_tls_verify``/``tls_skip_verify``/
                      ``insecure_skip_tls_verify`` set to true (booleans and their string forms;
                      a templated value such as ``"{{ x }}"`` is not judged here)

Out of scope: test code and fixtures (``tests/``, ``*/tests/``, ``test_*.py``, ``conftest.py``),
which plant these on purpose. A reviewed exception is either a path glob in
``tools/tls_verify.allow.yml`` with a ``reason``, or an inline ``tls-verify: allow <reason>``
comment on the offending line.

Usage: python tools/tls_verify_lint.py [ROOT] [--allowlist FILE] [--json]
Exit: 0 clean, 1 verification disabled somewhere, 2 usage / bad allowlist.
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

DEFAULT_ALLOWLIST = "tools/tls_verify.allow.yml"
INLINE_ALLOW = re.compile(r"tls-verify:\s*allow\s+\S")
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
OFF_WHEN_FALSE = {
    "validate_certs",
    "verify_ssl",
    "ssl_verify",
    "sslverify",
    "tls_verify",
    "verify_certs",
    "verify_tls",
    "verify",
    "check_hostname",
}
OFF_WHEN_TRUE = {
    "insecure_skip_verify",
    "insecure",
    "skip_tls_verify",
    "tls_skip_verify",
    "insecure_skip_tls_verify",
}
FALSE = {"false", "no", "off", "0"}
TRUE = {"true", "yes", "on", "1"}


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


def _dotted(node: ast.AST) -> str:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return ""


def _falsy(node: ast.AST | None) -> bool:
    return isinstance(node, ast.Constant) and node.value in (False, 0) and node.value is not None


def lint_python(source: str, rel: str = "<string>") -> list[Finding]:
    tree = ast.parse(source, filename=rel)
    lines = source.splitlines()
    imported: dict[str, str] = {}  # local name -> "ssl.X" for from-imports
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.ImportFrom)
            and node.module in ("ssl", "urllib3")
            and not node.level
        ):
            for a in node.names:
                imported[a.asname or a.name] = f"{node.module}.{a.name}"
    found: list[Finding] = []

    def add(node: ast.AST, rule: str, detail: str) -> None:
        n = getattr(node, "lineno", 0)
        if 0 < n <= len(lines) and INLINE_ALLOW.search(lines[n - 1]):
            return
        found.append(Finding(rel, n, rule, detail))

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            for kw in node.keywords:
                if kw.arg == "verify" and _falsy(kw.value):
                    add(node, "verify-false", "verify=False")
                if kw.arg == "check_hostname" and _falsy(kw.value):
                    add(node, "no-hostname-check", "check_hostname=False")
            name = _dotted(node.func)
            name = imported.get(name, name)
            if name.endswith("disable_warnings") and name.split(".")[0] in ("urllib3", "requests"):
                add(node, "warnings-silenced", f"{name}()")
        elif isinstance(node, ast.Attribute | ast.Name):
            name = _dotted(node)
            name = imported.get(name, name)
            if name.endswith("_create_unverified_context") or name.endswith(
                "ssl._create_default_https_context"
            ):
                add(node, "unverified-context", name)
            elif name.endswith("CERT_NONE") and name.split(".")[0] in ("ssl", "CERT_NONE"):
                add(node, "cert-none", "ssl.CERT_NONE")
        elif isinstance(node, ast.Assign):
            for t in node.targets:
                if (
                    isinstance(t, ast.Attribute)
                    and t.attr == "check_hostname"
                    and _falsy(node.value)
                ):
                    add(node, "no-hostname-check", f"{_dotted(t) or 'check_hostname'} = False")
    # an attribute chain is visited once per level; report each line/rule/detail once
    return sorted(set(found), key=lambda f: (f.line, f.rule))


class _Loader(getattr(yaml, "CSafeLoader", yaml.SafeLoader)):  # C parser when available
    pass


_Loader.add_multi_constructor("!", lambda loader, suffix, node: None)


def _scalar_state(node: yaml.Node) -> bool | None:
    """True/False for a boolean-ish scalar, None for anything else (templated, numbers...)."""
    if not isinstance(node, yaml.ScalarNode):
        return None
    v = str(node.value).strip().strip("'\"").lower()
    if v in TRUE:
        return True
    if v in FALSE:
        return False
    return None


def lint_config(text: str, rel: str = "<string>") -> list[Finding]:
    lines = text.splitlines()
    found: list[Finding] = []

    def walk(node: yaml.Node) -> None:
        if isinstance(node, yaml.MappingNode):
            for k, v in node.value:
                if isinstance(k, yaml.ScalarNode):
                    key = str(k.value).strip().lower().replace("-", "_")
                    state = _scalar_state(v)
                    off = (key in OFF_WHEN_FALSE and state is False) or (
                        key in OFF_WHEN_TRUE and state is True
                    )
                    n = k.start_mark.line + 1
                    if off and not (n <= len(lines) and INLINE_ALLOW.search(lines[n - 1])):
                        found.append(Finding(rel, n, "config-verify-off", f"{k.value}: {v.value}"))
                walk(v)
        elif isinstance(node, yaml.SequenceNode):
            for item in node.value:
                walk(item)

    loader = _Loader(text)
    try:
        while loader.check_node():
            walk(loader.get_node())
    finally:
        loader.dispose()
    return found


def load_allowlist(path: Path | None) -> list[tuple[str, str]]:
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
        if not str(e.get("reason", "")).strip():
            raise AllowlistError(f"{path}: entry {i} ({e['path']}) has no 'reason'")
        out.append((str(e["path"]), str(e["reason"]).strip()))
    return out


def _in_scope(rel: str) -> bool:
    parts = rel.split("/")
    if any(p in SKIP_DIRS or p.endswith(".egg-info") for p in parts):
        return False
    if parts[0] == "tests" or "tests" in parts[:-1]:
        return False
    return not (parts[-1].startswith("test_") or parts[-1] == "conftest.py")


def scan(root: Path, allow: list[tuple[str, str]]) -> tuple[list[Finding], int]:
    findings: list[Finding] = []
    n = 0
    for p in sorted(root.rglob("*")):
        rel = p.relative_to(root).as_posix()
        if not p.is_file() or p.is_symlink() or not _in_scope(rel):
            continue
        if p.suffix not in (".py", ".yml", ".yaml", ".json"):
            continue
        if any(fnmatch.fnmatchcase(rel, g) for g, _ in allow):
            continue
        n += 1
        try:
            text = p.read_text(encoding="utf-8")
            if p.suffix == ".py":
                findings += lint_python(text, rel)
            else:
                findings += lint_config(text, rel)
        except (SyntaxError, UnicodeDecodeError, yaml.YAMLError) as exc:
            findings.append(Finding(rel, 0, "parse", f"cannot parse: {exc.__class__.__name__}"))
    return findings, n


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
        print(f"tls_verify_lint: allowlist {al} not found", file=err)
        return 2
    try:
        allow = load_allowlist(al)
    except (AllowlistError, yaml.YAMLError) as exc:
        print(f"tls_verify_lint: bad allowlist: {exc}", file=err)
        return 2
    findings, n = scan(root, allow)
    if args.json:
        doc = {"scanned_files": n, "findings": [f.as_dict() for f in findings]}
        print(json.dumps(doc, indent=2), file=out)
    else:
        for f in findings:
            print(
                f"{f.path}:{f.line}: [{f.rule}] {f.detail}: certificate verification is off; "
                "trust the internal CA instead (or allowlist with a reason)",
                file=err,
            )
        print(
            f"tls_verify_lint: {len(findings)} client(s) with verification off, {n} files scanned",
            file=out,
        )
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
