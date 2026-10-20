#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# hnx-script:
#   id: run-output-lint
#   kind: check
#   purpose: Fail when a repository script or tool writes scratch files to a literal path outside its run directory or build/.
#   owner: maintainers
#   trigger: [ci:ci/schemas, make:run-output-lint]
#   inputs: every Python script with an hnx-script header and tools/run_output_lint.allow.yml
#   outputs: one line per out-of-run write or stale allowlist entry
#   exit:
#     "0": clean
#     "1": an out-of-run write or a stale allowlist entry
#     "2": usage error or a bad allowlist
"""Gate: scripts write scratch output into their own run directory (or ``build/``), nowhere else.

Two runs of a script that both write ``/tmp/report.json`` or ``out/scan.txt`` overwrite each
other, and leave files a later run mistakes for its own.  ``homelabnext.runs.run_dir(run_id)``
gives each run ``runs/<run_id>/``; ``build/`` is the other place generated output goes.  This
lint walks the AST of every Python script carrying an ``hnx-script:`` header (the script catalog:
``tools/``, the lab-in-a-box helpers, the conformance fakes) and reports:

  literal-write   ``open(P, "w"|"a"|"x"|...)``, ``P.write_text/write_bytes/mkdir/touch``,
                  ``P.open("w")``, ``os.makedirs/mkdir(P)``, ``shutil.copy*/move(_, P)``,
                  ``os.replace/rename(_, P)`` where ``P`` is a *literal* path (a string, a
                  ``Path("...")``, a ``/``-join or an f-string with a literal head, or a
                  module-level constant holding one; a name ending in ``root`` such as
                  ``REPO_ROOT`` or ``args.root`` stands for the repository, so
                  ``REPO_ROOT / "out"`` is the literal ``out``) not under ``build/`` or ``runs/``
  tempfile        ``tempfile.mktemp`` (racy, always), and ``mkdtemp``/``mkstemp``/
                  ``NamedTemporaryFile(delete=False)`` without ``dir=``: a file in the shared temp
                  directory that no run owns and nothing removes

Paths computed at run time (an argument, ``--out``, a variable) are not literal and are not
judged: the caller chose them.  A reviewed exception is an entry in
``tools/run_output_lint.allow.yml`` (``path`` glob, optional ``match`` regex limiting it to the
lines it excuses, ``reason``) or an inline ``run-output: allow <reason>`` comment on the line.
An allowlist entry that excuses nothing is reported as stale.

Usage: python tools/run_output_lint.py [ROOT] [--allowlist FILE] [--json] [FILE ...]
Exit: 0 clean, 1 findings (or a stale allowlist entry), 2 usage / bad allowlist.
"""

from __future__ import annotations

import argparse
import ast
import fnmatch
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

import yaml

DEFAULT_ALLOWLIST = "tools/run_output_lint.allow.yml"
ALLOWED_ROOTS = ("build/", "runs/")
ALLOWED_EXACT = ("/dev/null", "/dev/stdout", "/dev/stderr", "-")
INLINE_ALLOW = re.compile(r"run-output:\s*allow\s+\S")
HEADER = re.compile(r"^# hnx-script:\s*$", re.M)
WRITE_MODE = re.compile(r"[wax+]")
PATH_METHODS = {"write_text", "write_bytes", "mkdir", "touch"}
DEST_CALLS = {  # call name -> index of the destination argument
    "os.makedirs": 0,
    "os.mkdir": 0,
    "shutil.copy": 1,
    "shutil.copy2": 1,
    "shutil.copyfile": 1,
    "shutil.copytree": 1,
    "shutil.move": 1,
    "os.replace": 1,
    "os.rename": 1,
}
TEMP_UNOWNED = {"tempfile.mkdtemp", "tempfile.mkstemp"}


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    rule: str
    detail: str
    text: str

    def __str__(self) -> str:
        return f"{self.path}:{self.line}: {self.rule}: {self.detail}"


def _dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        head = _dotted(node.value)
        return f"{head}.{node.attr}" if head else ""
    return ""


class _Literal:
    """The literal head of a path expression, or None when it is computed at run time."""

    def __init__(self, consts: dict[str, str]):
        self.consts = consts

    def __call__(self, node: ast.AST) -> str | None:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if isinstance(node, ast.Attribute) and node.attr == "parent":
            head = self(node.value)
            return None if head is None else head.rstrip("/").rpartition("/")[0]
        name = _dotted(node)
        if name and re.search(r"(?:^|[._])root$", name, re.I):
            return ""  # REPO_ROOT, ROOT, args.root: the repository itself, so the tail decides
        if isinstance(node, ast.Name):
            return self.consts.get(node.id)
        if isinstance(node, ast.JoinedStr):
            first = node.values[0] if node.values else None
            if isinstance(first, ast.Constant) and isinstance(first.value, str) and first.value:
                return first.value
            return None
        if isinstance(node, ast.Call) and _dotted(node.func) in ("Path", "pathlib.Path"):
            if node.args:
                head = self(node.args[0])
                for extra in node.args[1:]:
                    tail = self(extra)
                    if head is None or tail is None:
                        break
                    head = f"{head.rstrip('/')}/{tail}" if head else tail
                return head
            return None
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div | ast.Add):
            left = self(node.left)
            if left is None:
                return None
            right = self(node.right)
            if right is None:
                return left if isinstance(node.op, ast.Div) else None
            if isinstance(node.op, ast.Add) or left == "":
                return left + right
            return f"{left.rstrip('/')}/{right}"
        return None


def _allowed(path: str) -> bool:
    if path in ALLOWED_EXACT:
        return True
    p = path[2:] if path.startswith("./") else path
    return any(p == r.rstrip("/") or p.startswith(r) for r in ALLOWED_ROOTS)


def _consts(body: list[ast.stmt], lit: _Literal) -> None:
    """Names assigned a literal path in ``body`` (flow-insensitive: the last one wins)."""
    for stmt in body:
        for node in ast.walk(stmt) if not isinstance(stmt, ast.FunctionDef) else ():
            if isinstance(node, ast.Assign) and len(node.targets) == 1:
                t = node.targets[0]
                if isinstance(t, ast.Name) and (v := lit(node.value)) is not None:
                    lit.consts[t.id] = v


def _kw(call: ast.Call, name: str) -> ast.AST | None:
    return next((k.value for k in call.keywords if k.arg == name), None)


def scan_source(rel: str, text: str) -> list[Finding]:
    try:
        tree = ast.parse(text)
    except SyntaxError as ex:
        return [Finding(rel, ex.lineno or 0, "parse", str(ex), "")]
    module = _Literal({})
    _consts(tree.body, module)
    lines = text.splitlines()
    out: list[Finding] = []
    # each call is judged with the module's literal names plus its own function's
    scope: dict[int, _Literal] = {}
    for fn in ast.walk(tree):
        if isinstance(fn, ast.FunctionDef | ast.AsyncFunctionDef):
            lit = _Literal(dict(module.consts))
            _consts(fn.body, lit)
            for node in ast.walk(fn):
                scope[id(node)] = lit  # an inner function overrides when walked later

    def add(node: ast.AST, rule: str, detail: str) -> None:
        ln = getattr(node, "lineno", 0)
        src = lines[ln - 1] if 0 < ln <= len(lines) else ""
        if not INLINE_ALLOW.search(src):
            out.append(Finding(rel, ln, rule, detail, src.strip()))

    def judge(node: ast.AST, target: ast.AST | None, what: str) -> None:
        if target is None:
            return
        path = scope.get(id(node), module)(target)
        if path is not None and not _allowed(path):
            add(node, "literal-write", f"{what} writes {path!r} outside build/ or a run directory")

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _dotted(node.func)
        if name == "open" and node.args:
            mode = node.args[1] if len(node.args) > 1 else _kw(node, "mode")
            if isinstance(mode, ast.Constant) and WRITE_MODE.search(str(mode.value)):
                judge(node, node.args[0], "open()")
        elif isinstance(node.func, ast.Attribute) and node.func.attr in PATH_METHODS:
            judge(node, node.func.value, f".{node.func.attr}()")
        elif isinstance(node.func, ast.Attribute) and node.func.attr == "open":
            mode = node.args[0] if node.args else _kw(node, "mode")
            if isinstance(mode, ast.Constant) and WRITE_MODE.search(str(mode.value)):
                judge(node, node.func.value, ".open()")
        elif name in DEST_CALLS:
            i = DEST_CALLS[name]
            judge(node, node.args[i] if len(node.args) > i else _kw(node, "dst"), f"{name}()")
        elif name == "tempfile.mktemp":
            add(node, "tempfile", "tempfile.mktemp is racy; use tempfile.mkstemp or run_dir")
        elif name in TEMP_UNOWNED and _kw(node, "dir") is None:
            add(node, "tempfile", f"{name}() without dir= leaves an unowned file in the temp dir")
        elif name == "tempfile.NamedTemporaryFile":
            delete = _kw(node, "delete")
            if isinstance(delete, ast.Constant) and delete.value is False and not _kw(node, "dir"):
                add(node, "tempfile", "NamedTemporaryFile(delete=False) without dir=")
    return sorted(out, key=lambda f: (f.path, f.line, f.rule))


def scripts(root: Path) -> list[str]:
    """Repo-relative Python files git tracks (or every one, outside git) with a script header."""
    try:
        r = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-co", "--exclude-standard", "*.py"],
            capture_output=True,
            text=True,
            check=False,
        )
        names = r.stdout.split() if r.returncode == 0 else []
    except OSError:
        names = []
    if not names:
        names = [p.relative_to(root).as_posix() for p in root.rglob("*.py")]
    out = []
    for n in sorted(set(names)):
        if n.startswith(("tests/", "tools/tests/")) or "/tests/" in n:
            continue
        p = root / n
        try:
            head = p.read_text(encoding="utf-8")[:4096]
        except (OSError, UnicodeDecodeError):
            continue
        if HEADER.search(head):
            out.append(n)
    return out


def load_allowlist(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    entries = data.get("allow") if isinstance(data, dict) else None
    if not isinstance(entries, list):
        raise ValueError(f"{path}: top level must be a mapping with an `allow:` list")
    for n, e in enumerate(entries, 1):
        if not isinstance(e, dict) or not e.get("path") or not str(e.get("reason", "")).strip():
            raise ValueError(f"{path}: entry #{n} needs `path` and a `reason`")
        if set(e) - {"path", "match", "reason"}:
            raise ValueError(f"{path}: entry #{n}: only path, match, reason")
        if "match" in e:
            re.compile(e["match"])
    return entries


def apply_allowlist(findings: list[Finding], entries: list[dict]) -> tuple[list[Finding], list]:
    used = [False] * len(entries)
    left = []
    for f in findings:
        hit = False
        for i, e in enumerate(entries):
            if fnmatch.fnmatch(f.path, e["path"]) and (
                "match" not in e or re.search(e["match"], f.text)
            ):
                used[i] = hit = True
        if not hit:
            left.append(f)
    return left, [e for e, u in zip(entries, used, strict=True) if not u]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("root", nargs="?", default=".")
    ap.add_argument("files", nargs="*", help="check these files instead of the script catalog")
    ap.add_argument("--allowlist", help=f"default ROOT/{DEFAULT_ALLOWLIST}")
    ap.add_argument("--json", action="store_true")
    ns = ap.parse_args(argv)
    root = Path(ns.root)
    try:
        entries = load_allowlist(Path(ns.allowlist) if ns.allowlist else root / DEFAULT_ALLOWLIST)
    except (ValueError, re.error, yaml.YAMLError) as ex:
        print(f"run-output-lint: {ex}", file=sys.stderr)
        return 2
    files = ns.files or scripts(root)
    found: list[Finding] = []
    for rel in files:
        found += scan_source(rel, (root / rel).read_text(encoding="utf-8"))
    left, stale = apply_allowlist(found, entries)
    if ns.json:
        print(json.dumps({"findings": [vars(f) for f in left], "stale": stale}, indent=1))
        return 1 if left or stale else 0
    for f in left:
        print(str(f))
    for e in stale:
        print(f"stale allowlist entry (excuses nothing): {e['path']} {e.get('match', '')}".strip())
    if left or stale:
        print(
            "run-output-lint: write scratch output under homelabnext.runs.run_dir(run_id) or "
            "build/, take the path as an argument, or allowlist it with a reason",
            file=sys.stderr,
        )
        return 1
    print(f"run-output-lint: {len(files)} script(s), no out-of-run writes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
