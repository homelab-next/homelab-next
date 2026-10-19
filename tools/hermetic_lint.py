#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# hnx-script:
#   id: hermetic-lint
#   kind: check
#   purpose: Fail when test code reads the wall clock or unseeded randomness directly, or library code reads the clock other than as an injectable default.
#   owner: maintainers
#   trigger: [ci:ci/lint, make:hermetic-lint]
#   invariant: [Q-11]
#   inputs: every .py under tests/ and tools/tests/ and homelabnext/ (or the files named)
#   outputs: one line per finding
#   exit:
#     "0": clean
#     "1": findings
"""Gate: test code reads neither the wall clock nor unseeded randomness directly, and library
code reads the clock only where a caller can inject another one.

Hermetic tests inject the clock and the random source (``now=...``, ``random.Random(seed)``).
This lint walks the AST of the test code -- every ``*.py`` under ``tests/`` and ``tools/tests/``,
plus ``test_*.py`` and ``conftest.py`` under ``conformance/`` -- and reports a direct call to:

* the wall clock: ``time.time()``, ``time.time_ns()``, ``datetime.now()``, ``datetime.utcnow()``,
  ``datetime.today()``, ``date.today()`` (through any import spelling);
* unseeded randomness: the module-level ``random.*`` functions (the shared global generator),
  ``random.Random()`` without a seed, ``random.SystemRandom``, ``secrets.*``, ``os.urandom``,
  ``uuid.uuid1``/``uuid.uuid4``.

``time.monotonic``/``perf_counter`` (durations, not dates) and ``time.sleep`` are not flagged.
A deliberate use is waived on its line with ``# hermetic: allow <reason>``.

**Library pass** (every ``*.py`` under ``homelabnext/``, or ``--library FILE ...``): a library
function that reads the clock itself cannot be made deterministic by a test, so a clock read is
allowed only where it is the *default* of an injectable clock:

* inside a **clock provider**: a parameterless function whose body is one ``return`` of a clock
  read (``def _utcnow(): return datetime.now(UTC)``); a call or reference to a provider is
  itself a clock read, here and in every module that imports it;
* in a parameter's **default** (``clock=time.time``, ``clock=lambda: datetime.now(UTC)``), or
  as a reference that is a dataclass field's default (``clock: Callable = time.time``);
* in a parameter's **fallback** arm: ``now or _now()``, ``_now() if now is None else now``,
  ``now if now is not None else _now()``, where ``now`` is a parameter of the enclosing function.

Anything else - a direct read in a function body, a provider called unconditionally - is a
finding.  Clock reads here are the test-pass set plus ``time.monotonic``/``perf_counter`` (a
budget or timeout is time-dependent too) and ``time.gmtime()``/``localtime()``/``ctime()``/
``asctime()``/``strftime(fmt)`` called without a time.  The process edge (a CLI's ``--now``
fallback) is the one place the real clock belongs; it is waived on its line, with its reason.

What this cannot see: network use (the suite-wide runtime guard, ``tests/network_guard.py``,
covers that), and a clock read through a dynamic lookup (``getattr``).

Usage: python tools/hermetic_lint.py [--root DIR] [FILE ...] [--library FILE ...]
Exit: 0 clean, 1 findings.
"""

from __future__ import annotations

import argparse
import ast
import re
import sys
from collections.abc import Iterable
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
WAIVER = re.compile(r"#\s*hermetic:\s*allow\s+\S")

CLOCK = {
    ("time", "time"),
    ("time", "time_ns"),
    ("datetime.datetime", "now"),
    ("datetime.datetime", "utcnow"),
    ("datetime.datetime", "today"),
    ("datetime.date", "today"),
}
RANDOM_GLOBAL = {
    "random", "randint", "randrange", "randbytes", "getrandbits", "choice", "choices",
    "shuffle", "sample", "uniform", "gauss", "normalvariate", "triangular", "betavariate",
    "expovariate", "lognormvariate", "vonmisesvariate", "paretovariate", "weibullvariate",
    "binomialvariate",
}  # fmt: skip


def test_files(root: Path) -> list[Path]:
    out: list[Path] = []
    for top in ("tests", "tools/tests"):
        base = root / top
        if base.is_dir():
            out += base.rglob("*.py")
    conf = root / "conformance"
    if conf.is_dir():
        out += [
            p for p in conf.rglob("*.py") if p.name.startswith("test_") or p.name == "conftest.py"
        ]
    return sorted(p for p in set(out) if "__pycache__" not in p.parts)


class _Visitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.aliases: dict[str, str] = {}  # local name -> dotted origin
        self.found: list[tuple[int, str]] = []

    def visit_Import(self, node: ast.Import) -> None:
        for a in node.names:
            self.aliases[a.asname or a.name.split(".")[0]] = (
                a.name if a.asname else a.name.split(".")[0]
            )

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module and not node.level:
            for a in node.names:
                self.aliases[a.asname or a.name] = f"{node.module}.{a.name}"

    def _dotted(self, node: ast.expr) -> str | None:
        parts = []
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        if not isinstance(node, ast.Name) or node.id not in self.aliases:
            return None
        return ".".join([self.aliases[node.id], *reversed(parts)])

    def visit_Call(self, node: ast.Call) -> None:
        name = self._dotted(node.func)
        if name:
            owner, _, fn = name.rpartition(".")
            reason = None
            if (owner, fn) in CLOCK:
                reason = f"wall clock {name}() (inject the time instead)"
            elif owner == "random" and fn in RANDOM_GLOBAL:
                reason = f"unseeded global {name}() (use random.Random(seed))"
            elif name == "random.Random" and not node.args and not node.keywords:
                reason = "random.Random() without a seed"
            elif name == "random.SystemRandom" or owner == "secrets" or name == "os.urandom":
                reason = f"unseedable randomness {name}()"
            elif name in ("uuid.uuid1", "uuid.uuid4"):
                reason = f"random identifier {name}() (pass a fixed id)"
            if reason:
                self.found.append((node.lineno, reason))
        self.generic_visit(node)


# ---------------------------------------------------------------- library pass
LIB_CLOCK = CLOCK | {
    ("time", "monotonic"),
    ("time", "monotonic_ns"),
    ("time", "perf_counter"),
    ("time", "perf_counter_ns"),
}
# called with at most this many positional arguments, these read the current time
IMPLICIT = {("time", "gmtime"): 0, ("time", "localtime"): 0, ("time", "ctime"): 0,
            ("time", "asctime"): 0, ("time", "strftime"): 1}  # fmt: skip


def module_name(path: Path, root: Path) -> str:
    parts = list(path.relative_to(root).with_suffix("").parts)
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def library_files(root: Path) -> list[Path]:
    base = root / "homelabnext"
    return sorted(p for p in base.rglob("*.py") if "__pycache__" not in p.parts)


def _aliases(tree: ast.Module, module: str, is_pkg: bool) -> dict[str, str]:
    """Local name -> dotted origin: imports (relative ones resolved) and top-level functions."""
    out: dict[str, str] = {}
    package = module if is_pkg else module.rpartition(".")[0]
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                out[a.asname or a.name.split(".")[0]] = a.name if a.asname else a.name.split(".")[0]
        elif isinstance(node, ast.ImportFrom):
            base = node.module or ""
            if node.level:
                pkg = package.split(".")
                pkg = pkg[: len(pkg) - (node.level - 1)] if node.level > 1 else pkg
                base = ".".join([*pkg, *([base] if base else [])])
            for a in node.names:
                out[a.asname or a.name] = f"{base}.{a.name}"
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            out.setdefault(node.name, f"{module}.{node.name}")
    return out


def _dotted_name(node: ast.AST, aliases: dict[str, str]) -> str | None:
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name) or node.id not in aliases:
        return None
    return ".".join([aliases[node.id], *reversed(parts)])


def _parents(tree: ast.AST) -> dict[ast.AST, ast.AST]:
    return {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}


def _reads(tree: ast.AST, aliases: dict[str, str], providers: set[str]):
    """``(node, dotted)`` for every clock read under ``tree``: a call to a clock function or
    provider, or a reference to one that is not being called."""
    parents = _parents(tree)
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Attribute, ast.Name)):
            continue
        name = _dotted_name(node, aliases)
        if name is None:
            continue
        owner, _, fn = name.rpartition(".")
        parent = parents.get(node)
        called = isinstance(parent, ast.Call) and parent.func is node
        if (owner, fn) in LIB_CLOCK or name in providers:
            yield (parent if called else node), name
        elif called and (owner, fn) in IMPLICIT and len(parent.args) <= IMPLICIT[(owner, fn)]:
            yield parent, name


def _body(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> list[ast.stmt]:
    body = list(fn.body)
    if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
        body = body[1:]  # docstring
    return body


def _is_provider(fn: ast.AST, aliases: dict[str, str], providers: set[str]) -> bool:
    if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return False
    a = fn.args
    if a.posonlyargs or a.args or a.vararg or a.kwonlyargs or a.kwarg:
        return False
    body = _body(fn)
    return (
        len(body) == 1
        and isinstance(body[0], ast.Return)
        and body[0].value is not None
        and any(True for _ in _reads(body[0].value, aliases, providers))
    )


def find_providers(modules: dict[str, tuple[ast.Module, dict[str, str]]]) -> set[str]:
    """Dotted names of every clock provider (to a fixpoint: a provider may wrap a provider)."""
    providers: set[str] = set()
    while True:
        found = {
            f"{mod}.{node.name}"
            for mod, (tree, aliases) in modules.items()
            for node in tree.body
            if _is_provider(node, aliases, providers)
        }
        if found <= providers:
            return providers
        providers |= found


def _params(fn: ast.AST) -> set[str]:
    a = fn.args
    return {x.arg for x in [*a.posonlyargs, *a.args, *a.kwonlyargs, a.vararg, a.kwarg] if x}


def _param_test(test: ast.AST, params: set[str]) -> tuple[str, bool] | None:
    """``(param, read_in_body)`` for ``P is None`` (True) / ``P is not None`` or ``P`` (False)."""
    if isinstance(test, ast.Name) and test.id in params:
        return test.id, False
    if (
        isinstance(test, ast.Compare)
        and isinstance(test.left, ast.Name)
        and test.left.id in params
        and len(test.ops) == 1
        and isinstance(test.comparators[0], ast.Constant)
        and test.comparators[0].value is None
    ):
        if isinstance(test.ops[0], ast.Is):
            return test.left.id, True
        if isinstance(test.ops[0], ast.IsNot):
            return test.left.id, False
    return None


def _allowed(node: ast.AST, parents: dict[ast.AST, ast.AST], provider_defs: set[ast.AST]) -> bool:
    child, cur = node, parents.get(node)
    if (
        not isinstance(node, ast.Call)
        and isinstance(cur, ast.AnnAssign)
        and isinstance(parents.get(cur), ast.ClassDef)
    ):
        return True  # a dataclass field's default (``clock: Callable = time.time``)
    func = None  # innermost enclosing def (lambdas are part of the expression)
    path: list[tuple[ast.AST, ast.AST]] = []
    while cur is not None:
        path.append((cur, child))
        if isinstance(cur, ast.arguments) and any(
            child is d for d in cur.defaults + cur.kw_defaults
        ):
            return True  # a parameter's default: the caller can pass another clock
        if isinstance(cur, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if cur in provider_defs:
                return True
            func = cur
            break
        child, cur = cur, parents.get(cur)
    if func is None:
        return False
    params = _params(func)
    for expr, sub in path:
        if isinstance(expr, ast.BoolOp) and isinstance(expr.op, ast.Or):
            first = expr.values[0]
            if isinstance(first, ast.Name) and first.id in params and sub is not first:
                return True
        if isinstance(expr, ast.IfExp) and sub is not expr.test:
            hit = _param_test(expr.test, params)
            if hit and (sub is expr.body) == hit[1]:
                return True
    return False


def lint_library(files: Iterable[Path], root: Path) -> list[tuple[Path, int, str]]:
    """Clock reads in library code that a caller cannot replace (see the module doc)."""
    modules: dict[str, tuple[ast.Module, dict[str, str]]] = {}
    texts: dict[str, tuple[Path, str]] = {}
    for f in files:
        mod = module_name(f, root) if f.is_relative_to(root) else f.stem
        text = f.read_text()
        tree = ast.parse(text)
        modules[mod] = (tree, _aliases(tree, mod, f.name == "__init__.py"))
        texts[mod] = (f, text)
    providers = find_providers(modules)
    found: list[tuple[Path, int, str]] = []
    for mod, (tree, aliases) in modules.items():
        f, text = texts[mod]
        lines = text.splitlines()
        parents = _parents(tree)
        provider_defs = {
            n for n in tree.body if getattr(n, "name", None) and f"{mod}.{n.name}" in providers
        }
        for node, name in _reads(tree, aliases, providers):
            if _allowed(node, parents, provider_defs) or WAIVER.search(lines[node.lineno - 1]):
                continue
            found.append(
                (
                    f,
                    node.lineno,
                    f"library clock read {name}() outside a parameter's default or fallback "
                    "(take an injectable clock or now)",
                )
            )
    return sorted(set(found))


def lint_source(text: str) -> list[tuple[int, str]]:
    v = _Visitor()
    v.visit(ast.parse(text))
    lines = text.splitlines()
    return [(n, r) for n, r in sorted(v.found) if not WAIVER.search(lines[n - 1])]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--root", type=Path, default=REPO_ROOT)
    ap.add_argument("files", nargs="*", type=Path)
    ap.add_argument("--library", nargs="+", type=Path, help="lint these as library code")
    args = ap.parse_args(argv)
    whole_repo = not args.files and not args.library
    files = test_files(args.root) if whole_repo else args.files
    lib = library_files(args.root) if whole_repo else (args.library or [])
    bad = 0
    for f in files:
        for line, reason in lint_source(f.read_text()):
            print(f"{f}:{line}: {reason}", file=sys.stderr)
            bad += 1
    for f, line, reason in lint_library(lib, args.root.resolve()):
        print(f"{f}:{line}: {reason}", file=sys.stderr)
        bad += 1
    if bad:
        print(f"hermetic_lint: {bad} finding(s); waive a deliberate one with "
              "'# hermetic: allow <reason>'", file=sys.stderr)  # fmt: skip
        return 1
    print(f"hermetic_lint: {len(files)} test files and {len(lib)} library modules clean")
    return 0


if __name__ == "__main__":
    sys.exit(main())
