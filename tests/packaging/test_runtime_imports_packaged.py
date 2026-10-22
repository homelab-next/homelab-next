# SPDX-License-Identifier: Apache-2.0
"""Every repo-level package that ``homelabnext`` imports unguarded is packaged into the wheel.

Regression: the wheel shipped only ``homelabnext*``, while the broker, the StackStorm bridge and
several adapters import ``conformance.protocols`` when they load.  From a checkout that went
unnoticed (``python -m`` puts the working directory on ``sys.path``); an installed ``hnx`` failed
with "missing optional dependency 'conformance'" and ``hnx broker serve`` died at start.

This check is static and fast: it walks ``homelabnext/`` with :mod:`ast`, collects every import
of ``conformance.*`` that is not inside a ``try`` handling :class:`ImportError` (an import guarded
that way is a checkout-only path, such as the recorded fakes), and asks setuptools' own package
discovery, configured exactly as ``pyproject.toml`` configures it, whether the package holding
each one is in the wheel.  ``test_wheel_install.py`` proves the same against a built wheel.
"""

import ast
import tomllib
from pathlib import Path

from setuptools.discovery import PackageFinder, PEP420PackageFinder

ROOT = Path(__file__).resolve().parents[2]
TOP = "conformance"  # repo-level packages homelabnext may reach for at run time


def _discovered() -> set[str]:
    cfg = tomllib.loads((ROOT / "pyproject.toml").read_text("utf-8"))
    find = cfg["tool"]["setuptools"]["packages"]["find"]
    finder = PEP420PackageFinder if find.get("namespaces", True) else PackageFinder
    where = find.get("where", ["."])
    return {
        pkg
        for w in where
        for pkg in finder.find(
            where=str(ROOT / w), include=find.get("include", ["*"]), exclude=find.get("exclude", [])
        )
    }


def _guards_import_error(node: ast.Try) -> bool:
    names = {"ImportError", "ModuleNotFoundError", "Exception", "BaseException"}
    for handler in node.handlers:
        if handler.type is None:
            return True
        types = handler.type.elts if isinstance(handler.type, ast.Tuple) else [handler.type]
        if any(isinstance(t, ast.Name) and t.id in names for t in types):
            return True
    return False


def _unguarded_imports(tree: ast.AST) -> list[tuple[int, str]]:
    found: list[tuple[int, str]] = []

    def visit(node: ast.AST, guarded: bool) -> None:
        if isinstance(node, ast.Try):
            inner = guarded or _guards_import_error(node)
            for child in node.body:
                visit(child, inner)
            for child in (*node.handlers, *node.orelse, *node.finalbody):
                visit(child, guarded)
            return
        if not guarded:
            if isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                found.append((node.lineno, node.module))
            elif isinstance(node, ast.Import):
                found.extend((node.lineno, a.name) for a in node.names)
        for child in ast.iter_child_nodes(node):
            visit(child, guarded)

    visit(tree, False)
    return [(line, mod) for line, mod in found if mod == TOP or mod.startswith(TOP + ".")]


def _package_of(module: str) -> str:
    """The package that holds ``module`` in the source tree (itself, if it is a package)."""
    path = ROOT.joinpath(*module.split("."))
    return module if path.is_dir() else module.rpartition(".")[0]


def test_collector_sees_guarded_and_unguarded_imports():
    src = (
        "from conformance.protocols.broker import Denied\n"
        "def f():\n"
        "    from conformance.protocols import object_store\n"
        "    try:\n"
        "        from conformance.fakes.x import Fake\n"
        "    except ImportError:\n"
        "        import conformance.fakes.y\n"
    )
    got = [m for _line, m in _unguarded_imports(ast.parse(src))]
    assert got == ["conformance.protocols.broker", "conformance.protocols", "conformance.fakes.y"]


def test_every_unguarded_conformance_import_is_packaged():
    packaged = _discovered()
    imports = [
        (path.relative_to(ROOT).as_posix(), line, mod)
        for path in sorted((ROOT / "homelabnext").rglob("*.py"))
        for line, mod in _unguarded_imports(ast.parse(path.read_text("utf-8")))
    ]
    assert imports, "expected homelabnext to import conformance.protocols (collector broken?)"
    missing = [
        f"{p}:{line} imports {m}" for p, line, m in imports if _package_of(m) not in packaged
    ]
    assert missing == [], "not in the wheel (pyproject [tool.setuptools.packages.find])"


def test_fakes_and_suites_stay_out_of_the_wheel():
    """Only the contracts are runtime code; fakes, suites and targets need a source checkout."""
    stray = sorted(
        p for p in _discovered() if p.split(".")[0] == TOP and p != "conformance.protocols"
    )
    assert stray == []
