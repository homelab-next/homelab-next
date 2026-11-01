# SPDX-License-Identifier: Apache-2.0
"""The lake's read boundary (ADR-0033 decision 6): outside the lake library, no module that
imports it calls a lake client's ``query`` or ``named`` itself.  A consumer reads through
``homelabnext.lake.ceiling`` (``reader_for``, a ``CeilingReader``), and a read at ``red`` goes
through ``raw_query``/``raw_named`` with a ``RedGrant`` its call site names.

Exempt: ``homelabnext/lake/`` (the adapters and the ceiling reader themselves) and
``homelabnext/conform/`` (the conformance harness, whose subject is the adapter's own ``query``).
"""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PACKAGE = ROOT / "homelabnext"
EXEMPT = ("homelabnext/lake/", "homelabnext/conform/")
RAW = {"query", "named"}


def _imports_lake(tree: ast.AST, module: str) -> bool:
    """Whether ``module`` (dotted) imports ``homelabnext.lake`` or anything under it."""
    pkg = module.split(".")[:-1]
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names = [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom):
            base = pkg[: len(pkg) - node.level + 1] if node.level else []
            target = ".".join([*base, *(node.module.split(".") if node.module else [])])
            names = [target, *(f"{target}.{a.name}" for a in node.names)]
        else:
            continue
        if any(n == "homelabnext.lake" or n.startswith("homelabnext.lake.") for n in names):
            return True
    return False


def raw_reads(source: str, module: str) -> list[int]:
    """The lines of ``.query(`` / ``.named(`` calls in a module that imports the lake library."""
    tree = ast.parse(source)
    if not _imports_lake(tree, module):
        return []
    return sorted(
        node.lineno
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in RAW
    )


def test_no_module_outside_the_lake_reads_it_raw():
    bad = []
    for path in sorted(PACKAGE.rglob("*.py")):
        rel = path.relative_to(ROOT).as_posix()
        if rel.startswith(EXEMPT):
            continue
        module = rel[: -len(".py")].replace("/", ".")
        bad += [f"{rel}:{n}" for n in raw_reads(path.read_text(encoding="utf-8"), module)]
    assert not bad, (
        "raw lake reads outside homelabnext/lake/: read through lake.ceiling.reader_for, or at"
        f" red through raw_query/raw_named with a RedGrant: {bad}"
    )


def test_the_check_finds_a_raw_read():
    absolute = (
        "from homelabnext.lake import FakeLake\n\ndef f(c):\n    return c.query('SELECT 1')\n"
    )
    relative = "from ..lake.errors import LakeError\n\ndef f(c):\n    return c.named('n')\n"
    elsewhere = "import json\n\ndef f(store):\n    return store.query('x')\n"
    assert raw_reads(absolute, "homelabnext.status.reader") == [4]
    assert raw_reads(relative, "homelabnext.status.reader") == [4]
    assert raw_reads(elsewhere, "homelabnext.mcp.catalog") == []  # not a lake client
    granted = "from homelabnext.lake.ceiling import raw_query\n\ndef f(c, g):\n    return raw_query(c, g, 'x')\n"  # fmt: skip
    assert raw_reads(granted, "homelabnext.swap.x") == []
