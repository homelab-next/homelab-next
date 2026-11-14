# SPDX-License-Identifier: Apache-2.0
"""No test imports a ``conftest`` by module name, and suites that share none collect together.

No test directory has an ``__init__.py``, so pytest imports every ``conftest.py`` as the module
``conftest``.  ``from conftest import X`` then reads whichever one pytest loaded last:
``pytest tests/golden tests/status`` handed ``tests/golden/test_golden_runner.py`` the status
hub's conftest and its collection failed.  CI collects the whole tree and passed only by
collection order.  Shared constants and helpers go in a module with a name of its own
(``tests/golden/golden_helpers.py``, ``tests/status/status_helpers.py``)."""

from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TEST_TREES = ("tests", "tools/tests", "conformance")


def _conftest_imports(path: Path) -> list[int]:
    tree = ast.parse(path.read_text(), filename=str(path))

    def names(node: ast.AST) -> list[str]:
        if isinstance(node, ast.ImportFrom) and node.level == 0:
            return [node.module or ""]
        return [a.name for a in node.names] if isinstance(node, ast.Import) else []

    return [n.lineno for n in ast.walk(tree) if "conftest" in names(n)]


def test_no_test_module_imports_conftest_by_name():
    found = [
        f"{p.relative_to(ROOT)}:{line}"
        for tree in TEST_TREES
        for p in sorted((ROOT / tree).rglob("*.py"))
        for line in _conftest_imports(p)
    ]
    assert found == [], "import from a named helper module, not conftest: " + ", ".join(found)


def test_the_golden_and_status_suites_collect_together():
    # the order that failed: the status hub's conftest is loaded after the golden one's
    r = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "--collect-only",
            "-q",
            "-p",
            "no:cacheprovider",
            "tests/golden",
            "tests/status",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert r.returncode == 0, r.stdout[-4000:] + r.stderr[-2000:]
