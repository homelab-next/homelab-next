# SPDX-License-Identifier: Apache-2.0
"""No test module sits directly under ``tests/``.

Pytest (``prepend`` import mode, no ``__init__.py``) puts the directory of each test module on
``sys.path``.  A module directly under ``tests/`` therefore puts ``tests/`` there, and every suite
directory becomes an importable namespace package: ``tests/mcp`` answers ``import mcp``, so
``pytest.importorskip("mcp")`` stops skipping where the optional ``mcp`` extra is absent and the
test fails on the extra's own dependencies (``anyio``) instead.  Put the module in a suite
directory (``tests/<suite>/``)."""

from __future__ import annotations

from pathlib import Path

TESTS = Path(__file__).resolve().parents[1]


def test_no_test_module_directly_under_tests():
    stray = sorted(p.name for p in TESTS.glob("test_*.py")) + sorted(
        p.name for p in TESTS.glob("*_test.py")
    )
    assert not stray, f"move into a suite directory (tests/<suite>/): {stray}"
