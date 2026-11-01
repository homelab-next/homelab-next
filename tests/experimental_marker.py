# SPDX-License-Identifier: Apache-2.0
"""Pytest plugin: mark the tests of experimental and frozen components ``experimental``.

``tools/experimental.yml`` is the one list of the components out of the blocking set (v0 cuts,
2026-10-31).  Every collected test under one of their ``tests:`` paths gets the marker before
``-m`` selects, so the blocking runs (``make test``, CI's test job: ``-m "not live and not
experimental"``) deselect them and ``make experimental`` (CI's non-blocking job: ``-m
"experimental and not live"``) runs them: they still run, they just block no merge.  The marker is
never written by hand on a test; it comes from the list only (tools/tests/test_experimental.py).
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
_TOOL = ROOT / "tools" / "experimental.py"


def _tool():
    """``tools/experimental.py`` (``tools/`` is not a package); registered before it runs, as a
    module defining dataclasses must be."""
    name = "hnx_tools_experimental"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, _TOOL)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


experimental = _tool()


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers",
        f"{experimental.MARKER}: a test of a component listed in tools/experimental.yml; set by "
        "tests/experimental_marker.py from that list, never by hand",
    )


@pytest.hookimpl(tryfirst=True)  # before -m deselects
def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    try:
        paths = experimental.marked_paths(experimental.load())
    except experimental.ListError as exc:
        raise pytest.UsageError(f"tools/experimental.yml: {exc}") from None
    for item in items:
        try:
            rel = Path(item.path).resolve().relative_to(ROOT).as_posix()
        except ValueError:
            continue  # a test outside the checkout (a planted tmp tree) is no component's
        if experimental.is_experimental(rel, paths):
            item.add_marker(pytest.mark.experimental)
