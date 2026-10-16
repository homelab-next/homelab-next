# SPDX-License-Identifier: Apache-2.0
"""Fixtures: the synthetic example site and its registry."""

from __future__ import annotations

import copy
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
for p in (ROOT, ROOT / "tools", Path(__file__).parent):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

from netutil import REGISTRY, SITE

from homelabnext.network import build_ir, load_site
from homelabnext.network.loader import load_registry


@pytest.fixture
def site_path() -> Path:
    return SITE


@pytest.fixture
def registry_path() -> Path:
    return REGISTRY


@pytest.fixture
def doc() -> dict:
    """A fresh, mutable copy of the example site document."""
    return copy.deepcopy(load_site(SITE))


@pytest.fixture(scope="session")
def registry():
    return load_registry(REGISTRY)


@pytest.fixture
def ir(doc, registry):
    return build_ir(doc, registry)
