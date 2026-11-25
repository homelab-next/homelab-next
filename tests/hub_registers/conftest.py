# SPDX-License-Identifier: Apache-2.0
"""Fixtures for the register page tests (helpers in ``reg_helpers``)."""

from __future__ import annotations

import pytest
from reg_helpers import REGISTRY, Clock

from homelabnext.registry.model import load
from homelabnext.status import sources_from_registry


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def registry():
    return load(REGISTRY)


@pytest.fixture
def specs(registry):
    return sources_from_registry(registry)
