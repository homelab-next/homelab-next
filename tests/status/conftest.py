# SPDX-License-Identifier: Apache-2.0
"""Fixtures for the status hub tests (fakes live in ``status_helpers``)."""

from __future__ import annotations

import pytest
from status_helpers import REGISTRY, Clock, FakeHttp

from homelabnext.registry.model import load
from homelabnext.state import StateStore
from homelabnext.status import StatusHub, sources_from_registry


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def http() -> FakeHttp:
    return FakeHttp()


@pytest.fixture
def registry():
    return load(REGISTRY)


@pytest.fixture
def specs(registry):
    return sources_from_registry(registry)


@pytest.fixture
def make_hub(tmp_path, clock):
    def make(specs, **kw):
        return StatusHub(specs, StateStore(tmp_path / "state.json", clock=clock), clock=clock, **kw)

    return make
