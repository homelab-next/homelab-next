# SPDX-License-Identifier: Apache-2.0
"""Fixtures for the orchestration telemetry tests (fakes live in ``orch_helpers``)."""

from __future__ import annotations

import pytest
from orch_helpers import T0, body, examples

from homelabnext.orchestration.store import TelemetryStore


@pytest.fixture
def store(tmp_path) -> TelemetryStore:
    return TelemetryStore(tmp_path / "telemetry.db", clock=lambda: T0)


@pytest.fixture
def filled(store) -> TelemetryStore:
    """The store holding the four example job records."""
    for ev in examples():
        assert store.consume(body(ev)).status == "processed"
    return store
