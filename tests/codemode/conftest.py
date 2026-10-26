# SPDX-License-Identifier: Apache-2.0
"""Fixtures of the Code Mode tests: the forking test executor (not an isolation boundary)."""

from __future__ import annotations

import pytest

from conformance.fakes.code_executor import ForkingExecutor


@pytest.fixture
def executor():
    ex = ForkingExecutor()
    yield ex
    ex.close()
