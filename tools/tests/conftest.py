# SPDX-License-Identifier: Apache-2.0
"""Fixtures of the gate-tool tests.

``go_toolchain``: the path of ``go`` for the tests that run a real Go toolchain.  Without one they
skip ("go is not installed", a registered skip reason), except where ``HNX_REQUIRE_GO=1`` says Go
must be there (CI's test leg that installs it): then a missing toolchain fails, so those tests
cannot quietly stop running.  Use it as ``@pytest.mark.usefixtures("go_toolchain")``.
"""

import os
import shutil

import pytest


@pytest.fixture
def go_toolchain() -> str:
    go = shutil.which("go")
    if go is None:
        if os.environ.get("HNX_REQUIRE_GO") == "1":
            pytest.fail("go is not on PATH, and HNX_REQUIRE_GO=1 requires it", pytrace=False)
        pytest.skip("go is not installed")
    return go
