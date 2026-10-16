# SPDX-License-Identifier: Apache-2.0
import pytest

from homelabnext.customization import discover
from homelabnext.customization.loader import REPO_ROOT


@pytest.fixture
def uni():
    """Universe built from the real repository tree (registry, roles, schemas, ADRs)."""
    return discover(REPO_ROOT)


@pytest.fixture
def repo_root():
    return REPO_ROOT
