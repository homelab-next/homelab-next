# SPDX-License-Identifier: Apache-2.0
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# the role tests' own helpers, beside this file
from rolerun import prefetch_first_runs


@pytest.fixture
def first(request, tmp_path_factory):
    """The first run of a test marked ``rolerun.first_run``: ``(result, tmp)``."""
    return prefetch_first_runs(request, tmp_path_factory)
