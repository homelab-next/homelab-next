# SPDX-License-Identifier: Apache-2.0
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
for p in (ROOT, ROOT / "tools"):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))


@pytest.fixture(autouse=True)
def _today(monkeypatch):
    """Exemption review dates are judged against a fixed day, so a fixture never expires."""
    monkeypatch.setenv("HNX_TODAY", "2026-10-27")
