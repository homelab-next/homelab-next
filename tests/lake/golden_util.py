# SPDX-License-Identifier: Apache-2.0
"""Golden-file helper: compare to the checked-in text, or rewrite it with HNX_UPDATE_GOLDEN=1."""

from __future__ import annotations

import os
from pathlib import Path

GOLDEN = Path(__file__).parent / "golden"


def check_golden(name: str, actual: str) -> None:
    path = GOLDEN / name
    if os.environ.get("HNX_UPDATE_GOLDEN") == "1":
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(actual, encoding="utf-8")
        return
    assert path.exists(), f"missing golden {path}; run with HNX_UPDATE_GOLDEN=1 to create it"
    expected = path.read_text(encoding="utf-8")
    assert actual == expected, (
        f"{name} differs from its golden; if the change is intended run with HNX_UPDATE_GOLDEN=1"
    )
