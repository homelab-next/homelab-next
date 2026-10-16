# SPDX-License-Identifier: Apache-2.0
"""Golden-tree helper for the integration tests (HNX_UPDATE_GOLDEN=1 rewrites the goldens)."""

from __future__ import annotations

import os
from pathlib import Path

GOLDEN = Path(__file__).parent / "golden"
UPDATE = os.environ.get("HNX_UPDATE_GOLDEN") == "1"


def check_tree(label: str, rendered: dict[str, str]) -> None:
    base = GOLDEN / label
    if UPDATE:
        base.mkdir(parents=True, exist_ok=True)
        for old in base.rglob("*"):
            if old.is_file():
                old.unlink()
        for rel, text in rendered.items():
            target = base / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text, encoding="utf-8")
    expected = {
        p.relative_to(base).as_posix(): p.read_text(encoding="utf-8")
        for p in sorted(base.rglob("*"))
        if p.is_file()
    }
    assert sorted(rendered) == sorted(expected), f"{label}: set of files differs from golden"
    for rel, text in rendered.items():
        assert text == expected[rel], f"{label}/{rel} differs from golden (HNX_UPDATE_GOLDEN=1)"
