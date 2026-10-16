# SPDX-License-Identifier: Apache-2.0
"""Helpers shared by the network tests (a uniquely named module: conftest names collide)."""

from __future__ import annotations

import os
from pathlib import Path

from homelabnext.network import adapters

ROOT = Path(__file__).resolve().parents[2]
SITE = ROOT / "schemas" / "platform" / "examples" / "site.valid.yml"
REGISTRY = Path(__file__).parent / "fixtures" / "services.yml"
GOLDEN = Path(__file__).parent / "golden"
UPDATE = os.environ.get("HNX_UPDATE_GOLDEN") == "1"


def render(name: str, ir) -> dict[str, str]:
    return adapters.get(name).render(ir)


def check_golden(label: str, rendered: dict[str, str]) -> None:
    """Compare ``rendered`` with tests/network/golden/<label>/; HNX_UPDATE_GOLDEN=1 rewrites."""
    base = GOLDEN / label
    if UPDATE:
        base.mkdir(parents=True, exist_ok=True)
        for old in base.rglob("*"):
            if old.is_file():
                old.unlink()
        for path, text in rendered.items():
            target = base / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text, encoding="utf-8")
        return
    expected = {
        p.relative_to(base).as_posix(): p.read_text(encoding="utf-8")
        for p in sorted(base.rglob("*"))
        if p.is_file()
    }
    assert sorted(rendered) == sorted(expected), "set of rendered files differs from golden"
    for path, text in rendered.items():
        assert text == expected[path], f"{label}/{path} differs from golden (HNX_UPDATE_GOLDEN=1)"
