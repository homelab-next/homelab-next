# SPDX-License-Identifier: Apache-2.0
"""Shared helpers: a fixed clock, the example registry with a candidate host, golden checks."""

from __future__ import annotations

import os
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
GOLDEN = Path(__file__).parent / "golden"


class FakeClock:
    def __init__(self, start: datetime | None = None):
        self.now = start or datetime(2026, 4, 1, 9, 0, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.now

    def advance(self, **kw: float) -> None:
        self.now += timedelta(**kw)


def registry_text() -> str:
    """examples/services.yml plus a second lake host, the candidate's home."""
    text = (ROOT / "examples" / "services.yml").read_text(encoding="utf-8")
    m = re.search(r"^  lake-core: .*address: (\d+\.\d+\.\d+)\.(\d+),.*$", text, re.M)
    assert m, "examples/services.yml has no lake-core host line"
    line = m.group(0)
    twin = line.replace("lake-core:", "lake-core-2:").replace(
        f"{m.group(1)}.{m.group(2)},", f"{m.group(1)}.{int(m.group(2)) + 1},"
    )
    return text.replace(line, line + "\n" + twin, 1)


def check_golden(name: str, actual: str) -> None:
    path = GOLDEN / name
    if os.environ.get("HNX_UPDATE_GOLDEN") == "1":
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(actual, encoding="utf-8")
        return
    assert path.exists(), f"missing golden {path}; run with HNX_UPDATE_GOLDEN=1 to create it"
    assert actual == path.read_text(encoding="utf-8"), (
        f"{name} differs from its golden; if intended run with HNX_UPDATE_GOLDEN=1"
    )


def check_example(label: str, actual: str) -> None:
    """Goldens of the end-to-end runs (current record format, with state digests).

    The published schema examples stay v1.0 documents: the evolution test checks that every
    example still validates against the frozen 1.0 schema, and record_problems accepts them.
    """
    path = GOLDEN / f"swap_record.{label}.json"
    if os.environ.get("HNX_UPDATE_GOLDEN") == "1":
        path.write_text(actual, encoding="utf-8")
        return
    assert path.exists(), f"missing example {path}; run with HNX_UPDATE_GOLDEN=1 to create it"
    assert actual == path.read_text(encoding="utf-8"), (
        f"{label} differs from its published example; if intended run with HNX_UPDATE_GOLDEN=1"
    )
