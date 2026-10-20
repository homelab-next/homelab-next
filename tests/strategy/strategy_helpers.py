# SPDX-License-Identifier: Apache-2.0
"""Shared constants and helpers of the strategy tests (an injected clock, a text edit)."""

import datetime as dt
import pathlib

REPO = pathlib.Path(__file__).resolve().parents[2]
EXAMPLE = REPO / "examples" / "strategy"
NOW = dt.datetime(2026, 10, 20, 13, 10, tzinfo=dt.UTC)


def edit(root: pathlib.Path, rel: str, old: str, new: str) -> None:
    p = root / rel
    text = p.read_text()
    assert old in text, f"{old!r} not in {rel}"
    p.write_text(text.replace(old, new, 1))


def clock(at: dt.datetime = NOW):
    return lambda: at
