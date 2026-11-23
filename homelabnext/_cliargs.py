# SPDX-License-Identifier: Apache-2.0
"""Argument helpers the ``hnx`` sub-command front ends share (one copy, not one per command)."""

from __future__ import annotations

import argparse
import json
from datetime import datetime
from pathlib import Path
from typing import Any

__all__ = ["iso_when", "load_doc"]


def iso_when(text: str) -> datetime:
    """An argparse ``type=``: an ISO 8601 time that carries a UTC offset."""
    try:
        t = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        raise argparse.ArgumentTypeError(f"not an ISO 8601 time: {text!r}") from None
    if t.utcoffset() is None:
        raise argparse.ArgumentTypeError(f"{text!r} has no UTC offset (write Z or +00:00)")
    return t


def load_doc(path: str, usage: type[Exception]) -> Any:
    """Load a JSON or YAML document; any read or parse failure is raised as ``usage``."""
    p = Path(path)
    try:
        if p.suffix == ".json":
            return json.loads(p.read_text(encoding="utf-8"))
        from homelabnext._yaml import load_unique

        return load_unique(p, usage)
    except (OSError, ValueError) as exc:
        raise usage(f"cannot read {p}: {exc}") from exc
