# SPDX-License-Identifier: Apache-2.0
"""The path-glob allowlist file the repository's gates share (``tools/*.allow.yml``).

One shape: ``allow:`` is a list of mappings, each with a ``path`` glob and a ``reason`` (an
exemption must say why); a gate may read more keys from each entry.  An absent file is an empty
allowlist.  Each gate raises its own error class, so its exit code for a bad allowlist is kept.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

__all__ = ["entries"]


def entries(path: Path | None, error: type[Exception], why: str = "") -> list[dict[str, Any]]:
    """The entries of the allowlist at ``path``; ``error`` names the first malformed one.

    ``why`` is appended to the message for an entry without a ``reason``."""
    if path is None or not path.is_file():
        return []
    import yaml

    doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    out = doc.get("allow", [])
    if not isinstance(out, list):
        raise error(f"{path}: 'allow' must be a list")
    for i, e in enumerate(out):
        if not isinstance(e, dict) or not str(e.get("path", "")).strip():
            raise error(f"{path}: entry {i} needs a 'path' glob")
        if not str(e.get("reason", "")).strip():
            raise error(f"{path}: entry {i} ({e['path']}) has no 'reason'{why}")
    return out
