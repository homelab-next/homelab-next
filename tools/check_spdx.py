#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Fail if a Python file lacks an SPDX-License-Identifier header in its first five lines."""

from __future__ import annotations

import sys
from pathlib import Path

HEADER = "SPDX-License-Identifier: Apache-2.0"
SKIP_DIRS = {".git", ".venv", "venv", "build", "dist", "__pycache__", "node_modules"}


def missing_header(path: Path) -> bool:
    if path.stat().st_size == 0:
        return False  # empty __init__.py is allowed
    head = path.read_text(encoding="utf-8", errors="replace").splitlines()[:5]
    return not any(HEADER in line for line in head)


def collect(args: list[str]) -> list[Path]:
    if args:
        return [Path(a) for a in args]
    return [p for p in Path(".").rglob("*.py") if not SKIP_DIRS & set(p.parts)]


def main(argv: list[str] | None = None) -> int:
    bad = [p for p in collect(sys.argv[1:] if argv is None else argv) if missing_header(p)]
    for p in bad:
        print(f"{p}: missing '{HEADER}'")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
