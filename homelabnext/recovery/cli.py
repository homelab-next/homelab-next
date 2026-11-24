# SPDX-License-Identifier: Apache-2.0
"""``hnx recovery drills check ...`` (ADR-0042 decision 4)."""

from __future__ import annotations

import sys

from . import drills


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "drills":
        return drills.main(argv[1:])
    help_asked = bool(argv) and argv[0] in ("-h", "--help")
    print(
        "usage: hnx recovery drills check --records drills.json [--max-age 90d] [--interval 30d] "
        "[--require ID,ID] [--require-export N] [--strict]",
        file=sys.stdout if help_asked else sys.stderr,
    )
    return 0 if help_asked else 2
