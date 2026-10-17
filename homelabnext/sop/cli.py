# SPDX-License-Identifier: Apache-2.0
"""``hnx docs systems generate|check|template REGISTRY [DIR]``.

Exit codes: 0 ok, 1 a registry row has no page, a page has no row, or a generated block is stale,
2 usage error.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from homelabnext.registry.model import RegistryError, load

from .pages import check_pages, generate_pages, render_template


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="hnx docs", description="generate and check documentation")
    ap.add_argument("topic", choices=["systems"])
    ap.add_argument("cmd", choices=["generate", "check", "template"])
    ap.add_argument("registry", nargs="?")
    ap.add_argument("dir", nargs="?", default="docs/systems")
    ap.add_argument(
        "--require-complete", action="store_true", help="also fail on unfilled TODO blocks"
    )
    try:
        args = ap.parse_args(argv)
    except SystemExit as exc:
        return 2 if exc.code else 0
    if args.cmd == "template":
        print(render_template(), end="")
        return 0
    if not args.registry:
        print("hnx docs systems: a REGISTRY file is required", file=sys.stderr)
        return 2
    try:
        reg = load(args.registry)
    except (RegistryError, OSError) as exc:
        print(f"hnx docs systems: {exc}", file=sys.stderr)
        return 2
    if args.cmd == "generate":
        res = generate_pages(reg, args.dir)
        Path(args.dir, "_TEMPLATE.md").write_text(render_template(), encoding="utf-8")
        print(
            f"systems pages: {len(res.created)} created, {len(res.updated)} updated,"
            f" {len(res.unchanged)} unchanged in {args.dir}"
        )
        return 0
    rep = check_pages(reg, args.dir)
    for line in rep.lines():
        print(line)
    open_todos = sum(rep.todo_open.values())
    ok = rep.ok(args.require_complete)
    print(
        f"systems pages: {'ok' if ok else 'FAIL'} ({len(reg.services)} services,"
        f" {open_todos} unfilled TODO blocks)"
    )
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
