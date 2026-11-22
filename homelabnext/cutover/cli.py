# SPDX-License-Identifier: Apache-2.0
"""``hnx cutover check|render|gate LEDGER_DIR``.

Exit codes: 0 clean, 1 problems (or, for ``gate``, rows that are not finished), 2 usage error.
``LEDGER_DIR`` is the overlay's ``lab/registers/cutover``.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import sys

from .model import check_ledger, load_ledger, plane_gate, render_json, render_markdown


def _parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="hnx cutover", description="The cutover ledger (ADR-0043).")
    ap.add_argument("cmd", choices=["check", "render", "gate"])
    ap.add_argument("ledger", help="ledger directory (the overlay's lab/registers/cutover)")
    ap.add_argument(
        "--format", choices=["json", "md"], metavar="FMT", default="md", help="render format"
    )
    ap.add_argument(
        "--plane",
        action="append",
        default=[],
        help="gate: a plane every row of which must be finished (repeatable)",
    )
    ap.add_argument(
        "--archive-gate",
        action="store_true",
        help="gate: every row old-retired, none undecided, none soaking",
    )
    ap.add_argument("--today", help="YYYY-MM-DD (default: today)")
    return ap


def main(argv: list[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
    except SystemExit as exc:
        return 2 if exc.code else 0
    try:
        today = dt.date.fromisoformat(args.today) if args.today else dt.date.today()
    except ValueError:
        print("hnx cutover: --today must be YYYY-MM-DD", file=sys.stderr)
        return 2
    ledger = load_ledger(args.ledger)
    if args.cmd == "render":
        if args.format == "json":
            print(json.dumps(render_json(ledger, today), indent=2))
        else:
            print(render_markdown(ledger, today), end="")
        return 0
    problems = check_ledger(ledger, today)
    if args.cmd == "gate":
        if not args.plane and not args.archive_gate:
            print("hnx cutover gate: name --plane or --archive-gate", file=sys.stderr)
            return 2
        for plane in args.plane:
            problems += [f"[{plane}] {p}" for p in plane_gate(ledger, plane, today)]
        if args.archive_gate:
            for r in sorted(ledger.rows.values(), key=lambda r: r.get("title")):
                if r.state != "old-retired" or r.soaking(today) or r.disposition == "undecided":
                    problems.append(
                        f"[archive] {r.uid} {r.get('title')}: {r.state}, {r.disposition}"
                    )
    for p in problems:
        print(p)
    print(f"cutover {args.cmd}: {len(ledger.rows)} rows, {len(problems)} problems")
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
