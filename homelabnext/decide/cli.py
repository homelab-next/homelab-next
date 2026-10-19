# SPDX-License-Identifier: Apache-2.0
"""``hnx decide``: eval (synthetic gold set), scan (impact keywords), lint (decision specs)."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .evalset import EXAMPLES, demo_cascade, generate_gold_set
from .impact_scan import ImpactScanner
from .replay import gate, replay


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="hnx decide", description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    ev = sub.add_parser("eval", help="replay the synthetic gold set through the demo cascade")
    ev.add_argument("--n", type=int, default=200)
    ev.add_argument("--seed", type=int, default=7)
    sc = sub.add_parser("scan", help="run the deterministic impact scan over TEXT")
    sc.add_argument("text")
    sc.add_argument("--keywords", default=str(EXAMPLES / "impact_keywords.yml"))
    li = sub.add_parser("lint", help="lint every decision spec in the git tree, or PATHS")
    li.add_argument("paths", nargs="*", type=Path, help="spec files or directories")
    li.add_argument("--root", type=Path, default=None, help="git tree to search (default: cwd)")
    args = ap.parse_args(argv)
    if args.cmd == "lint":
        return _lint(args.paths, args.root)
    if args.cmd == "scan":
        res = ImpactScanner.load(args.keywords).scan(args.text)
        print(json.dumps({"tier": res.tier, "keywords": list(res.keywords)}))
        return 0
    rep = replay(generate_gold_set(args.n, args.seed), demo_cascade())
    g = gate(rep)
    print(json.dumps({"report": rep.to_dict(), "gate": g.to_dict()}, indent=2, sort_keys=True))
    return 0 if g.passed else 1


def _lint(paths: list[Path], root: Path | None) -> int:
    from .lint import LintError, lint_paths

    try:
        n, problems = lint_paths(paths, root=root)
    except LintError as exc:
        print(f"decide lint: {exc}", file=sys.stderr)
        return exc.code
    for p in problems:
        print(p)
    print(f"decide lint: {n} spec(s), {len(problems)} problem(s)")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
