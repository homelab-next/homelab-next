# SPDX-License-Identifier: Apache-2.0
"""``hnx graph build|check|related``.

* ``build [--out DIR] [--root CHECKOUT]`` writes ``docs/graph/graph.json`` and the index pages
  (a local build for Obsidian and scripts; ``docs/graph/`` is gitignored);
* ``check [--out DIR] [--root CHECKOUT]`` fails on a dangling edge or a duplicate id (with
  ``--out``, also on a stale, missing or orphan file there), and reports orphan nodes and
  unresolved system tags;
* ``related ID|PATH... [--depth N] [--budget N] [--json] [--include-inactive]`` prints the
  ranked neighbourhood of the given node ids or edited file paths, from a fresh build.

Exit codes: 0 ok, 1 check failed (including a register that does not load), or ``related``
resolved no seed, 2 usage error or no source checkout.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .build import build, check, generate
from .model import Graph
from .query import related, seeds_for


def _root(arg: str | None) -> Path | None:
    from homelabnext import paths

    if arg:
        return Path(arg).resolve()
    return paths.checkout_root()


def _graph(root: Path) -> Graph:
    return build(root)[0]  # always fresh: docs/graph/ is a local, uncommitted build


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="hnx graph", description="the repository knowledge graph (docs/graph/)"
    )
    ap.add_argument("cmd", choices=["build", "check", "related"])
    ap.add_argument("items", nargs="*", help="related: node ids or repo-relative paths")
    ap.add_argument("--root", help="source checkout (default: this checkout)")
    ap.add_argument("--out", help="build/check: output directory (default: <root>/docs/graph)")
    ap.add_argument("--depth", type=int, default=2, help="related: maximum hops (default 2)")
    ap.add_argument("--budget", type=int, default=25, help="related: maximum nodes (default 25)")
    ap.add_argument("--json", action="store_true", help="related: JSON output")
    ap.add_argument(
        "--include-inactive",
        action="store_true",
        help="related: also return retired and superseded records",
    )
    try:
        args = ap.parse_args(argv)
    except SystemExit as exc:
        return 2 if exc.code else 0
    root = _root(args.root)
    if root is None or not (root / "homelabnext").is_dir():
        print(
            "hnx graph: needs a homelabnext source checkout (run it from one or pass --root)",
            file=sys.stderr,
        )
        return 2
    if args.cmd == "build":
        written, removed = generate(root, args.out)
        print(f"graph: {len(written)} file(s) written, {len(removed)} orphan(s) removed")
        return 0
    if args.cmd == "check":
        from homelabnext.registers.schema import RegisterError

        try:
            rep = check(root, args.out)
        except RegisterError as exc:
            # a register the graph reads does not load (two record files claiming one id, ...)
            print(f"graph: FAIL, a register does not load: {exc}")
            return 1
        for line in rep.lines():
            print(line)
        n, e = rep.counts
        print(f"graph: {'ok' if rep.ok() else 'FAIL'} ({n} nodes, {e} edges)")
        return 0 if rep.ok() else 1
    if not args.items:
        print("hnx graph related: give at least one node id or path", file=sys.stderr)
        return 2
    graph = _graph(root)
    ids = [i for i in args.items if i in graph.nodes]
    rest = [i for i in args.items if i not in graph.nodes]
    seeds = sorted(set(ids) | set(seeds_for(graph, rest, include_inactive=args.include_inactive)))
    if not seeds:
        print(f"hnx graph related: no node matches {args.items}", file=sys.stderr)
        return 1
    found = related(
        graph,
        seeds,
        budget=args.budget,
        max_depth=args.depth,
        include_inactive=args.include_inactive,
    )
    if args.json:
        print(json.dumps({"seeds": seeds, "related": [r.as_dict() for r in found]}, indent=2))
        return 0
    print("seeds: " + ", ".join(seeds))
    for r in found:
        print(f"{r.distance}  {r.score:.3f}  {r.id:<48} {r.via} <- {r.parent}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
