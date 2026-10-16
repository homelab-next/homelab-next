# SPDX-License-Identifier: Apache-2.0
"""CLI: ``python -m homelabnext.detections <cmd>`` (to be mounted as ``hnx detections``)."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import detmap, lint
from .adapters import Target, get_backend
from .runner import run_all
from .sigma import load_mapping, load_rules


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="hnx detections")
    ap.add_argument("--root", default="detections", type=Path)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("lint")
    sub.add_parser("run")
    mp = sub.add_parser("map")
    mp.add_argument("--check", action="store_true")
    ln = sub.add_parser("lint-ids")
    ln.add_argument("paths", nargs="*", type=Path)
    cp = sub.add_parser("compile")
    cp.add_argument("backend")
    a = ap.parse_args(argv)
    root: Path = a.root
    mapfile = root / "det_map.yml"

    if a.cmd == "lint":
        probs = lint.lint_rules(root)
        print("\n".join(probs) or "lint ok")
        return 1 if probs else 0
    if a.cmd == "run":
        rep = run_all(root)
        print(rep.render())
        return 0 if rep.ok else 1
    if a.cmd == "map":
        rules = load_rules(root)
        existing = detmap.load(mapfile) if mapfile.exists() else None
        if a.check:
            probs = detmap.check_current(rules, existing or {"entries": {}})
            print("\n".join(probs) or "det map current")
            return 1 if probs else 0
        mapfile.write_text(detmap.dump(detmap.generate(rules, existing)), encoding="utf-8")
        print(f"wrote {mapfile}")
        return 0
    if a.cmd == "lint-ids":
        m = detmap.load(mapfile) if mapfile.exists() else None
        files = a.paths or lint.find_agent_files(Path("."))
        probs = lint.lint_no_rule_numbers(files, m)
        print("\n".join(probs) or "no engine rule numbers in agent-facing files")
        return 1 if probs else 0
    if a.cmd == "compile":
        m = detmap.load(mapfile) if mapfile.exists() else {"entries": {}}
        fm = root / "mappings" / "generic.yml"
        tgt = Target(a.backend, load_mapping(fm if fm.exists() else None), m["entries"])
        be = get_backend(a.backend)
        arts = [be.compile(r, tgt) for r in load_rules(root)]
        sys.stdout.write(
            be.bundle(arts) if hasattr(be, "bundle") else "\n".join(x.content for x in arts)
        )
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
