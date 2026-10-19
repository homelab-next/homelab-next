# SPDX-License-Identifier: Apache-2.0
"""``hnx scripts catalog [--check] | reality | runner-lint | list`` (checklist M-01, M-02, M-04).

Exit codes: 0 ok, 1 findings (an invalid or missing header, a stale catalog, a mismatch with
reality, a check outside the runner), 2 usage error or an unreadable allowlist.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys

from .catalog import CATALOG_JSON, CATALOG_MD, build, check_current, tracked_files, write
from .reality import ALLOW_FILE, AllowError, discover, load_allow, reality_problems, runner_problems


def _report(name: str, problems: list[str], ok: str) -> int:
    for p in problems:
        print(f"  {p}")
    if problems:
        print(f"{name}: FAIL ({len(problems)} problem{'s' if len(problems) != 1 else ''})")
        return 1
    print(f"{name}: {ok}")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="hnx scripts", description=__doc__.split("\n")[0])
    ap.add_argument("--root", default=".", help="repository root (default: .)")
    ap.add_argument("--allow", help=f"settings and allowlist (default: ROOT/{ALLOW_FILE})")
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("catalog", help=f"write {CATALOG_JSON} and {CATALOG_MD} from the headers")
    c.add_argument("--check", action="store_true", help="write nothing; fail if not current")
    sub.add_parser("reality", help="compare the headers with what really runs each script")
    sub.add_parser("runner-lint", help="every check runs through the runner; no check timers")
    ls = sub.add_parser("list", help="print the catalog entries")
    ls.add_argument("--json", action="store_true")
    try:
        ns = ap.parse_args(argv)
    except SystemExit as exc:
        return 2 if exc.code else 0
    root = pathlib.Path(ns.root)
    files = tracked_files(root)
    cat = build(root, files)

    if ns.cmd == "list":
        if ns.json:
            print(json.dumps(cat.entries, indent=2, sort_keys=True))
        else:
            for e in cat.entries:
                print(f"{e['id']:24s} {e['kind']:8s} {e['path']}")
        return 1 if cat.problems else 0
    if ns.cmd == "catalog":
        if ns.check:
            probs = cat.problems + check_current(root, cat)
            return _report("scripts catalog", probs, f"current ({len(cat.entries)} scripts)")
        if cat.problems:
            return _report("scripts catalog", cat.problems, "")
        for p in write(root, cat):
            print(p)
        return 0
    try:
        allow = load_allow(root, ns.allow)
    except AllowError as exc:
        print(f"hnx scripts: {exc}", file=sys.stderr)
        return 2
    real = discover(root, cat, files, allow)
    if ns.cmd == "reality":
        probs = [p for p in cat.problems if "duplicate script id" not in p]
        probs += reality_problems(cat, real, allow)
        return _report(
            "scripts reality", probs, f"catalog matches reality ({len(cat.entries)} scripts)"
        )
    checks = sum(e["kind"] == "check" for e in cat.entries)
    probs = cat.problems + runner_problems(cat, real, allow)
    return _report(
        "scripts runner-lint", probs, f"every check runs through the invariants runner ({checks})"
    )


if __name__ == "__main__":
    sys.exit(main())
