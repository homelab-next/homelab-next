# SPDX-License-Identifier: Apache-2.0
"""hnx registers: build the pages, convert between the two register forms, refresh links.

build SRC_DIR OUT_DIR [--results FILE] [--policy FILE]
                     validate and render lessons/runbooks/invariants (fatal)
split FILE.yml DIR   a single-file register -> one record file per entry
join DIR FILE.yml    the reverse (for review or a downstream tool)
links DIR... [--check]
                     regenerate each record's `## Links` block; --check only reports stale
                     ones (exit 1)
review SRC_DIR [--today YYYY-MM-DD] [--strict] [--json]
                     what the lesson review should do (missing reviews, retire, incorporate,
                     supersede, update, keep); warns and exits 0 unless --strict
"""

import argparse
import datetime as dt
import json
import sys

from . import RegisterError, build_all, join_register, split_register, stale_links


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="hnx registers", description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build", help="validate and render registers to HTML + JSON")
    b.add_argument("src")
    b.add_argument("out")
    b.add_argument(
        "--results", help="invariants results JSON (default SRC/invariants.results.json)"
    )
    b.add_argument("--policy", help="review policy (default review-policy.yml in or beside SRC)")
    s = sub.add_parser("split", help="convert lessons.yml/runbooks.yml into a record directory")
    s.add_argument("src")
    s.add_argument("dir")
    j = sub.add_parser("join", help="convert a record directory back into one YAML file")
    j.add_argument("dir")
    j.add_argument("out")
    lk = sub.add_parser("links", help="regenerate the `## Links` block of every record file")
    lk.add_argument("dirs", nargs="+")
    lk.add_argument("--check", action="store_true", help="report stale blocks, write nothing")
    rv = sub.add_parser("review", help="what is due in the lesson review, grouped by action")
    rv.add_argument("src")
    rv.add_argument("--today", type=dt.date.fromisoformat, help="YYYY-MM-DD (default: today)")
    rv.add_argument("--strict", action="store_true", help="exit 1 when anything is due")
    rv.add_argument("--json", action="store_true", help="machine-readable output")
    rv.add_argument("--results", help="invariants results JSON (default SRC/...results.json)")
    rv.add_argument("--policy", help="review policy (default review-policy.yml in or beside SRC)")
    ns = ap.parse_args(argv)
    try:
        if ns.cmd == "build":
            for p in build_all(ns.src, ns.out, ns.results, ns.policy):
                print(p)
        elif ns.cmd == "review":
            from .due import review
            from .render import load_sources

            rep = review(load_sources(ns.src, ns.policy, ns.results), ns.today)
            if ns.json:
                print(json.dumps(rep.as_json(), indent=2, sort_keys=True))
            else:
                for line in rep.lines():
                    print(f"[registers] {line}")
            if (rep.items or rep.warnings) and ns.strict:
                return 1
        elif ns.cmd == "split":
            written = split_register(ns.src, ns.dir)
            print(f"[registers] {ns.src}: {len(written)} record file(s) in {ns.dir}")
        elif ns.cmd == "join":
            print(join_register(ns.dir, ns.out))
        else:
            stale = [p for d in ns.dirs for p in stale_links(d, write=not ns.check)]
            for p in stale:
                print(f"[registers] {'stale' if ns.check else 'rewrote'} links block: {p}")
            if ns.check and stale:
                print(
                    "[registers] FATAL: run `hnx registers links " + " ".join(ns.dirs) + "`",
                    file=sys.stderr,
                )
                return 1
    except RegisterError as ex:
        print(f"[registers] FATAL: {ex}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
