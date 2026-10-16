# SPDX-License-Identifier: Apache-2.0
"""python -m homelabnext.registers build SRC_DIR OUT_DIR [--results FILE]"""

import argparse
import sys

from . import RegisterError, build_all


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="hnx registers")
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build", help="validate and render registers to HTML + JSON")
    b.add_argument("src")
    b.add_argument("out")
    b.add_argument(
        "--results", help="invariants results JSON (default SRC/invariants.results.json)"
    )
    ns = ap.parse_args(argv)
    try:
        for p in build_all(ns.src, ns.out, ns.results):
            print(p)
    except RegisterError as ex:
        print(f"[registers] FATAL: {ex}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
