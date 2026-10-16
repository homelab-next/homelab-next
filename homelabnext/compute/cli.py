# SPDX-License-Identifier: Apache-2.0
"""``hnx guests``: validate, render and plan the guest (compute) model."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from .loader import load_fleet
from .model import ComputeError
from .plan import plan as make_plan
from .plan import read_tree, write_tree
from .render import TARGETS, render
from .zones import open_site


def _common(p: argparse.ArgumentParser) -> None:
    p.add_argument("directory", help="directory of guest files (one <name>.yml per guest)")
    p.add_argument("--site", required=True, help="site model file that defines the zones")
    p.add_argument(
        "--policies", help="backup policy file (default: DIRECTORY/_backup_policies.yml)"
    )
    p.add_argument("--keys", help="file mapping ssh key names to public keys (optional)")
    p.add_argument(
        "--domain", help="DNS domain (default: the site's domain, else example.internal)"
    )


def _fleet(args: argparse.Namespace):
    zones, site_domain = open_site(args.site)
    return load_fleet(
        args.directory,
        zones,
        domain=args.domain or site_domain or "example.internal",
        policies_path=args.policies,
        keys_path=args.keys,
    )


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="hnx guests", description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    v = sub.add_parser("validate", help="schema and semantic validation")
    _common(v)
    r = sub.add_parser("render", help="render one target")
    _common(r)
    r.add_argument("--target", required=True, choices=sorted(TARGETS))
    r.add_argument("--out", help="write files here (default: print a file list)")
    pl = sub.add_parser("plan", help="diff a fresh render against a previous render directory")
    _common(pl)
    pl.add_argument("--target", required=True, choices=sorted(TARGETS))
    pl.add_argument("--against", required=True, help="directory holding the previous render")
    pl.add_argument("--exit-code", action="store_true", help="exit 2 when there are changes")
    return ap


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(list(argv) if argv is not None else None)
    try:
        fleet = _fleet(args)
    except ComputeError as exc:
        print(f"hnx guests: {exc}", file=sys.stderr)
        return 1
    if args.cmd == "validate":
        iac = len(fleet.iac())
        print(f"ok: {len(fleet.guests)} guests ({iac} rendered, {len(fleet.manual())} manual)")
        return 0
    files = render(fleet, args.target)
    if args.cmd == "render":
        if args.out:
            write_tree(args.out, files)
            print(f"wrote {len(files)} files to {args.out}")
        else:
            for name in sorted(files):
                print(f"==> {name} <==")
                print(files[name], end="")
        return 0
    p = make_plan(read_tree(args.against), files)
    print(f"plan: {p.summary()}")
    print(p.diff, end="")
    return 2 if (args.exit_code and not p.empty) else 0


if __name__ == "__main__":
    sys.exit(main())
