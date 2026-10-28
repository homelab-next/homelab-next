# SPDX-License-Identifier: Apache-2.0
"""``hnx guests``: validate, render and plan the guest (compute) model; report baseline coverage.

Exit codes: 0 ok, 1 an invalid guest set (or a failed ``baselines --check``), 2 a usage error or an
input that cannot be read or parsed (the site, the guest directory or a guest, policies, nodes,
keys or baselines file), 3 ``plan --exit-code`` found changes (as ``hnx site plan --exit-code``)."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence

from .baselines import coverage, coverage_text
from .loader import load_fleet
from .model import ComputeError, ComputeUnreadable
from .plan import plan as make_plan
from .plan import read_tree, write_tree
from .render import TARGETS, render
from .zones import (
    open_site,
    site_addresses,
    site_delegated6,
    site_deploy,
    site_flows,
    site_power,
)


def _common(p: argparse.ArgumentParser) -> None:
    p.add_argument("directory", help="directory of guest files (one <name>.yml per guest)")
    p.add_argument("--site", required=True, help="site model file that defines the zones")
    p.add_argument(
        "--policies", help="backup policy file (default: DIRECTORY/_backup_policies.yml)"
    )
    p.add_argument(
        "--baselines",
        help="baseline set file (default: DIRECTORY/_baselines.yml; without one no guest "
        "needs a baseline)",
    )
    p.add_argument("--keys", help="file mapping ssh key names to public keys (optional)")
    p.add_argument(
        "--nodes",
        help="node firewall file (default: DIRECTORY/_nodes.yml; nodes not listed run a firewall)",
    )
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
        nodes_path=args.nodes,
        baselines_path=args.baselines,
        # the coverage report lists guests without a baseline instead of refusing to load
        require_baselines=args.cmd != "baselines",
        flows=site_flows(args.site),
        power=site_power(args.site),
        deploy=site_deploy(args.site),
        site_addresses=site_addresses(args.site),
        delegated6=site_delegated6(args.site),
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
    pl.add_argument("--exit-code", action="store_true", help="exit 3 when there are changes")
    b = sub.add_parser("baselines", help="guest x defense-layer baseline coverage")
    _common(b)
    b.add_argument("--json", action="store_true", help="print the report as JSON")
    b.add_argument(
        "--check",
        action="store_true",
        help="exit 1 when there is no baseline set or a guest has neither a baseline nor an "
        "exemption",
    )
    b.add_argument(
        "--require-bound",
        action="store_true",
        help="like --check, and also exit 1 when a control some guest needs has no role yet, or "
        "is applied centrally on a group that holds no guest",
    )
    return ap


def _baselines(args: argparse.Namespace, fleet) -> int:
    if fleet.baselines is None:
        print(
            f"hnx guests baselines: no baseline set in {args.directory} "
            "(_baselines.yml or --baselines)",
            file=sys.stderr,
        )
        return 1 if (args.check or args.require_bound) else 0
    report = coverage(fleet.sorted(), fleet.baselines)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(coverage_text(report), end="")
    if not (args.check or args.require_bound):
        return 0
    bad = [r["id"] for r in report["guests"] if r["missing"]]
    if bad:
        print(f"hnx guests baselines: no baseline or exemption: {', '.join(bad)}", file=sys.stderr)
    if args.require_bound and report["unbound"]:
        print(
            "hnx guests baselines: needed controls not bound to a role: "
            + ", ".join(report["unbound"]),
            file=sys.stderr,
        )
        bad.append("unbound")
    if args.require_bound and report["unplaced"]:
        print(
            "hnx guests baselines: central controls whose group holds no guest (nowhere to run): "
            + ", ".join(f"{c} ({report['controls'][c]['group']})" for c in report["unplaced"]),
            file=sys.stderr,
        )
        bad.append("unplaced")
    if not bad:
        print("baselines: ok")
    return 1 if bad else 0


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(list(argv) if argv is not None else None)
    try:
        fleet = _fleet(args)
    except ComputeUnreadable as exc:  # docs/interfaces.md: bad input is 2, a failed check 1
        print(f"hnx guests: {exc}", file=sys.stderr)
        return 2
    except ComputeError as exc:
        print(f"hnx guests: {exc}", file=sys.stderr)
        return 1
    if args.cmd == "baselines":
        return _baselines(args, fleet)
    if args.cmd == "validate":
        iac = len(fleet.iac())
        print(f"ok: {len(fleet.guests)} guests ({iac} rendered, {len(fleet.manual())} manual)")
        from .validate import usage_lines

        for line in usage_lines(fleet):
            print(f"  {line}")
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
    # 3, not 2: 2 is an input that cannot be read, which must never read as "changes pending"
    return 3 if (args.exit_code and not p.empty) else 0


if __name__ == "__main__":
    sys.exit(main())
