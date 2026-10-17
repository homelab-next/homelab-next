# SPDX-License-Identifier: Apache-2.0
"""``hnx decommission check|plan NAME``.

Exit codes: 0 clean, 1 remnants (or nothing could be measured, or the positive control came back
clean), 2 usage error.
"""

from __future__ import annotations

import argparse
import json
import sys

from .adapters import Adapters, DirTree
from .engine import plan, positive_control, render, run
from .model import Target
from .planes import PLANES


def _parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="hnx decommission",
        description="Read-only audit: what of a retired guest is still lying around?",
    )
    ap.add_argument("cmd", choices=["check", "plan", "planes"])
    ap.add_argument("name", nargs="?", help="guest name")
    ap.add_argument("--root", action="append", default=[], help="source tree to scan (repeatable)")
    ap.add_argument("--vmid", type=int)
    ap.add_argument("--node")
    ap.add_argument("--ip", action="append", default=[])
    ap.add_argument("--alias", action="append", default=[])
    ap.add_argument("--snapshot", help="JSON snapshot of hypervisor/SIEM/DNS/... state")
    ap.add_argument("--only", action="append", default=None, help="plane name (repeatable)")
    ap.add_argument("--strict", action="store_true", help="REVIEW and SKIP also fail")
    ap.add_argument(
        "--control", metavar="LIVE_NAME", help="positive control: a LIVE guest that must be flagged"
    )
    ap.add_argument("--control-vmid", type=int)
    ap.add_argument("--json", action="store_true")
    return ap


def main(argv: list[str] | None = None) -> int:
    ap = _parser()
    try:
        args = ap.parse_args(argv)
    except SystemExit as exc:
        return 2 if exc.code else 0
    if args.cmd == "planes":
        for n in PLANES:
            print(n)
        return 0
    if not args.name:
        print("hnx decommission: a guest NAME is required", file=sys.stderr)
        return 2
    try:
        tree = DirTree(*args.root) if args.root else None
        adapters = Adapters.from_file(args.snapshot, tree) if args.snapshot else Adapters(tree=tree)
        target = Target(args.name, args.vmid, args.node, tuple(args.ip), tuple(args.alias))
        if args.control:
            ctl = positive_control(Target(args.control, args.control_vmid), adapters, args.only)
            if not ctl.remnants:
                print(
                    f"hnx decommission: POSITIVE CONTROL FAILED: live guest {args.control!r} came "
                    "back clean, so this audit cannot be trusted",
                    file=sys.stderr,
                )
                return 1
        report = run(target, adapters, args.only)
    except (OSError, ValueError, KeyError) as exc:
        print(f"hnx decommission: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(report.to_dict(args.strict), indent=2))
    else:
        print(plan(report) if args.cmd == "plan" else render(report, args.strict))
    return report.exit_code(args.strict)


if __name__ == "__main__":
    sys.exit(main())
