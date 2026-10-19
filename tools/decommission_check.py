#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# hnx-script:
#   id: decommission-check
#   kind: tool
#   purpose: Report every remaining reference to a service retired by a swap (ADR-0005 step 8).
#   owner: maintainers
#   trigger: [manual]
#   inputs: the roots to scan and the retired service's names (flags, or --from-record)
#   outputs: one line per remaining reference, or JSON with --json
#   exit:
#     "0": no reference remains
#     "1": references remain
#     "2": usage error
"""Exit non-zero if any reference to a retired service remains.

    python tools/decommission_check.py ROOT [ROOT ...] --host old-host --impl oldproduct \\
        --alias old-query.svc.example.internal --env-var OLD_ENDPOINT --unit old-sync \\
        [--registry services.yml] [--inventory hosts.yml] [--allow allow.txt] [--json]
    python tools/decommission_check.py ROOT --from-record swaps/swap-0001.swap.json

Exit codes: 0 clean, 1 references remain, 2 usage error.

Scope: this is the SERVICE-swap scanner (ADR-0005 step 8): "does anything still point at the
retired product?".  For retiring a whole GUEST (inventory, IaC, hypervisor leftovers, SIEM roster,
secret names, DNS, DHCP ...) use ``hnx decommission check|plan NAME`` (docs/decommission.md).
This tool stays supported and unchanged; the swap runner calls the same scanner.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from homelabnext.swap.decommission import (  # noqa: E402
    Retired,
    load_allow,
    retired_from_record,
    scan,
)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="decommission_check", description=__doc__.split("\n")[0])
    ap.add_argument("roots", nargs="+", help="directories or files to scan")
    ap.add_argument("--name", default="retired", help="label for the retired service")
    for opt in ("host", "impl", "alias", "env-var", "unit", "word"):
        ap.add_argument(f"--{opt}", action="append", default=[], help=f"retired {opt} (repeatable)")
    ap.add_argument("--registry", help="registry YAML to check structurally")
    ap.add_argument("--inventory", action="append", default=[], help="inventory file (repeatable)")
    ap.add_argument("--allow", action="append", default=[], help="file of allow globs (repeatable)")
    ap.add_argument("--from-record", help="derive the retired names from a swap record")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    try:
        args = ap.parse_args(argv)
    except SystemExit as e:
        return 2 if e.code else 0

    retired = Retired(
        args.name,
        tuple(args.host),
        tuple(args.impl),
        tuple(args.alias),
        tuple(args.env_var),
        tuple(args.unit),
        tuple(args.word),
    )
    if args.from_record:
        try:
            base = retired_from_record(json.loads(Path(args.from_record).read_text("utf-8")))
        except (OSError, ValueError, KeyError) as exc:
            print(f"decommission_check: cannot read record: {exc}", file=sys.stderr)
            return 2
        retired = Retired(
            base.name,
            (*base.hosts, *retired.hosts),
            (*base.impls, *retired.impls),
            retired.aliases,
            retired.env_vars,
            retired.units,
            retired.words,
        )
    if not retired.terms():
        print(
            "decommission_check: nothing to look for; give --host/--impl/... or --from-record",
            file=sys.stderr,
        )
        return 2
    allow: list[str] = []
    try:
        for a in args.allow:
            allow += load_allow(a)
        findings = scan(
            args.roots, retired, registry=args.registry, inventory=args.inventory, allow=allow
        )
    except (OSError, ValueError) as exc:
        print(f"decommission_check: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(
            json.dumps(
                {"clean": not findings, "findings": [f.to_dict() for f in findings]}, indent=2
            )
        )
    elif findings:
        print(f"decommission_check: {len(findings)} reference(s) to {retired.name!r} remain:")
        for f in findings:
            print(f"  {f}")
    else:
        print(f"decommission_check: no references to {retired.name!r} remain")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
