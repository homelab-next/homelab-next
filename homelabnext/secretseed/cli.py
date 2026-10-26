# SPDX-License-Identifier: Apache-2.0
"""``hnx secrets``: list the credentials a lab names, and create the missing ones.

    hnx secrets plan PATH... [--spec lab/secrets.yml] [--json]
    hnx secrets seed PATH... --spec lab/secrets.yml [--vaultwarden] [--ask] [--dry-run]

``plan`` reads files only.  ``seed`` writes to OpenBao as the operator (``BAO_ADDR``,
``BAO_TOKEN``, ``BAO_CACERT``) and, with ``--vaultwarden``, to the folder the spec names through
an unlocked ``bw`` (``BW_SESSION``).  Both print names and outcomes, never a value.
"""

from __future__ import annotations

import argparse
import getpass
import json
import sys
from collections.abc import Sequence

from . import OpenBaoKV, Rule, SeedError, Spec, Vaultwarden, load_spec, scan, seed


def _ask(name: str, rule: Rule) -> str:
    if not sys.stdin.isatty():
        return ""
    print(f"secret:{name} is external: {rule.how}", file=sys.stderr)
    return getpass.getpass(f"value for secret:{name} (empty to skip): ").strip()


def main(argv: Sequence[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="hnx secrets", description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    pl = sub.add_parser("plan", help="list every secret:<name> the files name, and its kind")
    sd = sub.add_parser("seed", help="create the missing secrets in OpenBao (and Vaultwarden)")
    for p in (pl, sd):
        p.add_argument("paths", nargs="+", help="files or directories to scan (the overlay, roles)")
    pl.add_argument("--spec", help="secrets.yml: how each name gets its value")
    pl.add_argument("--json", action="store_true")
    sd.add_argument("--spec", required=True, help="secrets.yml: how each name gets its value")
    sd.add_argument("--vaultwarden", action="store_true", help="also copy into Vaultwarden (bw)")
    sd.add_argument("--ask", action="store_true", help="prompt for each missing external secret")
    sd.add_argument("--dry-run", action="store_true", help="read OpenBao, write nothing")
    args = ap.parse_args(argv)
    try:
        found = scan(args.paths)
        spec = load_spec(args.spec) if args.spec else Spec()
        if args.cmd == "plan":
            rows = [
                {"name": n, "kind": spec.rule(n).kind, "named_in": where}
                for n, where in found.items()
            ]
            if args.json:
                print(json.dumps(rows, indent=2))
            else:
                for r in rows:
                    more = len(r["named_in"]) - 1
                    also = f" and {more} more" if more else ""
                    print(f"{r['kind']:<9} secret:{r['name']}  ({r['named_in'][0]}{also})")
                print(f"{len(rows)} secret(s)")
            return 0
        bao = OpenBaoKV.from_env()
        vault = Vaultwarden(spec.vaultwarden_folder) if args.vaultwarden else None
        out = seed(found, spec, bao, vault, dry_run=args.dry_run, ask=_ask if args.ask else None)
    except SeedError as exc:
        print(f"hnx secrets: {exc}", file=sys.stderr)
        return 2
    for o in out:
        line = f"{o.openbao:<12} {o.vaultwarden:<12} {o.kind:<9} secret:{o.name}"
        print(line + (f"  {o.detail}" if o.detail else ""))
    errors = sum(1 for o in out if "error" in (o.openbao, o.vaultwarden))
    missing = [o.name for o in out if o.openbao == "needs-value"]
    print(f"{len(out)} secret(s); {errors} error(s); {len(missing)} external still need a value")
    return 1 if errors else 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
