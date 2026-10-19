# SPDX-License-Identifier: Apache-2.0
"""``hnx custom``: list, check, plan and register customizations.

Exit codes: 0 clean (warnings allowed unless ``--strict``), 1 findings, 2 usage or unreadable
input. Nothing here modifies a deployment; ``plan`` prints what WOULD change.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import date
from pathlib import Path

from .apply import build_plan, write_plan
from .lint import lint
from .loader import REPO_ROOT, load_all, resolve_settings
from .model import days_left, extension_points
from .register import build_register, state_of
from .universe import discover


def _common(p: argparse.ArgumentParser) -> None:
    p.add_argument("--dir", action="append", default=[], help="local customizations directory")
    p.add_argument("--config", help="config file (customizations_dir, enable)")
    p.add_argument("--enable", action="append", default=[], metavar="ID[=HOST,HOST]")
    p.add_argument("--root", default=str(REPO_ROOT), help="tree providing registry/roles/schemas")
    p.add_argument("--registry")
    p.add_argument("--roles")
    p.add_argument("--profiles", help="shipped profiles directory (default: <root>/profiles)")
    p.add_argument("--today", help="YYYY-MM-DD (default: today)")
    p.add_argument("--json", action="store_true")


def _setup(ns: argparse.Namespace):
    root = Path(ns.root)
    settings = resolve_settings(
        ns.dir,
        ns.config,
        ns.enable,
        public_dir=Path(ns.profiles) if ns.profiles else root / "profiles",
    )
    items, load_problems = load_all(settings)
    uni = discover(
        root,
        Path(ns.registry) if ns.registry else None,
        Path(ns.roles) if ns.roles else None,
    )
    today = date.fromisoformat(ns.today) if ns.today else date.today()  # hermetic: allow CLI edge, --today
    return settings, items, load_problems, uni, today


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="hnx custom", description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    _common(sub.add_parser("list", help="list every customization with owner and expiry"))
    c = sub.add_parser("check", help="lint every customization (schema, owner, expiry, scope)")
    _common(c)
    c.add_argument("--strict", action="store_true", help="warnings fail too")
    pl = sub.add_parser("plan", help="show what the active customizations would change")
    _common(pl)
    pl.add_argument("--out", help="also write the plan JSON to this file (never inside core)")
    r = sub.add_parser("register", help="write customizations.html and customizations.json")
    _common(r)
    r.add_argument("out_dir")
    try:
        ns = ap.parse_args(argv)
        settings, items, load_problems, uni, today = _setup(ns)
    except SystemExit as exc:
        return 2 if exc.code else 0
    except (OSError, ValueError, KeyError) as exc:
        print(f"hnx custom: {exc}", file=sys.stderr)
        return 2
    enabled = settings.enabled

    if ns.cmd == "list":
        rows = [
            {
                "id": x.id,
                "kind": x.kind,
                "state": state_of(x, today, enabled),
                "owner": x.doc.get("owner", ""),
                "review_by": x.doc.get("review_by", ""),
                "days_left": days_left(x, today),
                "upstream_maintained": x.upstream_maintained,
                "upstream": x.doc.get("upstream", ""),
                "origin": x.origin,
                "extension_points": extension_points(x) if not x.schema_errors else [],
            }
            for x in sorted(items, key=lambda x: (x.origin, x.id))
        ]
        if ns.json:
            print(json.dumps(rows, indent=2, sort_keys=True))
        else:
            for r_ in rows:
                print(
                    f"{r_['id']:44s} {r_['kind']:14s} {r_['state']:9s} "
                    f"{r_['owner']:16s} "
                    f"{'upstream-maintained' if r_['upstream_maintained'] else r_['review_by']}"
                    f"  upstream={r_['upstream']}"
                )
            if not rows:
                print("no customizations found")
        return 0

    if ns.cmd == "check":
        findings = [*load_problems, *lint(items, uni, today, enabled)]
        if ns.json:
            print(json.dumps([f.as_dict() for f in findings], indent=2))
        else:
            for f in findings:
                print(f)
            print(f"hnx custom check: {len(items)} customization(s), {len(findings)} finding(s)")
        bad = any(f.severity == "error" or ns.strict for f in findings)
        return 1 if bad else 0

    if ns.cmd == "plan":
        plan = build_plan(items, uni, today, enabled)
        plan["findings"] += [f.as_dict() for f in load_problems]
        plan["ok"] = plan["ok"] and not load_problems
        if ns.out:
            try:
                write_plan(plan, Path(ns.out), uni)
            except PermissionError as exc:
                print(f"hnx custom: {exc}", file=sys.stderr)
                return 2
        print(json.dumps(plan, indent=2, sort_keys=True))
        return 0 if plan["ok"] else 1

    if ns.cmd == "register":
        for p in build_register(items, Path(ns.out_dir), today, enabled):
            print(p)
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
