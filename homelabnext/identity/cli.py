# SPDX-License-Identifier: Apache-2.0
"""``hnx records``: record identity (ADR-0019).

    hnx records assign-uids TREE... [--also PATH...] [--customizations DIR...] [--dry-run]
        give every record without a uid its UUIDv7, rename it <uid>.md, rewrite every reference
        to its numbered code (records, sidecar events, the --also files, the ``links`` of every
        customization) and record the code in TREE/aliases.yml; idempotent (exit 0; 1 on a
        problem, nothing written).  The customizations are the ones ``hnx custom`` loads (the
        shipped profiles, HNX_CUSTOMIZATIONS_CONFIG and HNX_CUSTOMIZATIONS_DIR) unless
        --customizations names the directories (none: ``--customizations`` alone)
    hnx records numbers TREE [--json]
        every record of a strategy or registers tree with its computed display number
    hnx records uid [-n N]
        print N new uids (UUIDv7), for a new record's ``uid:`` and file name

A TREE is a strategy directory (``examples/strategy``) or a registers directory holding
``lessons/`` and ``runbooks/`` (``examples/registers``).
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys


def _numbers(tree: pathlib.Path) -> list[dict[str, str]]:
    """[{uid, type, label, title}] of a tree's records, in display-number order."""
    if (tree / "strategy.md").is_file():
        from homelabnext.strategy.records import load_tree

        t = load_tree(tree)
        return [
            {"uid": k, "type": str(e.get("type")), "label": t.label(k), "title": e.get("title")}
            for kind, k, e in t.items()
            if kind != "strategy"
        ]
    from homelabnext.identity import node_of
    from homelabnext.identity.numbers import sibling_key
    from homelabnext.registers.records import load_register, register_source
    from homelabnext.registers.schema import labels_of

    out = []
    for kind in ("lessons", "runbooks"):
        src = register_source(tree, kind)
        if src is None:
            continue
        entries = [e for e in load_register(src, kind)[kind] if isinstance(e, dict)]
        labels = labels_of(entries)
        for e in sorted(entries, key=lambda e: sibling_key(node_of(e))):
            out.append(
                {
                    "uid": str(e.get("uid")),
                    "type": str(e.get("type")),
                    "label": labels.get(str(e.get("uid")), "?"),
                    "title": e.get("title"),
                }
            )
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="hnx records", description="record identity (ADR-0019)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("assign-uids", help="migrate numbered records to uids (idempotent)")
    a.add_argument("trees", nargs="+", help="strategy or registers directories")
    a.add_argument("--also", nargs="*", default=[], help="other files whose codes to rewrite")
    a.add_argument(
        "--customizations",
        nargs="*",
        default=None,
        help="customization directories whose links to rewrite (default: those hnx custom loads)",
    )
    a.add_argument("--dry-run", action="store_true", help="report, write nothing")
    n = sub.add_parser("numbers", help="the computed display number of every record")
    n.add_argument("tree")
    n.add_argument("--json", action="store_true")
    u = sub.add_parser("uid", help="print new uids (UUIDv7) for new records")
    u.add_argument("-n", type=int, default=1)
    try:
        ns = ap.parse_args(argv)
    except SystemExit as exc:
        return 2 if exc.code else 0
    if ns.cmd == "uid":
        from .uid import uuid7

        print("\n".join(uuid7() for _ in range(max(ns.n, 1))))
        return 0
    if ns.cmd == "numbers":
        from homelabnext.registers.schema import RegisterError

        try:
            rows = _numbers(pathlib.Path(ns.tree))
        except RegisterError as ex:
            print(f"[records] FATAL: {ex}", file=sys.stderr)
            return 1
        if ns.json:
            print(json.dumps(rows, indent=1))
        else:
            for r in rows:
                print(f"{r['label']:<12} {r['uid']}  {r['title']}")
        return 0
    from .migrate import MigrationError, assign_uids

    custom = ns.customizations
    if custom is None:
        from homelabnext.customization.loader import resolve_settings

        settings = resolve_settings()
        custom = [settings.public_dir, *settings.local_dirs]
    try:
        plan = assign_uids(ns.trees, also=ns.also, customizations=custom, dry_run=ns.dry_run)
    except MigrationError as ex:
        print(f"[records] FATAL: {ex}", file=sys.stderr)
        return 1
    verb = "would" if ns.dry_run else ""
    for code, uid in plan.assigned.items():
        print(f"[records] {code} -> {uid}")
    for old, new in plan.renamed:
        print(f"[records] {verb + ' ' if verb else ''}rename {old} -> {new.name}")
    for uid in plan.rekeyed:
        print(f"[records] rekey {uid}: its current reviews carried across the rewrite")
    n_written = len(set(plan.written))
    state = "nothing to do" if not plan.changed else f"{n_written} file(s) written"
    if ns.dry_run:
        state = f"dry run: {n_written} file(s) would be written"
    print(f"[records] {len(plan.assigned)} uid(s) assigned; {state}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
