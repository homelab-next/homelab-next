# SPDX-License-Identifier: Apache-2.0
"""``hnx models``: the model store and the serving plan.

``hnx models store validate STORE [--roles ROLES]``  the manifest is well formed (one copy per
    source, revision and quant; pinned commits; engines that can serve the format) and, with
    ``--roles``, every model-role binding resolves to a store entry an engine may serve
``hnx models store check STORE [--root DIR] [--only ID] [--sizes-only]``  the files on disk are
    the manifest's, by size and sha256 (and nothing unlisted sits beside them)
``hnx models store list STORE [--json]``  every entry with its size and digest (the value a role
    binding pins)
``hnx models serving render|check SPEC OUT_DIR``  the vllm_server role's instances from a
    serving spec (store + role table + engines), or a drift check

Exit codes: 0 ok, 1 invalid or drift, 2 usage or unreadable input.
"""

from __future__ import annotations

import argparse
import json
import sys

from homelabnext.registry.models import RoleTable, RoleTableError

from . import serving
from .store import StoreError, StoreUnreadable, bindings_problems, check_disk, load


def main(argv: list[str]) -> int:
    if argv[:1] == ["serving"]:
        return serving.main(argv[1:])
    ap = argparse.ArgumentParser(prog="hnx models", description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    st = sub.add_parser("store", help="the model store manifest")
    st.add_argument("action", choices=("validate", "check", "list"))
    st.add_argument("store")
    st.add_argument("--roles", help="validate: also resolve every binding of this role table")
    st.add_argument("--root", help="check: the store root on disk (default: the manifest's)")
    st.add_argument("--only", action="append", help="check: this entry only (repeatable)")
    st.add_argument("--sizes-only", action="store_true", help="check: skip the sha256 pass")
    st.add_argument("--json", action="store_true", help="list: JSON")
    sub.add_parser("serving", help="render|check SPEC OUT_DIR (the vllm_server instances)")
    args = ap.parse_args(argv)
    try:
        store = load(args.store)
    except StoreUnreadable as exc:
        print(f"models: {exc}", file=sys.stderr)
        return 2
    except StoreError as exc:
        print(f"models: {args.store}: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"models: cannot read {args.store}: {exc}", file=sys.stderr)
        return 2
    if args.action == "list":
        rows = store.to_listing()
        if args.json:
            print(json.dumps(rows, indent=2))
        else:
            for r in rows:
                print(f"{r['id']}\t{r['format']}/{r['quant']}\t{r['size']}\t{r['digest']}")
        return 0
    if args.action == "validate":
        problems: list[str] = []
        if args.roles:
            try:
                problems = bindings_problems(store, RoleTable.load(args.roles))
            except (RoleTableError, OSError, ValueError) as exc:
                print(f"models: role table {args.roles}: {exc}", file=sys.stderr)
                return 2
        for p in problems:
            print(f"models: {p}", file=sys.stderr)
        if not problems:
            print(f"models: {len(store.entries)} store entries valid")
        return 1 if problems else 0
    problems = check_disk(store, args.root, only=args.only, sizes_only=args.sizes_only)
    for p in problems:
        print(f"models: {p}", file=sys.stderr)
    if not problems:
        n = len(args.only) if args.only else len(store.entries)
        how = "by size" if args.sizes_only else "by sha256"
        print(f"models: {n} store entries match the manifest {how}")
    return 1 if problems else 0
