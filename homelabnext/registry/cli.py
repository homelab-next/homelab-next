# SPDX-License-Identifier: Apache-2.0
"""``hnx`` command line: validate, resolve, generate, check.

Exit codes: 0 ok, 1 an invalid registry, an unresolvable capability or drift, 2 usage error or a
registry file that cannot be read or parsed.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from homelabnext.generators import GENERATORS, check_tree, flatten, generate, write_tree
from homelabnext.registry.model import RegistryError, RegistryUnreadable, load
from homelabnext.registry.resolver import ResolutionError, Resolver


def main(argv: list[str] | None = None, out=None, err=None) -> int:
    out = out or sys.stdout
    err = err or sys.stderr
    ap = argparse.ArgumentParser(
        prog="hnx registry", description="HomelabNext service registry tools"
    )
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("validate", "list-generators"):
        p = sub.add_parser(name)
        if name == "validate":
            p.add_argument("registry")
    p = sub.add_parser(
        "resolve", help="resolve one capability using the registry, DNS and hosts file"
    )
    p.add_argument("registry")
    p.add_argument("capability")
    for name in ("generate", "check"):
        p = sub.add_parser(
            name,
            help="render generators into a tree"
            if name == "generate"
            else "fail on drift between registry and tree",
        )
        p.add_argument("registry")
        p.add_argument("out_dir")
        p.add_argument("--only", action="append", default=None, help="generator name (repeatable)")
    try:
        args = ap.parse_args(argv)
    except SystemExit as exc:
        return int(exc.code or 0) if exc.code != 0 else 0
    if args.cmd == "list-generators":
        for n in _names():
            print(n, file=out)
        return 0
    try:
        reg = load(args.registry)
    except RegistryUnreadable as exc:
        print(f"hnx: {exc}", file=err)
        return 2
    except RegistryError as exc:
        print(f"hnx: {exc}", file=err)
        return 1
    if args.cmd == "validate":
        print(
            f"ok: {len(reg.services)} services, {len(reg.hosts)} hosts, sha256:{reg.digest[:16]}",
            file=out,
        )
        return 0
    if args.cmd == "resolve":
        try:
            print(Resolver(reg).resolve(args.capability).url, file=out)
            return 0
        except ResolutionError as exc:
            print(f"hnx: {exc}", file=err)
            return 1
    try:
        files = flatten(generate(reg, args.only))
    except KeyError as exc:
        print(f"hnx: {exc.args[0]}", file=err)
        return 2
    if args.cmd == "generate":
        res = write_tree(Path(args.out_dir), files, prune=args.only is None)
        print(
            f"written={len(res.written)} unchanged={len(res.unchanged)} pruned={len(res.pruned)}",
            file=out,
        )
        return 0
    problems = check_tree(Path(args.out_dir), files)
    for p in problems:
        print(p, file=err)
    return 1 if problems else 0


def _names() -> list[str]:
    from homelabnext.generators import builtin  # noqa: F401

    return sorted(GENERATORS)


if __name__ == "__main__":
    raise SystemExit(main())
