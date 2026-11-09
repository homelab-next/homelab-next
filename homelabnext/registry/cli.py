# SPDX-License-Identifier: Apache-2.0
"""``hnx`` command line: validate, resolve, bindings, generate, check.

Exit codes: 0 ok, 1 an invalid registry, an unresolvable capability or drift, 2 usage error or a
registry file that cannot be read or parsed.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from homelabnext.generators import (
    GENERATORS,
    GeneratorRefusal,
    check_tree,
    flatten,
    generate,
    write_tree,
)
from homelabnext.generators.core import owned_dirs
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
    p.add_argument(
        "--row",
        action="store_true",
        help="resolve an eval or retiring row by its row name (ADR-0039), not a capability",
    )
    p = sub.add_parser(
        "bindings",
        help="refuse a binding to a non-primary row (ADR-0039 decision 3): upstreams, role "
        "bindings, pack targets and event sources, requires through the selection",
    )
    p.add_argument("registry")
    p.add_argument("--roles", action="append", default=[], help="a model-role table (repeatable)")
    p.add_argument(
        "--eval-report",
        action="append",
        default=[],
        help="an evaluation report whose canary bindings may name an eval row (repeatable); "
        "with --base or --ci-base also read from that commit, as the swap gate reads it",
    )
    which = p.add_mutually_exclusive_group()
    which.add_argument("--base", help="also read --eval-report from this commit")
    which.add_argument(
        "--ci-base",
        action="store_true",
        help="also read --eval-report from the base CI compares with",
    )
    p.add_argument("--root", default=".", help="the git checkout --eval-report is relative to")
    p.add_argument(
        "--packs", action="append", default=[], help="a workflow pack or a directory of packs"
    )
    p.add_argument(
        "--deployed",
        help="a workflow deploy manifest (workflows/deploy.yml): check only the --packs it pins",
    )
    p.add_argument(
        "--target", action="append", default=[], help="a conformance target file (repeatable)"
    )
    p.add_argument(
        "--gateway",
        action="append",
        default=[],
        help="an LLM gateway spec: its backends and role table against the registry (repeatable)",
    )
    p.add_argument("--site", help="a site selection: its modules' requires (with --modules)")
    p.add_argument(
        "--modules",
        action="append",
        default=[],
        help="a directory of module manifests the selection names (repeatable)",
    )
    p = sub.add_parser(
        "standing",
        help="list the non-primary rows and their until dates; --overdue fails on one past its "
        "date (ADR-0039 decision 8, checklist X-12)",
    )
    p.add_argument("registry")
    p.add_argument("--overdue", action="store_true", help="only rows past their until; exit 1")
    p.add_argument("--today", help="judge against this date (YYYY-MM-DD; default HNX_TODAY)")
    p.add_argument("--json", action="store_true", help="print the rows as JSON")
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
            f"ok: {len(reg.services)} services, {len(reg.non_primary)} non-primary, "
            f"{len(reg.hosts)} hosts, sha256:{reg.digest[:16]}",
            file=out,
        )
        return 0
    if args.cmd == "bindings":
        return _bindings(args, reg, out, err)
    if args.cmd == "standing":
        from homelabnext.registry import standing

        try:
            on = standing.today(_date(args.today) if args.today else None)
        except ValueError as exc:
            print(f"hnx: {exc}", file=err)
            return 2
        return standing.run(reg, on, overdue_only=args.overdue, as_json=args.json, out=out, err=err)
    if args.cmd == "resolve":
        try:
            res = Resolver(reg)
            ep = res.resolve_row(args.capability) if args.row else res.resolve(args.capability)
            print(ep.url, file=out)
            return 0
        except ResolutionError as exc:
            print(f"hnx: {exc}", file=err)
            return 1
    try:
        files = flatten(generate(reg, args.only))
    except KeyError as exc:
        print(f"hnx: {exc.args[0]}", file=err)
        return 2
    except GeneratorRefusal as exc:
        # a generator refusing this registry (an edge site with no login, a realm asked for by
        # name with no idp row of its format): the registry cannot be rendered as it is
        print(f"hnx: {exc}", file=err)
        return 1
    if args.cmd == "generate":
        res = write_tree(
            Path(args.out_dir), files, prune=args.only is None, dirs=owned_dirs(args.only)
        )
        print(
            f"written={len(res.written)} unchanged={len(res.unchanged)} pruned={len(res.pruned)}",
            file=out,
        )
        return 0
    problems = check_tree(Path(args.out_dir), files, owned_dirs(args.only))
    for p in problems:
        print(p, file=err)
    return 1 if problems else 0


def _bindings(args: argparse.Namespace, reg, out, err) -> int:
    """``hnx registry bindings``: exit 0 when every binding reaches a primary, 1 when one does
    not, 2 when an input cannot be read (:mod:`homelabnext.registry.bindings`)."""
    from homelabnext.registry import bindings as bd

    try:
        if bool(args.site) != bool(args.modules):
            raise bd.BindingsInputError("--site and --modules go together")
        tables = bd.load_role_tables(args.roles)
        reports = bd.load_eval_reports(args.eval_report, root=args.root, base=_base(args))
        packs = bd.load_packs(args.packs, args.deployed)
        targets = bd.load_targets(args.target)
        gateways = bd.load_gateways(args.gateway)
        site = mods = None
        if args.site:
            site, mods = bd.load_selection(args.site, args.modules)
        rep = bd.check(
            reg,
            tables=tables,
            reports=reports,
            packs=packs,
            targets=targets,
            gateways=gateways,
            site=site,
            mods=mods,
        )
    except bd.BindingsInputError as exc:
        print(f"hnx registry bindings: {exc}", file=err)
        return 2
    for n in rep.notes:
        print(f"note: {n}", file=out)
    for p in rep.problems:
        print(p, file=err)
    print(
        f"bindings: {len(rep.problems)} problem(s); {len(tables)} role table(s), "
        f"{len(reports)} report(s), {len(packs)} pack(s), {len(targets)} target(s), "
        f"{len(gateways)} gateway spec(s)" + (", the selection's requires" if site else ""),
        file=out,
    )
    return 1 if rep.problems else 0


def _base(args: argparse.Namespace) -> str | None:
    """The commit ``--eval-report`` is also read from: ``--base``, or ``--ci-base``'s pick (None
    for a root commit, which has no base)."""
    if args.base:
        return args.base
    if not args.ci_base:
        return None
    from homelabnext.gitbase import ci_base_from_env
    from homelabnext.registry.bindings import BindingsInputError

    try:
        base, _why = ci_base_from_env(Path(args.root))
    except ValueError as exc:
        raise BindingsInputError(f"--ci-base: {exc}") from None
    return base or None


def _date(raw: str):
    import datetime as dt

    try:
        return dt.date.fromisoformat(raw)
    except ValueError:
        raise ValueError(f"--today {raw!r} is not a YYYY-MM-DD date") from None


def _names() -> list[str]:
    from homelabnext.generators import builtin  # noqa: F401

    return sorted(GENERATORS)


if __name__ == "__main__":
    raise SystemExit(main())
