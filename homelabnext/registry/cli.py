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
        "with --base or --ci-base read from that commit, as the swap gate reads it",
    )
    which = p.add_mutually_exclusive_group()
    which.add_argument("--base", help="read --eval-report from this commit")
    which.add_argument(
        "--ci-base", action="store_true", help="read --eval-report from the base CI compares with"
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


class _Usage(Exception):
    """An input of ``bindings`` that cannot be read (exit 2)."""


def _bindings(args: argparse.Namespace, reg, out, err) -> int:
    """``hnx registry bindings``: exit 0 when every binding reaches a primary, 1 when one does
    not, 2 when an input cannot be read."""
    from homelabnext.registry.bindings import check

    try:
        if bool(args.site) != bool(args.modules):
            raise _Usage("--site and --modules go together")
        tables = [(path, _role_table(path)) for path in args.roles]
        reports = _eval_reports(args)
        packs = _packs(args.packs, args.deployed)
        targets = [(path, _doc(path)) for path in args.target]
        site = mods = None
        if args.site:
            site, mods = _selection(args.site, args.modules)
    except _Usage as exc:
        print(f"hnx registry bindings: {exc}", file=err)
        return 2
    rep = check(
        reg, tables=tables, reports=reports, packs=packs, targets=targets, site=site, mods=mods
    )
    for n in rep.notes:
        print(f"note: {n}", file=out)
    for p in rep.problems:
        print(p, file=err)
    print(
        f"bindings: {len(rep.problems)} problem(s); {len(tables)} role table(s), "
        f"{len(reports)} report(s), {len(packs)} pack(s), {len(targets)} target(s)"
        + (", the selection's requires" if site is not None else ""),
        file=out,
    )
    return 1 if rep.problems else 0


def _doc(path: str):
    from homelabnext.workflows.pack import WorkflowError, load_doc

    try:
        return load_doc(Path(path))
    except WorkflowError as exc:
        raise _Usage(str(exc)) from None


def _role_table(path: str):
    from homelabnext.registry.models import RoleTable, RoleTableError

    try:
        return RoleTable.load(path)
    except (OSError, RoleTableError) as exc:
        raise _Usage(f"{path}: {exc}") from None


def _eval_reports(args: argparse.Namespace) -> list:
    """Each ``--eval-report``: from the working tree, or with ``--base``/``--ci-base`` from that
    commit (absent there: skipped, as the swap gate has no report from it either)."""
    if not args.eval_report:
        return []
    if not (args.base or args.ci_base):
        return [(path, _doc(path)) for path in args.eval_report]
    import json

    from homelabnext.gitbase import ci_base_from_env
    from homelabnext.modules.swap_evidence import EvidenceError, read_base

    root = Path(args.root)
    base = args.base
    if args.ci_base:
        try:
            base, _why = ci_base_from_env(root)
        except ValueError as exc:
            raise _Usage(f"--ci-base: {exc}") from None
        if not base:
            return []  # a root commit: no base, so no report the gate would trust
    out = []
    for rel in args.eval_report:
        try:
            data = read_base(root, base, rel, missing_ok=True)
        except EvidenceError as exc:
            raise _Usage(str(exc)) from None
        if data is None:
            continue
        try:
            out.append((f"{rel}@{base[:12]}", json.loads(data.decode("utf-8"))))
        except (UnicodeDecodeError, ValueError) as exc:
            why = f"not valid JSON ({exc.__class__.__name__})"
            raise _Usage(f"{rel} at {base[:12]}: {why}") from None
    return out


def _packs(paths: list[str], deployed: str | None) -> list:
    from homelabnext.workflows.pack import WorkflowError, expand

    try:
        files = expand(Path(p) for p in paths)
    except WorkflowError as exc:
        raise _Usage(str(exc)) from None
    packs = [(str(f), _doc(str(f))) for f in files]
    if deployed is None:
        return packs
    manifest = _doc(deployed)
    pins = manifest.get("pins") if isinstance(manifest, dict) else None
    if not isinstance(pins, list):
        raise _Usage(f"{deployed}: no pins list")
    names = {p.get("pack") for p in pins if isinstance(p, dict)}
    held = {doc.get("pack") for _w, doc in packs if isinstance(doc, dict)}
    missing = sorted(str(n) for n in names - held)
    if missing:
        raise _Usage(f"{deployed} pins {', '.join(missing)}, which --packs does not hold")
    return [(w, doc) for w, doc in packs if isinstance(doc, dict) and doc.get("pack") in names]


def _selection(site_path: str, modules: list[str]):
    from homelabnext.modules import loader as ld

    try:
        site = ld.load_input(site_path)
    except (OSError, ValueError) as exc:
        raise _Usage(f"{site_path}: {exc}") from None
    if not isinstance(site, dict):
        raise _Usage(f"{site_path}: not a mapping")
    mods: dict = {}
    for d in modules:
        tree, problems = ld.discover(public=Path(d))
        if problems:
            raise _Usage("; ".join(str(p) for p in problems))
        twice = sorted(set(mods) & set(tree.mods))
        if twice:
            raise _Usage(f"{d}: module(s) {', '.join(twice)} already under another --modules")
        mods.update(tree.mods)
    return site, mods


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
