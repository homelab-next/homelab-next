# SPDX-License-Identifier: Apache-2.0
"""``hnx site``: validate, plan and render the site / network model.

Exit codes: 0 success, 1 invalid site or registry, 2 usage error / unknown or deferred adapter /
a site or registry file that cannot be read or parsed, 3 ``plan --exit-code`` found changes.  Nothing here contacts a device.

``hnx site review-tier --base REV | --ci-base [--root DIR] [--site REL] [--selection REL]``
prints the review tier of each change to the lab's site and module selection since the base
(:mod:`homelabnext.network.review_tier`); it exits 1 when a human-approve change has no valid
CODEOWNERS owner as of the base, 2 when the base or a file cannot be read.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from homelabnext.gitbase import add_base_arguments

from . import adapters
from .adapters.base import AdapterError, UnknownAdapter
from .ir import build_ir
from .loader import SiteError, SiteUnreadable, load_registry, load_site
from .plan import compute_plan, write_rendered
from .validate import validate

EXIT_INVALID = 1
EXIT_USAGE = 2
EXIT_CHANGES = 3


def _common(p: argparse.ArgumentParser) -> None:
    p.add_argument("site", help="path to site.yml")
    p.add_argument(
        "--registry",
        help="service registry (services.yml); default: services.yml next to the site file",
    )


def _parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="hnx site", description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("validate", help="schema + semantic validation")
    _common(p)
    p.add_argument("--json", action="store_true", help="machine-readable result")

    p = sub.add_parser("plan", help="show what rendering would change against a current tree")
    _common(p)
    p.add_argument("--adapter", help="adapter name (default: adapters.network or router.model)")
    p.add_argument("--current", help="directory holding the current state (default: empty)")
    p.add_argument("--format", choices=("text", "json"), default="text")
    p.add_argument("--no-diff", action="store_true", help="summary only")
    p.add_argument("--exit-code", action="store_true", help="exit 3 when there are changes")

    p = sub.add_parser("render", help="write the adapter's files into a directory")
    _common(p)
    p.add_argument("--adapter", help="adapter name (default: adapters.network or router.model)")
    p.add_argument("--out", required=True, help="output directory (acts as the target root)")
    p.add_argument("--prune", action="store_true", help="remove stale generated files in --out")

    p = sub.add_parser("ir", help="print the vendor-neutral intermediate representation as JSON")
    _common(p)

    sub.add_parser("adapters", help="list adapters and their status")

    t = sub.add_parser(
        "review-tier", help="the review tier of each change to the site and selection since a base"
    )
    t.add_argument("--root", default=".", help="the repository root (default: the current one)")
    t.add_argument("--site", default=None, help="the site file, relative to the root")
    t.add_argument("--selection", default=None, help="the module selection, relative to the root")
    add_base_arguments(t)
    t.add_argument("--json", action="store_true")
    return ap


def _load(args):
    site = Path(args.site)
    reg_path = Path(args.registry) if args.registry else site.parent / "services.yml"
    doc = load_site(site)
    reg = load_registry(reg_path)
    return doc, reg


def _validated(args, out, err):
    doc, reg = _load(args)
    report = validate(doc, reg)
    if report.warnings:
        print("\n".join(f"warning: {w}" for w in report.warnings), file=err)
    if not report.ok:
        print("\n".join(f"error: {e}" for e in report.errors), file=err)
        print(f"hnx site: {args.site} is invalid ({len(report.errors)} errors)", file=err)
        return None
    return doc, reg


def _pick(args, doc) -> str:
    return args.adapter or doc.get("adapters", {}).get("network") or doc["router"]["model"]


def main(argv: list[str] | None = None, out=None, err=None) -> int:
    out = out or sys.stdout
    err = err or sys.stderr
    try:
        args = _parser().parse_args(argv)
    except SystemExit as exc:
        return int(exc.code or 0) if isinstance(exc.code, int) or exc.code is None else EXIT_USAGE
    try:
        return _run(args, out, err)
    except SiteUnreadable as exc:
        print(f"hnx site: {exc}", file=err)
        return EXIT_USAGE
    except SiteError as exc:
        print(f"hnx site: {exc}", file=err)
        return EXIT_INVALID
    except AdapterError as exc:
        print(f"hnx site: {exc}", file=err)
        return EXIT_USAGE


def _review_tier(args, out, err) -> int:
    """Print each changed file's tier and its fields; 1 when a human-approve change has no valid
    code owner as of the base (the code-owner review is the human approval), 2 when the base or
    a file cannot be read."""
    from homelabnext.gitbase import ci_base_from_env
    from homelabnext.modules import swap_evidence as se

    from . import review_tier as rt

    root = Path(args.root)
    if args.ci_base:
        try:
            base, why = ci_base_from_env(root)
        except ValueError as exc:
            print(f"hnx site review-tier: --ci-base: {exc}", file=err)
            return EXIT_USAGE
        print(f"hnx site review-tier: base {base or 'none'} ({why})", file=err)
    else:
        base = args.base
    try:
        results, problems = rt.review(
            root, base, site=args.site or rt.SITE, selection=args.selection or rt.SELECTION
        )
    except se.EvidenceError as exc:
        print(f"hnx site review-tier: {exc}", file=err)
        return EXIT_USAGE
    from homelabnext.modules.review_tier import report

    return report(
        results,
        problems,
        as_json=args.json,
        prog="hnx site review-tier",
        key="files",
        title="Site review tiers",
        out=out,
    )


def _run(args, out, err) -> int:
    if args.cmd == "review-tier":
        return _review_tier(args, out, err)
    if args.cmd == "adapters":
        for name, status, summary in adapters.listing():
            print(f"{name:<9} {status:<9} {summary}", file=out)
        return 0

    if args.cmd == "validate":
        doc, reg = _load(args)
        report = validate(doc, reg)
        if args.json:
            body = {"ok": report.ok, "errors": report.errors, "warnings": report.warnings}
            print(json.dumps(body, indent=2), file=out)
        else:
            for w in report.warnings:
                print(f"warning: {w}", file=err)
            for e in report.errors:
                print(f"error: {e}", file=err)
            if report.ok:
                print("ok", file=out)
        return 0 if report.ok else EXIT_INVALID

    adapter_name = None
    if args.cmd in ("plan", "render"):
        # an unknown adapter is a usage error: reject it before reading anything
        adapter_name = args.adapter
        if adapter_name:
            adapters.get(adapter_name)
    loaded = _validated(args, out, err)
    if loaded is None:
        return EXIT_INVALID
    doc, reg = loaded
    ir = build_ir(doc, reg)

    if args.cmd == "ir":
        print(json.dumps(ir.to_dict(), indent=2, sort_keys=True), file=out)
        return 0

    name = adapter_name or _pick(args, doc)
    adapter = adapters.get(name)
    own = doc.get("adapters", {}).get("network") or doc["router"]["model"]
    if ir.router.wan6 and name != "linux" and own == "linux":
        # validation warned only about the site's own adapter, which renders it
        print(
            f"warning: router.wan6 is rendered by the linux adapter only; {name} ignores it",
            file=err,
        )
    rendered = adapter.render(ir)

    if args.cmd == "render":
        out_dir = Path(args.out)
        touched = write_rendered(rendered, out_dir, prune=args.prune)
        print(
            f"render ({name}): {len(touched)} written, {len(rendered) - len(touched)} unchanged",
            file=out,
        )
        for t in touched:
            print(f"  {t}", file=out)
        return 0

    plan = compute_plan(name, rendered, Path(args.current) if args.current else None)
    if args.format == "json":
        print(json.dumps(plan.to_dict(), indent=2), file=out)
    else:
        print(plan.render(diffs=not args.no_diff), end="", file=out)
    return EXIT_CHANGES if (args.exit_code and plan.changed) else 0


__all__ = ["UnknownAdapter", "main"]
