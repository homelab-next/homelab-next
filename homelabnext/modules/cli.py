# SPDX-License-Identifier: Apache-2.0
"""``hnx modules``: the module loader (ADR-0027 follow-up 9; docs/modules.md, "What the loader
checks").

``hnx modules check [--overlay DIR] [--examples] [--site FILE] [--running FILE] [--json]``
    discover the manifests (the public ``modules/``, with ``--examples`` the fictional
    ``examples/modules/`` as a fixture root, and an overlay's ``lab/modules/``), and run every
    rule: per manifest, across manifests, per site, the supply chain and, with ``--running``, the
    runtime half of the two-way check.  What was not checked is printed as a note.
``hnx modules render --site FILE --out DIR [...]``
    the same check, then (only when it is clean) the footprint limits and the egress policy for
    the site's hosts, under ``DIR/limits/`` and ``DIR/egress/``.  ``DIR`` must not exist or be
    empty: a render never mixes with stale files from an earlier one.

Defaults follow the overlay layout: with ``--overlay DIR`` the site is ``DIR/lab/modules.yml``,
the lock ``DIR/lab/modules.lock``, the review policy ``DIR/lab/review-policy.yml``, the role table
``DIR/lab/model_roles.json`` and the core registry ``DIR/lab/services.yml`` when they exist;
otherwise the repository's examples (``examples/model_roles.json``, ``examples/services.yml``),
each such fallback printed as a note.  The slot registry is the draft
``examples/modules/slots.yml``.  A path given on the command line must exist.

Exit: 0 clean, 1 problems, 2 usage or an input that cannot be read, 100 an internal error.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from homelabnext import paths
from homelabnext.modules import loader as ld


def _root(arg: Path | None) -> Path:
    if arg is not None:
        if not arg.is_dir():
            raise ld.LoaderError(f"--root {arg}: not a directory")
        return arg.resolve()
    root = paths.checkout_root()
    if root is None:
        raise ld.LoaderError("not a source checkout: pass --root (the repository root)")
    return root


def _read(path: Path, what: str) -> Any:
    try:
        return ld.load_json(path) if path.suffix == ".json" else ld.load_yaml(path)
    except ld.Unreadable as exc:
        raise ld.LoaderError(f"{what} {path}: {exc}") from None


def _given(path: Path | None, flag: str) -> Path | None:
    """A path named on the command line: it must exist (a typo must not read as "none")."""
    if path is not None and not path.exists():
        raise ld.LoaderError(f"{flag} {path}: does not exist")
    return path


def _existing(path: Path | None) -> Path | None:
    return path if path is not None and path.is_file() else None


def _parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="hnx modules", description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("check", "render"):
        p = sub.add_parser(name)
        p.add_argument("--root", type=Path, help="the repository root (default: this checkout)")
        p.add_argument("--overlay", type=Path, help="a private overlay checkout (lab/modules/)")
        p.add_argument(
            "--examples", action="store_true", help="also load the fictional examples/modules/"
        )
        p.add_argument("--site", type=Path, help="the site selection (lab/modules.yml)")
        p.add_argument("--slots", type=Path, help="the slot registry (draft)")
        p.add_argument("--roles", type=Path, help="the model role table")
        p.add_argument("--services", type=Path, help="the core service registry")
        p.add_argument("--lock", type=Path, help="lab/modules.lock")
        p.add_argument("--review-policy", type=Path, help="the review policy")
        p.add_argument("--json", action="store_true")
        if name == "check":
            p.add_argument("--running", type=Path, help="what runs (platform/module_inventory)")
        else:
            p.add_argument("--out", type=Path, required=True, help="a new or empty directory")
    return ap


def _run(args: argparse.Namespace) -> int:
    root = _root(args.root)
    if args.overlay is not None and not args.overlay.is_dir():
        raise ld.LoaderError(f"--overlay {args.overlay}: not a directory")
    for flag in ("site", "slots", "roles", "services", "lock", "review_policy"):
        _given(getattr(args, flag), "--" + flag.replace("_", "-"))
    _given(getattr(args, "running", None), "--running")
    if args.cmd == "render" and args.out.exists() and any(args.out.iterdir()):
        raise ld.LoaderError(f"--out {args.out}: not empty (render writes a fresh directory)")
    notes: list[str] = []
    lab = args.overlay / "lab" if args.overlay else None
    public = root / "modules"
    if not public.is_dir() or not any(public.iterdir()):
        notes.append(f"the public modules/ tree ({public}) is missing or empty")
    fixtures = root / "examples" / "modules" if args.examples else None
    tree, problems = ld.discover(public, fixtures, args.overlay)
    in_tree = (public, *([fixtures] if fixtures else []))
    slots = _read(args.slots or root / "examples" / "modules" / "slots.yml", "slot registry")
    roles_path = args.roles or _existing(lab and lab / "model_roles.json")
    if roles_path is None:
        roles_path = root / "examples" / "model_roles.json"
        notes.append(f"the role table is the repository's example ({roles_path})")
    roles = _read(roles_path, "role table")
    services = args.services or _existing(lab and lab / "services.yml")
    if services is None:
        services = root / "examples" / "services.yml"
        notes.append(f"the core registry is the repository's example ({services})")
    core, registry_problems = ld.core_names(_read(services, "core registry"))
    site_path = args.site or _existing(lab and lab / "modules.yml")
    lock_path = args.lock or _existing(lab and lab / "modules.lock")
    policy_path = args.review_policy or _existing(lab and lab / "review-policy.yml")
    policy = None
    if policy_path is not None:
        from homelabnext.reviews import ReviewError, load_policy

        try:
            policy = load_policy(policy_path)
        except ReviewError as exc:
            raise ld.LoaderError(f"review policy {policy_path}: {exc}") from None
    site = _read(site_path, "site selection") if site_path else None
    if args.cmd == "render" and site is None:
        raise ld.LoaderError(
            "render needs a site selection (--site, or --overlay with lab/modules.yml)"
        )
    running = getattr(args, "running", None)
    for what, doc in (("slot registry", slots), ("role table", roles)):
        if not isinstance(doc, dict):
            raise ld.LoaderError(f"the {what} is not a mapping")
    report = ld.check(
        tree,
        slots=slots.get("slots") or {},
        roles=roles.get("roles") or {},
        in_tree_roots=in_tree,
        core=core,
        site=site,
        lock=_read(lock_path, "lock") if lock_path else None,
        policy=policy,
        inventory=_read(running, "inventory") if running else None,
    )
    found = sorted({*problems, *registry_problems, *report.problems})
    notes += report.notes
    written: dict[str, int] = {}
    if not found and args.cmd == "render":
        written = _render(args, tree, site)
        if not written:
            return 1
    if args.json:
        doc = {"problems": [str(p) for p in found], "notes": notes, "modules": len(tree.mods)}
        if args.cmd == "render":
            doc["written"] = written
        print(json.dumps(doc, indent=2))
    else:
        for p in found:
            print(p)
        for n in notes:
            print(f"note: {n}")
        if written:
            print(
                f"hnx modules render: wrote {written['limits']} limits and {written['egress']} "
                f"egress file(s) under {args.out}"
            )
        print(f"hnx modules: {len(tree.mods)} module(s), {len(found)} problem(s)")
    return 1 if found else 0


def _render(args: argparse.Namespace, tree: ld.Tree, site: dict) -> dict[str, int]:
    from homelabnext.modules import egress, limits

    ins = ld.inputs(tree)
    try:
        lim = limits.render(site, tree.mods, ld.units_fn(ins))
        egr = egress.render(site, tree.mods, ld.rows_fn(ins), ld.units_fn(ins))
    except (limits.LimitsError, egress.EgressError) as exc:
        print(f"hnx modules render: {exc}", file=sys.stderr)
        return {}
    limits.write(lim, args.out / "limits")
    egress.write(egr, args.out / "egress")
    return {"limits": len(lim), "egress": len(egr)}


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        return _run(args)
    except ld.LoaderError as exc:
        print(f"hnx modules: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # an internal failure: "could not check", never a pass or a fail
        print(f"hnx modules: internal error: {exc.__class__.__name__}: {exc}", file=sys.stderr)
        return 100
