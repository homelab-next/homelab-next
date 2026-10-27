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
    the site's hosts, under ``DIR/limits/`` and ``DIR/egress/``.

Defaults follow the overlay layout: with ``--overlay DIR`` the site is ``DIR/lab/modules.yml``,
the lock ``DIR/lab/modules.lock``, the review policy ``DIR/lab/review-policy.yml``, the role table
``DIR/lab/model_roles.json`` and the core registry ``DIR/lab/services.yml`` when they exist;
otherwise the repository's examples (``examples/model_roles.json``, ``examples/services.yml``).
The slot registry is the draft ``examples/modules/slots.yml``.

Exit: 0 clean, 1 problems, 2 usage or an input that cannot be read, 100 an internal error.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

import yaml

from homelabnext import paths
from homelabnext.modules import loader as ld


def _root(arg: Path | None) -> Path:
    if arg is not None:
        return arg.resolve()
    root = paths.checkout_root()
    if root is None:
        raise ld.LoaderError("not a source checkout: pass --root (the repository root)")
    return root


def _read(path: Path, what: str) -> Any:
    try:
        if path.suffix == ".json":
            return json.loads(path.read_text(encoding="utf-8"))
        return ld.load_yaml(path)
    except (OSError, ValueError, yaml.YAMLError) as exc:
        raise ld.LoaderError(
            f"{what} {path}: cannot be read ({exc.__class__.__name__}: {exc})"
        ) from None


def _first(*candidates: Path | None) -> Path | None:
    return next((p for p in candidates if p is not None and p.is_file()), None)


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
            p.add_argument("--out", type=Path, required=True, help="the output directory")
    return ap


def _run(args: argparse.Namespace) -> int:
    root = _root(args.root)
    lab = args.overlay / "lab" if args.overlay else None
    fixtures = root / "examples" / "modules" if args.examples else None
    tree, problems = ld.discover(root / "modules", fixtures, args.overlay)
    in_tree = (root / "modules", *([fixtures] if fixtures else []))
    slots = _read(args.slots or root / "examples" / "modules" / "slots.yml", "slot registry")
    roles_path = (
        args.roles
        or _first(lab and lab / "model_roles.json")
        or root / "examples" / "model_roles.json"
    )
    roles = _read(roles_path, "role table")
    services = _first(
        args.services, lab and lab / "services.yml", root / "examples" / "services.yml"
    )
    site_path = args.site or _first(lab and lab / "modules.yml")
    lock_path = args.lock or _first(lab and lab / "modules.lock")
    policy_path = args.review_policy or _first(lab and lab / "review-policy.yml")
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
            "render needs a site selection (--site or --overlay with lab/modules.yml)"
        )
    running = getattr(args, "running", None)
    report = ld.check(
        tree,
        slots=(slots or {}).get("slots", {}),
        roles=(roles or {}).get("roles", {}),
        in_tree_roots=in_tree,
        core=ld.core_names(_read(services, "core registry") if services else None),
        site=site,
        lock=_read(lock_path, "lock") if lock_path else None,
        policy=policy,
        inventory=_read(running, "inventory") if running else None,
    )
    found = sorted({*problems, *report.problems})
    if args.json:
        print(
            json.dumps(
                {
                    "problems": [str(p) for p in found],
                    "notes": report.notes,
                    "modules": len(tree.mods),
                },
                indent=2,
            )
        )
    else:
        for p in found:
            print(p)
        for n in report.notes:
            print(f"note: {n}")
        print(f"hnx modules: {len(tree.mods)} module(s), {len(found)} problem(s)")
    if found or args.cmd == "check":
        return 1 if found else 0
    from homelabnext.modules import egress, limits

    ins = ld.inputs(tree)
    try:
        lim = limits.render(site, tree.mods, ld.units_fn(ins))
        egr = egress.render(site, tree.mods, ld.rows_fn(ins), ld.units_fn(ins))
    except (limits.LimitsError, egress.EgressError) as exc:
        print(f"hnx modules render: {exc}", file=sys.stderr)
        return 1
    limits.write(lim, args.out / "limits")
    egress.write(egr, args.out / "egress")
    print(
        f"hnx modules render: wrote {len(lim)} limits and {len(egr)} egress file(s) under {args.out}"
    )
    return 0


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
