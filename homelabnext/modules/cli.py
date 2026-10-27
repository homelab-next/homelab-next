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

``hnx modules review-tier --base REV | --ci-base [--json]``
    the review tier of every module path the working tree changes against the base
    (:mod:`homelabnext.modules.review_tier`): human-approve for what the Trust-tiers table gives an
    approver other than the owner (credentials, control-plane readers, egress, data, lifecycle,
    interfaces, agents and their grants, roles, entry points, fleet units, service rows, MCP
    records, shared config, hooks, workflow packs, a privileged slot, the module's identity, the
    files these name, and any file nothing names), for a change to what decides the tier, and for
    anything it cannot read; owner otherwise.  The approval is the pull request's code-owner
    review, so it fails when a human-approve change has no valid owner in CODEOWNERS as of the
    base.  ``--ci-base`` picks the base by :func:`homelabnext.gitbase.ci_base`, the rule
    ``tools/schema_check.py --ci-base`` takes.
``hnx modules swap-check RECORD --site FILE --base REV | --ci-base [--examples] [--roles REL]
[--report FILE ...] [--json]``
    a swap record 1.2 end to end: it validates against ``platform/module_swap``, then
    :func:`homelabnext.modules.swap.module_swap_problems` against the discovered manifests and
    the site it starts from, with the model evidence read from the repository
    (:mod:`homelabnext.modules.swap_evidence`): the role table after from the working tree, and
    everything that vouches for the new model (the table before, the model store, the evaluation
    reports, the golden suites) from the base commit; live evidence required.  ``--report`` adds a
    report for a local run.  ``--overlay`` is refused: the evidence is read at the repository's
    fixed paths, so an overlay is checked from its own checkout (``--root``).
``hnx modules swap-gate --base REV | --ci-base [--roles REL] [--json]``
    the CI gate: when the role table differs from the base's, a swap record added or changed under
    ``examples/swaps/`` must cover it, its ``model_roles`` legs holding against the base's
    evidence.  An unchanged table passes.

For ``check`` and ``render``, defaults follow the overlay layout: with ``--overlay DIR`` the site
is ``DIR/lab/modules.yml``, the lock ``DIR/lab/modules.lock``, the review policy
``DIR/lab/review-policy.yml``, the role table ``DIR/lab/model_roles.json`` and the core registry
``DIR/lab/services.yml`` when they exist; otherwise the repository's examples
(``examples/model_roles.json``, ``examples/services.yml``), each such fallback printed as a note.  The slot registry is the draft
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


def _read(path: Path, what: str, budget: ld.Budget | None = None) -> Any:
    try:
        return ld.load_input(path, budget)
    except ld.Unreadable as exc:
        raise ld.LoaderError(f"{what} {path}: {exc}") from None


def _shown_path(path: Path, root: Path) -> str:
    """A path in a note: relative to the repository root when it is under it."""
    p = path.resolve()
    return p.relative_to(root).as_posix() if p.is_relative_to(root) else str(path)


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
    t = sub.add_parser("review-tier", help="the review tier of each manifest changed since a base")
    t.add_argument("--root", type=Path, help="the repository root (default: this checkout)")
    which = t.add_mutually_exclusive_group(required=True)
    which.add_argument("--base", help="the commit to compare with")
    which.add_argument(
        "--ci-base",
        action="store_true",
        help="pick the base like tools/schema_check.py --ci-base (GITHUB_EVENT_NAME, "
        "HNX_PR_BASE, HNX_PUSH_BEFORE)",
    )
    t.add_argument("--json", action="store_true")
    w = sub.add_parser("swap-check", help="a swap record against the repository's evidence")
    w.add_argument("record", type=Path, help="the swap record (platform/module_swap, JSON or YAML)")
    w.add_argument("--root", type=Path, help="the repository root (default: this checkout)")
    w.add_argument(
        "--overlay", type=Path, help="refused: the evidence is the repository's, not an overlay's"
    )
    w.add_argument(
        "--examples", action="store_true", help="also load the fictional examples/modules/"
    )
    w.add_argument("--site", type=Path, required=True, help="the selection the swap starts from")
    w.add_argument(
        "--roles",
        default=None,
        help="the role table, relative to the root: the base's before, the working tree's after "
        "(the store, the reports and the suites are always the base's, at their fixed paths)",
    )
    w.add_argument(
        "--report",
        type=Path,
        action="append",
        default=[],
        help="another evaluation report, for a local run (CI never passes one)",
    )
    which = w.add_mutually_exclusive_group(required=True)
    which.add_argument("--base", help="the commit the swap starts from")
    which.add_argument(
        "--ci-base", action="store_true", help="pick the base like tools/schema_check.py --ci-base"
    )
    w.add_argument("--json", action="store_true")
    g = sub.add_parser(
        "swap-gate", help="a role-table change must be covered by a swap record in the change"
    )
    g.add_argument("--root", type=Path, help="the repository root (default: this checkout)")
    g.add_argument("--roles", default=None, help="the role table, relative to the root")
    which = g.add_mutually_exclusive_group(required=True)
    which.add_argument("--base", help="the commit the change starts from")
    which.add_argument(
        "--ci-base", action="store_true", help="pick the base like tools/schema_check.py --ci-base"
    )
    g.add_argument("--json", action="store_true")
    return ap


def _ci_base(root: Path, prog: str = "review-tier") -> str:
    """The base CI compares with (:func:`homelabnext.gitbase.ci_base`: a pull request's base; a
    push's previous tip, else ``HEAD^``; a root commit, the empty tree).  The rule is the
    package's, never a file loaded from the checkout."""
    import os

    from homelabnext.gitbase import ci_base
    from homelabnext.modules import review_tier as rt

    try:
        base, why = ci_base(
            root,
            os.environ.get("GITHUB_EVENT_NAME", ""),
            os.environ.get("HNX_PR_BASE", ""),
            os.environ.get("HNX_PUSH_BEFORE", ""),
        )
    except ValueError as exc:
        raise ld.LoaderError(f"--ci-base: {exc}") from None
    print(f"hnx modules {prog}: base {base or 'the empty tree'} ({why})", file=sys.stderr)
    return base or rt.EMPTY_TREE


def _review_tier(args: argparse.Namespace) -> int:
    """Print each changed manifest's tier and its fields; fail (1) when a human-approve change
    has no valid code owner as of the base, since the code-owner review is the human approval."""
    import os

    from homelabnext.modules import review_tier as rt

    root = _root(args.root)
    base = _ci_base(root) if args.ci_base else args.base
    if not base or not base.strip():
        raise ld.LoaderError("--base needs a commit (an empty value would skip the check)")
    try:
        results, problems = rt.review(root, base)
    except ValueError as exc:
        raise ld.LoaderError(str(exc)) from None
    rows = [
        {
            "path": r.path,
            "tier": r.tier,
            "owners": r.owners,
            "changes": [{"field": c.field, "tier": c.tier, "why": c.why} for c in r.changes],
        }
        for r in results
    ]
    if args.json:
        print(json.dumps({"manifests": rows, "problems": problems}, indent=2))
    else:
        for r in rows:
            print(f"{r['path']}: {r['tier']} (owners: {' '.join(r['owners']) or 'none'})")
            for c in r["changes"]:
                print(f"  {c['tier']}: {c['field']}: {c['why']}")
        for p in problems:
            print(p)
        human = sum(r["tier"] == rt.HUMAN for r in rows)
        print(
            f"hnx modules review-tier: {len(rows)} changed path(s), {human} human-approve, "
            f"{len(problems)} problem(s)"
        )
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary and rows:
        with open(summary, "a", encoding="utf-8") as fh:
            fh.write("### Module review tiers\n\n| path | tier | fields |\n|---|---|---|\n")
            for r in rows:
                fields = ", ".join(
                    f"`{c['field']}`" for c in r["changes"] if c["tier"] == r["tier"]
                )
                fh.write(f"| `{r['path']}` | {r['tier']} | {fields} |\n")
    return 1 if problems else 0


def _swap_check(args: argparse.Namespace) -> int:
    """The record's problems with the repository's evidence: 1 when it does not hold, 2 when an
    input (the record, the role table at either end, the store, a report) cannot be read."""
    import tempfile

    from homelabnext.modules import swap as ms
    from homelabnext.modules import swap_evidence as se

    if args.overlay is not None:
        raise ld.LoaderError(
            "--overlay: swap-check reads the role table, the store and the reports at their fixed "
            "repository paths (the base's), never an overlay's; run it in the overlay's own "
            "checkout with --root, its tables at those paths"
        )
    root = _root(args.root)
    base = _ci_base(root, "swap-check") if args.ci_base else args.base
    base = se.resolve_base(root, base or "")
    _given(args.record, "record")
    if args.record.is_symlink():
        raise ld.LoaderError(f"record {args.record}: a symbolic link")
    budget = ld.Budget()
    record = _read(args.record, "record", budget)
    problems = [
        f"record: {e}"
        for e in ld._errors(ld._schema("platform", "module_swap.schema.json"), record)
    ]
    tree, found = ld.discover(
        root / "modules", root / "examples" / "modules" if args.examples else None, None, budget
    )
    problems += [str(p) for p in found]
    site = _read(_given(args.site, "--site"), "site selection", budget)
    if not isinstance(site, dict):
        raise ld.LoaderError("the site selection is not a mapping")
    models = None
    with tempfile.TemporaryDirectory(prefix="hnx-swap-check-") as tmp:
        if not problems and (
            "model_roles" in record or any(s["slot"] == "inference" for s in record["slots"])
        ):
            models = se.from_git(
                root,
                base,
                roles=args.roles or se.ROLES,
                extra_reports=args.report,
                workdir=Path(tmp),
            )
        if not problems:
            problems = ms.module_swap_problems(record, tree.mods, site, models=models)
    if args.json:
        print(
            json.dumps(
                {"problems": problems, "base": base, "evidence": models is not None}, indent=2
            )
        )
    else:
        for p in problems:
            print(p)
        what = "with model evidence from the base" if models else "no model evidence needed"
        print(f"hnx modules swap-check: {len(problems)} problem(s) ({what}, base {base})")
    return 1 if problems else 0


def _swap_gate(args: argparse.Namespace) -> int:
    """1 when the role table changed and no passing swap record in the change covers it."""
    from homelabnext.modules import swap_evidence as se

    root = _root(args.root)
    base = _ci_base(root, "swap-gate") if args.ci_base else args.base
    problems, what = se.gate(root, base or "", roles=args.roles or se.ROLES)
    if args.json:
        print(json.dumps({"problems": problems, "decided": what}, indent=2))
    else:
        for p in problems:
            print(p)
        print(f"hnx modules swap-gate: {len(problems)} problem(s) ({what})")
    return 1 if problems else 0


def _run(args: argparse.Namespace) -> int:
    if args.cmd == "review-tier":
        return _review_tier(args)
    if args.cmd == "swap-check":
        return _swap_check(args)
    if args.cmd == "swap-gate":
        return _swap_gate(args)
    root = _root(args.root)
    if args.overlay is not None and not args.overlay.is_dir():
        raise ld.LoaderError(f"--overlay {args.overlay}: not a directory")
    for flag in ("site", "slots", "roles", "services", "lock", "review_policy"):
        _given(getattr(args, flag), "--" + flag.replace("_", "-"))
    _given(getattr(args, "running", None), "--running")
    if args.cmd == "render" and (args.out.exists() or args.out.is_symlink()):
        if not args.out.is_dir() or args.out.is_symlink():
            raise ld.LoaderError(f"--out {args.out}: not a directory")
        if any(args.out.iterdir()):
            raise ld.LoaderError(f"--out {args.out}: not empty (render writes a fresh directory)")
    notes: list[str] = []
    lab = args.overlay / "lab" if args.overlay else None
    budget = ld.Budget()
    public = root / "modules"
    if not public.is_dir() or not any(public.iterdir()):
        notes.append("the public modules/ tree is missing or empty")
    fixtures = root / "examples" / "modules" if args.examples else None
    tree, problems = ld.discover(public, fixtures, args.overlay, budget)
    in_tree = (public, *([fixtures] if fixtures else []))
    slots = _read(
        args.slots or root / "examples" / "modules" / "slots.yml", "slot registry", budget
    )
    roles_path = args.roles or _existing(lab and lab / "model_roles.json")
    if roles_path is None:
        roles_path = root / "examples" / "model_roles.json"
        notes.append(
            f"the role table is the repository's example ({_shown_path(roles_path, root)})"
        )
    roles = _read(roles_path, "role table", budget)
    services = args.services or _existing(lab and lab / "services.yml")
    if services is None:
        services = root / "examples" / "services.yml"
        notes.append(
            f"the core registry is the repository's example ({_shown_path(services, root)})"
        )
    core, registry_problems = ld.core_names(_read(services, "core registry", budget))
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
    site = _read(site_path, "site selection", budget) if site_path else None
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
        lock=_read(lock_path, "lock", budget) if lock_path else None,
        policy=policy,
        inventory=_read(running, "inventory", budget) if running else None,
        budget=budget,
    )
    found = sorted({*problems, *registry_problems, *report.problems})
    notes += report.notes
    written: dict[str, int] = {}
    error = None
    if not found and args.cmd == "render":
        written, error = _render(args, tree, site)
    if args.json:
        doc = {"problems": [str(p) for p in found], "notes": notes, "modules": len(tree.mods)}
        if args.cmd == "render":
            doc["written"] = written
        if error:
            doc["error"] = error
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
    if error:
        print(f"hnx modules render: {error}", file=sys.stderr)
    return 1 if found or error else 0


def _render(
    args: argparse.Namespace, tree: ld.Tree, site: dict
) -> tuple[dict[str, int], str | None]:
    """(files written per output, or the generator's refusal)."""
    from homelabnext.modules import egress, limits

    ins = ld.inputs(tree)
    try:
        lim = limits.render(site, tree.mods, ld.units_fn(ins))
        egr = egress.render(site, tree.mods, ld.rows_fn(ins), ld.units_fn(ins))
    except (limits.LimitsError, egress.EgressError) as exc:
        return {}, str(exc)
    limits.write(lim, args.out / "limits")
    egress.write(egr, args.out / "egress")
    return {"limits": len(lim), "egress": len(egr)}, None


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
