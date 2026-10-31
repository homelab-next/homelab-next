# SPDX-License-Identifier: Apache-2.0
"""``hnx modules``: the module loader (ADR-0027 follow-up 9; docs/modules.md, "What the loader
checks").

``hnx modules check [--overlay DIR] [--examples] [--site FILE] [--running FILE] [--keyring FILE]
[--mcp-catalog DIR] [--deploy] [--json]``
    discover the manifests (the public ``modules/``, with ``--examples`` the fictional
    ``examples/modules/`` as a fixture root, and an overlay's ``lab/modules/``), and run every
    rule: per manifest, across manifests, per site, the supply chain and, with ``--running``, the
    runtime half of the two-way check.  What was not checked is printed as a note.  ``--deploy``
    is the check a deploy runs (the private overlay's deploy workflow, before anything changes on
    a host, and again after it with the gathered inventory): it needs ``--overlay``, refuses
    ``--examples``, and every input the overlay layout names must be the overlay's own (the site
    selection ``lab/modules.yml``, the role table, the core registry) or given on the command
    line; a fallback to the repository's examples is a problem, never a note.  A lab with none
    of ``lab/modules.yml``, ``lab/modules/`` and ``lab/modules.lock`` (a dangling link counts as
    present) has an **empty selection**: the check still runs, and with ``--running`` every
    running name bound to a module is one the site does not select.  With modules selected and
    no review policy, every fetched module is refused (the supply chain fails closed), so a lab
    of in-tree modules needs none.
``hnx modules gather DIR --out FILE``
    the inventory of what runs (``platform/module_inventory``), built from the census the
    ``module_census`` role wrote under ``DIR`` (:mod:`homelabnext.modules.census`): the fleet
    units some host reports enabled or active; the kinds the hosts do not report are named in
    ``not_gathered``.  ``FILE`` must not exist.  Exit 2 when the census cannot be read or does
    not cover every host the play targeted.
``hnx modules catalog-tables --url URL --warehouse NAME [--token-file FILE] [--api-root PATH]``
    run by the ``module_census`` role on a lake catalog host: the tables the Iceberg REST catalog
    at ``URL`` (plain http to a loopback IP literal: the catalog's own host) lists in the
    warehouse, within two minutes, as JSON
    ``{"tables": ["<namespace>.<name>", ...], "left_out": n}``
    (:func:`homelabnext.modules.census.catalog_tables`).  GET requests only; the token in
    ``FILE`` (a plain name in ``/etc/homelabnext``, owner only, the caller's own) is sent to that
    address alone and never printed.  Exit 2 when the catalog cannot be listed; the error names
    the request and its HTTP status, never what the catalog answered.
``hnx modules render --site FILE [--network FILE] --out DIR [...]``
    the same check, then (only when it is clean) the footprint limits and the egress policy for
    the site's hosts, under ``DIR/limits/`` and ``DIR/egress/``.  ``DIR`` must not exist or be
    empty: a render never mixes with stale files from an earlier one.  ``--network`` is the
    network model (``site.yml``; with ``--overlay``, ``DIR/lab/site.yml`` by default): its zone
    ``subnet6`` and ``delegated_prefixes6`` prefixes are
    then never the internet for a role with ``internet``; without it the render prints a note
    that a lab IPv6 address outside the listed host addresses and ``scope.trusted.nets`` is
    treated as the internet.

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
``hnx modules swap-gate --base REV | --ci-base [--roles REL | --overlay DIR] [--json]``
    the CI gate: when the role table differs from the base's, a swap record added or changed under
    ``examples/swaps/`` must cover it, its ``model_roles`` legs holding against the base's
    evidence.  An unchanged table passes.  ``--overlay DIR`` runs it over a private overlay
    checkout (``DIR`` is the git root): the role table, the store, the reports and the swap
    records are the overlay's ``lab/model_roles.json``, ``lab/model-serving/model_store.json``,
    ``lab/model_roles.eval.json`` + ``lab/model-evals/`` and ``lab/swaps/``, with the same
    guarantees; the golden suites are the installed package's.  It refuses ``--root`` and
    ``--roles`` (the layout is fixed).

For ``check`` and ``render``, defaults follow the overlay layout: with ``--overlay DIR`` the site
is ``DIR/lab/modules.yml``, the lock ``DIR/lab/modules.lock``, the review policy
``DIR/lab/review-policy.yml``, the role table ``DIR/lab/model_roles.json``, the core registry
``DIR/lab/services.yml`` and, for ``render``, the network model ``DIR/lab/site.yml`` when they
exist, otherwise the repository's examples
(``examples/model_roles.json``, ``examples/services.yml``), each such fallback printed as a note.
The core's own names (:class:`homelabnext.modules.loader.CoreNames`) are read from the registry,
the MCP catalog, the keyring's agent principals, the OCSF tables and the core's notify pairs.
With ``--overlay`` the catalog is ``DIR/lab/mcp/`` and the keyring ``DIR/lab/keyring/keyring.json``,
and a missing one is a problem unless ``--mcp-catalog`` or ``--keyring`` names it (an example
never answers for a lab); without, they are the catalog beside the registry and the example
keyring, each fallback a note.  With ``--json`` the notes also go to stderr.  The slot registry
is the draft ``examples/modules/slots.yml``.  A path given on the command line must exist.

Exit: 0 clean, 1 problems, 2 usage or an input that cannot be read, 100 an internal error.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

from homelabnext import paths
from homelabnext.gitbase import add_base_arguments
from homelabnext.modules import loader as ld

#: what a lab names when it takes up modules: with none of them, ``--deploy`` checks an empty
#: selection
MODULE_INPUTS = ("modules.yml", "modules", "modules.lock")


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


def _core(
    args: argparse.Namespace,
    root: Path,
    lab: Path | None,
    services: Path,
    budget: ld.Budget,
    notes: list[str],
    strict: bool = True,
) -> tuple[ld.CoreNames, list[ld.Problem]]:
    """The core's names from the sources it already has (:func:`ld.core_names`): the registry,
    its MCP catalog, the keyring, the OCSF tables, the core's notify pairs and its own fleet units
    (read from ``ansible/roles`` under the root and the generators, :func:`ld.core_units`; a
    deploy without them is a ``registry`` problem).

    With ``--overlay``, the MCP catalog (``lab/mcp/``) and the keyring
    (``lab/keyring/keyring.json``) are the overlay's: one that is missing is a ``registry``
    problem unless it is given (``--mcp-catalog``, ``--keyring``), since the repository's
    examples would answer for a lab they do not describe (with ``strict`` false, an empty
    selection's check, it is a note: those names judge only modules).  Without one, the catalog
    beside the
    core registry (``mcp/``) and the example keyring are used, each fallback a note, and a missing
    source is a note: never a silently smaller set."""
    from homelabnext.lake.tables import CORE_NAMESPACE
    from homelabnext.notify.core_pairs import CORE_PAIRS

    problems: list[ld.Problem] = []
    catalog = args.mcp_catalog or (lab / "mcp" if lab is not None else services.parent / "mcp")
    mcp: list[tuple[str, Any]] = []
    if catalog.exists() or catalog.is_symlink():
        mcp, problems = ld.core_mcp_records(catalog, budget)
    elif lab is not None:
        why = (
            f"the overlay has no MCP catalog ({_shown_path(catalog, root)}): give "
            "--mcp-catalog, or the core's MCP server ids cannot be compared"
        )
        if strict:
            problems.append(ld.Problem("registry", why))
        else:
            notes.append(why)
    else:
        notes.append(
            f"no MCP catalog beside the core registry ({_shown_path(catalog, root)}): the core's "
            "MCP server ids were not compared"
        )
    keyring_path = args.keyring
    if keyring_path is None and lab is not None:
        keyring_path = _existing(lab / "keyring" / "keyring.json")
        if keyring_path is None:
            why = (
                "the overlay has no keyring (lab/keyring/keyring.json): give --keyring, or "
                "the core's agent keys cannot be compared"
            )
            if strict:
                problems.append(ld.Problem("registry", why))
            else:
                notes.append(why)
    elif keyring_path is None:
        keyring_path = _existing(root / "examples" / "keyring" / "keyring.json")
        if keyring_path is not None:
            notes.append(
                f"the keyring is the repository's example ({_shown_path(keyring_path, root)})"
            )
        else:
            notes.append("no keyring: the core's agent keys were not compared")
    keyring = _read(keyring_path, "keyring", budget) if keyring_path is not None else None
    tables, found = ld.core_table_names(paths.ocsf_dir(), budget)
    problems += found
    units = None
    roles_dir = root / "ansible" / "roles"
    if roles_dir.exists() or roles_dir.is_symlink():
        names, families, found = ld.core_units(roles_dir, budget)
        problems += found
        units = (names, families)
    elif getattr(args, "deploy", False):
        why = "the core's roles (ansible/roles under --root) are missing: its units cannot be read"
        problems.append(ld.Problem("registry", why))
    else:
        notes.append(
            "no ansible/roles under the root: the core's own units were not read, so a running "
            "unit bound to no module is not judged"
        )
    core, found = ld.core_names(
        _read(services, "core registry", budget),
        mcp=mcp,
        keyring=keyring,
        tables=tables,
        table_namespace=CORE_NAMESPACE,
        pairs=CORE_PAIRS,
        units=units,
    )
    return core, [*problems, *found]


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
        p.add_argument("--keyring", type=Path, help="the generated keyring (its agent principals)")
        p.add_argument("--mcp-catalog", type=Path, help="the core MCP catalog directory")
        p.add_argument("--lock", type=Path, help="lab/modules.lock")
        p.add_argument("--review-policy", type=Path, help="the review policy")
        p.add_argument("--json", action="store_true")
        if name == "check":
            p.add_argument("--running", type=Path, help="what runs (platform/module_inventory)")
            p.add_argument(
                "--deploy",
                action="store_true",
                help="the deploy's check: the overlay's own inputs only, never the examples",
            )
        else:
            p.add_argument(
                "--network",
                type=Path,
                help="the network model (site.yml): its zone subnet6 and delegated_prefixes6 "
                "prefixes are never the internet for egress",
            )
            p.add_argument("--out", type=Path, required=True, help="a new or empty directory")
    c = sub.add_parser("gather", help="the inventory of what runs, from the hosts' census")
    c.add_argument("census", type=Path, help="the directory the module_census role wrote")
    c.add_argument(
        "--out", type=Path, required=True, help="the inventory to write (must not exist)"
    )
    k = sub.add_parser("catalog-tables", help="the lake tables a loopback catalog lists (JSON)")
    k.add_argument("--url", required=True, help="the catalog, http on a loopback IP literal")
    k.add_argument("--warehouse", required=True, help="the warehouse whose tables are listed")
    k.add_argument(
        "--token-file",
        type=Path,
        help="a bearer token in /etc/homelabnext, the caller's own (0600)",
    )
    k.add_argument(
        "--api-root", default="/catalog", help="the catalog's API root (default /catalog)"
    )
    t = sub.add_parser("review-tier", help="the review tier of each manifest changed since a base")
    t.add_argument("--root", type=Path, help="the repository root (default: this checkout)")
    add_base_arguments(t)
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
    g.add_argument(
        "--overlay",
        type=Path,
        help="a private overlay checkout (its git root): the evidence, swap records and role "
        "table are its lab/ files (refuses --root and --roles)",
    )
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
    from homelabnext.gitbase import ci_base_from_env
    from homelabnext.modules import review_tier as rt

    try:
        base, why = ci_base_from_env(root)
    except ValueError as exc:
        raise ld.LoaderError(f"--ci-base: {exc}") from None
    print(f"hnx modules {prog}: base {base or 'the empty tree'} ({why})", file=sys.stderr)
    return base or rt.EMPTY_TREE


def _review_tier(args: argparse.Namespace) -> int:
    """Print each changed manifest's tier and its fields; fail (1) when a human-approve change
    has no valid code owner as of the base, since the code-owner review is the human approval."""
    from homelabnext.modules import review_tier as rt

    root = _root(args.root)
    base = _ci_base(root) if args.ci_base else args.base
    if not base or not base.strip():
        raise ld.LoaderError("--base needs a commit (an empty value would skip the check)")
    try:
        results, problems = rt.review(root, base)
    except ValueError as exc:
        raise ld.LoaderError(str(exc)) from None
    return rt.report(
        results,
        problems,
        as_json=args.json,
        prog="hnx modules review-tier",
        key="manifests",
        title="Module review tiers",
    )


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

    layout = se.REPO
    if args.overlay is not None:
        if args.root is not None or args.roles is not None:
            raise ld.LoaderError(
                "--overlay: the overlay is the git root and its lab/ layout is fixed; "
                "--root and --roles are refused"
            )
        if not args.overlay.is_dir():
            raise ld.LoaderError(f"--overlay {args.overlay}: not a directory")
        root = args.overlay.resolve()
        shown = se.git_toplevel(root)
        if shown != root:
            raise ld.LoaderError(
                f"--overlay {args.overlay}: not the root of a git checkout"
                + (f" (its root is {shown})" if shown else "")
                + "; the gate reads the base commit from it"
            )
        layout = se.OVERLAY
    else:
        root = _root(args.root)
    base = _ci_base(root, "swap-gate") if args.ci_base else args.base
    problems, what = se.gate(root, base or "", roles=args.roles, layout=layout)
    if args.json:
        print(json.dumps({"problems": problems, "decided": what}, indent=2))
    else:
        for p in problems:
            print(p)
        print(f"hnx modules swap-gate: {len(problems)} problem(s) ({what})")
    return 1 if problems else 0


def _gather(args: argparse.Namespace) -> int:
    """Write the gathered inventory; 2 when the census cannot be read (a host missing, an entry
    that is no listed host's answer, a line that is not a fleet unit in its query's shape)."""
    from homelabnext.modules import census

    if args.out.exists() or args.out.is_symlink():
        raise ld.LoaderError(f"--out {args.out}: exists (gather writes a new file)")
    try:
        inventory, notes = census.gather(args.census)
    except census.CensusError as exc:
        raise ld.LoaderError(f"census {args.census}: {exc}") from None
    # the runner's alone, like the census answers it is gathered from (mode 0600)
    fd = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with open(fd, "w", encoding="utf-8") as fh:
        json.dump(inventory, fh, indent=2)
        fh.write("\n")
    for n in notes:
        print(f"note: {n}")
    print(f"hnx modules gather: {len(inventory['units'])} unit(s) written to {args.out}")
    return 0


def _catalog_tables(args: argparse.Namespace) -> int:
    """Print the tables a loopback lake catalog lists; 2 when it cannot be listed."""
    from homelabnext.modules import census

    try:
        found = census.catalog_tables(
            args.url, args.warehouse, token_file=args.token_file, api_root=args.api_root
        )
    except census.CensusError as exc:
        raise ld.LoaderError(f"catalog-tables: {exc}") from None
    print(json.dumps(found, separators=(",", ":")))
    return 0


def _run(args: argparse.Namespace) -> int:
    if args.cmd == "gather":
        return _gather(args)
    if args.cmd == "catalog-tables":
        return _catalog_tables(args)
    if args.cmd == "review-tier":
        return _review_tier(args)
    if args.cmd == "swap-check":
        return _swap_check(args)
    if args.cmd == "swap-gate":
        return _swap_gate(args)
    root = _root(args.root)
    if args.overlay is not None and not args.overlay.is_dir():
        raise ld.LoaderError(f"--overlay {args.overlay}: not a directory")
    deploy = getattr(args, "deploy", False)
    if deploy and args.overlay is None:
        raise ld.LoaderError("--deploy needs --overlay (the lab the deploy applies)")
    if deploy and args.examples:
        raise ld.LoaderError("--deploy refuses --examples (a deploy never loads the fixtures)")
    for flag in (
        "site",
        "slots",
        "roles",
        "services",
        "keyring",
        "mcp_catalog",
        "lock",
        "review_policy",
    ):
        _given(getattr(args, flag), "--" + flag.replace("_", "-"))
    _given(getattr(args, "running", None), "--running")
    _given(getattr(args, "network", None), "--network")
    if args.cmd == "render" and (args.out.exists() or args.out.is_symlink()):
        if not args.out.is_dir() or args.out.is_symlink():
            raise ld.LoaderError(f"--out {args.out}: not a directory")
        if any(args.out.iterdir()):
            raise ld.LoaderError(f"--out {args.out}: not empty (render writes a fresh directory)")
    notes: list[str] = []
    #: a deploy's input that fell back to the repository's example: a problem, never a note
    fallbacks: list[ld.Problem] = []

    def fallback(what: str, path: Path) -> None:
        if deploy and not empty:
            shown = path.relative_to(args.overlay).as_posix()  # never resolved: a link stays one
            why = (
                f"{shown} is not a regular file"
                if os.path.lexists(path)
                else f"the overlay has no {shown}"
            )
            fallbacks.append(ld.Problem("deploy", f"{what}: {why}"))

    lab = args.overlay / "lab" if args.overlay else None
    #: under --deploy, a lab that names none of its module inputs selects no module at all: the
    #: check still runs (and, with --running, judges every running unit of a module), but an
    #: input that only judges selected modules is not required of it
    empty = (
        deploy and args.site is None and not any(os.path.lexists(lab / f) for f in MODULE_INPUTS)
    )
    if empty:
        notes.append(
            "this lab selects no modules (none of "
            + ", ".join(f"lab/{f}" for f in MODULE_INPUTS)
            + "): an empty selection"
        )
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
        if lab:
            fallback("the role table", lab / "model_roles.json")
        roles_path = root / "examples" / "model_roles.json"
        notes.append(
            f"the role table is the repository's example ({_shown_path(roles_path, root)})"
        )
    roles = _read(roles_path, "role table", budget)
    services = args.services or _existing(lab and lab / "services.yml")
    if services is None:
        if lab:
            fallback("the core registry", lab / "services.yml")
        services = root / "examples" / "services.yml"
        notes.append(
            f"the core registry is the repository's example ({_shown_path(services, root)})"
        )
    core, registry_problems = _core(args, root, lab, services, budget, notes, strict=not empty)
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
    if site_path is None and lab and not empty:
        fallback("the site selection", lab / "modules.yml")
    if deploy and site_path is not None and policy_path is None:
        notes.append(
            "no review policy (lab/review-policy.yml): every fetched module is refused, so only "
            "in-tree modules load"
        )
    site = _read(site_path, "site selection", budget) if site_path else None
    network = None
    if args.cmd == "render":
        # the overlay's own network model by default, as the role table and registry are
        network_path = args.network or _existing(lab and lab / "site.yml")
        if network_path is not None:
            network = _read(network_path, "network model", budget)
            if not isinstance(network, dict):
                raise ld.LoaderError("the network model is not a mapping")
        else:
            notes.append(
                "no network model (--network, or --overlay with lab/site.yml): the egress "
                "policy cannot exclude the lab's IPv6 "
                "zone and delegated prefixes, so a lab IPv6 address outside the listed host "
                "addresses and scope.trusted.nets is treated as the internet"
            )
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
        empty_selection=empty,
    )
    found = sorted({*problems, *registry_problems, *report.problems, *fallbacks})
    notes += report.notes
    written: dict[str, int] = {}
    error = None
    if not found and args.cmd == "render":
        written, error = _render(args, tree, site, network)
    if args.json:
        doc = {"problems": [str(p) for p in found], "notes": notes, "modules": len(tree.mods)}
        if args.cmd == "render":
            doc["written"] = written
        if error:
            doc["error"] = error
        print(json.dumps(doc, indent=2))
        for n in notes:  # the report is JSON on stdout; what was not checked also on stderr
            print(f"note: {n}", file=sys.stderr)
    else:
        for p in found:
            print(p)
        for n in notes:
            print(f"note: {n}")
        if written:
            from homelabnext.modules.tlp_sources import FILE as tlp_sources_file

            print(
                f"hnx modules render: wrote {written['limits']} limits and {written['egress']} "
                f"egress file(s), and {written['tlp_sources']} TLP source(s) in "
                f"{tlp_sources_file}, under {args.out}"
            )
        print(f"hnx modules: {len(tree.mods)} module(s), {len(found)} problem(s)")
    if error:
        print(f"hnx modules render: {error}", file=sys.stderr)
    return 1 if found or error else 0


def _render(
    args: argparse.Namespace, tree: ld.Tree, site: dict, network: dict | None = None
) -> tuple[dict[str, int], str | None]:
    """(files written per output, or the generator's refusal)."""
    from homelabnext.logpipeline.tlp_labels import SourceTableError
    from homelabnext.modules import egress, limits, tlp_sources

    ins = ld.inputs(tree)
    try:
        lim = limits.render(site, tree.mods, ld.units_fn(ins))
        egr = egress.render(site, tree.mods, ld.rows_fn(ins), ld.units_fn(ins), network)
        src = tlp_sources.render(site, tree.mods)
    except (limits.LimitsError, egress.EgressError, SourceTableError) as exc:
        return {}, str(exc)
    limits.write(lim, args.out / "limits")
    egress.write(egr, args.out / "egress")
    tlp_sources.write(src, args.out)
    return {"limits": len(lim), "egress": len(egr), "tlp_sources": len(src["sources"])}, None


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
