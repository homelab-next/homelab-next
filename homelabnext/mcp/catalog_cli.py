# SPDX-License-Identifier: Apache-2.0
"""``hnx mcp catalog check|list|classes|render|import`` (the MCP catalog, docs/mcp-catalog.md).

* ``check [--catalog DIR] [--registry FILE] [--policy FILE|none] [--grants PATH ...]``: the
  catalog's own rules (:func:`.servers.check`), the registry cross-references, the review
  policy, and every agent profile and context manifest under ``--grants`` (default: this
  checkout) judged against the catalog (unknown, retired, draft, reader, data tier);
* ``list [--json]``: one line per server; ``classes``: the derived ``mcp`` class table;
* ``render --profile FILE --client CLIENT [--param SERVER.NAME=VALUE ...] [--lanes L,L]
  [--out FILE] [--check]`` or ``render --spec FILE [--root DIR] [--check]``: client
  configurations (:mod:`.clients`) of profiles ``hnx agent verify`` would accept; ``--check``
  fails on drift in any output;
* ``import CONFIG ... [--out DIR] [--force]``: draft records from existing client configs
  (:mod:`.importer`); the report names every secret it stripped, never a value.

Defaults: ``--catalog`` is the example data's ``mcp/`` (``HNX_EXAMPLES_DIR`` aware), and
``--registry`` the ``services.yml`` beside the catalog directory.

Exit codes: 0 ok, 1 problems or drift, 2 usage error or unreadable input.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from homelabnext.registry.model import RegistryError

from . import clients, importer, servers


def _paths(args) -> tuple[Path, Path | None]:
    cat = Path(args.catalog) if args.catalog else servers.default_dir()
    if getattr(args, "registry", None):
        return cat, Path(args.registry)
    guess = cat.resolve().parent / "services.yml"
    return cat, guess if guess.is_file() else None


def _registry(path: Path | None):
    from homelabnext.registry.model import load

    return load(path) if path else None


def _check(args) -> int:
    from homelabnext import paths
    from homelabnext.agent.readers import ToolClasses, lint_paths
    from homelabnext.reviews import load_policy

    cat_dir, reg_path = _paths(args)
    cat = servers.load(cat_dir)
    root = paths.checkout_root()
    if args.policy == "none":
        policy = None
    else:
        pol = Path(args.policy) if args.policy else cat_dir.resolve().parent / "review-policy.yml"
        policy = load_policy(pol) if args.policy or pol.is_file() else None
    problems = servers.check(cat, registry=_registry(reg_path), policy=policy, source_root=root)
    grants = args.grants or ([str(root)] if root else [])
    classes = ToolClasses.load(catalog=cat_dir)
    notes: list[tuple[str, str]] = []
    gp, counts = (
        lint_paths(grants, classes, notes) if grants else ([], {"profile": 0, "manifest": 0})
    )
    problems += [f"{f}: {p}" for f, p in gp]
    for p in problems:
        print(p)
    for f, n in notes:
        print(f"note: {f}: {n}", file=sys.stderr)
    print(
        f"hnx mcp catalog: {len(cat.servers)} server(s), {counts['profile']} profile(s), "
        f"{counts['manifest']} manifest(s), {len(problems)} problem(s)",
        file=sys.stderr,
    )
    return 1 if problems else 0


def _list(args) -> int:
    cat = servers.load(_paths(args)[0])
    classes = cat.classes()
    if args.json:
        print(json.dumps(dict(cat), indent=1, sort_keys=True, default=str))
        return 0
    for sid, rec in cat:
        t = rec.get("transport") or {}
        where = t.get("endpoint") or t.get("command")
        print(
            f"{sid}\t{rec.get('status')}\t{rec.get('owner')}\t{t.get('type')} {where}\t"
            f"{','.join(classes.get(sid, ())) or '-'}"
        )
    return 0


def _classes(args) -> int:
    import yaml

    print(yaml.safe_dump({"mcp": servers.load(_paths(args)[0]).classes()}, sort_keys=True), end="")
    return 0


def _params(items: list[str]) -> dict[str, dict[str, str]]:
    out: dict[str, dict[str, str]] = {}
    for item in items:
        key, eq, value = item.partition("=")
        server, dot, name = key.rpartition(".")
        if not eq or not dot or not server or not name:
            raise ValueError(
                f"--param {item!r}: write SERVER.NAME=VALUE (SERVER@LANE for one lane)"
            )
        out.setdefault(server, {})[name] = value
    return out


def _render(args) -> int:
    if bool(args.spec) == bool(args.profile):
        print(
            "hnx mcp catalog render: give --spec FILE, or --profile FILE --client C",
            file=sys.stderr,
        )
        return 2
    if args.spec:
        rendered = clients.render_spec(args.spec, args.root)
    else:
        if not args.client:
            print("hnx mcp catalog render: --profile needs --client", file=sys.stderr)
            return 2
        cat_dir, reg_path = _paths(args)
        text, notes = clients.render_profile(
            servers.load(cat_dir),
            args.profile,
            args.client,
            registry=_registry(reg_path),
            params=_params(args.param),
            lanes=[x for x in args.lanes.split(",") if x],
            profile_file=args.profile_path,
        )
        if not args.out:
            if args.check:
                print("hnx mcp catalog render: --check needs --out (or --spec)", file=sys.stderr)
                return 2
            sys.stdout.write(text)
            for n in notes:
                print(f"note: {n}", file=sys.stderr)
            return 0
        out = Path(args.out)
        splice = args.client == "llm-orchestrator"
        rendered = clients.Rendered([clients.Output(out, text, splice=splice)], notes)
    for n in rendered.notes:
        print(f"note: {n}", file=sys.stderr)
    if args.check:
        bad = clients.drift(rendered)
        for b in bad:
            print(b)
        print(
            f"hnx mcp catalog render: {len(rendered.outputs)} output(s), {len(bad)} drifted",
            file=sys.stderr,
        )
        return 1 if bad else 0
    for p in clients.write(rendered):
        print(f"wrote {p}", file=sys.stderr)
    return 0


def _import(args) -> int:
    out = Path(args.out) if args.out else servers.default_dir()
    existing = [f.stem for f in out.glob("*.yml")] if out.is_dir() else []
    res = importer.import_configs(args.configs, existing)
    written, skipped = importer.write_records(res.records, out, force=args.force)
    for line in res.report + skipped:
        print(line)
    print(
        f"hnx mcp catalog import: {len(res.records)} server(s), {len(written)} draft record(s) "
        f"written to {out}; run `hnx mcp catalog check --catalog {out}` and fix what it lists",
        file=sys.stderr,
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="hnx mcp catalog", description="the MCP catalog (docs/mcp-catalog.md)"
    )
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("check", "list", "classes", "render", "import"):
        p = sub.add_parser(name)
        p.add_argument("--catalog", help="the catalog directory (default: the example data's mcp/)")
        if name in ("check", "render"):
            p.add_argument(
                "--registry", help="the service registry (default: services.yml beside the catalog)"
            )
    chk = sub.choices["check"]
    chk.add_argument(
        "--policy", help="review policy (default: review-policy.yml beside the catalog; none skips)"
    )
    chk.add_argument(
        "--grants",
        nargs="*",
        default=None,
        help="profiles/manifests to judge (default: the checkout)",
    )
    sub.choices["list"].add_argument("--json", action="store_true")
    r = sub.choices["render"]
    r.add_argument("--spec", help="a render spec: every output it names")
    r.add_argument("--profile", help="one compiled or lean agent profile")
    r.add_argument("--client", choices=clients.CLIENTS)
    r.add_argument(
        "--param",
        action="append",
        default=[],
        help="SERVER.NAME=VALUE; SERVER may be SERVER@LANE for one lane",
    )
    r.add_argument("--lanes", default="real", help="comma-separated lanes (default real)")
    r.add_argument(
        "--profile-path", help="the profile's path as the client sees it ({profile_file})"
    )
    r.add_argument("--out", help="write here instead of stdout")
    r.add_argument(
        "--root",
        help="with --spec: the directory output paths are relative to and confined to "
        "(default: the spec's directory)",
    )
    r.add_argument(
        "--check", action="store_true", help="fail when an output differs from the render"
    )
    i = sub.choices["import"]
    i.add_argument("configs", nargs="+", help="client config files (JSON or YAML)")
    i.add_argument("--out", help="where the drafts go (default: the catalog directory)")
    i.add_argument("--force", action="store_true", help="replace existing records")
    try:
        args = ap.parse_args(argv)
    except SystemExit as exc:
        return 2 if exc.code else 0
    if args.cmd == "import" and args.catalog and not args.out:
        args.out = args.catalog
    try:
        return {
            "check": _check,
            "list": _list,
            "classes": _classes,
            "render": _render,
            "import": _import,
        }[args.cmd](args)
    except clients.RenderError as exc:
        for p in exc.problems:
            print(p)
        print(f"hnx mcp catalog render: refused ({len(exc.problems)} problem(s))", file=sys.stderr)
        return 1
    except (servers.CatalogError, ValueError, OSError, RegistryError) as exc:
        print(f"hnx mcp catalog: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
