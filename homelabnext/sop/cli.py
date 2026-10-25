# SPDX-License-Identifier: Apache-2.0
"""``hnx docs systems generate|check|template REGISTRY [DIR]`` and ``hnx docs capabilities``.

``hnx docs index generate|check [FILE]`` fills or checks the page summaries in ``docs/README.md``
(see :mod:`homelabnext.sop.index`).

``hnx docs capabilities generate|check [--out DIR] [--registry FILE] [--root CHECKOUT]`` renders or
checks ``docs/capabilities/`` (see :mod:`homelabnext.sop.capabilities`).

Exit codes: 0 ok, 1 a registry row has no page, a page has no row, or a generated block is stale
(capabilities: a page is stale, missing or orphaned), 2 usage error (or no source checkout).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from homelabnext.registry.model import RegistryError, load
from homelabnext.reviews import ReviewError, load_policy

from .pages import check_pages, generate_pages, render_template


def _shown(p: Path) -> str:
    try:
        return p.resolve().relative_to(Path.cwd().resolve()).as_posix()
    except ValueError:
        return str(p)


def capabilities_main(argv: list[str]) -> int:
    from . import capabilities as caps

    ap = argparse.ArgumentParser(
        prog="hnx docs capabilities",
        description="generate or check the capability reference pages (docs/capabilities/)",
    )
    ap.add_argument("cmd", choices=["generate", "check"])
    ap.add_argument("--root", help="source checkout holding conformance/ (default: this checkout)")
    ap.add_argument("--out", help="pages directory (default: <root>/docs/capabilities)")
    ap.add_argument("--registry", help="service registry (default: <root>/examples/services.yml)")
    try:
        args = ap.parse_args(argv)
    except SystemExit as exc:
        return 2 if exc.code else 0
    try:
        root = caps.resolve_root(args.root)
        reg = load(args.registry or root / "examples" / "services.yml")
    except caps.NotACheckoutError as exc:
        print(f"hnx docs capabilities: {exc}", file=sys.stderr)
        return 2
    except (RegistryError, OSError) as exc:
        print(f"hnx docs capabilities: {exc}", file=sys.stderr)
        return 2
    out = Path(args.out) if args.out else root / caps.PAGES_DIR
    if args.cmd == "generate":
        written, removed = caps.generate(out, root, reg)
        print(
            f"capability pages: {len(written)} written, {len(removed)} orphan(s) removed"
            f" in {_shown(out)}"
        )
        return 0
    rep = caps.check(out, root, reg)
    for line in rep.lines():
        print(line)
    print(f"capability pages: {'ok' if rep.ok() else 'FAIL'} ({_shown(out)})")
    return 0 if rep.ok() else 1


def _mcp_catalog(option: str | None, registry: str):
    """The MCP catalog for the pages: ``--mcp-catalog`` (``none``: no catalog), else ``mcp/``
    beside the registry when it is a directory."""
    from homelabnext.mcp import servers

    if option == "none":
        return None
    path = Path(option) if option else servers.beside(registry)
    if option is None and not path.is_dir():
        return None
    return servers.load(path)


def index_main(argv: list[str]) -> int:
    from . import index

    ap = argparse.ArgumentParser(
        prog="hnx docs index",
        description="fill or check the page summaries in docs/README.md from the pages' front matter",
    )
    ap.add_argument("cmd", choices=["generate", "check"])
    ap.add_argument("file", nargs="?", default="docs/README.md")
    try:
        args = ap.parse_args(argv)
    except SystemExit as exc:
        return 2 if exc.code else 0
    path = Path(args.file)
    if not path.is_file():
        print(f"hnx docs index: {_shown(path)}: no such file", file=sys.stderr)
        return 2
    if args.cmd == "generate":
        changed, problems = index.generate(path)
        for line in problems:
            print(f"FAIL {line}")
        print(
            f"docs index: {'FAIL' if problems else 'written' if changed else 'unchanged'}"
            f" ({_shown(path)})"
        )
        return 1 if problems else 0
    lines = index.check(path)
    for line in lines:
        print(f"FAIL {line}")
    if lines:
        print(f"docs index: FAIL ({_shown(path)}); run `hnx docs index generate`")
        return 1
    print(f"docs index: ok ({_shown(path)})")
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv[:1] == ["capabilities"]:
        return capabilities_main(argv[1:])
    if argv[:1] == ["index"]:
        return index_main(argv[1:])
    ap = argparse.ArgumentParser(prog="hnx docs", description="generate and check documentation")
    ap.add_argument("topic", choices=["systems", "capabilities", "index"])
    ap.add_argument("cmd", choices=["generate", "check", "template"])
    ap.add_argument("registry", nargs="?")
    ap.add_argument("dir", nargs="?", default="docs/systems")
    ap.add_argument(
        "--require-complete", action="store_true", help="also fail on unfilled TODO blocks"
    )
    ap.add_argument(
        "--policy",
        help="review policy (default examples/review-policy.yml when it exists; `none` skips)",
    )
    ap.add_argument(
        "--mcp-catalog",
        help="the MCP catalog the pages' MCP lines come from (default: mcp/ beside the "
        "registry when it exists; `none` uses the registry's mcp entries)",
    )
    try:
        args = ap.parse_args(argv)
    except SystemExit as exc:
        return 2 if exc.code else 0
    if args.cmd == "template":
        print(render_template(), end="")
        return 0
    if not args.registry:
        print("hnx docs systems: a REGISTRY file is required", file=sys.stderr)
        return 2
    try:
        reg = load(args.registry)
    except (RegistryError, OSError) as exc:
        print(f"hnx docs systems: {exc}", file=sys.stderr)
        return 2
    try:
        catalog = _mcp_catalog(args.mcp_catalog, args.registry)
    except ValueError as exc:
        print(f"hnx docs systems: {exc}", file=sys.stderr)
        return 2
    if args.cmd == "generate":
        res = generate_pages(reg, args.dir, catalog)
        Path(args.dir, "_TEMPLATE.md").write_text(render_template(), encoding="utf-8")
        print(
            f"systems pages: {len(res.created)} created, {len(res.updated)} updated,"
            f" {len(res.unchanged)} unchanged in {args.dir}"
        )
        return 0
    policy_path = args.policy or (
        "examples/review-policy.yml" if Path("examples/review-policy.yml").is_file() else "none"
    )
    try:
        policy = None if policy_path == "none" else load_policy(policy_path)
    except ReviewError as exc:
        print(f"hnx docs systems: {exc}", file=sys.stderr)
        return 2
    rep = check_pages(reg, args.dir, policy, catalog)
    for line in rep.lines():
        print(line)
    for line in rep.info():
        print(f"info: {line}")
    open_todos = sum(rep.todo_open.values())
    ok = rep.ok(args.require_complete)
    print(
        f"systems pages: {'ok' if ok else 'FAIL'} ({len(reg.services)} services,"
        f" {open_todos} unfilled TODO blocks)"
    )
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
