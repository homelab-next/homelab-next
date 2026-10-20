# SPDX-License-Identifier: Apache-2.0
"""``hnx mcp serve|tools|call``.

* ``serve [--root CHECKOUT] [--registry FILE] [--scope-from-profile PROFILE.json]`` runs the
  read-only MCP server on stdio (needs ``pip install 'homelabnext[mcp]'``); there is no network
  transport.  With ``--scope-from-profile``, every tool but ``get_schema`` and
  ``invariants_status`` is bounded by the compiled profile's grants (the profile must verify and be granted ``hnx-catalog``);
* ``tools`` lists the tools and what each answers (no SDK needed);
* ``call TOOL [--args JSON] [...]`` runs one tool in-process and prints its JSON result, the
  same handler the server calls (no SDK needed; for debugging and scripts).

Exit codes: 0 ok, 1 the call was refused or the profile cannot scope the server, 2 usage error,
no source checkout, or the ``mcp`` extra is missing.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .catalog import TOOLS, Catalog, CatalogError
from .scope import ScopeError, load_profile_scope


def _catalog(args) -> Catalog:
    from homelabnext import paths

    root = Path(args.root).resolve() if args.root else paths.checkout_root()
    if root is None:
        raise CatalogError("needs a homelabnext source checkout (run it from one or pass --root)")
    cat = Catalog(root, registry_path=args.registry)
    if args.scope_from_profile:
        pid, scope = load_profile_scope(args.scope_from_profile, cat.registry)
        cat.scope, cat.scope_source = scope, pid
    return cat


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="hnx mcp", description="the read-only MCP server over this repository (docs/mcp.md)"
    )
    ap.add_argument("cmd", choices=["serve", "tools", "call"])
    ap.add_argument("tool", nargs="?", help="call: the tool to run")
    ap.add_argument("--args", default="{}", help="call: the tool's arguments as a JSON object")
    ap.add_argument("--root", help="source checkout (default: this checkout)")
    ap.add_argument("--registry", help="service registry (default: <root>/examples/services.yml)")
    ap.add_argument(
        "--scope-from-profile",
        metavar="PROFILE",
        help="a compiled agent profile whose grants bound the tools (all but get_schema and "
        "invariants_status)",
    )
    try:
        args = ap.parse_args(argv)
    except SystemExit as exc:
        return 2 if exc.code else 0
    if args.cmd == "tools":
        for name, text in sorted(TOOLS.items()):
            print(f"{name}: {text}")
        return 0
    if args.cmd == "call" and args.tool not in TOOLS:
        print(f"hnx mcp call: give one of {', '.join(sorted(TOOLS))}", file=sys.stderr)
        return 2
    try:
        cat = _catalog(args)
    except CatalogError as exc:
        print(f"hnx mcp: {exc}", file=sys.stderr)
        return 2
    except ScopeError as exc:
        print(f"hnx mcp: {exc}", file=sys.stderr)
        return 1
    if args.cmd == "serve":
        try:
            from .server import _sdk, serve

            _sdk()
        except ImportError:
            print(
                "hnx mcp serve: the MCP SDK is not installed (pip install 'homelabnext[mcp]')",
                file=sys.stderr,
            )
            return 2
        serve(cat)
        return 0
    try:
        arguments = json.loads(args.args)
    except ValueError:
        print("hnx mcp call: --args is not valid JSON", file=sys.stderr)
        return 2
    if not isinstance(arguments, dict):
        print("hnx mcp call: --args must be a JSON object", file=sys.stderr)
        return 2
    try:
        print(cat.call(args.tool, arguments))
    except CatalogError as exc:
        print(f"hnx mcp call: refused: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
