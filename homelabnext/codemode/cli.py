# SPDX-License-Identifier: Apache-2.0
"""``hnx codemode gen [--manifest FILE] [--out DIR] [--check]``: the Code Mode namespaces;
``hnx codemode mcp --index DIR --socket PATH``: the search and describe tools (stdio).

Renders, for every profile the broker manifest grants actions to, ``<out>/<profile>/types.d.ts``,
``stubs.pyi`` and ``search.json`` (:mod:`homelabnext.codemode.render`).  The defaults are the
public example and its committed goldens, ``examples/broker/manifest.yml`` into
``examples/codemode/``, relative to the working directory (the checkout, as ``make gates`` and CI
run it).  ``--check`` writes nothing and fails on any drift: a hand edit, a manifest or handler
document change that was not regenerated, or a profile directory no longer rendered.

``mcp`` serves ``codemode_search`` and ``codemode_describe`` (:mod:`homelabnext.codemode.mcp_tools`)
over the index ``gen`` wrote, for the profile the broker socket maps this process to.

Exit (``docs/interfaces.md``): 0 written or clean; 1 drift; 2 bad input (an unreadable or
invalid manifest, one that cannot be rendered, an output directory that cannot be written or
holds a symlinked profile directory or file); 100 ``--check`` could not read the output
directory (it could not measure).
"""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Sequence

from .model import CodemodeError
from .render import DEFAULT_MANIFEST, DEFAULT_OUT, check, render, write

#: ``--check`` could not read what it compares (docs/interfaces.md: >= 100)
COULD_NOT_MEASURE = 100


def main(argv: Sequence[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="hnx codemode",
        description="Code Mode (ADR-0031): the per-profile namespaces and search index",
    )
    sub = ap.add_subparsers(dest="cmd", required=True)
    gen = sub.add_parser("gen", help="render the stubs and search index of every granted profile")
    gen.add_argument("--manifest", default=DEFAULT_MANIFEST, help="broker manifest")
    gen.add_argument(
        "--out", default=DEFAULT_OUT, help="output directory, one subdirectory per profile"
    )
    gen.add_argument("--check", action="store_true", help="write nothing; fail on drift")
    m = sub.add_parser("mcp", help="codemode_search and codemode_describe over stdio (MCP)")
    m.add_argument("--index", default=DEFAULT_OUT, help="the directory gen wrote")
    m.add_argument("--socket", default=os.environ.get("HNX_BROKER_SOCKET"), help="broker socket")
    args = ap.parse_args(list(argv) if argv is not None else None)
    if args.cmd == "mcp":
        return _mcp(args)
    from homelabnext.broker.service import ManifestError

    try:
        files = render(args.manifest)
    except (ManifestError, CodemodeError) as exc:
        print(exc, file=sys.stderr)
        return 2
    if args.check:
        try:
            problems = check(args.out, files)
        except OSError as exc:
            print(f"codemode: cannot read {args.out}: {exc.strerror or exc}", file=sys.stderr)
            return COULD_NOT_MEASURE
        for p in problems:
            print(f"codemode: {p} (run `hnx codemode gen` and commit)", file=sys.stderr)
        if problems:
            return 1
        print(f"codemode: {len(files)} files in {args.out} match {args.manifest}")
        return 0
    try:
        written, unchanged, removed = write(args.out, files)
    except CodemodeError as exc:
        print(exc, file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"codemode: cannot write {args.out}: {exc.strerror or exc}", file=sys.stderr)
        return 2
    print(
        f"codemode: wrote {len(written)}, unchanged {len(unchanged)}, removed {len(removed)} "
        f"in {args.out}"
    )
    return 0


def _mcp(args) -> int:
    from homelabnext.broker.client import BrokerClient
    from homelabnext.mcp.server import sdk_missing

    from .mcp_tools import serve

    if not args.socket:
        print("hnx codemode mcp: --socket (or HNX_BROKER_SOCKET) is required", file=sys.stderr)
        return 2
    if sdk_missing():
        print(
            "hnx codemode mcp: the MCP SDK is not installed (pip install 'homelabnext[mcp]')",
            file=sys.stderr,
        )
        return 2
    serve(args.index, BrokerClient(args.socket))
    return 0


if __name__ == "__main__":
    sys.exit(main())
