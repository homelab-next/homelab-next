# SPDX-License-Identifier: Apache-2.0
"""``hnx codemode gen [--manifest FILE] [--out DIR] [--check]``: the Code Mode namespaces.

Renders, for every profile the broker manifest grants actions to, ``<out>/<profile>/types.d.ts``,
``stubs.pyi`` and ``search.json`` (:mod:`homelabnext.codemode.render`).  The defaults are the
public example and its committed goldens, ``examples/broker/manifest.yml`` into
``examples/codemode/``, relative to the working directory (the checkout, as ``make gates`` and CI
run it).  ``--check`` writes nothing and fails on any drift: a hand edit, a manifest or handler
document change that was not regenerated, or a profile directory no longer rendered.

Exit: 0 written or clean, 1 drift, 2 an unreadable or invalid manifest, or one that cannot be
rendered.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from .model import CodemodeError
from .render import DEFAULT_MANIFEST, DEFAULT_OUT, check, render, write


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
    args = ap.parse_args(list(argv) if argv is not None else None)
    from homelabnext.broker.service import ManifestError

    try:
        files = render(args.manifest)
    except (ManifestError, CodemodeError) as exc:
        print(exc, file=sys.stderr)
        return 2
    if args.check:
        problems = check(args.out, files)
        for p in problems:
            print(f"codemode: {p} (run `hnx codemode gen` and commit)", file=sys.stderr)
        if problems:
            return 1
        print(f"codemode: {len(files)} files in {args.out} match {args.manifest}")
        return 0
    written, unchanged, removed = write(args.out, files)
    print(
        f"codemode: wrote {len(written)}, unchanged {len(unchanged)}, removed {len(removed)} "
        f"in {args.out}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
