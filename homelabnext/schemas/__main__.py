# SPDX-License-Identifier: Apache-2.0
"""``python -m homelabnext.schemas [--root DIR] [--check]``: regenerate (or check) the generated
module-manifest schemas, examples and negatives (see :mod:`homelabnext.schemas`).

Exit: 0 written or current, 1 a committed file differs (``--check``), 2 usage error.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import module_manifest, module_negatives


def outputs(root: Path) -> dict[str, str]:
    """Every generated file, repository-relative path -> text."""
    out = dict(module_manifest.render())
    out.update(module_negatives.render(root))
    return out


def stale(root: Path) -> list[str]:
    """Generated files whose committed text differs from the generators' output."""
    bad = []
    for rel, text in sorted(outputs(root).items()):
        p = root / rel
        if not p.is_file() or p.read_text(encoding="utf-8") != text:
            bad.append(rel)
    return bad


def orphans(root: Path) -> list[str]:
    """Committed module negatives and schema-directory examples no generator writes any more."""
    made = set(outputs(root))
    plat = root / "schemas" / "platform"
    found = [
        p
        for g in ("module", "module_selection", "lake_table", "interface")
        for d in ("negative", "examples")
        for p in plat.glob(f"{d}/{g}.*.yml")
    ]
    return sorted(
        p.relative_to(root).as_posix() for p in found if p.relative_to(root).as_posix() not in made
    )


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m homelabnext.schemas", description=__doc__)
    ap.add_argument("--root", type=Path, default=Path.cwd(), help="repository root (default: .)")
    ap.add_argument("--check", action="store_true", help="exit 1 if a committed file differs")
    args = ap.parse_args(argv)
    root = args.root
    if not (root / "schemas" / "platform").is_dir() or not (root / "examples" / "modules").is_dir():
        print(
            f"{root}: not a repository root (no schemas/platform or examples/modules)",
            file=sys.stderr,
        )
        return 2
    if args.check:
        problems = [
            f"{r}: differs from the generator (python -m homelabnext.schemas)" for r in stale(root)
        ]
        problems += [f"{r}: no generator writes it (remove it)" for r in orphans(root)]
        for p in problems:
            print(p)
        return 1 if problems else 0
    for rel, text in sorted(outputs(root).items()):
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        if not p.is_file() or p.read_text(encoding="utf-8") != text:
            p.write_text(text, encoding="utf-8")
            print("wrote", rel)
    for rel in orphans(root):
        (root / rel).unlink()
        print("removed", rel)
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
