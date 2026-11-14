#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# hnx-script:
#   id: yaml-loader-lint
#   kind: check
#   purpose: Fail when package code parses YAML with yaml.safe_load or SafeLoader instead of the budgeted loaders of homelabnext/_yaml.py, beyond the counts in tools/yaml_loader.allow.yml.
#   owner: maintainers
#   trigger: [ci:ci/schemas, make:gates]
#   inputs: homelabnext/**/*.py; tools/yaml_loader.allow.yml
#   outputs: one line per file above or below its reviewed count
#   exit:
#     "0": every file at its count
#     "1": a file with more unbudgeted uses than its count (or one not listed), or fewer (lower the count)
#     "2": usage error or a malformed allowlist
"""Gate: package code parses YAML through the budgeted loaders only.

``yaml.safe_load`` and ``yaml.SafeLoader`` construct whatever a document says, so a few hundred
bytes of nested aliases or merges, or a node that contains itself, keep a reader busy for minutes
or forever (the alias and merge bombs of #350).  ``homelabnext/_yaml.py`` holds the budgeted ones:
``safe_load``, ``BudgetedLoader`` and ``UniqueKeyLoader`` built on it.  This gate counts each
package file's lines that name ``safe_load(`` on ``yaml`` or ``SafeLoader`` (``_yaml.py`` itself
excepted) and holds them to ``tools/yaml_loader.allow.yml``: a ``path``, its ``count`` and a
``reason`` per file.  A file above its count, or with uses and no entry, fails: use the budgeted
loaders.  A file below its count fails too, with the count to lower it to, so the baseline only
shrinks.  ``allowlist_ratchet`` holds the number of entries.

Usage: python tools/yaml_loader_lint.py [ROOT] [--allowlist FILE]
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

REPO_ROOT_FOR_IMPORT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT_FOR_IMPORT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT_FOR_IMPORT))

from homelabnext.allowlist import entries  # noqa: E402

DEFAULT_ALLOWLIST = "tools/yaml_loader.allow.yml"
#: a use of the unbudgeted loaders: ``yaml.safe_load(``/``yaml.safe_load_all(`` or ``SafeLoader``
USE = re.compile(r"\byaml\.safe_load(?:_all)?\s*\(|\bSafeLoader\b")
EXEMPT = ("homelabnext/_yaml.py",)


class AllowlistError(ValueError):
    """A malformed allowlist (exit 2)."""


def counts(root: Path) -> dict[str, int]:
    """``{path: uses}`` of every package file with at least one unbudgeted use."""
    out: dict[str, int] = {}
    for p in sorted((root / "homelabnext").rglob("*.py")):
        rel = p.relative_to(root).as_posix()
        if rel in EXEMPT or "__pycache__" in p.parts:
            continue
        n = sum(1 for line in p.read_text(encoding="utf-8").splitlines() if USE.search(line))
        if n:
            out[rel] = n
    return out


def load_allowlist(path: Path) -> dict[str, int]:
    out: dict[str, int] = {}
    for e in entries(path, AllowlistError):
        n = e.get("count")
        if not isinstance(n, int) or isinstance(n, bool) or n < 1:
            raise AllowlistError(f"{path}: {e['path']}: 'count' must be a whole number >= 1")
        if e["path"] in out:
            raise AllowlistError(f"{path}: {e['path']} is listed twice")
        out[str(e["path"])] = n
    return out


def problems(found: dict[str, int], allowed: dict[str, int]) -> list[str]:
    out = []
    for rel in sorted(set(found) | set(allowed)):
        have, may = found.get(rel, 0), allowed.get(rel, 0)
        if have > may:
            out.append(
                f"{rel}: {have} use(s) of yaml.safe_load/SafeLoader, {may} allowed: parse with "
                "homelabnext._yaml (safe_load, BudgetedLoader, UniqueKeyLoader)"
            )
        elif have < may:
            out.append(
                f"{rel}: {have} use(s), {may} allowed: lower its count in "
                f"{DEFAULT_ALLOWLIST} (to {have}, or drop the entry) so the baseline shrinks"
            )
    return out


def main(argv: list[str] | None = None, out=None, err=None) -> int:
    out, err = out or sys.stdout, err or sys.stderr
    ap = argparse.ArgumentParser(prog="yaml_loader_lint", description=__doc__.split("\n\n")[0])
    ap.add_argument("root", nargs="?", default=".")
    ap.add_argument("--allowlist", help=f"default: <root>/{DEFAULT_ALLOWLIST}")
    try:
        args = ap.parse_args(argv)
    except SystemExit as exc:
        return 2 if exc.code else 0
    root = Path(args.root)
    try:
        allowed = load_allowlist(
            Path(args.allowlist) if args.allowlist else root / DEFAULT_ALLOWLIST
        )
    except AllowlistError as exc:
        print(f"yaml_loader_lint: {exc}", file=err)
        return 2
    found = counts(root)
    found_problems = problems(found, allowed)
    for p in found_problems:
        print(f"yaml_loader_lint: {p}", file=err)
    print(
        f"yaml_loader_lint: {len(found_problems)} problem(s); {sum(found.values())} unbudgeted "
        f"use(s) in {len(found)} file(s) at the reviewed baseline",
        file=out,
    )
    return 1 if found_problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
