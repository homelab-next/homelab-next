#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# hnx-script:
#   id: go-modules
#   kind: check
#   purpose: List the repository's Go modules for CI's Go job, and fail when Go code lies outside every module or a go.work would change how modules resolve.
#   owner: maintainers
#   trigger: [ci:ci/go-modules, script:component-tests]
#   inputs: the tracked files (git ls-files) of the repository, or of --repo
#   outputs: the modules as JSON on stdout; with --github-output, its `modules` and `present` lines; one line per problem
#   exit:
#     "0": the modules are listed
#     "1": Go outside every module or inside a linters' module, a go.work, a go.mod that is not a regular file, or a linters' module without its go.mod
#     "2": the tracked files could not be read
"""Discover the Go modules of the repository: every tracked ``go.mod`` is one.

CI's Go job runs once per module (a matrix over this tool's output), so a second module, or one
nested inside another, is built, vetted and tested without anyone listing it; ``./...`` in a module
never crosses into a nested one, which is why a list kept by hand would hide it.

One explicit rule: ``<module>/tools/go.mod`` is that module's **linters' module** (staticcheck,
govulncheck pinned as ``tool`` dependencies), run from the module's own job with
``go tool -modfile=tools/go.mod``.  It is not a module of its own in the list, and
``<module>/tools/`` holding Go without that go.mod is a problem, so deleting the file
cannot silently turn the linters off.  Nor may the linters' module hold Go source of its own: it
pins tools with ``tool`` directives and needs none, and no job would build, vet or test it.

Problems (exit 1), each also an ``::error::`` line for the GitHub log:

* a ``.go`` file or a ``go.sum`` in no module (a go.mod missing, renamed or moved), or a go.sum
  that is not beside a go.mod;
* a ``.go`` file in a linters' module (``<module>/tools/``, not in a module nested below it);
* a ``go.mod`` that is a symbolic link, or a path that runs through a directory named ``go.mod``;
* a ``go.work`` or ``go.work.sum``: CI runs with ``GOWORK=off``, so a workspace would make a local
  build resolve modules differently from the one CI checked.

With no Go in the repository at all the list is empty and the Go job is skipped: a no-op.

Usage: python tools/go_modules.py [--repo DIR] [--github-output FILE]
Exit: 0 listed, 1 a problem, 2 the tracked files could not be read.
"""

from __future__ import annotations

import argparse
import json
import posixpath
import subprocess
import sys
from collections.abc import Iterable
from dataclasses import asdict, dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
LINTERS_DIR = "tools"  # <module>/tools/go.mod: the module's linters, not a module of its own
WORKSPACE_FILES = ("go.work", "go.work.sum")


@dataclass(frozen=True)
class Module:
    dir: str  # relative to the repository root, posix; "." for the root
    tools: bool  # it has a linters' module at <dir>/tools/go.mod


def _dir(path: str) -> str:
    return posixpath.dirname(path) or "."


def _join(d: str, name: str) -> str:
    return name if d == "." else f"{d}/{name}"


def _owner(path: str, dirs: Iterable[str]) -> str | None:
    """The nearest directory of ``dirs`` that holds ``path`` (``.`` holds everything)."""
    best = None
    for d in dirs:
        if (d == "." or path.startswith(d + "/")) and (best is None or len(d) > len(best)):
            best = d
    return best


def _linters_of(d: str, module_dirs: set[str]) -> str | None:
    """The module whose linters' module ``d`` is, if ``d`` is ``<module>/tools``."""
    if posixpath.basename(d) != LINTERS_DIR:
        return None
    parent = _dir(d)
    return parent if parent in module_dirs else None


def modules(go_mods: Iterable[str]) -> list[Module]:
    """The modules, from the paths of the ``go.mod`` files; linters' modules fold into theirs."""
    dirs = {_dir(p) for p in go_mods if posixpath.basename(p) == "go.mod"}
    linters = {d for d in dirs if _linters_of(d, dirs)}
    return [
        Module(d, _join(d, LINTERS_DIR) in linters) for d in sorted(dirs - linters, key=_sort_key)
    ]


def _sort_key(d: str) -> tuple[int, str]:
    return (0 if d == "." else d.count("/") + 1, d)


def problems(files: Iterable[str], symlinks: Iterable[str] = ()) -> list[str]:
    """Go that no module covers, a go.work, and go.mod files that are not regular files."""
    files = sorted(set(files))
    links = set(symlinks)
    out: list[str] = []
    go_mods = [f for f in files if posixpath.basename(f) == "go.mod"]
    mod_dirs = {_dir(f) for f in go_mods}
    for f in files:
        parts = f.split("/")
        name = parts[-1]
        if "go.mod" in parts[:-1]:
            out.append(f"{f}: lies in a directory named go.mod; a module's go.mod is a file")
        elif name == "go.mod" and f in links:
            out.append(f"{f}: a symbolic link; a module's go.mod must be a regular file")
        elif name in WORKSPACE_FILES:
            out.append(
                f"{f}: a Go workspace file; CI builds every module on its own (GOWORK=off), so a "
                "workspace would make local builds resolve modules differently: remove it"
            )
        elif name == "go.sum" and _dir(f) not in mod_dirs:
            out.append(f"{f}: a go.sum with no go.mod beside it")
        elif name.endswith(".go") and (owner := _owner(f, mod_dirs)) is None:
            out.append(f"{f}: Go source in no module (no go.mod in a directory above it)")
        elif name.endswith(".go") and _linters_of(owner, mod_dirs):
            out.append(
                f"{f}: Go source in the linters' module {owner}/, which no job builds, vets or "
                f"tests (it only pins tools); move it into {_dir(owner)}/ or a module of its own"
            )
    for d in sorted(mod_dirs):
        linters = _join(d, LINTERS_DIR)
        if linters in mod_dirs:
            continue
        stray = [
            f
            for f in files
            if f.startswith(linters + "/") and f.endswith(".go") and _owner(f, mod_dirs) == d
        ]
        if stray:
            out.append(
                f"{linters}/: holds Go but has no go.mod; it is reserved for the linters' module "
                f"of {d} (go tool -modfile=tools/go.mod), which would otherwise silently not run"
            )
    return out


def dependabot_directories(mods: Iterable[Module]) -> list[str]:
    """The ``directories`` a ``gomod`` Dependabot entry needs: each module and its linters'.

    Dependabot cannot glob for modules, so its entries stay explicit; a test compares them with
    this list, so a discovered module without one fails instead of never being updated."""
    out = []
    for m in mods:
        top = "/" if m.dir == "." else f"/{m.dir}"
        out.append(top)
        if m.tools:
            out.append(f"{top.rstrip('/')}/{LINTERS_DIR}")
    return out


def tracked(repo: Path) -> tuple[list[str], list[str]]:
    """``(paths, symlinks)`` of the files git tracks in ``repo``."""
    out = subprocess.run(
        ["git", "ls-files", "-s", "-z"], cwd=repo, capture_output=True, text=True, check=True
    ).stdout
    paths, links = [], []
    for entry in out.split("\0"):
        if not entry:
            continue
        meta, path = entry.split("\t", 1)
        paths.append(path)
        if meta.startswith("120000 "):
            links.append(path)
    return paths, links


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--repo", type=Path, default=REPO_ROOT)
    ap.add_argument("--github-output", type=Path, metavar="FILE", help="append modules= present=")
    args = ap.parse_args(argv)
    try:
        files, links = tracked(args.repo)
    except (OSError, subprocess.CalledProcessError) as exc:
        print(f"go_modules: cannot list the tracked files of {args.repo}: {exc}", file=sys.stderr)
        return 2
    found = problems(files, links)
    for p in found:
        print(f"::error::{p}")
    if found:
        return 1
    mods = modules(files)
    listing = json.dumps([asdict(m) for m in mods], separators=(",", ":"))
    print(listing)
    if args.github_output:
        with args.github_output.open("a", encoding="utf-8") as fh:
            fh.write(f"modules={listing}\npresent={'true' if mods else 'false'}\n")
    if not mods:
        print("::notice::no Go module in the repository: nothing to build or test")
    return 0


if __name__ == "__main__":
    sys.exit(main())
