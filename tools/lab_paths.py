#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# hnx-script:
#   id: lab-paths
#   kind: tool
#   purpose: Decide whether a change can affect the lab-in-a-box smoke, so CI runs the real stack on exactly those pull requests and pushes.
#   owner: lab-in-a-box
#   trigger: [ci:ci/lab-paths]
#   inputs: git diff --no-renames --name-only of --changed-since against HEAD (or the paths given); compose/lab-in-a-box for --check
#   outputs: the matching paths, one per line; with --github-output, its `affected` line; with --check, one line per stack input no entry covers
#   exit:
#     "0": decided (or, with --check, every stack input is covered)
#     "1": with --check, a stack input no entry covers
#     "2": the changed paths could not be read
"""Which changes can affect the lab-in-a-box smoke (``compose/lab-in-a-box/smoke.sh``).

CI's ``lab-in-a-box`` job brings the real stack up on a pull request (and a push to main) only
when the change touches one of :data:`LAB_PATHS`; ``lab-ok`` is the one check that sums it up, so
a change that touches none of them passes without starting a container.  The list is derived from
what the smoke actually uses, and ``--check`` (run by the unit tests) re-derives it from the
compose file, so a new build context, ``COPY``, bind mount or conformance adapter that the list
does not cover fails rather than silently skipping the stack:

* ``compose/lab-in-a-box/``: the compose file, its env file, config, Dockerfiles, fakes, targets,
  rehearsals and the smoke itself;
* what the images are built from (the build context is the repository root): every ``COPY``
  source of every Dockerfile a service builds (the broker image copies the whole package, the
  conformance suites, schemas, profiles and examples, and installs from ``pyproject.toml`` and
  ``constraints/``);
* what the runner side runs: the project with its ``core`` and ``nats`` extras, installed by
  ``.github/actions/python-deps`` from ``constraints/``, and ``hnx conform`` with the adapters
  the ``targets/*.yml`` name (inside ``homelabnext/``);
* the jobs that run it (``ci.yml``'s and ``nightly.yml``'s) and this file.

An entry ending in ``/`` covers everything below it; any other entry is one file.  Renames are
read as a deletion and an addition (``--no-renames``), so moving a file out of a covered
directory counts too.

Usage: python tools/lab_paths.py --changed-since REV [--github-output FILE] | PATH... | --check
"""

from __future__ import annotations

import argparse
import posixpath
import subprocess
import sys
from collections.abc import Iterable
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
LAB = "compose/lab-in-a-box"

LAB_PATHS: tuple[str, ...] = (
    # the stack: compose file, env file, config, Dockerfiles, fakes, targets, rehearsals, smoke
    f"{LAB}/",
    # the images' COPY sources (build context: the repository root)
    "homelabnext/",
    "conformance/",
    "schemas/",
    "profiles/",
    "examples/",
    "pyproject.toml",
    "constraints/",
    # the runner's install of the project and the jobs that run the smoke
    ".github/actions/python-deps/",
    ".github/workflows/ci.yml",
    ".github/workflows/nightly.yml",
    "tools/lab_paths.py",
)


def covered(path: str, entries: Iterable[str] = LAB_PATHS) -> bool:
    """True when ``path`` (a file, or a directory given with or without its trailing ``/``) is
    one of ``entries`` or lies below a directory entry."""
    path = path.removeprefix("./")
    for e in entries:
        if e.endswith("/"):
            if path.startswith(e) or path == e.rstrip("/"):
                return True
        elif path == e:
            return True
    return False


def affected(paths: Iterable[str]) -> list[str]:
    """The paths of ``paths`` that can affect the smoke, in order, without repeats."""
    return [p for p in dict.fromkeys(paths) if p and covered(p)]


def changed_since(rev: str, root: Path = REPO_ROOT) -> list[str]:
    """The paths that differ between ``rev`` and ``HEAD`` (both sides of a rename)."""
    r = subprocess.run(
        ["git", "-C", str(root), "diff", "--no-renames", "--name-only", rev, "HEAD", "--"],
        capture_output=True,
        text=True,
        check=False,
    )
    if r.returncode != 0:
        raise OSError(r.stderr.strip() or f"git diff {rev} HEAD failed")
    return [line for line in r.stdout.splitlines() if line]


# --- the derivation the list is checked against ------------------------------------------------


def _copy_sources(dockerfile: Path) -> list[str]:
    """The build-context paths a Dockerfile's ``COPY``/``ADD`` lines read (not ``--from`` copies
    out of another stage, which read no context)."""
    out = []
    for line in dockerfile.read_text(encoding="utf-8").splitlines():
        words = line.split()
        if len(words) < 3 or words[0].upper() not in ("COPY", "ADD"):
            continue
        args = words[1:]
        if any(a.startswith("--from") for a in args):
            continue
        args = [a for a in args if not a.startswith("--")]
        out += args[:-1]  # every source; the last word is the destination
    return out


def stack_inputs(root: Path = REPO_ROOT) -> set[str]:
    """Every repository path the lab-in-a-box smoke reads, from the compose file and targets:
    each built service's Dockerfile and its ``COPY`` sources, every bind-mount and ``env_file``
    source, and the module of every conformance adapter a target names."""
    import yaml  # the check only; deciding needs nothing beyond the standard library

    lab = root / LAB
    doc = yaml.safe_load((lab / "docker-compose.yml").read_text(encoding="utf-8"))

    def rel(base: Path, p: str) -> str:
        # a path outside the repository (a host bind mount) no diff can cover: always reported
        try:
            return posixpath.normpath((base / p).resolve().relative_to(root.resolve()).as_posix())
        except ValueError:
            return f"{p} (outside the repository)"

    out = {f"{LAB}/docker-compose.yml", f"{LAB}/.env.example", f"{LAB}/smoke.sh"}
    for spec in (doc.get("services") or {}).values():
        spec = spec or {}
        build = spec.get("build")
        if isinstance(build, str):
            build = {"context": build}
        if isinstance(build, dict):
            ctx = (lab / build.get("context", ".")).resolve()
            dockerfile = ctx / build.get("dockerfile", "Dockerfile")
            out.add(rel(ctx, build.get("dockerfile", "Dockerfile")))
            ignore = ctx / ".dockerignore"
            if ignore.is_file():
                out.add(rel(ctx, ".dockerignore"))
            out |= {rel(ctx, src) for src in _copy_sources(dockerfile)}
        for vol in spec.get("volumes") or []:
            src = vol.get("source", "") if isinstance(vol, dict) else str(vol).split(":", 1)[0]
            if src.startswith((".", "/")):
                out.add(rel(lab, src))
        env_files = spec.get("env_file") or []
        for ef in [env_files] if isinstance(env_files, str) else env_files:
            out.add(rel(lab, ef if isinstance(ef, str) else ef["path"]))
    for target in sorted((lab / "targets").glob("*.yml")):
        tdoc = yaml.safe_load(target.read_text(encoding="utf-8")) or {}
        for entry in _walk(tdoc):
            module = entry.split(":", 1)[0]
            out.add(module.replace(".", "/") + ".py")
    return out


def _walk(node: object) -> Iterable[str]:
    """Every ``adapter:`` value anywhere in a target document."""
    if isinstance(node, dict):
        for k, v in node.items():
            if k == "adapter" and isinstance(v, str):
                yield v
            else:
                yield from _walk(v)
    elif isinstance(node, list):
        for v in node:
            yield from _walk(v)


def uncovered(root: Path = REPO_ROOT) -> list[str]:
    """The stack's inputs that :data:`LAB_PATHS` does not cover (empty when the list holds)."""
    return sorted(p for p in stack_inputs(root) if not covered(p))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("paths", nargs="*", help="changed paths to judge (instead of git)")
    ap.add_argument("--changed-since", metavar="REV", help="judge git diff REV HEAD")
    ap.add_argument("--github-output", metavar="FILE", help="append affected=true|false here")
    ap.add_argument("--check", action="store_true", help="the list covers every stack input")
    ap.add_argument("--repo", type=Path, default=REPO_ROOT, help=argparse.SUPPRESS)
    args = ap.parse_args(argv)

    if args.check:
        missing = uncovered(args.repo)
        for p in missing:
            print(f"::error::{p}: the lab-in-a-box reads it, but no LAB_PATHS entry covers it")
        return 1 if missing else 0

    if args.changed_since:
        try:
            paths = changed_since(args.changed_since, args.repo)
        except OSError as exc:
            print(f"lab_paths: {exc}", file=sys.stderr)
            return 2
    else:
        paths = args.paths
    hits = affected(paths)
    for p in hits:
        print(p)
    verdict = "true" if hits else "false"
    print(
        f"lab_paths: {len(hits)} of {len(paths)} changed paths can affect the lab-in-a-box"
        f" (affected={verdict})",
        file=sys.stderr,
    )
    if args.github_output:
        with open(args.github_output, "a", encoding="utf-8") as fh:
            fh.write(f"affected={verdict}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
