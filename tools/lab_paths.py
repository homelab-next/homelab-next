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
when the change touches one of :data:`LAB_PATHS`, and ``lab-gateway`` its optional LLM gateway
profile on the same decision (the profile's services are in the compose file, so the derivation
below covers them too); ``lab-ok`` is the one check that sums both up, so a change that touches
none of them passes without starting a container.  The list is derived from
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

The **step-level** inputs are listed by hand, because no file declares them: what the job's steps
read outside the images (``setup.py``, which ``python-deps`` installs with ``pip install -e .``;
``capabilities.yml`` and ``registry/``, which ``hnx conform report`` reads through
``homelabnext/conform/registry.py``, so a capability added there without a suite fails the job).
``--check`` re-derives only the compose side; a new step that reads another file needs its entry
here, by hand, in the same change.

Most pull requests run the stack, by design: the broker image copies nearly the whole package,
the schemas and the examples, so a change there is a change to the image under test.  Do not
narrow the list to save runner time; a skipped stack is a green check that tested nothing.

A Dockerfile line ``--check`` cannot read (a heredoc, a variable in a source, a ``RUN --mount``
of the build context, malformed JSON) fails the check instead of being skipped.

An entry ending in ``/`` covers everything below it; any other entry is one file.  Renames are
read as a deletion and an addition (``--no-renames``), so moving a file out of a covered
directory counts too.

Usage: python tools/lab_paths.py --changed-since REV [--github-output FILE] | PATH... | --check
"""

from __future__ import annotations

import argparse
import json
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
    # step-level inputs (hand-listed: see above): the editable install and the capability registry
    "setup.py",
    "capabilities.yml",
    "registry/",
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
    """The paths that differ between ``rev`` and ``HEAD`` (both sides of a rename).  Read
    NUL-separated (``-z``): without it git quotes a path with a non-ASCII byte, a tab or a quote
    (``"caf\\303\\251.toml"``), and the quoted spelling matches no entry."""
    r = subprocess.run(
        ["git", "-C", str(root), "diff", "-z", "--no-renames", "--name-only", rev, "HEAD", "--"],
        capture_output=True,
        check=False,
    )
    if r.returncode != 0:
        err = r.stderr.decode("utf-8", "replace").strip()
        raise OSError(err or f"git diff {rev} HEAD failed")
    return [p for p in r.stdout.decode("utf-8", "surrogateescape").split("\0") if p]


# --- the derivation the list is checked against ------------------------------------------------


def _instructions(text: str) -> list[tuple[int, str]]:
    """A Dockerfile's instructions as (first line number, text), comments dropped and backslash
    continuations joined."""
    out: list[tuple[int, str]] = []
    buf: list[str] = []
    start = 0
    for n, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not buf and (not stripped or stripped.startswith("#")):
            continue
        if buf and stripped.startswith("#"):
            continue  # a comment inside a continued instruction
        if not buf:
            start = n
        if stripped.endswith("\\"):
            buf.append(stripped[:-1])
            continue
        buf.append(stripped)
        out.append((start, " ".join(w for w in buf if w)))
        buf = []
    if buf:
        out.append((start, " ".join(buf)))
    return out


def _copy_sources(dockerfile: Path) -> tuple[list[str], list[str]]:
    """The build-context paths a Dockerfile's ``COPY``/``ADD`` instructions read (not ``--from``
    copies out of another stage, which read no context), shell or JSON form, and one problem per
    instruction that reads the context in a way this cannot follow."""
    sources: list[str] = []
    problems: list[str] = []
    name = dockerfile.name
    for n, ins in _instructions(dockerfile.read_text(encoding="utf-8")):
        words = ins.split()
        op = words[0].upper()
        where = f"{dockerfile.as_posix()}:{n}"
        if op == "RUN":
            for w in words[1:]:
                if not w.startswith("--"):
                    break
                if w.startswith("--mount=") and "type=bind" in w and "from=" not in w:
                    problems.append(f"{where}: RUN --mount of the build context ({name})")
            continue
        if op not in ("COPY", "ADD"):
            continue
        flags = []
        rest = words[1:]
        while rest and rest[0].startswith("--"):
            flags.append(rest.pop(0))
        if any(f.startswith("--from") for f in flags):
            continue
        tail = ins.split(None, 1 + len(flags))[-1] if rest else ""
        if tail.startswith("["):
            try:
                args = json.loads(tail)
            except ValueError:
                args = None
            if not (isinstance(args, list) and all(isinstance(a, str) for a in args)):
                problems.append(f"{where}: {op} in JSON form that is not a list of strings")
                continue
        else:
            args = rest
        if len(args) < 2 or any(a.startswith("<<") or "$" in a for a in args[:-1]):
            problems.append(f"{where}: {op} whose sources cannot be read ({ins[:60]})")
            continue
        sources += args[:-1]  # every source; the last argument is the destination
    return sources, problems


def scan(root: Path = REPO_ROOT) -> tuple[set[str], list[str]]:
    """:func:`stack_inputs` and the Dockerfile lines it could not read."""
    problems: list[str] = []
    return stack_inputs(root, problems), problems


def stack_inputs(root: Path = REPO_ROOT, problems: list[str] | None = None) -> set[str]:
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
            sources, unread = _copy_sources(dockerfile)
            out |= {rel(ctx, src) for src in sources}
            if problems is not None:
                problems += [p.replace(ctx.as_posix() + "/", "") for p in unread]
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
    """The stack's inputs that :data:`LAB_PATHS` does not cover, and every Dockerfile line the
    derivation could not read (empty when the list holds)."""
    inputs, problems = scan(root)
    return sorted(p for p in inputs if not covered(p)) + sorted(set(problems))


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
            if ": " in p:  # a Dockerfile line the derivation could not read
                print(
                    f"::error::{p}: cannot tell what it reads; make it readable or extend lab_paths"
                )
            else:
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
