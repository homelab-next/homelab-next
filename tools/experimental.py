#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# hnx-script:
#   id: experimental
#   kind: tool
#   purpose: Run the gates and tests of the experimental and frozen components listed in tools/experimental.yml, outside the blocking set.
#   owner: maintainers
#   trigger: [make:experimental]
#   inputs: tools/experimental.yml (or --file)
#   outputs: one line per gate and the pytest run of the components' tests; `list` prints the components
#   exit:
#     "0": every gate and test of every listed component passed (list and validate, the file is valid)
#     "1": a gate or a test failed
#     "2": the list is invalid or unreadable
"""The one list of experimental and frozen components, and the runner of their checks.

``tools/experimental.yml`` names each component that the operator took out of the blocking set
(v0 cuts, 2026-10-31; docs/build-order.md, "Experimental and frozen components"): its status,
why, until when, the pages that say so, its tests, its gates and the invariants it owns.  This
module reads and validates that list (:func:`load`), says which test files are a component's
(:func:`is_experimental`, used by ``tests/experimental_marker.py`` to mark them), and runs every
gate plus ``pytest -m "experimental and not live"`` (:func:`run`), which is what
``make experimental`` and CI's non-blocking ``experimental`` job do.  It never decides what blocks
a merge: ``tools/tests/test_experimental.py`` holds the Makefile, CI and the invariants register
to the list.

Usage: python tools/experimental.py {run,list,validate} [--file FILE]
Exit: 0 passed (or valid), 1 a gate or a test failed, 2 the list is invalid.
"""

from __future__ import annotations

import argparse
import datetime as dt
import re
import shlex
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

import yaml

ROOT = Path(__file__).resolve().parent.parent
LIST = ROOT / "tools" / "experimental.yml"
STATUSES = ("experimental", "frozen")
MARKER = "experimental"
#: the pytest selection of the components' tests (the blocking runs select its complement)
SELECT = f"{MARKER} and not live"
BLOCKING_SELECT = f"not live and not {MARKER}"
_KEYS = {"status", "decided", "why", "until", "docs", "tests", "gates", "invariants"}
_REQUIRED = _KEYS - {"invariants"}
_ID = re.compile(r"^[a-z][a-z0-9]*(?:-[a-z0-9]+)*\Z")
_INVARIANT = re.compile(r"^[A-Z]-[0-9]{2}\Z")


class ListError(ValueError):
    def __init__(self, problems: list[str]):
        super().__init__("; ".join(problems))
        self.problems = problems


@dataclass(frozen=True)
class Component:
    name: str
    status: str
    decided: dt.date
    why: str
    until: str
    docs: tuple[str, ...]
    tests: tuple[str, ...]
    gates: tuple[str, ...]
    invariants: tuple[str, ...] = ()


def _strings(where: str, value: object, problems: list[str], *, empty_ok: bool = False):
    if not isinstance(value, list) or not all(isinstance(v, str) and v.strip() for v in value):
        problems.append(f"{where}: must be a list of non-empty strings")
        return ()
    if not value and not empty_ok:
        problems.append(f"{where}: must not be empty")
    if len(set(value)) != len(value):
        problems.append(f"{where}: lists an entry twice")
    return tuple(value)


def parse(doc: object, root: Path = ROOT) -> list[Component]:
    """The components of a parsed list; raises :class:`ListError` naming every problem."""
    problems: list[str] = []
    if not isinstance(doc, dict) or set(doc) != {"components"}:
        raise ListError(["the list is a mapping with exactly one key, components"])
    raw = doc["components"]
    if not isinstance(raw, dict):
        raise ListError(["components: must be a mapping of component name to entry"])
    out: list[Component] = []
    for name, entry in raw.items():
        where = f"components.{name}"
        if not isinstance(name, str) or not _ID.match(name):
            problems.append(f"{where}: the name must be a lower-case slug")
        if not isinstance(entry, dict):
            problems.append(f"{where}: must be a mapping")
            continue
        for k in sorted(set(entry) - _KEYS):
            problems.append(f"{where}.{k}: unknown key")
        for k in sorted(_REQUIRED - set(entry)):
            problems.append(f"{where}.{k}: is required")
        if _REQUIRED - set(entry):
            continue
        if entry["status"] not in STATUSES:
            problems.append(f"{where}.status: must be one of {', '.join(STATUSES)}")
        decided = entry["decided"]
        if not isinstance(decided, dt.date):
            problems.append(f"{where}.decided: must be a YYYY-MM-DD date")
        for k in ("why", "until"):
            if not isinstance(entry[k], str) or not entry[k].strip():
                problems.append(f"{where}.{k}: must be a non-empty string")
        docs = _strings(f"{where}.docs", entry["docs"], problems)
        tests = _strings(f"{where}.tests", entry["tests"], problems)
        gates = _strings(f"{where}.gates", entry["gates"], problems)
        invariants = _strings(
            f"{where}.invariants", entry.get("invariants", []), problems, empty_ok=True
        )
        for path in (*docs, *tests):
            p = PurePosixPath(path)
            if p.is_absolute() or ".." in p.parts or not (root / path).exists():
                problems.append(f"{where}: {path} is not a path in the repository")
        for path in tests:
            if not (path.startswith("tests/") or path.startswith("tools/tests/")):
                problems.append(f"{where}.tests: {path} is not under tests/ or tools/tests/")
        for gate in gates:
            words = shlex.split(gate)
            if words[:2] != ["python", "-m"] or len(words) < 3:
                problems.append(f"{where}.gates: {gate!r} must be `python -m <module> ...`")
        for inv in invariants:
            if not _INVARIANT.match(inv):
                problems.append(f"{where}.invariants: {inv!r} is not a criterion id")
        out.append(
            Component(
                name=str(name),
                status=str(entry["status"]),
                decided=decided,
                why=str(entry["why"]),
                until=str(entry["until"]),
                docs=docs,
                tests=tests,
                gates=gates,
                invariants=invariants,
            )
        )
    seen: dict[str, str] = {}
    for c in out:
        for path in c.tests:
            if path in seen:
                problems.append(f"{path} is listed by both {seen[path]} and {c.name}")
            seen.setdefault(path, c.name)
    if problems:
        raise ListError(problems)
    return out


def load(path: Path = LIST, root: Path = ROOT) -> list[Component]:
    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ListError([f"cannot read {path}: {exc}"]) from exc
    return parse(doc, root)


def marked_paths(components: list[Component]) -> tuple[str, ...]:
    return tuple(p for c in components for p in c.tests)


def is_experimental(relpath: str, paths: tuple[str, ...]) -> bool:
    """Whether a repository-relative test file is one of ``paths`` or under one of them."""
    rel = PurePosixPath(relpath)
    return any(rel == PurePosixPath(p) or PurePosixPath(p) in rel.parents for p in paths)


def gate_argv(gate: str, python: str = sys.executable) -> list[str]:
    words = shlex.split(gate)
    return [python, *words[1:]]


def run(components: list[Component], python: str = sys.executable) -> int:
    failed: list[str] = []
    for c in components:
        for gate in c.gates:
            print(f"experimental: [{c.name}, {c.status}] {gate}", flush=True)
            if subprocess.run(gate_argv(gate, python), cwd=ROOT, check=False).returncode != 0:
                failed.append(f"{c.name}: {gate}")
    print(f'experimental: pytest -m "{SELECT}"', flush=True)
    cmd = [python, "-m", "pytest", "-q", "-p", "no:cacheprovider", "-m", SELECT]
    if subprocess.run(cmd, cwd=ROOT, check=False).returncode != 0:
        failed.append("pytest of the components' tests")
    for f in failed:
        print(f"experimental: FAIL {f}", file=sys.stderr)
    if failed:
        print(
            "experimental: these components are out of the blocking set (tools/experimental.yml);"
            " a failure here blocks no merge, but fix it before it rots",
            file=sys.stderr,
        )
        return 1
    print(f"experimental: ok ({len(components)} component(s))")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("command", choices=("run", "list", "validate"))
    ap.add_argument("--file", type=Path, default=LIST)
    args = ap.parse_args(argv)
    try:
        components = load(args.file)
    except ListError as exc:
        for p in exc.problems:
            print(f"experimental: {p}", file=sys.stderr)
        return 2
    if args.command == "run":
        return run(components)
    if args.command == "list":
        for c in components:
            print(f"{c.name}\t{c.status}\tsince {c.decided}\tuntil {c.until}")
    else:
        print(f"experimental: {args.file.name} is valid ({len(components)} component(s))")
    return 0


if __name__ == "__main__":
    sys.exit(main())
