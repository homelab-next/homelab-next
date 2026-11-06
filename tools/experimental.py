#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# hnx-script:
#   id: experimental
#   kind: tool
#   purpose: Run the gates and tests of the experimental and frozen components listed in tools/experimental.yml, outside the blocking set.
#   owner: maintainers
#   trigger: [make:experimental]
#   inputs: tools/experimental.yml (or --file); the base commit's list (ratchet --base, --ci-base)
#   outputs: one line per gate and the pytest run of the components' tests; `list` prints the components; `ratchet` one line per growth
#   exit:
#     "0": every gate and test of every listed component passed (list and validate, the file is valid; ratchet, the list did not grow or the operator allowed it)
#     "1": a gate or a test failed (ratchet, the list grew against the base)
#     "2": the list is invalid or unreadable (ratchet, or the base is not a commit)
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

``ratchet`` holds the list to a base commit's (:func:`growth`): it may shrink freely, but a
component, test or code path, gate, invariant or conformance capability that the base's list does
not already take out of the blocking set is growth, and fails (exit 1) unless the operator allowed
it.  CI's ``trusted-gates`` job runs the base's copy of this file, so a change cannot argue its way
past a red test by listing it.  The operator allows growth with the pull-request label
``experimental-growth`` (:data:`GROWTH_LABEL`), which the workflow passes in
``HNX_EXPERIMENTAL_GROWTH`` (:data:`GROWTH_ENV`) as ``label`` only on the run that applying the
label triggered, so it approves that head and no later push; a push to ``main`` passes ``push``,
since its pull request was gated already.  Agents never apply the label.  The head's own
``tools/experimental.py`` must still point :data:`LIST` and :data:`MARKER` where this one does
(:func:`repointed`), or its marker plugin could read another list.

Usage: python tools/experimental.py {run,list,validate} [--file FILE]
       python tools/experimental.py ratchet (--base REV | --ci-base) [ROOT]
Exit: 0 passed (or valid, or no growth), 1 a gate or a test failed (or the list grew), 2 the list
is invalid (or the base is not a commit).
"""

from __future__ import annotations

import argparse
import ast
import datetime as dt
import os
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
_KEYS = {
    "status",
    "decided",
    "why",
    "until",
    "docs",
    "tests",
    "gates",
    "invariants",
    "conform",
    "code",
}
_REQUIRED = _KEYS - {"invariants", "conform", "code"}
#: the keys whose entries leave the blocking set: adding one (to any component) is growth
RATCHETED = ("tests", "code", "gates", "invariants", "conform")
#: the keys holding repository paths, matched by whole path segments (a path under a directory
#: the base lists is already out of the blocking set, so listing it is not growth)
_PATH_KEYS = ("tests", "code")
#: the pull-request label by which the operator allows the list to grow, and how CI passes it
GROWTH_LABEL = "experimental-growth"
GROWTH_ENV = "HNX_EXPERIMENTAL_GROWTH"
#: the values of GROWTH_ENV that allow growth: the operator's label, or a push to main (whose
#: pull request the label gated)
GROWTH_ALLOWED = {"label": f"the operator's {GROWTH_LABEL} label", "push": "a push to main"}
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
    conform: tuple[str, ...] = ()
    code: tuple[str, ...] = ()


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
        code = _strings(f"{where}.code", entry.get("code", []), problems, empty_ok=True)
        for path in (*docs, *tests, *code):
            p = PurePosixPath(path)
            if p.is_absolute() or ".." in p.parts or not (root / path).exists():
                problems.append(f"{where}: {path} is not a path in the repository")
        for path in tests:
            if not (path.startswith("tests/") or path.startswith("tools/tests/")):
                problems.append(f"{where}.tests: {path} is not under tests/ or tools/tests/")
        for path in code:
            if not path.endswith(".py") or path.startswith(("tests/", "tools/tests/")):
                problems.append(f"{where}.code: {path} is not a Python module outside the tests")
        for gate in gates:
            words = shlex.split(gate)
            if words[:2] != ["python", "-m"] or len(words) < 3:
                problems.append(f"{where}.gates: {gate!r} must be `python -m <module> ...`")
        for inv in invariants:
            if not _INVARIANT.match(inv):
                problems.append(f"{where}.invariants: {inv!r} is not a criterion id")
        conform = _strings(f"{where}.conform", entry.get("conform", []), problems, empty_ok=True)
        for cap in conform:
            named = [shlex.split(g) for g in gates]
            if not any("report" in w and ["--capability", cap] in _pairs(w) for w in named):
                problems.append(
                    f"{where}.conform: no gate runs `hnx conform report --capability {cap}`"
                )
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
                conform=conform,
                code=code,
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


def _pairs(words: list[str]) -> list[list[str]]:
    return [words[i : i + 2] for i in range(len(words) - 1)]


def experimental_capabilities(components: list[Component]) -> tuple[str, ...]:
    """The conformance capabilities the components own (``registry.EXPERIMENTAL`` is this)."""
    return tuple(c for comp in components for c in comp.conform)


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


# ----------------------------------------------------------------------------- the ratchet


def _listed(doc: object) -> dict[str, dict[str, tuple[str, ...]]]:
    """Each component's ratcheted entries, read leniently (the base's list was valid at the base,
    and its paths need not exist in the head's tree)."""
    if not isinstance(doc, dict) or not isinstance(doc.get("components"), dict):
        raise ListError(["the list is a mapping with a components mapping"])
    out: dict[str, dict[str, tuple[str, ...]]] = {}
    for name, entry in doc["components"].items():
        if not isinstance(entry, dict):
            raise ListError([f"components.{name}: must be a mapping"])
        out[str(name)] = {}
        for k in RATCHETED:
            value = entry.get(k) or []
            if not isinstance(value, list):
                raise ListError([f"components.{name}.{k}: must be a list"])
            out[str(name)][k] = tuple(str(v) for v in value)
    return out


def growth(base_doc: object, head_doc: object) -> list[str]:
    """What the head's list takes out of the blocking set that the base's did not: a component
    the base does not list, a test or code path neither equal to nor under one the base lists (in
    any component), and a gate, invariant or conformance capability the base does not list.
    Removing anything, moving an entry between components, and the other keys are free."""
    base, head = _listed(base_doc), _listed(head_doc)
    had = {k: tuple(dict.fromkeys(v for c in base.values() for v in c[k])) for k in RATCHETED}
    out = [f"components.{n}: a component the base does not list" for n in head if n not in base]
    for name, entries in head.items():
        for k in RATCHETED:
            for v in entries[k]:
                old = is_experimental(v, had[k]) if k in _PATH_KEYS else v in had[k]
                if not old:
                    out.append(
                        f"components.{name}.{k}: {v} is not out of the blocking set at the base"
                    )
    return out


#: the module-level names by which the head's own code (the marker plugin, coverage_floor) finds
#: the list and marks its tests: pointing one elsewhere would take tests out of the blocking set
#: without touching tools/experimental.yml, so the ratchet holds them to this file's own values
PINNED = ("LIST", "MARKER")


def _assignments(source: str) -> dict[str, list[str]]:
    """The dumped value of every module-level assignment to a :data:`PINNED` name, in order."""
    found: dict[str, list[str]] = {n: [] for n in PINNED}
    for node in ast.parse(source).body:
        if isinstance(node, ast.Assign):
            targets, value = node.targets, node.value
        elif isinstance(node, (ast.AnnAssign, ast.AugAssign)):
            targets, value = [node.target], node.value
        else:
            continue
        for t in targets:
            for name in (n.id for n in ast.walk(t) if isinstance(n, ast.Name)):
                if name in found:
                    found[name].append(ast.dump(value) if value is not None else "")
    return found


def repointed(root: Path) -> list[str]:
    """Each :data:`PINNED` name the head's ``tools/experimental.py`` assigns other than this
    file does (read as text, never run): like a new list entry, it is growth."""
    rel = Path(__file__).resolve().relative_to(ROOT).as_posix()
    mine = _assignments(Path(__file__).read_text(encoding="utf-8"))
    try:
        theirs = _assignments((root / rel).read_text(encoding="utf-8"))
    except (OSError, SyntaxError, ValueError) as exc:
        return [
            f"{rel}: the head's copy cannot be read ({type(exc).__name__}), so its list is unknown"
        ]
    return [
        f"{rel}: the head assigns {name} other than the base does (it decides which list and"
        " marker take tests out of the blocking set)"
        for name in PINNED
        if theirs[name] != mine[name]
    ]


def ratchet(root: Path, rev: str, environ=None, out=None) -> int:
    """The list in the checkout at ``root`` (read as data) against the one at commit ``rev``."""
    out = out or sys.stdout
    environ = os.environ if environ is None else environ
    rel = LIST.relative_to(ROOT).as_posix()

    def git(*a: str) -> subprocess.CompletedProcess:
        return subprocess.run(["git", "-C", str(root), *a], capture_output=True, check=False)

    if not rev.strip() or git("rev-parse", "--verify", "--quiet", f"{rev}^{{commit}}").returncode:
        print(f"experimental: --base {rev!r}: not a commit here", file=out)
        return 2
    listed = git("ls-tree", "--name-only", rev, "--", rel)
    if listed.returncode:
        print(f"experimental: cannot read the base's tree at {rev[:12]}", file=out)
        return 2
    try:
        if listed.stdout.strip():
            shown = git("show", f"{rev}:{rel}")
            if shown.returncode:
                raise OSError(f"cannot read {rel} at the base {rev[:12]}")
            base_doc = yaml.safe_load(shown.stdout)
        else:  # no list at the base: nothing was out of the blocking set, so every entry is growth
            print(
                f"experimental: the base {rev[:12]} has no {rel}: every entry is growth", file=out
            )
            base_doc = {"components": {}}
        head_doc = yaml.safe_load((root / rel).read_text(encoding="utf-8"))
        problems = growth(base_doc, head_doc)
    except (OSError, yaml.YAMLError, ListError) as exc:
        print(f"experimental: cannot compare the lists: {exc}", file=out)
        return 2
    problems += repointed(root)
    try:
        parse(head_doc, root)  # the head under the base's rules: a key they do not know is growth
    except ListError as exc:
        problems += [f"the base's rules refuse the list: {p}" for p in exc.problems]
    if not problems:
        print(f"experimental: {rel} did not grow against {rev[:12]}", file=out)
        return 0
    for p in problems:
        print(f"experimental: grew: {p}", file=out)
    allowed = GROWTH_ALLOWED.get(str(environ.get(GROWTH_ENV, "")).strip())
    if allowed:
        print(f"experimental: growth allowed by {allowed}", file=out)
        return 0
    print(
        f"experimental: {rel} may only shrink against the base: listing a test, gate, invariant or"
        " code path takes it out of what blocks a merge; growth needs the operator's"
        f" {GROWTH_LABEL} label on the pull request (CONTRIBUTING.md)",
        file=out,
    )
    return 1


def _ratchet_main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="experimental.py ratchet")
    ap.add_argument("root", nargs="?", default=".", type=Path, help="the checkout (read as data)")
    which = ap.add_mutually_exclusive_group(required=True)
    which.add_argument("--base", help="the commit whose list the checkout's may not grow past")
    which.add_argument(
        "--ci-base",
        action="store_true",
        help="pick --base by homelabnext.gitbase.ci_base "
        "(GITHUB_EVENT_NAME, HNX_PR_BASE, HNX_PUSH_BEFORE)",
    )
    args = ap.parse_args(argv)
    root = args.root.resolve()
    rev = args.base
    if args.ci_base:
        if str(ROOT) not in sys.path:
            sys.path.insert(0, str(ROOT))
        from homelabnext.gitbase import ci_base_from_env  # the one --ci-base rule

        try:
            rev, why = ci_base_from_env(root)
        except ValueError as exc:
            print(f"experimental: {exc}", file=sys.stderr)
            return 2
        print(f"experimental: base {rev or '-'} ({why})")
        if rev is None:
            return 0  # a root commit has nothing to ratchet against
    return ratchet(root, rev)


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] == ["ratchet"]:
        return _ratchet_main(argv[1:])
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
