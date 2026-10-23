#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# hnx-script:
#   id: fix-has-test
#   kind: check
#   purpose: "Fail when a bugfix commit (a fix subject or a Fixes trailer) ships no regression test; with --prove, also when that test passes on the parent commit."
#   owner: maintainers
#   trigger: [ci:ci/regression-tests, make:fix-check]
#   invariant: [Q-08]
#   inputs: git history over a revision range
#   outputs: one line per fix without a (failing-before) regression test
#   exit:
#     "0": clean
#     "1": a fix lacks a regression test
#     "2": usage error or an unresolvable range
"""Gate: every bugfix commit ships a regression test (checklist Q-08).

A commit is a *fix* when its subject is a conventional-commit fix (``fix: ...``,
``fix(scope): ...``, ``fix!: ...``) or its message carries a ``Fixes:`` trailer.  Every fix in the
range must touch at least one test file (a ``test_*.py``/``*_test.py`` file, or anything under a
``tests/`` or ``test/`` directory).  A fix that genuinely cannot have one (documentation, a CI
setting) says why in a ``No-regression-test: <reason>`` trailer; the gate lists every waiver.

``--prove`` also checks the "fails without the fix" half: for each fix, the commit's test files are
put on top of its parent in a temporary worktree and the touched test modules are run there; at
least one collected test must FAIL there.  A regression test that passes without the fix proves
nothing and is reported.  So is every case that cannot prove it, never counted as a pass:
- a collection or import error on the parent (pytest exit 2): a test module that imports a name
  the fix adds errors on the parent whatever its assertions check, so an error is not a failure;
  the modules run with ``--continue-on-collection-errors`` and the junit report must show at
  least one failed test (import a new name inside the test function to fail it);
- a fix whose only test files are fixtures, ``conftest.py`` or other non-test files under
  ``tests/``: nothing runnable shows the fix.  Such a fix says why in a ``No-regression-test:``
  trailer, or adds a test module.

Usage: python tools/fix_has_test.py [--range A..B] [--prove] [--allow-missing-base] [--repo DIR]
Exit: 0 every fix has a test, 1 some fix has none (or, with --prove, a test passes without the
fix), 2 the range could not be read.  See CONTRIBUTING.md "Bug fixes carry a regression test".
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
FIX_SUBJECT = re.compile(r"^fix(\([^)]*\))?!?:\s*\S", re.I)
FIXES_TRAILER = re.compile(r"^Fixes:\s*\S", re.M | re.I)
WAIVER = re.compile(r"^No-regression-test:[ \t]*(?P<why>\S.{7,})$", re.M | re.I)
TEST_PATH = re.compile(r"(^|/)tests?/|(^|/)test_[^/]*\.py$|_test\.py$")
TEST_MODULE = re.compile(r"(^|/)(test_[^/]*|[^/]*_test)\.py$")
#: files whose names look like tests but are not: this gate's own source ends in ``_test.py``, so
#: a fix to the gate counted as shipping a test (itself), and --prove staged the fixed gate on the
#: parent and collected its helper functions as tests
NOT_TESTS = frozenset({"tools/fix_has_test.py"})


@dataclass
class Commit:
    sha: str
    message: str
    files: list[str] = field(default_factory=list)

    @property
    def subject(self) -> str:
        return self.message.splitlines()[0] if self.message else ""

    @property
    def short(self) -> str:
        return f"{self.sha[:10]} {self.subject[:72]!r}"


def is_fix(message: str) -> bool:
    subject = message.splitlines()[0] if message else ""
    return bool(FIX_SUBJECT.match(subject) or FIXES_TRAILER.search(message))


def waiver(message: str) -> str | None:
    m = WAIVER.search(message)
    return m.group("why").strip() if m else None


def test_files(files: list[str]) -> list[str]:
    return [f for f in files if TEST_PATH.search(f) and f not in NOT_TESTS]


def _git(*args: str, cwd: Path = REPO_ROOT) -> str:
    return subprocess.run(
        ["git", *args], cwd=cwd, capture_output=True, text=True, check=True
    ).stdout


def commits_in(rev_range: str, cwd: Path = REPO_ROOT) -> list[Commit]:
    out = []
    for sha in _git("rev-list", "--no-merges", "--reverse", rev_range, cwd=cwd).split():
        msg = _git("log", "-1", "--format=%B", sha, cwd=cwd).strip()
        files = _git("diff-tree", "--root", "--no-commit-id", "--name-only", "-r", sha, cwd=cwd)
        out.append(Commit(sha, msg, files.split("\n") if files.strip() else []))
    return out


def check(commits: list[Commit]) -> tuple[list[str], list[str]]:
    """``(problems, notes)`` for the fix commits among ``commits``."""
    problems, notes = [], []
    for c in commits:
        if not is_fix(c.message):
            continue
        why = waiver(c.message)
        if test_files(c.files):
            continue
        if why:
            notes.append(f"waived {c.short}: {why}")
        else:
            problems.append(
                f"{c.short}: a fix without a regression test (touch a test file, or add a "
                "'No-regression-test: <reason>' trailer)"
            )
    return problems, notes


def failed_tests(report: Path) -> list[str]:
    """The tests a junit report records as failed (an ``error``, such as a collection error, is
    not a failure)."""
    try:
        root = ET.parse(report).getroot()
    except (OSError, ET.ParseError):
        return []
    return [
        f"{case.get('classname', '')}::{case.get('name', '')}"
        for case in root.iter("testcase")
        if case.find("failure") is not None
    ]


def prove(c: Commit, cwd: Path = REPO_ROOT, python: str = sys.executable) -> str | None:
    """Run the fix's test modules against its parent; None when at least one test fails there
    (good), else why the fix is not proven."""
    tests = [
        f
        for f in test_files(c.files)
        if subprocess.run(["git", "cat-file", "-e", f"{c.sha}:{f}"], cwd=cwd).returncode == 0
    ]  # deleted files are not staged
    modules = [f for f in tests if TEST_MODULE.search(f)]
    if not modules:
        if waiver(c.message):
            return None  # it says why it has no regression test; check() lists the waiver
        return (
            f"{c.short}: cannot prove the fix: it changes no test module, only "
            f"{', '.join(tests) or 'deleted test files'} (a fixture or a non-test file under "
            "tests/ shows nothing on its own); add a test module that fails without the fix, or "
            "a 'No-regression-test: <reason>' trailer"
        )
    with tempfile.TemporaryDirectory() as tmp:
        wt = Path(tmp) / "parent"
        report = Path(tmp) / "report.xml"
        try:
            _git("worktree", "add", "--detach", "--quiet", str(wt), f"{c.sha}^", cwd=cwd)
        except subprocess.CalledProcessError:
            return f"{c.short}: cannot check out its parent to prove the test"
        try:
            _git("checkout", c.sha, "--", *tests, cwd=wt)
            run = subprocess.run(
                [
                    python, "-m", "pytest", "-q", "-x", "-p", "no:cacheprovider",
                    "--continue-on-collection-errors", f"--junitxml={report}", *modules,
                ],
                cwd=wt,
                capture_output=True,
                text=True,
                check=False,
            )  # fmt: skip
            failed = failed_tests(report)
        except subprocess.CalledProcessError as exc:
            return f"{c.short}: could not stage its tests on the parent ({exc.stderr.strip()})"
        finally:
            subprocess.run(
                ["git", "worktree", "remove", "--force", str(wt)], cwd=cwd, capture_output=True
            )
    if run.returncode == 0:
        return f"{c.short}: its regression test passes WITHOUT the fix ({', '.join(modules)})"
    if run.returncode == 1 and failed:
        return None  # a collected test fails without the fix: proven
    if run.returncode in (1, 2):
        return (
            f"{c.short}: cannot prove the fix: no test failed on the parent (pytest exit "
            f"{run.returncode}; a collection or import error is not a failing test -- import a "
            f"name the fix adds inside the test function) ({', '.join(modules)})"
        )
    return f"{c.short}: its tests could not run on the parent (pytest exit {run.returncode})"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--range", default="origin/main..HEAD", help="git revision range")
    ap.add_argument("--prove", action="store_true", help="run each fix's tests on its parent")
    ap.add_argument("--repo", type=Path, default=REPO_ROOT, help="repository (default: this one)")
    ap.add_argument(
        "--allow-missing-base",
        action="store_true",
        help="exit 0 with a note when the range cannot be resolved (no origin/main yet)",
    )
    args = ap.parse_args(argv)
    try:
        commits = commits_in(args.range, cwd=args.repo)
    except subprocess.CalledProcessError as exc:
        msg = f"fix_has_test: cannot read range {args.range!r}: {exc.stderr.strip()}"
        if args.allow_missing_base:
            print(f"{msg} -- skipped")
            return 0
        print(msg, file=sys.stderr)
        return 2
    problems, notes = check(commits)
    if args.prove:
        for c in commits:
            if is_fix(c.message) and test_files(c.files):
                p = prove(c, cwd=args.repo)
                if p:
                    problems.append(p)
    for n in notes:
        print(n)
    for p in problems:
        print(f"FAIL {p}")
    fixes = sum(is_fix(c.message) for c in commits)
    print(
        f"fix_has_test: {len(commits)} commits in {args.range}, {fixes} fixes, "
        f"{len(notes)} waived, {len(problems)} problems"
    )
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
