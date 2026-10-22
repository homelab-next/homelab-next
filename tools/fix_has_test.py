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
range must touch at least one test file (a ``test_*.py``/``*_test.py``/``*_test.go`` file, or
anything under a ``tests/`` or ``test/`` directory).  A fix that genuinely cannot have one (documentation, a CI
setting) says why in a ``No-regression-test: <reason>`` trailer; the gate lists every waiver.

``--prove`` also checks the "fails without the fix" half: for each fix, the commit's test files are
put on top of its parent in a temporary worktree and the touched test modules are run there; they
must fail.  A regression test that passes without the fix proves nothing and is reported.

A Go test file (``*_test.go``) is proved in its module (the nearest directory with a ``go.mod``,
``orchestrator/`` in this repository): ``go test ./<pkg> -run '^(<Test funcs>)$'`` runs the test
and fuzz functions the commit added or changed (the whole package when only helpers changed) and
must fail; a package that no longer builds without the fix counts as failing, like pytest's exit
2.  Without a Go toolchain on PATH the commit cannot be proved, which is a problem, not a pass.

Usage: python tools/fix_has_test.py [--range A..B] [--prove] [--allow-missing-base] [--repo DIR]
Exit: 0 every fix has a test, 1 some fix has none (or, with --prove, a test passes without the
fix), 2 the range could not be read.  See CONTRIBUTING.md "Bug fixes carry a regression test".
"""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
FIX_SUBJECT = re.compile(r"^fix(\([^)]*\))?!?:\s*\S", re.I)
FIXES_TRAILER = re.compile(r"^Fixes:\s*\S", re.M | re.I)
WAIVER = re.compile(r"^No-regression-test:[ \t]*(?P<why>\S.{7,})$", re.M | re.I)
TEST_PATH = re.compile(r"(^|/)tests?/|(^|/)test_[^/]*\.py$|_test\.py$|_test\.go$")
TEST_MODULE = re.compile(r"(^|/)(test_[^/]*|[^/]*_test)\.py$")
GO_TEST_FILE = re.compile(r"(^|/)[^/]+_test\.go$")
# a top-level test or fuzz function; gofmt closes it with a ``}`` alone on a line
GO_TEST_FUNC = re.compile(r"^func ((?:Test|Fuzz)\w*)\(", re.M)


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
    return [f for f in files if TEST_PATH.search(f)]


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


def _go_funcs(text: str) -> dict[str, str]:
    """Top-level test and fuzz functions of a Go file -> their source."""
    out: dict[str, str] = {}
    for m in GO_TEST_FUNC.finditer(text):
        end = text.find("\n}\n", m.start())
        out[m.group(1)] = text[m.start() : len(text) if end < 0 else end + 3]
    return out


def changed_go_tests(c: Commit, path: str, cwd: Path = REPO_ROOT) -> list[str]:
    """The test and fuzz functions of ``path`` that ``c`` added or changed."""
    new = _go_funcs(_git("show", f"{c.sha}:{path}", cwd=cwd))
    try:
        old = _go_funcs(_git("show", f"{c.sha}^:{path}", cwd=cwd))
    except subprocess.CalledProcessError:
        old = {}  # a new file: every function is new
    return sorted(name for name, body in new.items() if old.get(name) != body)


def _go_module(wt: Path, path: str) -> Path | None:
    """The nearest directory above ``path`` (inside ``wt``) that holds a go.mod."""
    d = (wt / path).parent
    while d == wt or wt in d.parents:
        if (d / "go.mod").is_file():
            return d
        if d == wt:
            return None
        d = d.parent
    return None


def _prove_go(c: Commit, wt: Path, go: str, files: list[str], cwd: Path) -> list[str]:
    """Run the Go tests ``c`` touched on the parent tree ``wt``; problems when they pass."""
    targets: dict[tuple[Path, str], set[str] | None] = {}
    problems = []
    for f in files:
        mod = _go_module(wt, f)
        if mod is None:
            problems.append(f"{c.short}: {f} is in no Go module on the parent (no go.mod above it)")
            continue
        pkg = "./" + ((wt / f).parent.relative_to(mod).as_posix())
        funcs = changed_go_tests(c, f, cwd=cwd)
        key = (mod, pkg)
        if not funcs or targets.get(key, set()) is None:
            targets[key] = None  # only helpers changed: the whole package
        else:
            targets.setdefault(key, set()).update(funcs)
    for (mod, pkg), funcs in sorted(targets.items(), key=lambda t: (str(t[0][0]), t[0][1])):
        cmd = [go, "test", "-count=1", pkg]
        if funcs:
            cmd += ["-run", f"^({'|'.join(sorted(funcs))})$"]
        run = subprocess.run(cmd, cwd=mod, capture_output=True, text=True, check=False)
        what = f"{mod.relative_to(wt).as_posix()}: {' '.join(cmd[1:])}"
        out = run.stdout + run.stderr
        if run.returncode == 0:
            problems.append(f"{c.short}: its regression test passes WITHOUT the fix ({what})")
        elif run.returncode != 1 or "[setup failed]" in out or re.search(r"(?m)^go: ", out):
            # 1 is a failing test or a test package that does not build without the fix; a
            # setup or module error (missing go.mod, no network for a module) proves nothing
            problems.append(f"{c.short}: its Go tests could not run on the parent ({what})")
    return problems


def prove(
    c: Commit, cwd: Path = REPO_ROOT, python: str = sys.executable, go: str = "go"
) -> str | None:
    """Run the fix's test modules against its parent; None when they fail there (good)."""
    tests = [
        f
        for f in test_files(c.files)
        if subprocess.run(["git", "cat-file", "-e", f"{c.sha}:{f}"], cwd=cwd).returncode == 0
    ]  # deleted files are not staged
    modules = [f for f in tests if TEST_MODULE.search(f)]
    go_files = [f for f in tests if GO_TEST_FILE.search(f)]
    if not modules and not go_files:
        return None  # only fixtures changed: nothing runnable to prove with
    go_bin = shutil.which(go) if go_files else None
    if go_files and go_bin is None:
        return f"{c.short}: cannot prove its Go tests: no Go toolchain ({go!r}) on PATH"
    problems: list[str] = []
    with tempfile.TemporaryDirectory() as tmp:
        wt = Path(tmp) / "parent"
        try:
            _git("worktree", "add", "--detach", "--quiet", str(wt), f"{c.sha}^", cwd=cwd)
        except subprocess.CalledProcessError:
            return f"{c.short}: cannot check out its parent to prove the test"
        try:
            _git("checkout", c.sha, "--", *tests, cwd=wt)
            if modules:
                run = subprocess.run(
                    [python, "-m", "pytest", "-q", "-x", "-p", "no:cacheprovider", *modules],
                    cwd=wt,
                    capture_output=True,
                    text=True,
                    check=False,
                )
                if run.returncode == 0:
                    problems.append(
                        f"{c.short}: its regression test passes WITHOUT the fix "
                        f"({', '.join(modules)})"
                    )
                elif run.returncode not in (1, 2):  # 1 failed, 2 interrupted (a missing name)
                    problems.append(
                        f"{c.short}: its tests could not run on the parent "
                        f"(pytest exit {run.returncode})"
                    )
            if go_files and go_bin:
                problems += _prove_go(c, wt, go_bin, go_files, cwd)
        except subprocess.CalledProcessError as exc:
            return f"{c.short}: could not stage its tests on the parent ({exc.stderr.strip()})"
        finally:
            subprocess.run(
                ["git", "worktree", "remove", "--force", str(wt)], cwd=cwd, capture_output=True
            )
    return "; ".join(problems) or None


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
