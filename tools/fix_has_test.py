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
range must touch at least one test file (a ``test_*.py`` or ``*_test.go`` file, a ``*_test.py``
file under a test directory, or
anything under a ``tests/``, ``test/`` or Go ``testdata/`` directory: a fix whose only test
change is a fixture or golden file has a test).  A fix that genuinely cannot have one (documentation, a CI
setting) says why in a ``No-regression-test: <reason>`` trailer; the gate lists every waiver.

``--prove`` also checks the "fails without the fix" half: for each fix, the commit's test files are
put on top of its parent in a temporary worktree and the tests it added or changed are run there
(a Python test function or ``Test*`` method whose source, decorators included, differs, and
every test that reaches a module-level name the commit changed: ``@parametrize("x", CASES)``
when only ``CASES`` gained a case, a changed fixture or helper; the whole module only when a
change cannot be put down to a name; Go likewise, below).  At least one of them must FAIL
there.  A regression test that passes without the fix proves nothing and is
reported; so is every case that cannot prove it, never counted as a pass.

One rule for Python and Go decides what a failure on the parent proves.  A test that fails there
only because it does not build, collect or import counts as failing ONLY IF every such error names
a symbol (function, class, type, method, module attribute or variable, or a module or package) that
the fix's own diff adds; any other build, collection or import error, and any other error that is
not a failing test, means the fix cannot be proven.  For Python the junit report of the parent run
is read: an ``ImportError``/``ModuleNotFoundError``, an ``AttributeError`` on a module or a
``NameError``, at collection or inside a test, is a missing name; for Go, the compiler's
``undefined: X`` / ``has no field or method X`` errors and a missing package are.  The added
symbols are the definitions in the commit's non-test files that its parent lacks.

A fix whose only test files are fixtures, ``conftest.py`` or other non-test files (outside a Go
package's ``testdata/``) cannot be proven either, in both languages, unless it carries a
``No-regression-test:`` trailer saying why.

A Go test file (``*_test.go``) is proved in its module (the nearest directory with a ``go.mod``,
at any depth, so in any discovered module): ``go test ./<pkg> -run '^(<Test funcs>)$'`` runs the test
and fuzz functions the commit added or changed (the whole package when only helpers changed) and
must fail, under the rule above.  The commit's ``testdata/`` files are staged on the parent with
its tests (a test reading a fixture the parent lacks would otherwise "fail" for that reason
alone), and a package whose ``testdata/`` the commit changed is run whole.  Without a Go toolchain
on PATH the commit cannot be proved, which is a problem, not a pass.

Known limits, each a false "cannot prove" or a missed selection, never a false pass: a re-export of
an existing name (``from .calc import clamp`` in ``__init__``) is not a definition the fix adds; a
new namespace subpackage (no ``__init__.py``) is not matched as an added module; a
``unittest.TestCase`` subclass not named ``Test*`` is not selected; and added names are matched
across the commit, not per module.

Usage: python tools/fix_has_test.py [--range A..B] [--prove] [--allow-missing-base] [--repo DIR]
Exit: 0 every fix has a test, 1 some fix has none (or, with --prove, a test passes without the
fix), 2 the range could not be read.  See CONTRIBUTING.md "Bug fixes carry a regression test".
"""

from __future__ import annotations

import argparse
import ast
import re
import shutil
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
# a ``*_test.py`` name is a test only under a test directory (a tool may be called x_test.py,
# as this gate is): ``test_*.py`` anywhere, and anything under tests/ or test/
TEST_PATH = re.compile(r"(^|/)tests?/|(^|/)testdata/|(^|/)test_[^/]*\.py$|_test\.go$")
# Go's testdata directory: fixtures of the package in the directory that holds it
# (the outermost one: testdata/ below a testdata/ is still the outer package's data)
GO_TESTDATA = re.compile(r"^(?P<pkg>(?:.*?/)?)testdata/")
TEST_MODULE = re.compile(r"(^|/)test_[^/]*\.py$|(^|/)tests?/(?:[^/]+/)*[^/]*_test\.py$")
GO_TEST_FILE = re.compile(r"(^|/)[^/]+_test\.go$")
# a top-level test or fuzz function: go test's rule, Test/Fuzz then nothing or a non-lowercase
# character (``Testable`` is a helper); ``TestMain`` is the package's harness, not a test
GO_TEST_FUNC = re.compile(r"^func ((?:Test|Fuzz)(?:[A-Z0-9_]\w*)?)\(", re.M)
GO_NOT_A_TEST = frozenset({"TestMain"})
# go test output that means the tests never ran: not a failing test.  ``go: downloading ...`` (a
# cold module cache) is progress, not an error.
GO_SETUP_ERROR = re.compile(
    r"\[setup failed\]|^go: (?:errors parsing|cannot find main module|updates to go\.mod needed)",
    re.M,
)


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


PY_DEF = re.compile(
    r"^[ \t]*(?:async[ \t]+)?def[ \t]+([A-Za-z_]\w*)|^[ \t]*class[ \t]+([A-Za-z_]\w*)"
    r"|^([A-Za-z_]\w*)[ \t]*(?::[^=\n]*)?=(?!=)",
    re.M,
)
GO_DEF = re.compile(
    r"^func[ \t]+(?:\([^)]*\)[ \t]*)?([A-Za-z_]\w*)|^(?:type|var|const)[ \t]+([A-Za-z_]\w*)", re.M
)
GO_BLOCK_START = re.compile(r"^(?:type|var|const)\b.*[({][ \t]*(?://.*)?$")
GO_BLOCK_ENTRY = re.compile(r"^[ \t]+([A-Za-z_]\w*)\b")
# the names a missing-name error is about (Python messages; Go compiler and go command errors)
PY_MISSING = (
    re.compile(r"cannot import name '([^']+)'"),
    re.compile(r"module '[^']+' has no attribute '([^']+)'"),
    re.compile(r"NameError: name '([^']+)' is not defined"),
)
PY_MISSING_MODULE = re.compile(r"No module named '([^']+)'")
PY_IMPORT_ERROR = re.compile(r"\b(?:ImportError|ModuleNotFoundError|AttributeError|NameError)\b")
GO_ERROR_LINE = re.compile(r"^(?:\S+\.go:\d+(?::\d+)?: |\S+\.go: )(?P<msg>.*)$", re.M)
GO_MISSING = (
    re.compile(r"undefined: (?:[A-Za-z_]\w*\.)?([A-Za-z_]\w*)"),
    re.compile(r"has no field or method ([A-Za-z_]\w*)"),
    re.compile(r"([A-Za-z_]\w*) not declared by package"),
)
GO_MISSING_PACKAGE = (
    re.compile(r"no required module provides package ([^\s;]+)"),
    re.compile(r"package ([^\s;]+) is not in (?:std|GOROOT)"),
    re.compile(r'cannot find package "([^"]+)"'),
    re.compile(r"could not import ([^\s;]+)"),
)


@dataclass
class Added:
    """What a commit's non-test files define that its parent does not."""

    names: set[str] = field(default_factory=set)
    modules: set[str] = field(default_factory=set)  # dotted Python modules, Go package dirs

    def has_module(self, name: str) -> bool:
        name = name.strip().rstrip("/")
        return any(
            m == name or m.endswith("." + name) or m.endswith("/" + name) or name.endswith("/" + m)
            for m in self.modules
        )


def _show(cwd: Path, rev: str, path: str) -> str | None:
    try:
        return _git("show", f"{rev}:{path}", cwd=cwd)
    except subprocess.CalledProcessError:
        return None


def _py_defs(text: str) -> set[str]:
    return {next(g for g in m.groups() if g) for m in PY_DEF.finditer(text)}


def _go_defs(text: str) -> set[str]:
    names = {next(g for g in m.groups() if g) for m in GO_DEF.finditer(text)}
    inside = False
    for line in text.splitlines():
        if not inside and (
            GO_BLOCK_START.match(line) or re.match(r"^type\s+\w+\s+(?:struct|interface)\s*\{", line)
        ):
            inside = True
            continue
        if inside and re.match(r"^[)}]", line):
            inside = False
            continue
        if inside:
            m = GO_BLOCK_ENTRY.match(line)
            if m:
                names.add(m.group(1))
    return names


def added_symbols(c: Commit, cwd: Path = REPO_ROOT) -> Added:
    """The symbols, modules and Go packages ``c``'s non-test files define and its parent lacks."""
    out = Added()
    test = set(test_files(c.files))
    for f in c.files:
        if f in test or not f.endswith((".py", ".go")):
            continue
        new, old = _show(cwd, c.sha, f), _show(cwd, f"{c.sha}^", f)
        if new is None:
            continue
        defs = _py_defs if f.endswith(".py") else _go_defs
        out.names |= defs(new) - (defs(old) if old is not None else set())
        if old is None and f.endswith(".py"):
            parts = f[: -len(".py")].split("/")
            if parts[-1] == "__init__":
                parts = parts[:-1]
            out.modules |= {".".join(parts[i:]) for i in range(len(parts))}
        if old is None and f.endswith(".go"):
            pkg = f.rsplit("/", 1)[0] if "/" in f else "."
            parent_has_go = (
                any(
                    p.endswith(".go")
                    for p in _git("ls-tree", "--name-only", f"{c.sha}^", pkg + "/", cwd=cwd).split()
                )
                if pkg != "."
                else True
            )
            if not parent_has_go:
                out.modules.add(pkg)
    return out


@dataclass
class Outcome:
    """What the parent run of a fix's tests shows."""

    failed: int = 0  # tests that failed (a missing name the fix adds included)
    missing: set[str] = field(default_factory=set)  # names the errors are about, not added
    errors: list[str] = field(default_factory=list)  # errors that are not a missing name

    def verdict(self, c: Commit, what: str) -> str | None:
        if self.missing:
            return (
                f"{c.short}: cannot prove the fix: on the parent its tests do not import, collect "
                f"or build because of {', '.join(sorted(self.missing))}, which the fix does not "
                f"add; a missing name counts as failing without the fix only when the fix's own "
                f"diff adds it ({what})"
            )
        if self.errors:
            return (
                f"{c.short}: cannot prove the fix: on the parent its tests stop with an error that "
                f"is not a failing test ({self.errors[0][:160]}) ({what})"
            )
        if not self.failed:
            return f"{c.short}: cannot prove the fix: no test failed on the parent ({what})"
        return None


def _python_missing(text: str, added: Added) -> tuple[set[str], set[str]] | None:
    """``(added names, not-added names)`` an error text is about, or None when it is not a
    missing-name error."""
    names = {m.group(1) for rx in PY_MISSING for m in rx.finditer(text)}
    modules = {m.group(1) for m in PY_MISSING_MODULE.finditer(text)}
    if not (names or modules) or not PY_IMPORT_ERROR.search(text):
        return None
    ok = {n for n in names if n in added.names} | {m for m in modules if added.has_module(m)}
    return ok, (names | modules) - ok


def python_outcome(report: Path, added: Added) -> Outcome:
    """Read the junit report of the parent run under the one rule (see the module docstring)."""
    out = Outcome()
    try:
        root = ET.parse(report).getroot()
    except (OSError, ET.ParseError):
        out.errors.append("no junit report: pytest did not finish")
        return out
    for case in root.iter("testcase"):
        for child in case:
            if child.tag not in ("failure", "error"):
                continue
            text = f"{child.get('message') or ''}\n{child.text or ''}"
            missing = _python_missing(text, added)
            if missing is not None:
                _, bad = missing
                out.missing |= bad
                out.failed += not bad
            elif child.tag == "failure":
                out.failed += 1
            else:
                first = (child.get("message") or child.text or "error").strip().splitlines()
                out.errors.append(first[0] if first else "error")
    return out


def go_outcome(output: str, returncode: int, added: Added) -> Outcome:
    """Read ``go test`` output of the parent run under the one rule."""
    out = Outcome()
    broken = "[build failed]" in output or "[setup failed]" in output
    if not broken:
        if GO_SETUP_ERROR.search(output) or returncode != 1:
            out.errors.append(f"go test exit {returncode}, the tests did not run")
        else:
            out.failed = 1
        return out
    lines = [m.group("msg") for m in GO_ERROR_LINE.finditer(output)]
    lines = [m for m in lines if not m.startswith("too many errors")]
    if not lines:
        out.errors.append("the package does not build and the error names nothing")
    for msg in lines:
        names = {m.group(1) for rx in GO_MISSING for m in rx.finditer(msg)}
        pkgs = {m.group(1) for rx in GO_MISSING_PACKAGE for m in rx.finditer(msg)}
        if not (names or pkgs):
            out.errors.append(msg)
            continue
        out.missing |= {n for n in names if n not in added.names}
        out.missing |= {p for p in pkgs if not added.has_module(p)}
    if not out.missing and not out.errors:
        out.failed = 1  # it fails to build only for symbols the fix adds
    return out


def _src(lines: list[str], node: ast.AST) -> str:
    """A node's source, decorators included (a new parametrize case is a change)."""
    deco = getattr(node, "decorator_list", [])
    first = min([d.lineno for d in deco] + [node.lineno])
    return "\n".join(lines[first - 1 : node.end_lineno])


def _refs(*nodes: ast.AST) -> set[str]:
    """The names a node can reach: every name it reads, its parameters (fixtures) and every
    identifier-shaped string (``usefixtures("db")``, ``getfixturevalue("db")``)."""
    out: set[str] = set()
    for node in nodes:
        for n in ast.walk(node):
            if isinstance(n, ast.Name):
                out.add(n.id)
            elif isinstance(n, ast.arg):
                out.add(n.arg)
            elif (
                isinstance(n, ast.Constant) and isinstance(n.value, str) and n.value.isidentifier()
            ):
                out.add(n.value)
    return out


def _is_test(node: ast.AST) -> bool:
    return isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and node.name.startswith("test")


def _target_names(t: ast.AST) -> set[str] | None:
    if isinstance(t, ast.Name):
        return {t.id}
    if isinstance(t, ast.Tuple | ast.List):
        names: set[str] = set()
        for e in t.elts:
            sub = _target_names(e.value if isinstance(e, ast.Starred) else e)
            if sub is None:
                return None
            names |= sub
        return names
    if isinstance(t, ast.Subscript | ast.Attribute):  # CASES["x"] = ..., NS.attr = ...
        return _target_names(t.value)
    return None


def _bound(stmt: ast.stmt) -> set[str] | None:
    """The module-level names a statement binds; None when it binds none it can be blamed on."""
    if isinstance(stmt, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
        return {stmt.name}
    if isinstance(stmt, ast.Assign):
        names: set[str] = set()
        for t in stmt.targets:
            sub = _target_names(t)
            if sub is None:
                return None
            names |= sub
        return names
    if isinstance(stmt, ast.AnnAssign | ast.AugAssign):
        return _target_names(stmt.target)
    if isinstance(stmt, ast.Import | ast.ImportFrom):
        if any(a.name == "*" for a in stmt.names):
            return None
        return {(a.asname or a.name).split(".")[0] for a in stmt.names}
    return None


# a change to one of these reaches every test in the module without any test naming it
PY_MODULE_WIDE = frozenset(
    {"pytestmark", "setup_module", "teardown_module", "setup_function", "teardown_function",
     "setUpModule", "tearDownModule"}
)  # fmt: skip


@dataclass
class _PyModule:
    tests: dict[str, str] = field(default_factory=dict)  # node id -> source
    refs: dict[str, set[str]] = field(default_factory=dict)  # node id -> names it reaches
    classes: dict[str, str] = field(default_factory=dict)  # Test class -> its non-test source
    # module-level name -> the sources of the statements binding it, and the names they reach
    bindings: dict[str, list[str]] = field(default_factory=dict)
    deps: dict[str, set[str]] = field(default_factory=dict)
    module_wide: set[str] = field(default_factory=set)  # autouse fixtures, pytest_* hooks
    unattributed: list[str] = field(default_factory=list)  # statements that bind no name
    ok: bool = True


def _py_module(text: str) -> _PyModule:
    """A Python test module split into its tests (top level and in ``Test*`` classes) and the
    module-level code they can reach."""
    out = _PyModule()
    try:
        tree = ast.parse(text)
    except SyntaxError:
        out.ok = False
        return out
    lines = text.splitlines()
    for node in tree.body:
        if _is_test(node):
            out.tests[node.name] = _src(lines, node)
            out.refs[node.name] = _refs(node)
        elif isinstance(node, ast.ClassDef) and node.name.startswith("Test"):
            rest = [sub for sub in node.body if not _is_test(sub)]
            # the class's own decorators, bases and non-test body reach each of its tests
            class_refs = _refs(*node.decorator_list, *node.bases, *rest)
            out.classes[node.name] = "\n".join(
                [ast.dump(d) for d in node.decorator_list + node.bases]
                + [_src(lines, sub) for sub in rest]
            )
            for sub in node.body:
                if _is_test(sub):
                    nid = f"{node.name}::{sub.name}"
                    out.tests[nid] = _src(lines, sub)
                    out.refs[nid] = _refs(sub) | class_refs
        elif isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant):
            continue  # a docstring or a bare constant does nothing
        else:
            names = _bound(node)
            if names is None:
                out.unattributed.append(_src(lines, node))
                continue
            src = _src(lines, node)
            wide = any(
                n in PY_MODULE_WIDE or n.startswith("pytest_") for n in names
            ) or "autouse" in "".join(_src(lines, d) for d in getattr(node, "decorator_list", []))
            for n in names:
                out.bindings.setdefault(n, []).append(src)
                out.deps.setdefault(n, set()).update(_refs(node))
                if wide:
                    out.module_wide.add(n)
    return out


def _py_tests(text: str) -> dict[str, str]:
    """The test functions of a Python test module (top level and in ``Test*`` classes) -> their
    source, decorators included (a new parametrize case is a change)."""
    return _py_module(text).tests


def changed_py_tests(c: Commit, path: str, cwd: Path = REPO_ROOT) -> list[str]:
    """The pytest node ids of the tests in ``path`` that ``c`` added or changed, and of every test
    that reaches a module-level name the commit changed (``@parametrize("x", CASES)`` when only
    ``CASES`` gained a case, a test taking a changed fixture, a test calling a changed helper,
    through other module-level names too).  Empty, so the module runs whole, when it changed
    module-level code that names nothing (an ``if`` block, a bare call), something every test
    reaches unnamed (``pytestmark``, an autouse fixture, a ``pytest_*`` hook), or when a version
    does not parse."""
    new = _py_module(_show(cwd, c.sha, path) or "")
    old = _py_module(_show(cwd, f"{c.sha}^", path) or "")
    if not new.ok or not old.ok or new.unattributed != old.unattributed:
        return []
    names = set(new.bindings) | set(old.bindings)
    dirty = {n for n in names if new.bindings.get(n) != old.bindings.get(n)}
    if dirty & (new.module_wide | old.module_wide):
        return []
    grew = True
    while grew:  # a module-level name that reaches a changed one is changed with it
        more = {n for n, refs in new.deps.items() if n not in dirty and refs & dirty}
        grew = bool(more)
        dirty |= more
    changed_classes = {k for k, v in new.classes.items() if old.classes.get(k) != v}
    return [
        f"{path}::{nid}"
        for nid, body in new.tests.items()
        if old.tests.get(nid) != body
        or new.refs[nid] & dirty
        or ("::" in nid and nid.split("::")[0] in changed_classes)
    ]


def _go_func_end(text: str, start: int) -> int:
    """The index just past the ``}`` closing the function declared at ``start``.

    Counts braces, skipping string, raw-string and rune literals and comments, so a ``}`` inside
    a literal (a raw-string JSON fixture, say) does not end the function early; ``len(text)``
    when the source ends first.
    """
    depth, i, n = 0, start, len(text)
    while i < n:
        ch = text[i]
        if text.startswith("//", i):
            nl = text.find("\n", i)
            i = n if nl < 0 else nl
        elif text.startswith("/*", i):
            close = text.find("*/", i + 2)
            i = n if close < 0 else close + 2
            continue
        elif ch == "`":
            close = text.find("`", i + 1)
            i = n if close < 0 else close + 1
            continue
        elif ch in "\"'":
            i += 1
            while i < n and text[i] != ch and text[i] != "\n":
                i += 2 if text[i] == "\\" else 1
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return n


def _go_funcs(text: str) -> dict[str, str]:
    """Top-level test and fuzz functions of a Go file -> their source."""
    return {
        m.group(1): text[m.start() : _go_func_end(text, m.start())]
        for m in GO_TEST_FUNC.finditer(text)
        if m.group(1) not in GO_NOT_A_TEST
    }


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


def _go_module_at(c: Commit, path: str, cwd: Path) -> bool:
    """Whether ``path`` lies in a Go module (a go.mod in a directory above it) at commit ``c``."""
    parts = path.split("/")[:-1]
    for n in range(len(parts), -1, -1):
        mod = "/".join([*parts[:n], "go.mod"])
        probe = ["git", "cat-file", "-e", f"{c.sha}:{mod}"]  # quiet: a missing go.mod is the answer
        if subprocess.run(probe, cwd=cwd, capture_output=True).returncode == 0:
            return True
    return False


def _prove_go(
    c: Commit,
    wt: Path,
    go: str,
    files: list[str],
    cwd: Path,
    data: list[str] | None = None,
    added: Added | None = None,
) -> list[str]:
    """Run the Go tests ``c`` touched on the parent tree ``wt``; problems when they pass."""
    targets: dict[tuple[Path, str], set[str] | None] = {}
    problems = []
    for f in data or []:  # testdata/: the package in the directory holding it, run whole
        pkg_dir = wt / GO_TESTDATA.match(f).group("pkg")
        mod = _go_module(wt, (pkg_dir / "testdata").relative_to(wt).as_posix())
        if mod is not None:
            targets[(mod, "./" + pkg_dir.relative_to(mod).as_posix())] = None
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
            continue
        verdict = go_outcome(out, run.returncode, added or Added()).verdict(c, what)
        if verdict:
            problems.append(verdict)
    return problems


def _pytest(python: str, wt: Path, report: Path, targets: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        [
            python, "-m", "pytest", "-q", "-p", "no:cacheprovider",
            "--continue-on-collection-errors", f"--junitxml={report}", *targets,
        ],
        cwd=wt, capture_output=True, text=True, check=False,
    )  # fmt: skip


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
    # a Go package's fixtures: its tests run whole with them (and the tests' own changes)
    go_data = [f for f in tests if GO_TESTDATA.match(f) and _go_module_at(c, f, cwd)]
    if not modules and not go_files and not go_data:
        if waiver(c.message):
            return None  # it says why it has no regression test; check() lists the waiver
        return (
            f"{c.short}: cannot prove the fix: it changes no test module, only "
            f"{', '.join(tests) or 'deleted test files'} (a fixture or a non-test file under "
            "tests/ shows nothing on its own); add a test module that fails without the fix, or "
            "a 'No-regression-test: <reason>' trailer"
        )
    go_bin = shutil.which(go) if go_files or go_data else None
    if (go_files or go_data) and go_bin is None:
        return f"{c.short}: cannot prove its Go tests: no Go toolchain ({go!r}) on PATH"
    problems: list[str] = []
    added = added_symbols(c, cwd)
    with tempfile.TemporaryDirectory() as tmp:
        wt = Path(tmp) / "parent"
        report = Path(tmp) / "report.xml"
        try:
            _git("worktree", "add", "--detach", "--quiet", str(wt), f"{c.sha}^", cwd=cwd)
        except subprocess.CalledProcessError:
            return f"{c.short}: cannot check out its parent to prove the test"
        try:
            _git("checkout", c.sha, "--", *tests, cwd=wt)
            if modules:
                # like Go: the test functions the commit added or changed and the tests that
                # reach a module-level name it changed (the module whole when a change names
                # nothing), so the parent run is as narrow as the claim
                targets = [t for m in modules for t in (changed_py_tests(c, m, cwd) or [m])]
                run = _pytest(python, wt, report, targets)
                if run.returncode == 4 and targets != modules:
                    # a node id pytest cannot reach: its module does not collect on the parent;
                    # run the modules whole so the collection error itself is judged
                    run = _pytest(python, wt, report, modules)
                if run.returncode == 0:
                    problems.append(
                        f"{c.short}: its regression test passes WITHOUT the fix "
                        f"({', '.join(modules)})"
                    )
                elif run.returncode in (1, 2):
                    verdict = python_outcome(report, added).verdict(c, ", ".join(modules))
                    if verdict:
                        problems.append(verdict)
                else:
                    problems.append(
                        f"{c.short}: its tests could not run on the parent "
                        f"(pytest exit {run.returncode})"
                    )
            if (go_files or go_data) and go_bin:
                problems += _prove_go(c, wt, go_bin, go_files, cwd, data=go_data, added=added)
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
