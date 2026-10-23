#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# hnx-script:
#   id: component-tests
#   kind: check
#   purpose: Fail when a package, capability, role, plugin, compose stack or tool has no tests.
#   owner: maintainers
#   trigger: [ci:ci/lint, make:component-tests]
#   invariant: [Q-04]
#   inputs: the tree under --root; the reviewed ALLOW table in this file
#   outputs: one line per component without tests or stale ALLOW entry
#   exit:
#     "0": every component has tests
#     "1": some component has none or ALLOW is stale
"""Gate: every component ships tests.

A component, and what counts as its tests (a test file is ``test_*.py`` under ``tests/``,
``tools/tests/`` or ``conformance/``):

* ``homelabnext/<pkg>/`` (a directory with ``__init__.py``) -> ``tests/<pkg>/`` holds a test file;
* ``conformance/<capability>/``                       -> the directory itself holds a test file;
* ``ansible/roles/<role>/``, ``ansible/plugins/<type>/<plugin>.py``, ``compose/<stack>/`` and
  ``tools/<tool>.py``                                 -> some test file names it (as a whole word);
* a Go package: a directory holding a non-test ``.go`` file anywhere in a Go module (every
  ``go.mod`` is one, its root included, as tools/go_modules.py discovers them for CI; ``testdata``,
  ``_*`` and ``.*`` directories are not packages, as for the go tool, nor is a module's linters'
  module ``tools/``)                                  -> the directory itself holds a ``*_test.go``.

Genuine exceptions go in ``ALLOW`` below, each with the reason, so they are reviewed in one place.
An entry that names nothing, or a component that has since gained tests, is reported as stale.

Usage: python tools/component_tests.py [--root DIR]
Exit: 0 every component has tests, 1 some component has none (or ALLOW is stale).
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path

import go_modules

REPO_ROOT = Path(__file__).resolve().parent.parent
TEST_ROOTS = ("tests", "tools/tests", "conformance")
# top-level directories that hold build output or environments, never a Go module of the tree
NOT_SOURCE = frozenset({"build", "dist", "venv", "node_modules"})

# component path (relative, posix) -> why it has no tests of its own
ALLOW: dict[str, str] = {
    "conformance/fakes": "reference fakes; every one is exercised by its capability's suite",
    "conformance/fixtures": "recorded product shapes (data, not code), read by the fakes",
    "conformance/protocols": "typing protocols only (no behaviour); the suites check them",
    "conformance/suites": "the suites are the tests the capability directories run",
    "conformance/targets": "target descriptions (YAML), not code",
}


def _test_files(root: Path) -> list[Path]:
    out: list[Path] = []
    for top in TEST_ROOTS:
        base = root / top
        if base.is_dir():
            out += [p for p in base.rglob("test_*.py") if "__pycache__" not in p.parts]
    return sorted(set(out))


def _has_test_file(directory: Path) -> bool:
    return directory.is_dir() and any(directory.rglob("test_*.py"))


def _go_ignored(name: str) -> bool:
    return name == "testdata" or name.startswith(("_", "."))


def _walk(base: Path, root: Path):
    """``(directory, file names)`` under ``base``, skipping what the go tool skips (``testdata``,
    ``_*``, ``.*``), caches, and the tree's top-level build output and environments."""
    for d, subdirs, files in os.walk(base):
        top = Path(d) == root
        subdirs[:] = sorted(
            s
            for s in subdirs
            if not _go_ignored(s) and s != "__pycache__" and not (top and s in NOT_SOURCE)
        )
        yield Path(d), files


def _go_packages(root: Path) -> list[str]:
    """Every directory of a Go module that holds a non-test ``.go`` file (the module's root too)."""
    go_mods = [
        (d / "go.mod").relative_to(root).as_posix() for d, f in _walk(root, root) if "go.mod" in f
    ]
    out = []
    for mod in go_modules.modules(go_mods):
        base = root / mod.dir
        linters = base / go_modules.LINTERS_DIR if mod.tools else None
        for d, files in _walk(base, root):
            if linters and (d == linters or linters in d.parents):
                continue  # the module's linters' module: tool pins, not a package of its own
            if any(_is_go_source(Path(f)) for f in files):
                out.append(d.relative_to(root).as_posix())
    return sorted(set(out))


def _is_go_source(p: Path) -> bool:
    return p.suffix == ".go" and not p.name.endswith("_test.go")


def components(root: Path) -> dict[str, str]:
    """Every component -> its kind (``package``, ``capability``, ``named``, ``go-package``)."""
    found: dict[str, str] = {}
    pkg = root / "homelabnext"
    for d in sorted(pkg.iterdir()) if pkg.is_dir() else ():
        if (d / "__init__.py").is_file():
            found[f"homelabnext/{d.name}"] = "package"
    conf = root / "conformance"
    for d in sorted(conf.iterdir()) if conf.is_dir() else ():
        if d.is_dir() and not d.name.startswith((".", "_")):
            found[f"conformance/{d.name}"] = "capability"
    globs = ("ansible/roles/*/", "ansible/plugins/*/*.py", "compose/*/", "tools/*.py")
    for g in globs:
        for p in sorted(root.glob(g)):
            if p.name.startswith(("_", ".")) or p.name == "__pycache__":
                continue
            found[p.relative_to(root).as_posix().rstrip("/")] = "named"
    for d in _go_packages(root):
        found[d] = "go-package"
    return found


def has_tests(root: Path, component: str, kind: str, corpus: str) -> bool:
    if kind == "package":
        return _has_test_file(root / "tests" / component.split("/", 1)[1])
    if kind == "capability":
        return _has_test_file(root / component)
    if kind == "go-package":
        return any((root / component).glob("*_test.go"))
    name = Path(component).stem
    return re.search(rf"(?<![\w-]){re.escape(name)}(?![\w-])", corpus) is not None


def problems(root: Path, allow: dict[str, str] = ALLOW) -> list[str]:
    found = components(root)
    corpus = "\n".join(p.read_text(errors="replace") for p in _test_files(root))
    out = []
    for comp, kind in found.items():
        tested = has_tests(root, comp, kind, corpus)
        if comp in allow:
            if tested:
                out.append(f"{comp}: has tests now; remove its ALLOW entry")
        elif not tested:
            out.append(f"{comp}: no tests ({_expect(comp, kind)})")
    out += [f"{a}: ALLOW entry names no component" for a in sorted(set(allow) - set(found))]
    return out


def _expect(comp: str, kind: str) -> str:
    if kind == "package":
        return f"add tests/{comp.split('/', 1)[1]}/test_*.py"
    if kind == "capability":
        return f"add {comp}/test_*.py"
    if kind == "go-package":
        return f"add {comp}/*_test.go"
    return f"add a test_*.py under {', '.join(TEST_ROOTS)} that exercises {Path(comp).stem!r}"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--root", type=Path, default=REPO_ROOT)
    args = ap.parse_args(argv)
    found = problems(args.root)
    for p in found:
        print(f"component_tests: {p}", file=sys.stderr)
    if found:
        return 1
    n = len(components(args.root)) - len(ALLOW)
    print(f"component_tests: all {n} components ship tests ({len(ALLOW)} allowlisted)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
