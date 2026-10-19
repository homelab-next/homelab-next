#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Gate: every component ships tests.

A component, and what counts as its tests (a test file is ``test_*.py`` under ``tests/``,
``tools/tests/`` or ``conformance/``):

* ``homelabnext/<pkg>/`` (a directory with ``__init__.py``) -> ``tests/<pkg>/`` holds a test file;
* ``conformance/<capability>/``                       -> the directory itself holds a test file;
* ``ansible/roles/<role>/``, ``ansible/plugins/<type>/<plugin>.py``, ``compose/<stack>/`` and
  ``tools/<tool>.py``                                 -> some test file names it (as a whole word).

Genuine exceptions go in ``ALLOW`` below, each with the reason, so they are reviewed in one place.
An entry that names nothing, or a component that has since gained tests, is reported as stale.

Usage: python tools/component_tests.py [--root DIR]
Exit: 0 every component has tests, 1 some component has none (or ALLOW is stale).
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
TEST_ROOTS = ("tests", "tools/tests", "conformance")

# component path (relative, posix) -> why it has no tests of its own
ALLOW: dict[str, str] = {
    "conformance/fakes": "reference fakes; every one is exercised by its capability's suite",
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


def components(root: Path) -> dict[str, str]:
    """Every component -> its kind (``package``, ``capability``, ``named``)."""
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
    return found


def has_tests(root: Path, component: str, kind: str, corpus: str) -> bool:
    if kind == "package":
        return _has_test_file(root / "tests" / component.split("/", 1)[1])
    if kind == "capability":
        return _has_test_file(root / component)
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
