#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Gate: test code reads neither the wall clock nor unseeded randomness directly.

Hermetic tests inject the clock and the random source (``now=...``, ``random.Random(seed)``).
This lint walks the AST of the test code -- every ``*.py`` under ``tests/`` and ``tools/tests/``,
plus ``test_*.py`` and ``conftest.py`` under ``conformance/`` -- and reports a direct call to:

* the wall clock: ``time.time()``, ``time.time_ns()``, ``datetime.now()``, ``datetime.utcnow()``,
  ``datetime.today()``, ``date.today()`` (through any import spelling);
* unseeded randomness: the module-level ``random.*`` functions (the shared global generator),
  ``random.Random()`` without a seed, ``random.SystemRandom``, ``secrets.*``, ``os.urandom``,
  ``uuid.uuid1``/``uuid.uuid4``.

``time.monotonic``/``perf_counter`` (durations, not dates) and ``time.sleep`` are not flagged.
A deliberate use is waived on its line with ``# hermetic: allow <reason>``.  What this cannot see:
library code that falls back to the real clock because a test did not inject one, and network
use (the suite-wide runtime guard, ``tests/network_guard.py``, covers that).

Usage: python tools/hermetic_lint.py [--root DIR] [FILE ...]
Exit: 0 clean, 1 findings.
"""

from __future__ import annotations

import argparse
import ast
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
WAIVER = re.compile(r"#\s*hermetic:\s*allow\s+\S")

CLOCK = {
    ("time", "time"),
    ("time", "time_ns"),
    ("datetime.datetime", "now"),
    ("datetime.datetime", "utcnow"),
    ("datetime.datetime", "today"),
    ("datetime.date", "today"),
}
RANDOM_GLOBAL = {
    "random", "randint", "randrange", "randbytes", "getrandbits", "choice", "choices",
    "shuffle", "sample", "uniform", "gauss", "normalvariate", "triangular", "betavariate",
    "expovariate", "lognormvariate", "vonmisesvariate", "paretovariate", "weibullvariate",
    "binomialvariate",
}  # fmt: skip


def test_files(root: Path) -> list[Path]:
    out: list[Path] = []
    for top in ("tests", "tools/tests"):
        base = root / top
        if base.is_dir():
            out += base.rglob("*.py")
    conf = root / "conformance"
    if conf.is_dir():
        out += [
            p for p in conf.rglob("*.py") if p.name.startswith("test_") or p.name == "conftest.py"
        ]
    return sorted(p for p in set(out) if "__pycache__" not in p.parts)


class _Visitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.aliases: dict[str, str] = {}  # local name -> dotted origin
        self.found: list[tuple[int, str]] = []

    def visit_Import(self, node: ast.Import) -> None:
        for a in node.names:
            self.aliases[a.asname or a.name.split(".")[0]] = (
                a.name if a.asname else a.name.split(".")[0]
            )

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module and not node.level:
            for a in node.names:
                self.aliases[a.asname or a.name] = f"{node.module}.{a.name}"

    def _dotted(self, node: ast.expr) -> str | None:
        parts = []
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        if not isinstance(node, ast.Name) or node.id not in self.aliases:
            return None
        return ".".join([self.aliases[node.id], *reversed(parts)])

    def visit_Call(self, node: ast.Call) -> None:
        name = self._dotted(node.func)
        if name:
            owner, _, fn = name.rpartition(".")
            reason = None
            if (owner, fn) in CLOCK:
                reason = f"wall clock {name}() (inject the time instead)"
            elif owner == "random" and fn in RANDOM_GLOBAL:
                reason = f"unseeded global {name}() (use random.Random(seed))"
            elif name == "random.Random" and not node.args and not node.keywords:
                reason = "random.Random() without a seed"
            elif name == "random.SystemRandom" or owner == "secrets" or name == "os.urandom":
                reason = f"unseedable randomness {name}()"
            elif name in ("uuid.uuid1", "uuid.uuid4"):
                reason = f"random identifier {name}() (pass a fixed id)"
            if reason:
                self.found.append((node.lineno, reason))
        self.generic_visit(node)


def lint_source(text: str) -> list[tuple[int, str]]:
    v = _Visitor()
    v.visit(ast.parse(text))
    lines = text.splitlines()
    return [(n, r) for n, r in sorted(v.found) if not WAIVER.search(lines[n - 1])]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--root", type=Path, default=REPO_ROOT)
    ap.add_argument("files", nargs="*", type=Path)
    args = ap.parse_args(argv)
    files = args.files or test_files(args.root)
    bad = 0
    for f in files:
        for line, reason in lint_source(f.read_text()):
            print(f"{f}:{line}: {reason}", file=sys.stderr)
            bad += 1
    if bad:
        print(f"hermetic_lint: {bad} finding(s); waive a deliberate one with "
              "'# hermetic: allow <reason>'", file=sys.stderr)  # fmt: skip
        return 1
    print(f"hermetic_lint: {len(files)} test files clean")
    return 0


if __name__ == "__main__":
    sys.exit(main())
