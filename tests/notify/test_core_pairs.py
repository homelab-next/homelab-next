# SPDX-License-Identifier: Apache-2.0
"""The core's notify pairs are written once (:mod:`homelabnext.notify.core_pairs`) and that list
is what the core registers: every ``register_pair`` call in the package takes its titles from a
name (never a literal), each name resolves to a pair of the list, and every pair of the list is
registered somewhere.  The module loader refuses a module that declares one of these titles."""

from __future__ import annotations

import ast
import importlib
from pathlib import Path

from homelabnext.notify.core_pairs import CORE_PAIRS
from homelabnext.registry import serving

PKG = Path(__file__).resolve().parents[2] / "homelabnext"
#: call sites whose titles are loop variables over a table, checked by running them instead
RUN = {("homelabnext.registry.serving", "problem", "recovery")}


class Recorder:
    def __init__(self):
        self.pairs: list[tuple[str, str]] = []

    def register_pair(self, problem, recovery):
        self.pairs.append((problem, recovery))

    def is_registered(self, title):
        return any(p == title for p, _ in self.pairs)


def _calls():
    """``(module, problem arg, recovery arg)`` for every ``.register_pair(a, b)`` in the
    package (the notifier's own definition aside)."""
    out = []
    for f in sorted(PKG.rglob("*.py")):
        tree = ast.parse(f.read_text(encoding="utf-8"), str(f))
        mod = ".".join(f.relative_to(PKG.parent).with_suffix("").parts)
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "register_pair"
            ):
                out.append((mod, f, node))
    return out


def test_every_core_registration_names_its_titles_never_a_literal():
    calls = _calls()
    assert calls, "no register_pair call found: the scan is broken"
    for _mod, f, node in calls:
        assert len(node.args) == 2 and not node.keywords, f"{f}:{node.lineno}"
        for a in node.args:
            assert isinstance(a, ast.Name), (
                f"{f}:{node.lineno}: a title written in place; take it from "
                "homelabnext.notify.core_pairs"
            )


def test_each_registration_is_a_core_pair_and_every_core_pair_is_registered():
    registered = set()
    for mod, f, node in _calls():
        names = tuple(a.id for a in node.args)
        if (mod, *names) in RUN:
            continue
        m = importlib.import_module(mod)
        pair = tuple(getattr(m, n) for n in names)
        assert CORE_PAIRS.get(pair[0]) == pair[1], f"{f}:{node.lineno}: {pair} is not a core pair"
        registered.add(pair)
    rec = Recorder()
    serving.register(rec)
    for pair in rec.pairs:
        assert CORE_PAIRS.get(pair[0]) == pair[1], f"registry.serving: {pair} is not a core pair"
    registered.update(rec.pairs)
    assert registered == set(CORE_PAIRS.items())


def test_core_pair_titles_are_all_distinct():
    titles = [*CORE_PAIRS, *CORE_PAIRS.values()]
    assert len(titles) == len(set(titles))
