# SPDX-License-Identifier: Apache-2.0
"""A registry document is refused before it is constructed when nested aliases or merge keys
would expand it past a node budget: a few hundred bytes of either used to keep ``model.load``
(and ``hnx registry validate``, and every CI job that reads the registry) busy for minutes."""

from __future__ import annotations

import itertools
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from homelabnext._yaml import UniqueKeyLoader, expanded_size
from homelabnext.registry.model import MAX_EXPANDED_NODES, RegistryUnreadable, load, loads

ROOT = Path(__file__).resolve().parents[2]


def billion_laughs() -> str:
    """Nine levels of nine aliases each: about 300 bytes, 9**9 strings once constructed."""
    names = "abcdefghi"
    out = ["a: &a [lol, lol, lol, lol, lol, lol, lol, lol, lol]"]
    for prev, cur in itertools.pairwise(names):
        out.append(f"{cur}: &{cur} [{', '.join([f'*{prev}'] * 9)}]")
    return "\n".join(out) + "\n"


def merge_fan_out(levels: int = 24) -> str:
    """Each level merges the one before twice: under 1 KB, 2**levels keys to flatten."""
    out = ["l0: &l0 {k0: 0}"]
    for i in range(1, levels):
        out.append(f"l{i}: &l{i} {{<<: [*l{i - 1}, *l{i - 1}], k{i}: {i}}}")
    return "\n".join(out) + "\n"


@pytest.mark.parametrize("bomb", [billion_laughs, merge_fan_out], ids=lambda f: f.__name__)
def test_an_expansion_bomb_is_refused_before_it_is_constructed(bomb, tmp_path):
    text = bomb()
    assert len(text) < 1024
    path = tmp_path / "services.yml"
    path.write_text(text)
    # in a child with a deadline, so a loader that expands the bomb fails here instead of hanging
    code = (
        "import sys\n"
        "from homelabnext.registry.model import load, RegistryUnreadable\n"
        "try:\n"
        f"    load({str(path)!r})\n"
        "except RegistryUnreadable as exc:\n"
        "    print(exc)\n"
        "    sys.exit(0)\n"
        "sys.exit(3)\n"
    )
    res = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, timeout=30, cwd=ROOT
    )
    assert res.returncode == 0, res.stderr
    assert f"expands to over {MAX_EXPANDED_NODES} YAML nodes" in res.stdout
    with pytest.raises(RegistryUnreadable, match="refused before it is constructed"):
        loads(text)


def test_the_example_registries_are_far_under_the_budget():
    for path in sorted((ROOT / "examples").glob("**/services.yml")):
        node = yaml.compose(path.read_text(encoding="utf-8"), Loader=UniqueKeyLoader)
        assert expanded_size(node, MAX_EXPANDED_NODES) < MAX_EXPANDED_NODES // 10, path
    load(ROOT / "examples" / "services.yml")


def test_expanded_size_counts_each_alias_where_it_is_used():
    node = yaml.compose("a: &x [1, 2]\nb: *x\nc: [*x, *x]\n", Loader=UniqueKeyLoader)
    # root 1; keys a, b, c 3; [1, 2] under a, b and twice under c (3 nodes each) 12; c's list 1
    assert expanded_size(node, 1000) == 17
    assert expanded_size(node, 5) == 6
    assert expanded_size(None, 5) == 0


def test_a_deeply_nested_registry_is_unreadable_not_a_crash():
    with pytest.raises(RegistryUnreadable):
        loads("a: " + "[" * 5000 + "]" * 5000 + "\n")
