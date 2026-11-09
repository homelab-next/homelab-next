# SPDX-License-Identifier: Apache-2.0
"""Every YAML reader built on the shared loaders (``homelabnext._yaml``) refuses a document before
it is constructed when its aliases or merge keys would expand it past a node or byte budget, or a
node contains itself; a registry takes no alias at all and no text over its size cap.  A few
hundred bytes of nested aliases or merges, or a self-referencing anchor, used to keep
``model.load`` (``hnx registry validate``, ``hnx guests validate``, X-12) busy for minutes or
forever."""

from __future__ import annotations

import itertools
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from homelabnext._yaml import (
    MAX_EXPANDED_BYTES,
    AliasRefused,
    ExpansionRefused,
    RecursiveAlias,
    UniqueKeyLoader,
    expanded_cost,
    expanded_size,
)
from homelabnext.generators.safe import control_char_paths
from homelabnext.registry.model import MAX_REGISTRY_BYTES, RegistryUnreadable, load, loads

ROOT = Path(__file__).resolve().parents[2]


def billion_laughs() -> str:
    """Nine levels of nine aliases each: about 300 bytes, 9**9 strings once constructed."""
    out = ["a: &a [lol, lol, lol, lol, lol, lol, lol, lol, lol]"]
    for prev, cur in itertools.pairwise("abcdefghi"):
        out.append(f"{cur}: &{cur} [{', '.join([f'*{prev}'] * 9)}]")
    return "\n".join(out) + "\n"


def merge_fan_out(levels: int = 24) -> str:
    """Each level merges the one before twice: under 1 KB, 2**levels keys to flatten."""
    out = ["l0: &l0 {k0: 0}"]
    for i in range(1, levels):
        out.append(f"l{i}: &l{i} {{<<: [*l{i - 1}, *l{i - 1}], k{i}: {i}}}")
    return "\n".join(out) + "\n"


def byte_fan_out() -> str:
    """One 2 MiB scalar aliased 5,000 times: 5,001 nodes, 10 GB of string to walk."""
    return "x: {s: &s " + "a" * (2 * 1024 * 1024) + ", l: [" + ", ".join(["*s"] * 5000) + "]}\n"


SELF = {
    "sequence": "a: &a [*a]\n",
    "mapping": "a: &a {b: *a}\n",
    "merge": "a: &a {<<: *a, x: 1}\n",
}
BOMBS = {
    "billion-laughs": billion_laughs,
    "merge-fan-out": merge_fan_out,
    "bytes": byte_fan_out,
    **{f"self-{k}": (lambda v=v: v) for k, v in SELF.items()},
}

#: each reader the child runs, by name: the registry's, the swap planner's, the shared loader
READERS = {
    "registry": (
        "from homelabnext.registry.model import loads, RegistryUnreadable as E\n"
        "def read(t): loads(t)\n"
    ),
    "flip": (
        "from homelabnext.swap.flip import load_doc, FlipError as E\ndef read(t): load_doc(t)\n"
    ),
    "shared": (
        "import yaml\nfrom homelabnext._yaml import UniqueKeyLoader\nE = yaml.YAMLError\n"
        "def read(t): yaml.load(t, Loader=UniqueKeyLoader)\n"
    ),
    "pack": (
        "import yaml\nfrom homelabnext.workflows.pack import _yaml_loader\nE = yaml.YAMLError\n"
        "def read(t): yaml.load(t, Loader=_yaml_loader())\n"
    ),
}


@pytest.mark.parametrize("reader", sorted(READERS))
@pytest.mark.parametrize("bomb", sorted(BOMBS))
def test_every_reader_refuses_a_bomb_before_constructing_it(bomb, reader, tmp_path):
    """In a child with a deadline, so a reader that expands the bomb fails here, not hangs."""
    path = tmp_path / "doc.yml"
    path.write_text(BOMBS[bomb]())
    code = (
        READERS[reader]
        + "import sys\n"
        + "try:\n"
        + f"    read(open({str(path)!r}).read())\n"
        + "except E as exc:\n"
        + "    print(type(exc).__name__, exc)\n"
        + "    sys.exit(0)\n"
        + "sys.exit(3)\n"
    )
    res = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, timeout=60, cwd=ROOT
    )
    assert res.returncode == 0, (res.stdout, res.stderr[-2000:])


@pytest.mark.parametrize("form", sorted(SELF))
def test_a_self_referencing_anchor_is_a_recursive_alias(form):
    with pytest.raises(RecursiveAlias):
        yaml.load(SELF[form], Loader=UniqueKeyLoader)


def test_the_byte_budget_counts_aliased_scalars():
    node = yaml.compose(byte_fan_out(), Loader=yaml.SafeLoader)
    with pytest.raises(ExpansionRefused, match="bytes"):
        expanded_cost(node)
    assert MAX_EXPANDED_BYTES == 16 * 1024 * 1024


def test_a_registry_takes_no_alias_and_no_oversized_text():
    with pytest.raises(RegistryUnreadable, match="alias"):
        loads("registry_version: 1\nlab: &l {name: x}\nother: *l\n")
    with pytest.raises(RegistryUnreadable, match=f"over {MAX_REGISTRY_BYTES} bytes"):
        loads("# " + "x" * MAX_REGISTRY_BYTES + "\n")


def test_aliases_still_load_where_a_reader_takes_them():
    assert yaml.load("a: &x {k: 1}\nb: *x\n", Loader=UniqueKeyLoader) == {
        "a": {"k": 1},
        "b": {"k": 1},
    }
    node = yaml.compose("a: &x [1, 2]\nb: *x\n", Loader=yaml.SafeLoader)
    with pytest.raises(AliasRefused):
        expanded_cost(node, allow_aliases=False)


def test_the_example_registries_are_far_under_the_budget():
    for path in sorted((ROOT / "examples").glob("**/services.yml")):
        node = yaml.compose(path.read_text(encoding="utf-8"), Loader=UniqueKeyLoader)
        nodes, size = expanded_cost(node)
        assert nodes < 20_000 and size < MAX_EXPANDED_BYTES // 16, path
    load(ROOT / "examples" / "services.yml")


def test_expanded_size_counts_each_alias_where_it_is_used():
    node = yaml.compose("a: &x [1, 2]\nb: *x\nc: [*x, *x]\n", Loader=yaml.SafeLoader)
    # root 1; keys a, b, c 3; [1, 2] under a, b and twice under c (3 nodes each) 12; c's list 1
    assert expanded_size(node, 1000) == 17
    assert expanded_size(node, 5) == 6
    assert expanded_size(None, 5) == 0


def test_a_deeply_nested_document_is_unreadable_not_a_crash():
    with pytest.raises(RegistryUnreadable):
        loads("a: " + "[" * 5000 + "]" * 5000 + "\n")
    with pytest.raises(ExpansionRefused):
        yaml.load("a: " + "[" * 5000 + "]" * 5000 + "\n", Loader=UniqueKeyLoader)


def test_control_characters_are_searched_once_per_string():
    big = "a" * 1000
    doc = {"l": [big] * 1000, "bad": "x\n"}
    found = list(control_char_paths(doc))
    assert found == ["bad: control character '\\n' in 'x\\n'"]
    clean: set[int] = set()
    list(control_char_paths(doc, "", clean))
    assert id(big) in clean


# ---------------------------------------------------------------- the SOPS sniff
def _sops_tailed(body: str) -> str:
    """A plain registry-shaped document with a bomb in it and a trailing ``sops:`` mapping, so
    ``sops.read_text`` sniffs it before any reader's own budget: the sniff used to construct it
    with ``yaml.safe_load``."""
    base = (ROOT / "examples" / "minimal" / "services.yml").read_text(encoding="utf-8")
    return base + body + "sops:\n  version: x\n"


def _merge_chain(levels: int = 24) -> str:
    out = ["x_m0: &m0 {k: 0}"]
    for i in range(1, levels):
        out.append(f"x_m{i}: &m{i} {{<<: [*m{i - 1}, *m{i - 1}]}}")
    return "\n".join(out) + "\n"


SOPS_BOMBS = {
    "merge-chain": lambda: _sops_tailed(_merge_chain()),
    "deep-nesting": lambda: _sops_tailed("x: " + "[" * 30000 + "]" * 30000 + "\n"),
}
#: each reader that calls sops.read_text first: exits 0 when it refuses the file in time
SOPS_READERS = {
    "registry": (
        "from homelabnext.registry.model import load, RegistryUnreadable\n"
        "try:\n    load(P)\nexcept RegistryUnreadable:\n    ok()\n"
    ),
    "site": (
        "from homelabnext.network.loader import load_site, SiteUnreadable\n"
        "try:\n    load_site(P)\nexcept SiteUnreadable:\n    ok()\n"
    ),
    "guests": (
        "from homelabnext.compute.loader import load_guests\n"
        "guests, problems = load_guests(P.parent)\n"
        "if problems and not guests:\n    ok()\n"
    ),
    "customization": (
        "import yaml\nfrom homelabnext.customization.loader import read_document\n"
        "try:\n    read_document(P)\nexcept yaml.YAMLError:\n    ok()\n"
    ),
}


@pytest.mark.parametrize("reader", sorted(SOPS_READERS))
@pytest.mark.parametrize("bomb", sorted(SOPS_BOMBS))
def test_the_sops_sniff_constructs_nothing_before_a_reader_s_budget(bomb, reader, tmp_path):
    d = tmp_path / "docs"
    d.mkdir()
    path = d / ("g1.yml" if reader == "guests" else "doc.yml")
    path.write_text(SOPS_BOMBS[bomb]())
    code = (
        "import sys\nfrom pathlib import Path\n"
        f"P = Path({str(path)!r})\n"
        "def ok():\n    sys.exit(0)\n" + SOPS_READERS[reader] + "sys.exit(3)\n"
    )
    res = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, timeout=60, cwd=ROOT
    )
    assert res.returncode == 0, (res.stdout, res.stderr[-2000:])


def test_the_sops_sniff_still_finds_an_encrypted_document():
    from homelabnext import sops

    assert sops.format_of("a: ENC[AES256_GCM,data:x]\nsops:\n  mac: ENC[x]\n  version: 3.9.0\n")
    assert sops.format_of(_sops_tailed(_merge_chain(4))) is None  # an alias: no SOPS file has one
    assert sops.format_of("sops:\n  other: 1\n") is None
    assert sops.format_of("x: " + "[" * 30000 + "]" * 30000 + "\nsops:\n  version: x\n") is None
    assert sops.format_of('{"a": ' * 5000 + "1" + "}" * 5000) is None


def test_read_text_refuses_an_oversized_file(tmp_path):
    from homelabnext import sops

    p = tmp_path / "big.yml"
    p.write_text("# " + "x" * sops.MAX_TEXT_BYTES + "\n")
    with pytest.raises(sops.SopsError, match="over"):
        sops.read_text(p)
