# SPDX-License-Identifier: Apache-2.0
"""A ``data_tier`` maps to a TLP label in one place, ``homelabnext.registry.model_tlp``
(``tier_label``, ``receive_ceiling``, ``send_ceiling``, ``data_tier_of``, ``DATA_TIERS``): the
gateway, the profile compiler, the reader rule and the MCP catalog used to map it on their own, so
``local-only`` and ``cloud-allowed`` could read as different ceilings in different places."""

import ast
from pathlib import Path

import pytest

from homelabnext import tlp
from homelabnext.registry import model_tlp

REPO = Path(__file__).resolve().parents[2]
OWNER = REPO / "homelabnext" / "registry" / "model_tlp.py"
TIERS = set(model_tlp.DATA_TIERS)


def _names_tier(node: ast.AST) -> bool:
    return any(
        isinstance(n, ast.Constant) and n.value in TIERS
        for n in ast.walk(node)
        if isinstance(n, ast.Constant)
    )


def _names_label(nodes) -> bool:
    return any(
        isinstance(n, ast.Attribute)
        and n.attr in {str(label).upper() for label in tlp.Label}
        and isinstance(n.value, ast.Attribute | ast.Name)
        and (getattr(n.value, "attr", None) or getattr(n.value, "id", None)) == "Label"
        for node in nodes
        for n in ast.walk(node)
    )


def mapping_sites(source: str) -> list[int]:
    """Lines that map a data tier to a TLP label (a conditional on a tier literal choosing a
    ``Label``) or spell the data tiers out (a tuple, list or set of exactly the tiers)."""
    out = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.IfExp | ast.If) and _names_tier(node.test):
            branches = [node.body, node.orelse] if isinstance(node, ast.IfExp) else node.body
            if _names_label(branches if isinstance(branches, list) else [branches]):
                out.append(node.lineno)
        elif isinstance(node, ast.Tuple | ast.List | ast.Set) and len(node.elts) == len(TIERS):
            if (
                all(isinstance(e, ast.Constant) for e in node.elts)
                and {e.value for e in node.elts} == TIERS
            ):
                out.append(node.lineno)
    return out


@pytest.mark.parametrize(
    "src",
    [
        'X = tlp.Label.CLEAR if rec.get("data_tier") == "cloud-allowed" else tlp.Label.RED\n',
        'def f(t):\n    if t == "local-only":\n        return Label.RED\n    return Label.CLEAR\n',
        'DATA_TIERS = ("local-only", "cloud-allowed")\n',
    ],
)
def test_the_scan_finds_a_private_mapping(src):
    assert mapping_sites(src)


def test_no_module_but_model_tlp_maps_a_data_tier_to_a_label():
    found = []
    for path in sorted((REPO / "homelabnext").rglob("*.py")):
        if path == OWNER:
            continue
        found += [f"{path.relative_to(REPO)}:{n}" for n in mapping_sites(path.read_text())]
    assert found == [], "map data tiers through homelabnext.registry.model_tlp: " + str(found)


@pytest.mark.parametrize(
    ("tier", "send", "receive"),
    [
        ("cloud-allowed", tlp.Label.CLEAR, tlp.Label.CLEAR),
        ("local-only", tlp.Label.RED, tlp.Label.RED),
        (None, tlp.Label.RED, tlp.Label.CLEAR),
    ],
)
def test_every_reader_of_a_tier_agrees(tier, send, receive):
    from homelabnext.agent import readers
    from homelabnext.mcp import servers

    assert model_tlp.tier_label(tier) is send
    assert model_tlp.send_ceiling(data_tier=tier) is send
    assert readers.server_label({"data_tier": tier}) is send
    assert servers.record_label({"data_tier": tier}) is send
    assert model_tlp.receive_ceiling(None, tier) is readers.receive_ceiling(None, tier) is receive
    assert readers.DATA_TIERS is model_tlp.DATA_TIERS
