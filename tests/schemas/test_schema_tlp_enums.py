# SPDX-License-Identifier: Apache-2.0
"""Every copy of the TLP label enum in a schema is ``homelabnext.tlp.LABELS``, in order.

The five labels are inlined in about a dozen schemas (agent and platform profiles' ceilings, MCP
server and dataset labels, reader ceilings, the OCSF ``tlp`` columns, the status views) rather
than ``$ref``'d from one definition; until they share one, this test is what keeps the copies
one list.  An enum is a copy of it when it holds ``amber+strict``, the one value only TLP has
(doctrine's ``amber``/``red`` cap is another vocabulary)."""

import json
from pathlib import Path

from homelabnext.tlp import LABELS

ROOT = Path(__file__).resolve().parents[2]


def _enums(node, where):
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "enum" and isinstance(value, list) and "amber+strict" in value:
                yield where, value
            yield from _enums(value, f"{where}.{key}")
    elif isinstance(node, list):
        for i, value in enumerate(node):
            yield from _enums(value, f"{where}[{i}]")


def tlp_enums():
    for p in sorted((ROOT / "schemas").glob("*/*.json")):
        doc = json.loads(p.read_text(encoding="utf-8"))
        for where, value in _enums(doc, "$"):
            yield f"{p.relative_to(ROOT / 'schemas').as_posix()}:{where}", value


def test_every_tlp_enum_is_the_label_list():
    found = dict(tlp_enums())
    assert len(found) >= 11, sorted(found)  # the walk finds the copies it guards
    assert {where: v for where, v in found.items() if v != list(LABELS)} == {}


def test_a_drifted_copy_is_found():
    doc = {"properties": {"tlp": {"enum": ["clear", "green", "amber", "amber+strict"]}}}
    assert [v for _, v in _enums(doc, "$") if v != list(LABELS)]
