# SPDX-License-Identifier: Apache-2.0
"""The additivity gate on keywords it once let through: a new ``multipleOf``, a new ``then`` or
``else`` beside an ``if``, a schema replacing ``additionalProperties: true`` and a new pattern
property.  Each breaking case carries a document the old schema accepts and the new one refuses,
so the case is a real tightening, not a guess."""

from pathlib import Path

import pytest
import schema_check as sc

ROOT = Path(__file__).resolve().parents[2]
REG = sc.build_registry(ROOT)

IF_THEN = {"if": {"required": ["a"]}, "then": {"required": ["b"]}}
IF_ELSE = {"if": {"required": ["a"]}, "else": {"required": ["b"]}}

BREAKING = [
    ("new multipleOf", {"type": "integer"}, {"type": "integer", "multipleOf": 2}, 3),
    ("multipleOf not a divisor", {"multipleOf": 2}, {"multipleOf": 3}, 4),
    ("new else", IF_THEN, {**IF_THEN, "else": {"required": ["c"]}}, {}),
    ("new then", IF_ELSE, {**IF_ELSE, "then": {"required": ["c"]}}, {"a": 1}),
    (
        "additionalProperties true to a schema",
        {"type": "object", "additionalProperties": True},
        {"type": "object", "additionalProperties": {"type": "string"}},
        {"x": 1},
    ),
    (
        "new pattern property",
        {"type": "object", "patternProperties": {"^a": {"type": "string"}}},
        {
            "type": "object",
            "patternProperties": {"^a": {"type": "string"}, "^b": {"type": "string"}},
        },
        {"b": 1},
    ),
    (
        "new contentSchema",
        {"type": "string"},
        {"type": "string", "contentSchema": {"type": "object"}},
        "x",
    ),
]


@pytest.mark.parametrize(("label", "old", "new", "doc"), BREAKING, ids=[c[0] for c in BREAKING])
def test_a_tightening_keyword_is_not_additive(label, old, new, doc):
    if label != "new contentSchema":  # an annotation to a 2020-12 validator, still a contract
        assert sc.errors_for(old, doc, REG) == [], "the old schema must accept the document"
        assert sc.errors_for(new, doc, REG), "the new schema must refuse it"
    assert sc.is_additive(old, new), label


ADDITIVE = [
    ("multipleOf to a divisor", {"multipleOf": 4}, {"multipleOf": 2}),
    ("multipleOf to a decimal divisor", {"multipleOf": 0.5}, {"multipleOf": 0.25}),
    ("additionalProperties schema to true", {"additionalProperties": {"type": "string"}}, {}),
    ("then without an if", {"type": "object"}, {"type": "object", "then": {"required": ["b"]}}),
    (
        "additionalProperties true kept",
        {"additionalProperties": True},
        {"additionalProperties": True},
    ),
    (
        "new pattern property that constrains nothing",
        {"patternProperties": {"^a": {"type": "string"}}},
        {"patternProperties": {"^a": {"type": "string"}, "^b": True}},
    ),
]


@pytest.mark.parametrize(("label", "old", "new"), ADDITIVE, ids=[c[0] for c in ADDITIVE])
def test_a_loosening_or_neutral_change_stays_additive(label, old, new):
    assert sc.is_additive(old, new) == [], label


#: a closed discriminator, and a rule per value in an allOf branch (records/note's shape)
DISCRIMINATED = {
    "type": "object",
    "properties": {"kind": {"enum": ["task"]}},
    "required": ["kind"],
    "allOf": [{"if": {"properties": {"kind": {"const": "task"}}, "required": ["kind"]},
               "then": {"required": ["due"]}}],
}  # fmt: skip


def _with_else(cond_value, nested=False):
    import copy

    new = copy.deepcopy(DISCRIMINATED)
    new["properties"]["kind"]["enum"].append("bug")
    branch = {
        "if": {"properties": {"kind": {"const": cond_value}}, "required": ["kind"]},
        "then": {"required": ["severity"]},
    }
    if nested:
        new["properties"]["child"] = {"allOf": [{"if": False, "else": branch}]}
    else:
        new["allOf"][0]["else"] = branch
    return new


def test_a_new_else_for_a_new_discriminator_value_is_additive():
    """Only a document carrying the new value meets the new branch: every old one still passes."""
    assert sc.is_additive(DISCRIMINATED, _with_else("bug")) == []


def test_a_new_else_on_a_value_old_documents_carry_is_not_additive():
    new = _with_else("task")
    new["allOf"][0]["then"] = {}  # the old rule gone from then, a stricter else for it instead
    new["allOf"][0]["if"] = {"properties": {"kind": {"const": "bug"}}, "required": ["kind"]}
    assert sc.is_additive(DISCRIMINATED, new)


def test_the_discriminator_proof_holds_only_for_the_top_level_document():
    """A nested schema's ``kind`` is not the top-level property of that name: no proof there."""
    child = {"allOf": [{"if": False}]}
    old = {**DISCRIMINATED, "properties": {**DISCRIMINATED["properties"], "child": child}}
    new = _with_else("bug", nested=True)
    new["properties"]["kind"] = old["properties"]["kind"]
    assert sc.errors_for(old, {"kind": "task", "due": 1, "child": {"kind": "bug"}}, REG) == []
    assert sc.errors_for(new, {"kind": "task", "due": 1, "child": {"kind": "bug"}}, REG)
    assert sc.is_additive(old, new)
