# SPDX-License-Identifier: Apache-2.0
"""The link rules: objective parents by level, supports, serves by type, no cycles, both-way
measure links, raised_by; the example tree is the allowed case."""

import shutil

import pytest
from strategy_helpers import EXAMPLE, edit

from homelabnext.registers.schema import RegisterError
from homelabnext.strategy import find_cycle, load_tree, validate


def errors(root, **kw):
    return validate(load_tree(root), policy=False, **kw).errors


def test_the_example_tree_is_valid_with_its_reviews():
    rep = validate(load_tree(EXAMPLE))
    assert rep.errors == [] and rep.warnings == []


def test_the_example_links_are_the_allowed_shapes(lab):
    tree = load_tree(lab)
    reqs = tree.of("requirements")
    assert reqs["FFIR-001"]["serves"] == ["CCIR-001"]  # FFIR -> CCIR
    assert reqs["PIR-001"]["serves"] == ["FFIR-001"]  # PIR -> FFIR
    assert "serves" not in reqs["CCIR-001"]
    edit(lab, "requirements/PIR-001.md", "serves: [FFIR-001]", "serves: [FFIR-001, CCIR-001]")
    assert errors(lab) == []  # PIR -> CCIR is allowed too


@pytest.mark.parametrize(
    ("rel", "old", "new", "want"),
    [
        # a CCIR serves nothing (a CCIR may not link to a PIR, nor to anything else)
        ("requirements/CCIR-001.md", "supports: [SO-001]", "supports: [SO-001]\nserves: [FFIR-001]", "a CCIR serves nothing, not FFIR-001"),
        ("requirements/FFIR-001.md", "serves: [CCIR-001]", "serves: [FFIR-001]", "a FFIR serves CCIR, not FFIR-001"),
        # supports: one or more SO/OO/TO, never empty, never a TT
        ("requirements/PIR-001.md", "supports: [SO-002]", "supports: []", "supports: [] should be non-empty"),
        ("requirements/PIR-001.md", "supports: [SO-002]\n", "", "'supports' is a required property"),
        ("requirements/PIR-001.md", "supports: [SO-002]", "supports: [TT-001]", "supports TT-001 must be one of SO, OO, TO"),
        ("requirements/PIR-001.md", "supports: [SO-002]", "supports: [SO-009]", "supports SO-009 does not exist"),
        # objective parents: SO none, OO -> SO, TO -> OO, TT -> TO
        ("objectives/TO-001.md", "parent: OO-001", "parent: SO-001", "parent SO-001 must be one of OO"),
        ("objectives/TT-001.md", "parent: TO-001", "parent: OO-001", "parent OO-001 must be one of TO"),
        ("objectives/OO-001.md", "parent: SO-001", "parent: null", "a OO's parent is an SO; none is named"),
        ("objectives/SO-001.md", "parent: null", "parent: SO-002", "an SO has no parent"),
        ("objectives/OO-001.md", "level: OO", "level: TO", "level TO disagrees with its id prefix"),
        # a measure and its objective name each other
        ("measures/MOE-002.md", "objective: OO-001", "objective: SO-001", "lists MOE-002, which measures SO-001"),
        # an RFI is raised by a measure or a requirement
        ("rfis/RFI-001.md", "raised_by: MOE-001", "raised_by: MOE-099", "raised_by MOE-099 does not exist"),
        # bindings resolve against the invariants register and the registry
        ("measures/MOE-002.md", "invariant:L-05", "invariant:Z-99", "no such invariant"),
        ("measures/MOE-001.md", "status:uptime-monitors", "status:nowhere", "no such registered status source"),
    ],
)  # fmt: skip
def test_a_link_outside_the_rules_is_refused(lab, rel, old, new, want):
    assert errors(lab) == []
    edit(lab, rel, old, new)
    assert any(want in e for e in errors(lab)), errors(lab)


def test_a_serves_cycle_is_refused(lab):
    shutil.copy(lab / "requirements/FFIR-001.md", lab / "requirements/FFIR-002.md")
    edit(lab, "requirements/FFIR-002.md", "id: FFIR-001", "id: FFIR-002")
    edit(lab, "requirements/FFIR-002.md", "supports: [SO-001, OO-001]", "supports: [OO-001]")
    edit(lab, "requirements/FFIR-001.md", "serves: [CCIR-001]", "serves: [FFIR-002]")
    edit(lab, "requirements/FFIR-002.md", "serves: [CCIR-001]", "serves: [FFIR-001]")
    errs = errors(lab)
    assert "requirements: serves cycle FFIR-001 -> FFIR-002 -> FFIR-001" in errs


def test_find_cycle():
    assert find_cycle({"a": ["b"], "b": ["c"], "c": []}) is None
    assert find_cycle({"a": ["b"], "b": ["a"]}) == ["a", "b", "a"]
    assert find_cycle({"x": ["x"]}) == ["x", "x"]
    assert find_cycle({"a": ["b", "c"], "c": ["d"], "d": ["c"]}) == ["c", "d", "c"]


def test_a_status_is_closed_only_by_a_transition(lab):
    edit(lab, "requirements/PIR-001.md", "status: active", "status: answered")
    assert any("reached by a transition" in e for e in errors(lab))


def test_a_record_named_against_its_id_is_fatal(lab):
    (lab / "objectives/OO-001.md").rename(lab / "objectives/OO-007.md")
    with pytest.raises(RegisterError, match=r"name it OO-001\.md"):
        load_tree(lab)


def test_the_review_tiers_apply(lab):
    edit(lab, "objectives/SO-001.md", "an outage is known", "an outage is seen")
    errs = validate(load_tree(lab)).errors
    assert any(
        e.startswith("SO-001: status active needs agent check, agent challenge") for e in errs
    )
