# SPDX-License-Identifier: Apache-2.0
"""The link and identity rules: every record has its uid and the type of its directory; parents
by the doctrine's hierarchy, supports, serves by type, raised_by; no cycles; sibling orders
unique; every link a uid that resolves.  The example tree is the allowed case."""

import shutil

import pytest
from strategy_helpers import EXAMPLE, U, edit, rel, uids

from homelabnext.registers.schema import RegisterError
from homelabnext.strategy import find_cycle, load_tree, validate

OTHER = "01a15e4e-0000-7000-8000-00000000000f"  # a valid uid no example record has


def errors(root, **kw):
    return validate(load_tree(root), policy=False, **kw).errors


def test_the_example_tree_is_valid_with_its_reviews():
    rep = validate(load_tree(EXAMPLE))
    assert rep.errors == [] and rep.warnings == []


def test_the_example_links_are_the_allowed_shapes(lab):
    tree = load_tree(lab)
    reqs = tree.of("requirements")
    assert reqs[U["FFIR-001"]]["serves"] == [U["CCIR-001"]]  # FFIR -> CCIR
    assert reqs[U["PIR-001"]]["serves"] == [U["FFIR-001"]]  # PIR -> FFIR
    assert "serves" not in reqs[U["CCIR-001"]]
    edit(lab, "PIR-001", "serves: [FFIR-001]", "serves: [FFIR-001, CCIR-001]")
    assert errors(lab) == []  # PIR -> CCIR is allowed too


def test_the_example_numbers_are_computed_from_the_hierarchy(lab):
    tree = load_tree(lab)
    shown = {code: tree.label(U[code]) for code in U}
    assert shown == {
        "SO-001": "SO 1",
        "SO-002": "SO 2",
        "OO-001": "OO 1.1",
        "OO-002": "OO 2.1",
        "TO-001": "TO 1.1.1",
        "TT-001": "TT 1.1.1.1",
        "MOE-001": "MOE 1.1",
        "MOE-002": "MOE 1.1.1",
        "MOP-001": "MOP 1.1.1",
        "MOE-003": "MOE 1.1.1.1",
        "MOP-002": "MOP 1.1.1.1",
        "MOE-004": "MOE 1.1.1.1.1",
        "MOE-005": "MOE 2.1",
        "MOE-006": "MOE 2.1.1",
        "CCIR-001": "CCIR 1",
        "FFIR-001": "FFIR 1",
        "PIR-001": "PIR 1",
        "RFI-001": "RFI 1",
        "RFI-002": "RFI 2",
    }


def test_reparenting_renumbers_the_subtree_and_touches_no_other_record(lab):
    before = {p: p.read_text() for p in lab.rglob("*.md")}
    edit(lab, "TO-001", "parent: OO-001", "parent: OO-002")
    tree = load_tree(lab)
    moved = {c: tree.label(U[c]).split() for c in ("TO-001", "TT-001", "MOE-004")}
    assert moved == {  # each number's path, the whole subtree now under SO 2 / OO 2.1
        "TO-001": ["TO", "2.1.1"],
        "TT-001": ["TT", ".".join(["2", "1", "1", "1"])],
        "MOE-004": ["MOE", ".".join(["2", "1", "1", "1", "1"])],
    }
    changed = [p for p, text in before.items() if p.read_text() != text]
    assert changed == [lab / rel("TO-001")]  # the moved record only; no link, no file name
    assert errors(lab) == []


def test_an_order_reorders_siblings_and_no_two_may_share_one(lab):
    edit(lab, "SO-002", "type: SO", "type: SO\norder: 1")
    tree = load_tree(lab)
    assert tree.label(U["SO-002"]) == "SO 1" and tree.label(U["SO-001"]) == "SO 2"
    assert tree.label(U["OO-001"]) == "OO 2.1"  # the subtree follows its SO
    assert errors(lab) == []
    edit(lab, "SO-001", "type: SO", "type: SO\norder: 1")
    (err,) = errors(lab)
    assert err.startswith("SO 2 ") and ": order 1 is also the order of its sibling SO 1 " in err


def test_a_sub_pir_numbers_under_its_pir(lab):
    shutil.copy(lab / rel("PIR-001"), lab / f"requirements/{OTHER}.md")
    edit(lab, f"requirements/{OTHER}.md", f"uid: {U['PIR-001']}", f"uid: {OTHER}")
    edit(lab, f"requirements/{OTHER}.md", "type: PIR", "type: PIR\nparent: PIR-001")
    edit(lab, f"requirements/{OTHER}.md", "supports: [SO-002]", "supports: [OO-002]")
    tree = load_tree(lab)
    assert tree.label(OTHER) == "PIR 1.1"
    assert not [e for e in errors(lab) if "parent" in e]
    edit(lab, f"requirements/{OTHER}.md", f"parent: {U['PIR-001']}", "parent: FFIR-001")
    assert any("parent FFIR 1" in e and "a PIR names PIR as its parent" in e for e in errors(lab))


@pytest.mark.parametrize(
    ("code", "old", "new", "want"),
    [
        # a CCIR serves nothing (a CCIR may not link to a PIR, nor to anything else)
        ("CCIR-001", "supports: [SO-001]", "supports: [SO-001]\nserves: [FFIR-001]", "a CCIR carries no `serves`"),
        ("FFIR-001", "serves: [CCIR-001]", "serves: [FFIR-001]", "is an FFIR; an FFIR names CCIR as its serves"),
        # supports: one or more SO/OO/TO, never empty, never a TT
        ("PIR-001", "supports: [SO-002]", "supports: []", "supports: [] should be non-empty"),
        ("PIR-001", "supports: [SO-002]\n", "", "'supports' is a required property"),
        ("PIR-001", "supports: [SO-002]", "supports: [TT-001]", "is a TT; a PIR names SO, OO, TO as its supports"),
        ("PIR-001", "supports: [SO-002]", f"supports: [{OTHER}]", f"supports {OTHER} does not exist"),
        ("PIR-001", "supports: [SO-002]", "supports: [SO-009]", "does not match"),
        # parents per the doctrine's hierarchy: SO none, OO -> SO, TO -> OO, TT -> TO
        ("TO-001", "parent: OO-001", "parent: SO-001", "is an SO; a TO names OO as its parent"),
        ("TT-001", "parent: TO-001", "parent: OO-001", "is an OO; a TT names TO as its parent"),
        ("OO-001", "parent: SO-001\n", "", "an OO's parent is an SO; none is named"),
        ("SO-001", "parent: null", "parent: SO-002", "an SO has no parent"),
        ("MOE-002", "parent: OO-001", "parent: PIR-001", "is a PIR; a MOE names SO, OO, TO, TT as its parent"),
        ("OO-001", "type: OO", "type: TO", "a TO names OO as its parent"),
        ("OO-001", "type: OO", "type: PIR", "a PIR lives in requirements/, not objectives/"),
        # an RFI is raised by a measure or a requirement
        ("RFI-001", "raised_by: MOE-001", f"raised_by: {OTHER}", f"raised_by {OTHER} does not exist"),
        ("RFI-001", "raised_by: MOE-001", "raised_by: SO-001", "is an SO; an RFI names MOP, MOE, CCIR, FFIR, PIR"),
        # bindings resolve against the invariants register and the registry
        ("MOE-002", "invariant:L-05", "invariant:Z-99", "no such invariant"),
        ("MOE-001", "status:uptime-monitors", "status:nowhere", "no such registered status source"),
    ],
)  # fmt: skip
def test_a_link_outside_the_rules_is_refused(lab, code, old, new, want):
    assert errors(lab) == []
    edit(lab, code, old, new)
    errs = errors(lab)
    assert any(want in e for e in errs), errs


def test_a_legacy_code_in_a_record_is_refused(lab):
    p = lab / rel("PIR-001")
    p.write_text(p.read_text().replace(U["SO-002"], "SO-002"))  # what a merge of an old branch does
    errs = errors(lab)
    assert any("supports" in e and "SO-002" in e for e in errs), errs


def test_a_parent_cycle_is_refused(lab):
    edit(lab, "OO-001", "parent: SO-001", "parent: TT-001")
    edit(lab, "SO-001", "type: SO", "type: OO")
    edit(lab, "SO-001", "parent: null", "parent: OO-001")
    assert any("parent cycle" in e for e in errors(lab)), errors(lab)


def test_a_serves_cycle_is_refused(lab):
    shutil.copy(lab / rel("FFIR-001"), lab / f"requirements/{OTHER}.md")
    edit(lab, f"requirements/{OTHER}.md", f"uid: {U['FFIR-001']}", f"uid: {OTHER}")
    edit(lab, f"requirements/{OTHER}.md", "supports: [SO-001, OO-001]", "supports: [OO-001]")
    edit(lab, "FFIR-001", "serves: [CCIR-001]", f"serves: [{OTHER}]")
    edit(lab, f"requirements/{OTHER}.md", "serves: [CCIR-001]", "serves: [FFIR-001]")
    assert "requirements: serves cycle FFIR 1 -> FFIR 2 -> FFIR 1" in errors(lab)


def test_find_cycle():
    assert find_cycle({"a": ["b"], "b": ["c"], "c": []}) is None
    assert find_cycle({"a": ["b"], "b": ["a"]}) == ["a", "b", "a"]
    assert find_cycle({"x": ["x"]}) == ["x", "x"]
    assert find_cycle({"a": ["b", "c"], "c": ["d"], "d": ["c"]}) == ["c", "d", "c"]


def test_a_status_is_closed_only_by_a_transition(lab):
    edit(lab, "PIR-001", "status: active", "status: answered")
    assert any("reached by a transition" in e for e in errors(lab))


def test_a_record_named_against_its_uid_is_fatal(lab):
    (lab / rel("OO-001")).rename(lab / f"objectives/{OTHER}.md")
    with pytest.raises(RegisterError, match=rf"name it {U['OO-001']}\.md"):
        load_tree(lab)


@pytest.mark.parametrize(
    ("old", "new", "want"),
    [
        ("uid: {u}", "uid: LL-1", "`uid` must be a canonical UUIDv7"),
        ("uid: {u}", "id: OO-009", "numbered `id: OO-009` and no `uid:`"),
        ("uid: {u}\n", "", "`uid` must be a canonical UUIDv7"),
    ],
)
def test_a_record_without_its_uid_is_fatal(lab, old, new, want):
    u = U["OO-001"]
    edit(lab, "OO-001", old.format(u=u), new.format(u=u))
    with pytest.raises(RegisterError, match=want):
        load_tree(lab)


def test_two_files_with_one_uid_are_fatal(lab):
    shutil.copy(lab / rel("OO-001"), lab / f"objectives/{OTHER}.md")
    with pytest.raises(RegisterError, match="disagree"):
        load_tree(lab)


def test_the_review_tiers_apply(lab):
    edit(lab, "SO-001", "an outage is known", "an outage is seen")
    errs = validate(load_tree(lab)).errors
    want = f"SO 1 {U['SO-001']}: status active needs agent check, agent audit"
    assert any(e.startswith(want) for e in errs), errs


def test_uids_helper_writes_codes_as_uids():
    assert uids("supports: [SO-001, OO-001]") == f"supports: [{U['SO-001']}, {U['OO-001']}]"
