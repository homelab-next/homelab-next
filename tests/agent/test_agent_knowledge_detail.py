# SPDX-License-Identifier: Apache-2.0
"""``detail:`` on an include rule (ADR-0032): a pack can carry a node's summary or outline instead
of its whole content.  ``full`` stays the default and changes nothing; the record keeps the digest
of the FULL content whatever was emitted."""

from __future__ import annotations

import copy
import json

import pytest
from agent_support import inputs, manifest
from test_agent_knowledge import RULE, fake_graph, profile_with

from homelabnext.agent import SpecError, assemble_pack, verify_profile
from homelabnext.agent.digest import sha256_text
from homelabnext.agent.knowledge import select_knowledge

LESSON = (
    "---\n"
    "summary: Wide lake scans time out; always add a LIMIT.\n"
    "---\n"
    "# LL-010\n"
    "\n"
    "Body paragraph that is not the summary.\n"
    "\n"
    "## Context\n"
    "The long story " + "x" * 600 + "\n"
    "\n"
    "## Fix\n"
    "Add a LIMIT.\n"
)
RUNBOOK = (
    "# RB-010\n\nRestart the lake query service, then verify it answers.\n\n## Steps\n1. Restart.\n"
)
BARE = "# lake-query\n"  # a heading and nothing else: no summary at all
FILES = {
    "lessons/LL-010.md": LESSON,
    "lessons/LL-011.md": "# LL-011\nOnly an agent has checked this one.\n",
    "lessons/LL-012.md": "# LL-012\nRetired.\n",
    "runbooks/RB-010.md": RUNBOOK,
    "runbooks/RB-011.md": "# RB-011\nSecrets.\n",
    "docs/lake-query.md": BARE,
    "docs/mixed.md": "# mixed\nMixed.\n",
    "docs/orphan.md": "# orphan\nNothing.\n",
    "suites/lake_query.py": "SUITE = ...  # two checks\n",
}


@pytest.fixture
def root(tmp_path):
    for rel, text in FILES.items():
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text(text)
    return tmp_path


def _sel(root, *rules):
    return select_knowledge(profile_with(*rules), fake_graph(), root)


def _item(sel, nid):
    return next(i for i in sel.included if i["id"] == nid)


def _text(sel, nid):
    return _item(sel, nid)["text"]


# ------------------------------------------------------------------ the rule


def test_full_is_the_default_and_is_not_written(root):
    explicit = profile_with({**RULE, "detail": "full"})
    plain = profile_with(RULE)
    assert "detail" not in explicit["include"][0]
    assert explicit["digest"] == plain["digest"]  # existing profiles keep their digest
    assert verify_profile(explicit) == []


def test_a_non_full_detail_is_written_and_changes_the_digest():
    prof = profile_with({**RULE, "detail": "summary"})
    assert prof["include"][0]["detail"] == "summary"
    assert prof["digest"] != profile_with(RULE)["digest"]


@pytest.mark.parametrize("bad", ["brief", "", None, 3, ["summary"], "SUMMARY"])
def test_an_unknown_detail_is_refused(bad):
    with pytest.raises(SpecError, match="detail must be one of"):
        profile_with({**RULE, "detail": bad})


def test_full_is_unchanged_by_the_feature(root):
    """No detail, or detail full: the same record (no new keys) and the same text."""
    plain = _sel(root, RULE)
    explicit = _sel(root, {**RULE, "detail": "full"})
    assert plain.record() == explicit.record()
    for i in plain.included:
        assert "detail" not in i and "summary_source" not in i and "content_chars" not in i
    text = _text(plain, "lesson:LL-010")
    assert text.endswith("---\n" + LESSON)
    assert "detail:" not in text


# ------------------------------------------------------------------ summary


def test_summary_carries_the_authored_summary_not_the_body(root):
    sel = _sel(root, {**RULE, "detail": "summary"})
    text = _text(sel, "lesson:LL-010")
    assert text.startswith("knowledge lesson:LL-010 (lesson): LL-010\n")
    assert "path: lessons/LL-010.md\n" in text
    assert "detail: summary (summary source: authored; " in text
    assert text.endswith("---\nsummary: Wide lake scans time out; always add a LIMIT.\n")
    assert "Body paragraph" not in text and "long story" not in text
    i = _item(sel, "lesson:LL-010")
    assert (i["detail"], i["summary_source"]) == ("summary", "authored")
    assert i["content_chars"] == len(LESSON)


def test_summary_falls_back_to_the_first_paragraph(root):
    sel = _sel(root, {**RULE, "detail": "summary"})
    i = _item(sel, "runbook:RB-010")
    assert i["summary_source"] == "first-paragraph"
    assert _text(sel, "runbook:RB-010").endswith(
        "summary: Restart the lake query service, then verify it answers.\n"
    )


def test_a_node_built_from_attributes_gets_a_synthesized_summary(root):
    sel = _sel(root, {**RULE, "detail": "summary"})
    i = _item(sel, "check:lake-query/a")
    assert i["summary_source"] == "synthesized"
    assert "summary: " in i["text"]


def test_a_node_with_no_summary_is_title_only_and_never_full(root):
    sel = _sel(root, {**RULE, "detail": "summary"})
    i = _item(sel, "doc:docs/lake-query.md")
    assert i["summary_source"] == "none" and i["detail"] == "summary"
    assert i["text"].startswith("knowledge doc:docs/lake-query.md (doc): docs/lake-query.md\n")
    assert i["text"].endswith("---\n(no summary)\n")
    assert BARE not in i["text"].split("---\n", 1)[1]  # the body did not leak in


# ------------------------------------------------------------------ outline


def test_outline_lists_headings_with_slugs_paths_and_sizes(root):
    sel = _sel(root, {**RULE, "detail": "outline"})
    text = _text(sel, "lesson:LL-010")
    assert "detail: outline (summary source: authored; " in text
    body = text.split("---\n", 1)[1]
    assert body.startswith("summary: Wide lake scans time out; always add a LIMIT.\n")
    assert "outline (3 headings; open one with the MCP section tool" in body
    assert "## Context  slug=context  path=Context  chars=" in body
    assert "## Fix  slug=fix  path=Fix  chars=" in body
    assert "long story" not in body and "Add a LIMIT." not in body
    assert _item(sel, "lesson:LL-010")["detail"] == "outline"


def test_outline_of_a_non_markdown_node_says_it_has_no_headings(root):
    sel = _sel(root, {**RULE, "detail": "outline"})
    assert "outline: (no headings: not a Markdown document)" in _text(sel, "check:lake-query/a")


def test_outline_of_a_node_with_no_summary_still_says_so(root):
    sel = _sel(root, {**RULE, "detail": "outline"})
    i = _item(sel, "doc:docs/lake-query.md")
    assert i["summary_source"] == "none" and "(no summary)\n" in i["text"]
    assert "outline (1 heading;" in i["text"] and "# lake-query  slug=lake-query" in i["text"]


# ------------------------------------------------------------------ the record


@pytest.mark.parametrize("detail", ["summary", "outline"])
def test_the_record_keeps_the_digest_of_the_full_content(root, detail):
    full = _sel(root, RULE)
    lev = _sel(root, {**RULE, "detail": detail})
    assert ids(full) == ids(lev)  # grants, exclusions, ranking: untouched
    assert full.excluded == lev.excluded
    for a, b in zip(full.included, lev.included, strict=True):
        assert a["digest"] == b["digest"] and a["rank"] == b["rank"]
    want = sha256_text(LESSON)
    assert _item(lev, "lesson:LL-010")["digest"] == want
    assert f"content digest: {want}\n" in _text(lev, "lesson:LL-010")  # and the text says so
    rec = lev.record()
    assert all("text" not in i for i in rec["included"])
    assert {i["detail"] for i in rec["included"]} == {detail}
    assert rec["rules"][0]["detail"] == detail


def ids(sel):
    return [i["id"] for i in sel.included]


def test_the_richest_detail_of_several_rules_wins(root):
    sel = _sel(
        root,
        {**RULE, "kinds": ["lesson"], "detail": "summary"},
        {**RULE, "kinds": ["lesson", "doc"], "detail": "outline"},
        {**RULE, "kinds": ["lesson"]},
    )
    assert "detail" not in _item(sel, "lesson:LL-010")  # full beats both
    assert _text(sel, "lesson:LL-010").endswith("---\n" + LESSON)
    assert _item(sel, "doc:docs/lake-query.md")["detail"] == "outline"
    both = _sel(
        root,
        {**RULE, "kinds": ["lesson"], "detail": "summary"},
        {**RULE, "kinds": ["lesson"], "detail": "outline"},
    )
    assert _item(both, "lesson:LL-010")["detail"] == "outline"


def test_a_rule_with_a_detail_does_not_change_which_nodes_are_included(root):
    a = _sel(root, {**RULE, "budget": 3})
    b = _sel(root, {**RULE, "budget": 3, "detail": "summary"})
    assert ids(a) == ids(b) and a.excluded == b.excluded


# ------------------------------------------------------------------ the pack


def test_max_chars_applies_to_what_is_emitted(root):
    """A 600-character body fits nowhere near 200 characters, but its summary does."""
    m = manifest()
    m["budget_chars"] = 20000
    full = _sel(root, {**RULE, "kinds": ["lesson"], "max_chars": 200})
    lev = _sel(root, {**RULE, "kinds": ["lesson"], "max_chars": 400, "detail": "summary"})
    p_full, _ = assemble_pack(m, inputs(), knowledge=full)
    p_lev, _ = assemble_pack(m, inputs(), knowledge=lev)
    cut_full = {t["section"] for t in p_full["truncations"] if t["reason"] == "section-cap"}
    cut_lev = {t["section"] for t in p_lev["truncations"] if t["reason"] == "section-cap"}
    assert "knowledge-001-lesson-LL-010" in cut_full
    assert "knowledge-001-lesson-LL-010" not in cut_lev
    sec = next(s for s in p_lev["sections"] if s["name"] == "knowledge-001-lesson-LL-010")
    assert "always add a LIMIT." in sec["text"] and len(sec["text"]) <= 400


def test_a_summary_pack_is_smaller_and_carries_the_record(root):
    m = manifest()
    m["budget_chars"] = 20000
    p_full, _ = assemble_pack(m, inputs(), knowledge=_sel(root, RULE))
    p_sum, _ = assemble_pack(m, inputs(), knowledge=_sel(root, {**RULE, "detail": "summary"}))
    assert len(p_sum["text"]) < len(p_full["text"])
    assert "long story" not in p_sum["text"] and "long story" in p_full["text"]
    assert {i["detail"] for i in p_sum["knowledge"]["included"]} == {"summary"}
    assert json.dumps(p_sum["knowledge"]["included"][0]["digest"]) == json.dumps(
        p_full["knowledge"]["included"][0]["digest"]
    )


def test_a_summary_pack_is_byte_identical_for_the_same_inputs(root):
    prof = profile_with({**RULE, "detail": "outline"})
    a = assemble_pack(manifest(), inputs(), knowledge=select_knowledge(prof, fake_graph(), root))
    b = assemble_pack(
        manifest(), inputs(),
        knowledge=select_knowledge(copy.deepcopy(prof), fake_graph(), root),
    )  # fmt: skip
    assert a[1] == b[1]
