# SPDX-License-Identifier: Apache-2.0
"""``include:`` rules: linked knowledge in the context pack, filtered by what the profile is
granted.  A synthetic graph pins each rule (grant filter, inactive records, reviews, budget,
determinism); the CLI test runs ``--explain`` on the repository's own graph."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
import yaml
from agent_support import PARTS, inputs, library, manifest, spec

from homelabnext import cli
from homelabnext.agent import (
    IncludeViolation,
    ReaderViolation,
    SpecError,
    assemble_pack,
    compile_profile,
    profile_digest,
    start_session,
    verify_profile,
)
from homelabnext.agent.knowledge import explain, select_knowledge, subjects
from homelabnext.graph import Edge, Graph, Node
from homelabnext.graph.sources import _provenance
from homelabnext.registers.schema import record_digest_of
from homelabnext.registry import load

REPO = Path(__file__).resolve().parents[2]

FILES = {
    "lessons/LL-010.md": "# LL-010\nLake queries time out on wide scans; add a LIMIT.\n",
    "lessons/LL-011.md": "# LL-011\nOnly an agent has checked this one.\n",
    "lessons/LL-012.md": "# LL-012\nRetired: fixed for good.\n",
    "runbooks/RB-010.md": "# RB-010\n1. Restart the lake query service.\n",
    "runbooks/RB-011.md": "# RB-011\n1. Rotate the secrets store root token.\n",
    "docs/lake-query.md": "# lake-query\nThe read-only query capability.\n",
    "docs/mixed.md": "# mixed\nHow lake-query reads secrets.\n",
    "docs/orphan.md": "# orphan\nAbout nothing granted.\n",
    "suites/lake_query.py": "SUITE = ...  # two checks\n",
}
FULL = ["agent_check", "audit", "human"]


def _node(nid, kind, path="", **attrs):
    return Node(nid, kind, nid.split(":", 1)[1], path, attrs)


def fake_graph() -> Graph:
    nodes = [
        _node("cap:lake-query", "cap"),
        _node("cap:secrets", "cap"),
        _node("svc:lake-query", "svc"),
        _node("svc:secrets", "svc"),
        _node("mcp:lake", "mcp"),
        _node("system:lake-query", "system"),
        _node("system:secrets", "system"),
        _node("lesson:LL-010", "lesson", "lessons/LL-010.md", reviewed=FULL, status="open"),
        _node("lesson:LL-011", "lesson", "lessons/LL-011.md", reviewed=["agent_check"]),
        _node("lesson:LL-012", "lesson", "lessons/LL-012.md", status="retired"),
        _node("runbook:RB-010", "runbook", "runbooks/RB-010.md", reviewed=FULL),
        _node("runbook:RB-011", "runbook", "runbooks/RB-011.md", reviewed=FULL),
        _node("doc:docs/lake-query.md", "doc", "docs/lake-query.md"),
        _node("doc:docs/mixed.md", "doc", "docs/mixed.md"),
        _node("doc:docs/orphan.md", "doc", "docs/orphan.md"),
        _node("check:lake-query/a", "check", "suites/lake_query.py", severity="must"),
        _node("check:lake-query/b", "check", "suites/lake_query.py", severity="should"),
    ]
    e = [
        ("svc:lake-query", "cap:lake-query", "provides"),
        ("svc:secrets", "cap:secrets", "provides"),
        ("svc:lake-query", "mcp:lake", "exposes"),
        ("system:lake-query", "cap:lake-query", "resolves_to"),
        ("system:secrets", "cap:secrets", "resolves_to"),
        ("lesson:LL-010", "system:lake-query", "about"),
        ("lesson:LL-011", "system:lake-query", "about"),
        ("lesson:LL-012", "system:lake-query", "about"),
        ("runbook:RB-010", "svc:lake-query", "operates"),
        ("runbook:RB-010", "system:lake-query", "about"),
        ("runbook:RB-011", "system:secrets", "about"),
        ("runbook:RB-011", "lesson:LL-010", "mentions"),  # reachable at depth 2, ungranted
        ("doc:docs/lake-query.md", "cap:lake-query", "documents"),
        ("doc:docs/mixed.md", "cap:lake-query", "links"),
        ("doc:docs/mixed.md", "cap:secrets", "links"),  # one hop from a granted cap
        ("doc:docs/orphan.md", "doc:docs/lake-query.md", "links"),
        ("cap:lake-query", "check:lake-query/a", "checked_by"),
        ("cap:lake-query", "check:lake-query/b", "checked_by"),
    ]
    return Graph({n.id: n for n in nodes}, [Edge(s, d, t, "fake") for s, d, t in e])


@pytest.fixture
def root(tmp_path):
    for rel, text in FILES.items():
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text(text)
    return tmp_path


def profile_with(*rules, **changes):
    s = spec()
    s["include"] = list(rules)
    s.update(changes)
    return compile_profile(s, library())


RULE = {"from": "capabilities", "kinds": ["check", "doc", "lesson", "runbook"]}


def ids(sel):
    return [i["id"] for i in sel.included]


def reasons(sel):
    return {e["id"]: e["reason"] for e in sel.excluded}


# ------------------------------------------------------------------ the compiler


def test_no_include_means_no_include_key_and_no_knowledge():
    prof = compile_profile(spec(), library())
    assert "include" not in prof
    sel = select_knowledge(prof, fake_graph(), ".")
    assert sel.included == () and sel.excluded == ()


def test_include_is_normalised_into_the_profile_and_its_digest():
    prof = profile_with({**RULE, "kinds": ["runbook", "lesson", "runbook"]}, RULE)
    assert prof["include"] == [  # canonical order, defaults written
        {"budget": 12, "depth": 1, "from": "capabilities",
         "kinds": ["check", "doc", "lesson", "runbook"], "max_chars": 4000},
        {"budget": 12, "depth": 1, "from": "capabilities", "kinds": ["lesson", "runbook"],
         "max_chars": 4000},
    ]  # fmt: skip
    assert verify_profile(prof) == []
    assert prof["digest"] != compile_profile(spec(), library())["digest"]


@pytest.mark.parametrize(
    ("rule", "match"),
    [
        ({**RULE, "only": ["cap:secrets"]}, r"only names \['cap:secrets'\]"),
        ({**RULE, "only": ["cap:lake-query", "cap:records-propose"]}, "cap:records-propose"),
        ({"from": "mcp", "kinds": ["doc"], "only": ["records"]}, r"\['records'\]"),
    ],
)
def test_compiler_refuses_seeding_from_an_ungranted_thing(rule, match):
    with pytest.raises(IncludeViolation, match=match):
        profile_with(rule)


def test_compiler_refuses_a_grant_set_the_profile_does_not_hold():
    with pytest.raises(IncludeViolation, match="granted no mcp"):
        profile_with({"from": "mcp", "kinds": ["doc"]}, mcp=[])
    with pytest.raises(IncludeViolation, match="granted no capabilities"):
        profile_with({"from": "services", "kinds": ["runbook"]}, capabilities=[])


@pytest.mark.parametrize(
    "rule",
    [
        {"from": "registry", "kinds": ["doc"]},
        {"from": "capabilities", "kinds": ["svc"]},
        {"from": "capabilities", "kinds": []},
        {"from": "capabilities", "kinds": ["doc"], "depth": 4},
        {"from": "capabilities", "kinds": ["doc"], "budget": 0},
        {"from": "capabilities", "kinds": ["doc"], "require_reviews": ["approve"]},
        {"from": "task", "kinds": ["doc"], "only": ["cap:lake-query"]},
        {"from": "capabilities", "kinds": ["doc"], "grants": ["cap:secrets"]},
    ],
)
def test_compiler_refuses_a_malformed_rule(rule):
    with pytest.raises(SpecError):
        profile_with(rule)


def test_an_edited_profile_cannot_seed_from_an_ungranted_thing():
    prof = profile_with(RULE)
    bad = copy.deepcopy(prof)
    bad["include"][0]["only"] = ["cap:secrets"]
    bad["digest"] = profile_digest(bad)  # recomputed: the digest proves nothing here
    assert any("cap:secrets" in p for p in verify_profile(bad))
    with pytest.raises(IncludeViolation):
        select_knowledge(bad, fake_graph(), ".")
    stale = copy.deepcopy(prof)
    stale["include"][0]["depth"] = 3  # not recomputed
    with pytest.raises(SpecError, match="digest"):
        select_knowledge(stale, fake_graph(), ".")


def test_a_reader_gains_no_grant_through_include():
    """include adds knowledge, never a grant: a reader stays a reader."""
    plain = compile_profile(spec(), library())
    assert plain["reads_untrusted"] is True
    prof = profile_with(RULE, {"from": "task", "kinds": ["runbook"]})
    for key in ("grants", "parts", "ceiling", "reads_untrusted"):
        assert prof[key] == plain[key]
    with pytest.raises(IncludeViolation):  # it cannot even name an exec capability as a seed
        profile_with({**RULE, "only": ["cap:orchestration"]})
    lib = library({**PARTS, "cap:orchestration": "Run workflows."})
    s = spec()
    s["capabilities"] = ["cap:lake-query", "cap:orchestration"]
    s["ceiling"]["capabilities"].append("cap:orchestration")
    s["include"] = [{**RULE, "only": ["cap:orchestration"]}]
    with pytest.raises(ReaderViolation):  # granting it is still the reader rule's to refuse
        compile_profile(s, lib)
    pack, _ = start_session(
        manifest(),
        inputs(),
        prof,
        load(REPO / "examples" / "services.yml"),
        runs_on="runtime-core",
        knowledge=select_knowledge(prof, fake_graph(), "."),
    )
    plain_pack, _ = start_session(
        manifest(),
        inputs(),
        plain,
        load(REPO / "examples" / "services.yml"),
        runs_on="runtime-core",
    )
    assert pack["tools"] == plain_pack["tools"]
    access = next(s["text"] for s in pack["sections"] if s["name"] == "access")
    plain_access = next(s["text"] for s in plain_pack["sections"] if s["name"] == "access")
    assert access.split("\nprofile ")[0] == plain_access.split("\nprofile ")[0]


# ------------------------------------------------------------------ selection


def test_include_pulls_the_runbook_and_lesson_linked_to_a_granted_capability(root):
    sel = select_knowledge(profile_with(RULE), fake_graph(), root)
    # distance, then edge weight (documents 1.0 > about 0.7 > checked_by 0.5), then id
    assert ids(sel) == [
        "doc:docs/lake-query.md",
        "lesson:LL-010",
        "lesson:LL-011",
        "runbook:RB-010",
        "check:lake-query/a",
        "check:lake-query/b",
    ]
    lesson = next(i for i in sel.included if i["id"] == "lesson:LL-010")
    assert lesson["text"].endswith(FILES["lessons/LL-010.md"])  # the record itself, not a pointer
    assert "knowledge lesson:LL-010 (lesson)" in lesson["text"]
    assert "path: lessons/LL-010.md" in lesson["text"]
    assert "reviews: agent_check, audit, human" in lesson["text"]
    check = next(i for i in sel.included if i["id"] == "check:lake-query/a")
    assert 'severity: "must"' in check["text"]  # shared file: the node's own record
    assert "SUITE" not in check["text"]


def test_services_and_mcp_seed_only_granted_things(root):
    sel = select_knowledge(
        profile_with({"from": "services", "kinds": ["runbook"]}), fake_graph(), root
    )
    assert sel.seeds == (("svc:lake-query",),)
    assert ids(sel) == ["runbook:RB-010"]
    sel = select_knowledge(profile_with({"from": "mcp", "kinds": ["doc"]}), fake_graph(), root)
    assert sel.seeds == (("mcp:lake",),)


def test_a_node_about_an_ungranted_capability_one_hop_away_is_excluded(root):
    sel = select_knowledge(profile_with({**RULE, "depth": 2}), fake_graph(), root)
    why = reasons(sel)
    assert "doc:docs/mixed.md" not in ids(sel)
    assert why["doc:docs/mixed.md"] == "about what the profile is not granted: cap:secrets"
    assert "runbook:RB-011" not in ids(sel)  # reached through LL-010, about secrets
    assert why["runbook:RB-011"] == "about what the profile is not granted: cap:secrets"
    assert why["doc:docs/orphan.md"] == "not about anything the profile is granted"
    assert subjects(fake_graph(), "runbook:RB-010") == {"cap:lake-query", "svc:lake-query"}
    for text in (i["text"] for i in sel.included):
        assert "secrets" not in text


def _with(graph: Graph, nodes, edges) -> Graph:
    return Graph(
        {**graph.nodes, **{n.id: n for n in nodes}},
        [*graph.edges, *(Edge(s, d, t, "fake") for s, d, t in edges)],
    )


def test_a_tag_naming_a_product_reaches_the_services_that_run_it(root):
    """A lesson tagged ``lake-query`` and ``garage``: the garage tag resolves to the product, the
    product is run by the object-store service.  The profile holds lake-query only, so the lesson
    is about something ungranted and stays out."""
    g = _with(
        fake_graph(),
        [
            _node("system:garage", "system"),
            _node("product:garage", "product"),
            _node("svc:object-store", "svc"),
            _node("cap:object-store", "cap"),
            _node("lesson:LL-020", "lesson", "lessons/LL-010.md", reviewed=FULL),
        ],
        [
            ("lesson:LL-020", "system:lake-query", "about"),
            ("lesson:LL-020", "system:garage", "about"),
            ("system:garage", "product:garage", "resolves_to"),
            ("svc:object-store", "product:garage", "runs"),
            ("svc:object-store", "cap:object-store", "provides"),
        ],
    )
    assert subjects(g, "lesson:LL-020") == {"cap:lake-query", "svc:object-store"}
    sel = select_knowledge(profile_with(RULE), g, root)
    assert "lesson:LL-020" not in ids(sel)
    assert reasons(sel)["lesson:LL-020"] == (
        "about what the profile is not granted: svc:object-store"
    )


def test_a_proxy_that_resolves_to_nothing_grantable_fails_closed(root):
    """A product nothing registered runs (only a compose service with no capability): the tag is
    an ungranted subject, not a pass."""
    g = _with(
        fake_graph(),
        [
            _node("system:garage", "system"),
            _node("product:garage", "product"),
            _node("compose:lab/garage", "compose"),
            _node("lesson:LL-020", "lesson", "lessons/LL-010.md", reviewed=FULL),
        ],
        [
            ("lesson:LL-020", "system:lake-query", "about"),
            ("lesson:LL-020", "system:garage", "about"),
            ("system:garage", "product:garage", "resolves_to"),
            ("compose:lab/garage", "product:garage", "runs"),
        ],
    )
    assert subjects(g, "lesson:LL-020") == {"cap:lake-query", "system:garage"}
    sel = select_knowledge(profile_with(RULE), g, root)
    assert "lesson:LL-020" not in ids(sel)


def test_the_task_cannot_seed_an_ungranted_capability(root):
    rule = {"from": "task", "kinds": ["runbook", "lesson", "doc"]}
    sel = select_knowledge(
        profile_with(rule),
        fake_graph(),
        root,
        task_text="the secrets store, cap:secrets and runbook:RB-011 and lesson:LL-010",
    )
    why = reasons(sel)
    assert "cap:secrets" in why and "not a seed" in why["cap:secrets"]
    assert "svc:secrets" in why
    assert "runbook:RB-011" not in ids(sel) and "cap:secrets" in why["runbook:RB-011"]
    assert "lesson:LL-010" in ids(sel)  # named, and about a granted capability


def test_inactive_records_never_enter(root):
    rule = {"from": "task", "kinds": ["lesson"], "depth": 3}
    for prof, text in ((profile_with(RULE), ""), (profile_with(rule), "lesson:LL-012 lake-query")):
        sel = select_knowledge(prof, fake_graph(), root, task_text=text)
        assert "lesson:LL-012" not in ids(sel)
        assert "inactive" in reasons(sel).get("lesson:LL-012", "inactive")


def test_require_reviews_filters_records_only(root):
    sel = select_knowledge(profile_with({**RULE, "require_reviews": ["audit"]}), fake_graph(), root)
    assert "lesson:LL-011" not in ids(sel)
    assert reasons(sel)["lesson:LL-011"] == "reviews: no current audit (has: agent_check)"
    assert "lesson:LL-010" in ids(sel) and "check:lake-query/a" in ids(sel)  # not a record


def test_the_deprecated_tier_challenge_compiles_to_audit_with_a_warning(root):
    from homelabnext.reviews import DeprecatedReviewRole

    with pytest.warns(DeprecatedReviewRole, match="require_reviews"):
        prof = profile_with({**RULE, "require_reviews": ["challenge", "agent_check"]})
    assert prof["include"][0]["require_reviews"] == ["agent_check", "audit"]
    assert verify_profile(prof) == []
    # a profile written before the rename still selects as if it said audit
    old = copy.deepcopy(profile_with({**RULE, "require_reviews": ["audit"]}))
    old["include"][0]["require_reviews"] = ["challenge"]
    old["digest"] = profile_digest(old)
    with pytest.warns(DeprecatedReviewRole):  # the pack build re-checks the rules
        sel = select_knowledge(old, fake_graph(), root)
    assert reasons(sel)["lesson:LL-011"] == "reviews: no current audit (has: agent_check)"


def _ll010(author: str, edit_after_review: bool = False) -> Graph:
    """The fake graph with LL-010's ``reviewed`` built by the registers reader from a record that
    an agent checked and another audited (against its content as written, then maybe edited)."""
    rec = {"id": "LL-010", "title": "Lake queries time out", "kind": "pitfall", "author": author}
    digest = record_digest_of(rec)
    rec["reviews"] = [
        {"by": f"agent:fake-{who}", "kind": "agent", "role": role, "date": "2026-01-02",
         "verdict": "pass", "digest": digest}
        for who, role in (("checker", "check"), ("auditor", "audit"))
    ]  # fmt: skip
    if edit_after_review:
        rec["title"] += " (edited after review)"
    g = fake_graph()
    node = g.nodes["lesson:LL-010"]
    attrs = {k: v for k, v in node.attrs.items() if k != "reviewed"}
    attrs.update({k: v for k, v in _provenance(rec).items() if v is not None})
    return Graph({**g.nodes, node.id: Node(node.id, node.kind, node.title, node.path, attrs)},
                 list(g.edges))  # fmt: skip


@pytest.mark.parametrize(
    ("author", "edited", "has"),
    [
        ("agent:fake-author", False, None),  # current, independent: included
        ("agent:fake-author", True, "none"),  # content changed after the reviews
        ("agent:fake-checker", False, "audit"),  # the checker reviewed its own lesson
    ],
)
def test_require_reviews_trusts_only_current_valid_reviews(root, author, edited, has):
    """``require_reviews`` reads the graph's ``reviewed``, which drops a review of an earlier
    content and a self-review, so neither can satisfy it."""
    prof = profile_with({**RULE, "require_reviews": ["agent_check", "audit"]})
    sel = select_knowledge(prof, _ll010(author, edited), root)
    if has is None:
        assert "lesson:LL-010" in ids(sel)
    else:
        assert "lesson:LL-010" not in ids(sel)
        assert reasons(sel)["lesson:LL-010"].endswith(f"(has: {has})")


def test_another_rule_may_include_what_one_excluded(root):
    strict = {**RULE, "require_reviews": ["audit"]}
    sel = select_knowledge(
        profile_with(strict, {"from": "task", "kinds": ["lesson"]}),
        fake_graph(),
        root,
        task_text="lesson:LL-011",
    )
    assert "lesson:LL-011" in ids(sel) and "lesson:LL-011" not in reasons(sel)


def test_budget_truncates_by_rank_deterministically(root):
    sel = select_knowledge(profile_with({**RULE, "budget": 2}), fake_graph(), root)
    assert ids(sel) == ["doc:docs/lake-query.md", "lesson:LL-010"]
    over = [e["id"] for e in sel.excluded if e["reason"].startswith("over budget")]
    assert over == ["check:lake-query/a", "check:lake-query/b", "lesson:LL-011", "runbook:RB-010"]
    g = fake_graph()
    shuffled = Graph(dict(reversed(g.nodes.items())), list(reversed(g.edges)))
    again = select_knowledge(profile_with({**RULE, "budget": 2}), shuffled, root)
    assert again.record() == sel.record()


def test_unreadable_content_and_escaping_paths_are_excluded(root):
    (root / "docs/lake-query.md").unlink()
    g = fake_graph()
    g.nodes["lesson:LL-010"] = _node("lesson:LL-010", "lesson", "../outside.md", reviewed=FULL)
    (root.parent / "outside.md").write_text("outside the checkout")
    sel = select_knowledge(profile_with(RULE), Graph(g.nodes, g.edges), root)
    assert reasons(sel)["doc:docs/lake-query.md"] == "content unreadable: docs/lake-query.md"
    assert reasons(sel)["lesson:LL-010"] == "content unreadable: ../outside.md"


# ------------------------------------------------------------------ the pack


def _pack(prof, root, **kw):
    sel = select_knowledge(prof, fake_graph(), root, **kw)
    return assemble_pack(manifest(), inputs(), knowledge=sel)


def test_pack_carries_the_content_in_rank_order_and_a_manifest(root):
    m = manifest()
    m["budget_chars"] = 20000
    prof = profile_with(RULE)
    sel = select_knowledge(prof, fake_graph(), root)
    pack, _ = assemble_pack(m, inputs(), knowledge=sel)
    names = [s["name"] for s in pack["sections"] if s["name"].startswith("knowledge-")]
    assert names[:2] == ["knowledge-001-doc-docs-lake-query.md", "knowledge-002-lesson-LL-010"]
    sec = next(s for s in pack["sections"] if s["name"] == "knowledge-002-lesson-LL-010")
    assert sec["tier"] == "volatile" and FILES["lessons/LL-010.md"].strip() in sec["text"]
    assert "Lake queries time out" in pack["text"]
    k = pack["knowledge"]
    assert [i["id"] for i in k["included"]] == ids(sel)
    assert all(i["digest"].startswith("sha256:") and "text" not in i for i in k["included"])
    assert {e["id"] for e in k["excluded"]} >= {"doc:docs/mixed.md", "lesson:LL-012"}
    assert k["profile_digest"] == prof["digest"] and k["graph_digest"].startswith("sha256:")
    assert "knowledge" not in assemble_pack(m, inputs())[0]  # no selection, no change


def test_pack_is_byte_identical_for_the_same_profile_repo_and_task(root):
    prof = profile_with(RULE, {"from": "task", "kinds": ["lesson"]})
    a = _pack(prof, root, task_text="lesson:LL-011", task_paths=["docs/lake-query.md"])
    b = _pack(
        copy.deepcopy(prof), root, task_text="lesson:LL-011", task_paths=["docs/lake-query.md"]
    )
    assert a[1] == b[1]
    assert json.dumps(a[0], sort_keys=True) == json.dumps(b[0], sort_keys=True)
    c = _pack(prof, root, task_text="lesson:LL-010")
    assert c[1] != a[1]
    (root / "lessons/LL-010.md").write_text("changed\n")
    assert (
        _pack(prof, root, task_text="lesson:LL-011", task_paths=["docs/lake-query.md"])[1] != a[1]
    )


def test_knowledge_is_cut_first_lowest_rank_first(root):
    m = manifest()
    m["budget_chars"] = 1500
    pack, _ = assemble_pack(m, inputs(), knowledge=select_knowledge(
        profile_with(RULE), fake_graph(), root))  # fmt: skip
    dropped = [t["section"] for t in pack["truncations"] if t["reason"] == "budget-drop"]
    assert dropped and all(d.startswith("knowledge-") for d in dropped)
    kept = [s["name"] for s in pack["sections"] if s["name"].startswith("knowledge-")]
    assert all(k < d for k in kept for d in dropped)
    assert {"findings", "memory", "charter"} <= {s["name"] for s in pack["sections"]}


def test_the_knowledge_prefix_is_reserved_and_selection_bound_to_its_profile(root):
    m = manifest()
    m["sections"][0]["name"] = "knowledge-001-fake"
    with pytest.raises(SpecError, match="reserved"):
        assemble_pack(m, inputs())
    other = profile_with(RULE)
    sel = select_knowledge(
        profile_with(RULE, {"from": "task", "kinds": ["doc"]}), fake_graph(), root
    )
    with pytest.raises(SpecError, match="selected for"):
        start_session(
            manifest(), inputs(), other, load(REPO / "examples" / "services.yml"),
            runs_on="runtime-core", knowledge=sel,
        )  # fmt: skip


def test_explain_lists_included_and_excluded_with_reasons(root):
    text = explain(select_knowledge(profile_with({**RULE, "depth": 2}), fake_graph(), root))
    assert "included (" in text and "lesson:LL-010" in text
    assert "doc:docs/mixed.md  rule 0: about what the profile is not granted: cap:secrets" in text


# ------------------------------------------------------------------ the CLI on the real graph


def test_cli_explain_on_the_repository_graph(tmp_path, capsys):
    lib = {"persona:analyst": "Analyse.", "skill:triage": "Rank.", "cap:backup": "Backup."}
    for lid, text in lib.items():
        (tmp_path / (lid.replace(":", "-") + ".md")).write_text(text)
    (tmp_path / "library.yml").write_text(
        yaml.safe_dump({"parts": {lid: lid.replace(":", "-") + ".md" for lid in lib}})
    )
    s = spec()
    s.update(
        id="profile:backup-actor",
        skills=["skill:triage"],
        capabilities=["cap:backup"],
        mcp=[],
        reads_untrusted=False,
        include=[
            {"from": "capabilities", "kinds": ["lesson", "runbook", "check"], "budget": 3},
            {"from": "task", "kinds": ["lesson", "runbook"]},
        ],
    )
    s["ceiling"].update(capabilities=["cap:backup"], mcp=[])
    (tmp_path / "spec.yml").write_text(yaml.safe_dump(s))
    m = manifest()
    m["budget_chars"] = 20000
    (tmp_path / "manifest.json").write_text(json.dumps(m))
    (tmp_path / "inputs.json").write_text(json.dumps(inputs()))
    prof = tmp_path / "profile.json"
    assert cli.main(["agent", "compile", str(tmp_path / "spec.yml"), "--library",
                     str(tmp_path / "library.yml"), "--out", str(prof)]) == 0  # fmt: skip
    argv = [
        "agent", "pack", str(tmp_path / "manifest.json"), "--inputs", str(tmp_path / "inputs.json"),
        "--profile", str(prof), "--registry", str(REPO / "examples" / "services.yml"),
        "--runs-on", "runtime-core", "--root", str(REPO),
        "--task-text", "the backup job skipped a guest; also check the secrets service",
    ]  # fmt: skip
    capsys.readouterr()
    assert cli.main([*argv, "--explain"]) == 0
    out = capsys.readouterr().out
    assert "lesson:LL-003" in out.split("excluded (")[0]
    assert "cap:secrets  rule 0: task names cap:secrets" in out
    assert "over budget" in out
    assert cli.main([*argv, "--out", str(tmp_path / "pack.json")]) == 0
    pack = json.loads((tmp_path / "pack.json").read_text())["pack"]
    assert "lesson:LL-003" in [i["id"] for i in pack["knowledge"]["included"]]
    assert "Backup job silently skipped a new guest" in pack["text"]
    assert cli.main(["agent", "pack", str(tmp_path / "manifest.json"), "--inputs",
                     str(tmp_path / "inputs.json"), "--explain"]) == 1  # fmt: skip
