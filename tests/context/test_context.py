# SPDX-License-Identifier: Apache-2.0
"""The reference context store: the conformance suite on it, its rules, and the repository index."""

from __future__ import annotations

from pathlib import Path

import pytest

from homelabnext.conform.runner import mutation_runs, run_capability
from homelabnext.context import (
    ContextStore,
    Document,
    InvalidDocument,
    InvalidQuery,
    NotFound,
    Query,
    check_query,
    digest,
    documents_from_graph,
    in_scope,
    repo_store,
)
from homelabnext.graph import Graph, Node
from homelabnext.identity.aliases import load_aliases

ROOT = Path(__file__).resolve().parents[2]


def _q(allowed, **kw):
    return Query(allowed=frozenset(allowed), **kw)


# -- the suite ------------------------------------------------------------------------------------


def test_reference_store_passes_the_suite():
    run = run_capability("context", "context-reference", ROOT)
    assert run.error is None and run.too_few is None
    assert not run.failed_must and not run.failed_should, [r.evidence for r in run.results]


def test_every_context_mutant_is_caught():
    runs = mutation_runs("context", ROOT)
    assert {m.name for m in runs} >= {
        "scope-blind",
        "loose-prefix",
        "inactive-leak",
        "hidden-bridge",
        "stale-copy",
        "shuffled-ties",
    }
    assert all(m.detected for m in runs), [(m.name, m.reason) for m in runs if not m.detected]


# -- contract rules -------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("doc_id", "allowed", "want"),
    [
        ("lesson:LL-1", {"lesson:"}, True),
        ("lesson:LL-1", {"lesson:LL-1"}, True),
        ("lesson:LL-10", {"lesson:LL-1"}, False),
        ("doc:docs/a.md", {"doc:docs/"}, True),
        ("doc:docs-old/a.md", {"doc:docs/"}, False),
        ("lessons:x", {"lesson:"}, False),
        ("lesson:x", set(), False),
    ],
)
def test_in_scope(doc_id, allowed, want):
    assert in_scope(doc_id, allowed) is want


@pytest.mark.parametrize(
    "bad",
    [
        {"allowed": "doc:"},
        {"allowed": None},
        {"allowed": {"*"}},
        {"allowed": {""}},
        {"allowed": {"doc"}},
        {"allowed": {":x"}},
        {"allowed": {"doc:", 3}},
        {"allowed": {"doc:"}, "budget": -1},
        {"allowed": {"doc:"}, "budget": True},
        {"allowed": {"doc:"}, "text": b"bytes"},
        {"allowed": {"doc:"}, "text": "x" * 20_000},
        {"allowed": {"doc:"}, "seeds": "doc:a"},
        {"allowed": {"doc:"}, "seeds": ("doc:a", 1)},
        {"allowed": {"doc:"}, "kinds": "doc"},
        {"allowed": {"doc:"}, "include_inactive": "yes"},
    ],
)
def test_check_query_refuses(bad):
    with pytest.raises(InvalidQuery) as exc:
        check_query(Query(**bad))
    assert "x" * 100 not in str(exc.value)


def test_check_query_refuses_non_query():
    with pytest.raises(InvalidQuery):
        check_query({"allowed": {"doc:"}})  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "batch",
    [
        "doc:a",
        [Document("doc:a", "doc", "x"), Document("doc:a", "doc", "y")],
        [Document("no-colon", "doc", "x")],
        [Document("doc:with space", "doc", "x")],
        [Document("doc:*", "doc", "x")],
        [Document("doc:a", "", "x")],
        [Document("doc:a", "doc", b"x")],  # type: ignore[arg-type]
        [Document("doc:a", "doc", "x", title=None)],  # type: ignore[arg-type]
        [Document("doc:a", "doc", "x", links="doc:b")],  # type: ignore[arg-type]
        [{"id": "doc:a"}],
    ],
)
def test_index_refuses_bad_batches_atomically(batch):
    s = ContextStore()
    with pytest.raises(InvalidDocument):
        s.index([Document("doc:ok", "doc", "fine"), *batch] if isinstance(batch, list) else batch)
    with pytest.raises(NotFound):
        s.get("doc:ok", frozenset({"doc:"}))


def test_oversized_document_refused(monkeypatch):
    import homelabnext.context.model as model

    monkeypatch.setattr(model, "MAX_CONTENT_CHARS", 10)
    with pytest.raises(InvalidDocument):
        ContextStore().index([Document("doc:a", "doc", "x" * 11)])


def test_delete_unknown_and_get_non_string():
    s = ContextStore()
    with pytest.raises(NotFound):
        s.delete("doc:none")
    with pytest.raises(NotFound):
        s.get(3, frozenset({"doc:"}))  # type: ignore[arg-type]


def test_budget_zero_and_punctuation_only_text_return_nothing():
    s = ContextStore()
    s.index([Document("doc:a", "doc", "alpha")])
    assert s.query(_q({"doc:"}, text="alpha", budget=0)) == []
    assert s.query(_q({"doc:"}, text="!!! ---")) == []


def test_seed_that_links_to_itself_and_unknown_links():
    s = ContextStore()
    s.index([Document("doc:a", "doc", "alpha", links=("doc:a", "doc:missing"))])
    assert [h.id for h in s.query(_q({"doc:"}, seeds=("doc:a",)))] == ["doc:a"]


# -- the repository index -------------------------------------------------------------------------


@pytest.fixture(scope="module")
def repo():
    return repo_store(ROOT)


def test_capability_page_is_next_to_its_seed(repo):
    hits = repo.query(
        _q({"doc:", "cap:"}, text="secret lease expiry", seeds=("cap:secrets",), budget=5)
    )
    ids = [h.id for h in hits]
    assert ids[0] == "cap:secrets"
    assert "doc:docs/capabilities/secrets.md" in ids[:3]
    page = next(h for h in hits if h.id == "doc:docs/capabilities/secrets.md")
    text = (ROOT / "docs/capabilities/secrets.md").read_text(encoding="utf-8")
    assert page.content == text and page.digest == digest(text)


def test_retired_lessons_need_include_inactive(repo):
    hits = repo.query(_q({"lesson:"}, text="lesson", budget=50))
    statuses = {h.id for h in hits}
    ll2 = "lesson:" + load_aliases(ROOT / "examples/registers").codes["LL-002"]
    assert ll2 not in statuses  # retired in the example register
    every = repo.query(_q({"lesson:"}, text="lesson", budget=50, include_inactive=True))
    assert ll2 in {h.id for h in every}


def test_repo_scope_holds(repo):
    hits = repo.query(_q({"runbook:"}, text="lesson certificate proxy", budget=50))
    assert hits and all(h.id.startswith("runbook:") for h in hits)
    assert repo.query(_q(set(), text="lesson certificate proxy")) == []


def test_repo_index_is_deterministic(repo):
    again = repo_store(ROOT)
    q = _q(
        {"doc:", "cap:", "lesson:"}, text="conformance mutants", seeds=("cap:notify",), budget=20
    )
    assert [(h.id, h.score) for h in repo.query(q)] == [(h.id, h.score) for h in again.query(q)]


def test_documents_from_graph_content_rules(tmp_path):
    (tmp_path / "page.md").write_text("# Page\n\nbody\n", encoding="utf-8")
    (tmp_path / "shared.yml").write_text("rows: []\n", encoding="utf-8")
    (tmp_path / "big.md").write_text("x" * 50, encoding="utf-8")
    nodes = {
        "doc:page.md": Node("doc:page.md", "doc", "Page", "page.md"),
        "inv:A": Node("inv:A", "inv", "A holds", "shared.yml", {"status": "pass"}),
        "inv:B": Node("inv:B", "inv", "B holds", "shared.yml"),
        "doc:escape.md": Node("doc:escape.md", "doc", "Out", "../outside.md"),
        "cap:x": Node("cap:x", "cap"),
    }
    from homelabnext.graph import Edge

    g = Graph(
        nodes, [Edge("doc:page.md", "cap:x", "documents", "t"), Edge("cap:x", "zz", "t", "t")]
    )
    docs = {d.id: d for d in documents_from_graph(g, tmp_path)}
    assert docs["doc:page.md"].content == "# Page\n\nbody\n"
    assert docs["doc:page.md"].links == ("cap:x",)
    assert docs["cap:x"].links == ()  # an edge to a node the graph lacks is dropped
    assert docs["inv:A"].content.startswith("A holds\nid: inv:A\n") and 'status: "pass"' in (
        docs["inv:A"].content
    )
    assert docs["inv:A"].status == "pass"
    assert "Out" in docs["doc:escape.md"].content  # outside the root: summarised, never read
    assert docs["cap:x"].content.startswith("cap:x\n")


def test_documents_from_graph_skips_oversized_files(tmp_path, monkeypatch):
    import homelabnext.context.repo as repo_mod

    (tmp_path / "big.md").write_text("x" * 50, encoding="utf-8")
    monkeypatch.setattr(repo_mod, "MAX_CONTENT_CHARS", 10)
    g = Graph({"doc:big.md": Node("doc:big.md", "doc", "Big", "big.md")}, [])
    (doc,) = documents_from_graph(g, tmp_path)
    assert doc.content.startswith("Big\n")
