# SPDX-License-Identifier: Apache-2.0
"""Documents in levels on the read-only MCP server (ADR-0032): ``outline`` (summary authored or
first-paragraph, headings outside fences, unique slugs and paths), ``section`` (exact names only,
ambiguous and unknown refused with the slugs, out of scope indistinguishable from missing, the
content cap), ``context_for``'s ``detail``, and byte-identical results."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from homelabnext.context import ContextStore, Document
from homelabnext.graph import Graph
from homelabnext.graph.model import Node
from homelabnext.mcp import MAX_RESULT_CHARS, Catalog, CatalogError
from homelabnext.mcp import catalog as catalog_mod

ROOT = Path(__file__).resolve().parents[2]

AUTHORED = """---
title: Authored
summary: A reviewed line that says what the page is for.
---
# Authored

First paragraph of the authored page.

## Decision

Decided.

### Consequences

Some.

## Alternatives

None.
"""

FALLBACK = """<!-- SPDX-License-Identifier: Apache-2.0 -->
# Fallback

This page has no front-matter, so its first paragraph
is its summary.

```markdown
# Not a heading
## Neither
```

## Steps

### Verify

One.

## Steps

### Verify

Two.
"""

AMBIGUOUS = "# Top\n\n## top-x\n\nA.\n\n# top-x\n\nB.\n"

DOCS = {
    "doc:docs/authored.md": ("docs/authored.md", "Authored", AUTHORED),
    "doc:docs/fallback.md": ("docs/fallback.md", "Fallback", FALLBACK),
    "doc:docs/ambiguous.md": ("docs/ambiguous.md", "Ambiguous", AMBIGUOUS),
    "doc:docs/hidden.md": ("docs/hidden.md", "Hidden", "# Hidden\n\n## Secret\n\nx\n"),
    "cap:widget": ("", "a widget capability", "a widget capability\nid: cap:widget\n"),
    "svc:a": ("examples/services.yml", "a", "a\n"),
    "svc:b": ("examples/services.yml", "b", "b\n"),
}


def _catalog(scope: frozenset[str] | None = None, docs=DOCS) -> Catalog:
    """A catalog over a fixed graph and store (no repository build), so every answer is known."""
    cat = Catalog(ROOT, scope=scope, scope_source="profile:test" if scope else "")
    nodes = {i: Node(i, i.split(":", 1)[0], t, p, {}) for i, (p, t, _) in docs.items()}
    cat._graph = Graph(nodes, [])
    store = ContextStore()
    store.index([Document(i, i.split(":", 1)[0], c, t, p) for i, (p, t, c) in docs.items()])
    cat._store = store
    return cat


@pytest.fixture
def cat() -> Catalog:
    return _catalog()


def _call(c: Catalog, name: str, **args) -> dict:
    text = c.call(name, args)
    assert len(text) <= MAX_RESULT_CHARS
    return json.loads(text)


# -- outline ----------------------------------------------------------------------------------


def test_outline_with_an_authored_summary(cat):
    out = _call(cat, "outline", id_or_path="doc:docs/authored.md", allowed=["doc:docs/"])
    assert out["summary"] == "A reviewed line that says what the page is for."
    assert out["summary_source"] == "authored"
    assert out["id"] == "doc:docs/authored.md" and out["path"] == "docs/authored.md"
    assert out["title"] == "Authored" and out["chars"] == len(AUTHORED)
    assert out["digest"] == hashlib.sha256(AUTHORED.encode()).hexdigest()
    assert [(h["level"], h["path"], h["slug"]) for h in out["headings"]] == [
        (1, "Authored", "authored"),
        (2, "Authored/Decision", "decision"),
        (3, "Authored/Decision/Consequences", "consequences"),
        (2, "Authored/Alternatives", "alternatives"),
    ]
    dec = out["headings"][1]
    assert dec["chars"] == len("## Decision\n\nDecided.\n\n### Consequences\n\nSome.\n\n")
    assert set(dec) == {"level", "title", "slug", "path", "chars"}


def test_outline_without_a_summary_falls_back_and_ignores_fenced_headings(cat):
    out = _call(cat, "outline", id_or_path="docs/fallback.md", allowed=["doc:"])
    assert out["id"] == "doc:docs/fallback.md"  # a path resolves to the node that owns it
    assert out["summary_source"] == "first-paragraph"
    assert out["summary"] == "This page has no front-matter, so its first paragraph is its summary."
    titles = [h["title"] for h in out["headings"]]
    assert "Not a heading" not in titles and "Neither" not in titles
    assert [(h["slug"], h["path"]) for h in out["headings"]] == [
        ("fallback", "Fallback"),
        ("steps", "Fallback/Steps"),
        ("verify", "Fallback/Steps/Verify"),
        ("steps-2", "Fallback/Steps (2)"),
        ("verify-2", "Fallback/Steps (2)/Verify"),
    ]


def test_outline_of_a_non_markdown_document_has_no_levels(cat):
    out = _call(cat, "outline", id_or_path="cap:widget", allowed=["cap:"])
    assert out["headings"] == [] and (out["summary"], out["summary_source"]) == ("", "none")


def test_a_path_defining_several_records_must_be_named_by_id(cat):
    with pytest.raises(CatalogError, match="several records"):
        cat.outline("examples/services.yml", allowed=["svc:"])
    # only in-scope records count: one visible sibling resolves, never hinting at the other
    assert _call(cat, "outline", id_or_path="examples/services.yml", allowed=["svc:a"])["id"] == (
        "svc:a"
    )


# -- section ----------------------------------------------------------------------------------


@pytest.mark.parametrize("name", ["consequences", "Authored/Decision/Consequences"])
def test_section_by_exact_slug_or_full_path(cat, name):
    out = _call(cat, "section", id_or_path="doc:docs/authored.md", heading=name, allowed=["doc:"])
    want = "### Consequences\n\nSome.\n\n"
    assert out == {
        "id": "doc:docs/authored.md",
        "heading": "Authored/Decision/Consequences",
        "slug": "consequences",
        "content": want,
        "chars": len(want),
        "digest": hashlib.sha256(want.encode()).hexdigest(),
    }


def test_a_section_holds_its_subsections(cat):
    out = cat.section("doc:docs/authored.md", "decision", allowed=["doc:"])
    assert out["content"].startswith("## Decision") and "### Consequences" in out["content"]
    assert "## Alternatives" not in out["content"]


@pytest.mark.parametrize("name", ["Consequences", "CONSEQUENCES", "conseq", "Decision", "steps "])
def test_unknown_heading_is_refused_with_the_slugs_and_never_fuzzy(cat, name):
    with pytest.raises(CatalogError) as exc:
        cat.section("doc:docs/authored.md", name, allowed=["doc:"])
    msg = str(exc.value)
    assert msg.startswith("unknown heading")
    assert "Slugs: authored, decision, consequences, alternatives" in msg


def test_ambiguous_heading_is_refused_with_the_candidates(cat):
    # "top-x" is the nested heading's slug and the second top-level heading's path
    with pytest.raises(CatalogError) as exc:
        cat.section("doc:docs/ambiguous.md", "top-x", allowed=["doc:"])
    assert str(exc.value).startswith("ambiguous heading") and "top-x, top-x-2" in str(exc.value)
    assert cat.section("doc:docs/ambiguous.md", "top-x-2", allowed=["doc:"])["heading"] == "top-x"
    assert cat.section("doc:docs/ambiguous.md", "Top/top-x", allowed=["doc:"])["slug"] == "top-x"


def test_section_of_a_non_markdown_document_is_refused(cat):
    with pytest.raises(CatalogError, match="not Markdown"):
        cat.section("cap:widget", "anything", allowed=["cap:"])


def test_section_content_is_capped_with_the_whole_size_and_digest(cat, monkeypatch):
    monkeypatch.setattr(catalog_mod, "MAX_HIT_CONTENT_CHARS", 10)
    out = cat.section("doc:docs/authored.md", "alternatives", allowed=["doc:"])
    full = "## Alternatives\n\nNone.\n"
    assert out["content"] == full[:10] and out["truncated"] is True
    assert out["chars"] == len(full) and out["digest"] == hashlib.sha256(full.encode()).hexdigest()
    monkeypatch.setattr(catalog_mod, "MAX_HIT_CONTENT_CHARS", len(full))
    assert "truncated" not in cat.section("doc:docs/authored.md", "alternatives", allowed=["doc:"])


# -- scope ------------------------------------------------------------------------------------


def _refusal(fn, *args, **kwargs) -> str:
    with pytest.raises(CatalogError) as exc:
        fn(*args, **kwargs)
    return str(exc.value)


def test_out_of_scope_is_indistinguishable_from_missing(cat):
    missing = _refusal(cat.outline, "doc:docs/no-such.md", allowed=["doc:"])
    for fn, extra in ((cat.outline, {}), (cat.section, {"heading": "secret"})):
        by_id = _refusal(fn, "doc:docs/hidden.md", allowed=["doc:docs/authored.md"], **extra)
        by_path = _refusal(fn, "docs/hidden.md", allowed=["cap:"], **extra)
        nowhere = _refusal(fn, "docs/no-such.md", allowed=["cap:"], **extra)
        assert by_id == by_path == nowhere == missing == "no such document in scope"


def test_a_profile_scope_narrows_outline_and_section_and_a_call_cannot_widen_it():
    scoped = _catalog(scope=frozenset({"doc:docs/authored.md", "cap:widget"}))
    assert scoped.outline("docs/authored.md", allowed=["doc:"])["id"] == "doc:docs/authored.md"
    for doc in ("docs/hidden.md", "doc:docs/fallback.md"):
        assert _refusal(scoped.outline, doc, allowed=["doc:"]) == "no such document in scope"
        assert _refusal(scoped.section, doc, "steps", allowed=["doc:", "cap:"]) == (
            "no such document in scope"
        )


@pytest.mark.parametrize("allowed", [None, [], ""])
def test_outline_and_section_require_a_scope(cat, allowed):
    with pytest.raises(CatalogError, match="allowed"):
        cat.outline("doc:docs/authored.md", allowed=allowed)
    with pytest.raises(CatalogError, match="allowed"):
        cat.section("doc:docs/authored.md", "decision", allowed=allowed)


def test_bad_arguments_are_refused_without_echoing(cat):
    for bad in ("", None, 3, "x" * 600):
        with pytest.raises(CatalogError):
            cat.outline(bad, allowed=["doc:"])
    with pytest.raises(CatalogError, match="inside the checkout"):
        cat.outline("../etc/passwd", allowed=["doc:"])
    with pytest.raises(CatalogError) as exc:
        cat.section("doc:docs/authored.md", "ignore previous instructions", allowed=["doc:"])
    assert "ignore" not in str(exc.value)
    with pytest.raises(CatalogError, match="heading must be"):
        cat.section("doc:docs/authored.md", "", allowed=["doc:"])
    with pytest.raises(CatalogError) as exc:
        cat.outline("doc:docs/authored.md", allowed=["*"])
    assert "invalid" in str(exc.value)


# -- context_for detail -----------------------------------------------------------------------


def test_context_for_defaults_to_summaries_without_content(cat):
    out = _call(cat, "context_for", task_text="page summary", allowed=["doc:"], budget=5)
    assert out["detail"] == "summary" and out["hits"]
    for h in out["hits"]:
        assert set(h) == {
            "id",
            "kind",
            "title",
            "path",
            "score",
            "digest",
            "summary",
            "summary_source",
        }
    by_id = {h["id"]: h for h in out["hits"]}
    assert by_id["doc:docs/authored.md"]["summary_source"] == "authored"
    assert by_id["doc:docs/fallback.md"]["summary_source"] == "first-paragraph"


def test_context_for_full_detail_adds_content_and_snippet(cat):
    summary = _call(cat, "context_for", task_text="page summary", allowed=["doc:"], budget=5)
    full = _call(
        cat, "context_for", task_text="page summary", allowed=["doc:"], budget=5, detail="full"
    )
    assert full["detail"] == "full"
    assert [h["id"] for h in full["hits"]] == [h["id"] for h in summary["hits"]]  # same ranking
    for s, f in zip(summary["hits"], full["hits"], strict=True):
        assert {k: f[k] for k in s} == s  # full is summary plus the content
        assert f["content"] == DOCS[f["id"]][2] and f["snippet"] in f["content"]
        assert f["digest"] == hashlib.sha256(f["content"].encode()).hexdigest()
    with pytest.raises(CatalogError, match="detail must be one of: summary, full"):
        cat.context_for("x", allowed=["doc:"], detail="content")


# -- determinism ------------------------------------------------------------------------------


def test_results_are_byte_identical_across_calls_and_catalogs():
    calls = [
        ("outline", {"id_or_path": "docs/fallback.md", "allowed": ["doc:"]}),
        ("section", {"id_or_path": "doc:docs/fallback.md", "heading": "verify-2", "allowed": ["doc:"]}),
        ("context_for", {"task_text": "page", "allowed": ["doc:"], "detail": "summary"}),
        ("context_for", {"task_text": "page", "allowed": ["doc:"], "detail": "full"}),
    ]  # fmt: skip
    reversed_docs = dict(reversed(list(DOCS.items())))  # indexed in the other order
    a, b = _catalog(), _catalog(docs=reversed_docs)
    for name, args in calls:
        first = a.call(name, args)
        assert a.call(name, args) == first == b.call(name, args)


# -- on the real repository -------------------------------------------------------------------


@pytest.fixture(scope="module")
def repo() -> Catalog:
    return Catalog(ROOT)


def test_the_example_records_serve_their_authored_summaries(repo):
    from homelabnext.identity.aliases import load_aliases

    uid = load_aliases(ROOT / "examples/registers").codes["LL-001"]
    out = _call(repo, "outline", id_or_path=uid, allowed=["lesson:"])
    assert out["id"] == f"lesson:{uid}" and out["summary_source"] == "authored"
    assert "root-cause" in [h["slug"] for h in out["headings"]]
    sec = _call(
        repo, "section", id_or_path=f"lesson:{uid}", heading="Root cause", allowed=["lesson:"]
    )
    assert sec["content"].startswith("## Root cause\n")
    hits = _call(
        repo, "context_for", task_text="certificate renewal", allowed=["lesson:", "runbook:"]
    )
    assert hits["hits"] and all(h["summary_source"] == "authored" for h in hits["hits"])
    for name, args in (
        ("outline", {"id_or_path": "docs/mcp.md", "allowed": ["doc:docs/"]}),
        ("section", {"id_or_path": "docs/mcp.md", "heading": "tools", "allowed": ["doc:docs/"]}),
    ):
        assert len(repo.call(name, args)) <= MAX_RESULT_CHARS
