# SPDX-License-Identifier: Apache-2.0
"""Per-system SOP pages: prefill, regeneration keeps human text, missing/orphan/stale detection."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from homelabnext.cli import COMMANDS
from homelabnext.registry.model import load
from homelabnext.reviews import load_policy
from homelabnext.sop import SECTIONS, check_pages, generate_pages, render_page, render_template
from homelabnext.sop.cli import main
from homelabnext.sop.pages import page_digest, refresh_page

ROOT = Path(__file__).resolve().parents[2]
REGISTRY = ROOT / "examples" / "services.yml"


@pytest.fixture
def reg():
    return load(REGISTRY)


def test_one_page_per_row_with_prefilled_facts(reg, tmp_path):
    res = generate_pages(reg, tmp_path)
    assert len(res.created) == len(reg.services)
    page = (tmp_path / "lake-query.md").read_text()
    assert page.startswith("---\n") and "service: lake-query" in page
    assert "port `8443`" in page and "`/v1/info`" in page and "expects status `200`" in page
    # relative + path-qualified wiki link (docs/capabilities/ has pages of the same names)
    assert "[lake-catalog](lake-catalog.md) ([[systems/lake-catalog|lake-catalog]])" in page
    assert "Depended on by" in page and "agent-runtime" in page
    for _key, heading, _ in SECTIONS:
        assert f"## {heading}" in page
    assert page.count("TODO(human)") == len(SECTIONS)


def test_no_secret_values_only_names_slot(reg, tmp_path):
    generate_pages(reg, tmp_path)
    page = (tmp_path / "secrets.md").read_text()
    assert "NAMES only" in page and "HNX_ENDPOINT_SECRETS" in page


def test_regenerate_preserves_human_text_and_refreshes_generated(reg, tmp_path):
    generate_pages(reg, tmp_path)
    p = tmp_path / "events.md"
    text = p.read_text().replace(
        "> TODO(human): one paragraph: the job, who needs it, what breaks without it.",
        "Carries domain events between the runtime and the lake.",
    )
    text = text.replace("`4222`", "`9999`").replace("status: draft", "status: reviewed")
    p.write_text(text)
    rep = check_pages(reg, tmp_path)
    assert rep.stale == ["events.md"] and not rep.ok()
    res = generate_pages(reg, tmp_path)
    assert res.updated == ["events.md"]
    new = p.read_text()
    assert "Carries domain events" in new and "`4222`" in new and "status: reviewed" in new
    assert check_pages(reg, tmp_path).ok()
    assert generate_pages(reg, tmp_path).updated == []  # idempotent


def test_missing_page_fails(reg, tmp_path):
    generate_pages(reg, tmp_path)
    (tmp_path / "dns.md").unlink()
    rep = check_pages(reg, tmp_path)
    assert rep.missing == ["dns"] and not rep.ok()


def test_orphan_page_fails(reg, tmp_path):
    generate_pages(reg, tmp_path)
    (tmp_path / "ghost.md").write_text(
        "---\ntitle: ghost\ntype: system\nservice: ghost\n---\n# ghost\n"
    )
    rep = check_pages(reg, tmp_path)
    assert rep.orphans == ["ghost.md"] and not rep.ok()


def test_malformed_and_misnamed_pages_fail(reg, tmp_path):
    generate_pages(reg, tmp_path)
    (tmp_path / "junk.md").write_text("no front matter\n")
    (tmp_path / "wrongname.md").write_text("---\ntype: system\nservice: dns\n---\n")
    rep = check_pages(reg, tmp_path)
    assert set(rep.malformed) == {"junk.md", "wrongname.md"}


def test_require_complete_fails_on_todos(reg, tmp_path):
    generate_pages(reg, tmp_path)
    rep = check_pages(reg, tmp_path)
    assert rep.ok() and not rep.ok(require_complete=True)


def test_missing_directory_means_every_row_missing(reg, tmp_path):
    assert len(check_pages(reg, tmp_path / "nope").missing) == len(reg.services)


def test_committed_template_is_the_rendered_template():
    assert (ROOT / "docs" / "systems" / "_TEMPLATE.md").read_text() == render_template()


def test_committed_example_pages_match_the_example_registry():
    rep = check_pages(load(REGISTRY), ROOT / "docs" / "systems")
    assert rep.ok(), rep.lines()


def test_pages_contain_only_example_data(reg):
    for s in reg.sorted_services():
        page = render_page(reg, s)
        assert not re.search(r"\b(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d+\.\d+\b", page)


def test_cli(reg, tmp_path, capsys):
    reg_path = str(REGISTRY)
    assert main(["systems", "check", reg_path, str(tmp_path)]) == 1
    assert main(["systems", "generate", reg_path, str(tmp_path)]) == 0
    assert (tmp_path / "_TEMPLATE.md").is_file()
    assert main(["systems", "check", reg_path, str(tmp_path)]) == 0
    assert main(["systems", "check", reg_path, str(tmp_path), "--require-complete"]) == 1
    assert main(["systems", "check"]) == 2
    assert main(["systems", "check", str(tmp_path / "nope.yml")]) == 2
    assert main(["systems", "template"]) == 0
    assert main(["bogus"]) == 2
    capsys.readouterr()


def test_page_links_its_capability_reference(reg, tmp_path):
    generate_pages(reg, tmp_path)
    page = (tmp_path / "secrets.md").read_text()
    assert "[secrets capability reference](../capabilities/secrets.md)" in page
    assert "[[capabilities/secrets|secrets capability]]" in page
    # a capability without a conformance suite says so instead of linking nowhere
    assert (
        "Contract: none (`dns` is not one of the conformance capabilities)"
        in (tmp_path / "dns.md").read_text()
    )
    # and the committed page carries the link (the systems check above pins the rest)
    assert "../capabilities/secrets.md" in (ROOT / "docs" / "systems" / "secrets.md").read_text()


def test_hnx_dispatch_registered():
    assert "docs" in COMMANDS


# --- reviews (homelabnext.reviews): status reviewed is checked against the review policy ----------


POLICY = load_policy(ROOT / "examples" / "review-policy.yml")
REVIEWED = ROOT / "tests" / "sop" / "fixtures" / "dns.reviewed.md"


@pytest.fixture
def pages(reg, tmp_path):
    """The committed pages, with dns.md replaced by the fully reviewed fixture."""
    d = tmp_path / "systems"
    d.mkdir()
    for p in (ROOT / "docs" / "systems").glob("*.md"):
        (d / p.name).write_text(p.read_text())
    (d / "dns.md").write_text(
        refresh_page(REVIEWED.read_text(), render_page(reg, reg.services["dns"]))
    )
    return d


def test_the_committed_pages_are_drafts_that_list_their_missing_tiers(reg):
    rep = check_pages(reg, ROOT / "docs" / "systems", POLICY)
    assert rep.ok() and rep.review_problems == []
    assert set(rep.drafts) == {p.name for p in (ROOT / "docs/systems").glob("[!_]*.md")}
    assert rep.info() == [
        "draft (needs agent check, agent audit, human approve): " + ", ".join(sorted(rep.drafts))
    ]


def test_a_fully_reviewed_page_passes(reg, pages):
    rep = check_pages(reg, pages, POLICY)
    assert rep.ok(), rep.lines()
    assert "dns.md" not in rep.drafts


def test_sidecar_review_events_count_like_inline_reviews(reg, pages):
    from homelabnext.registers.migrate import migrate_pages

    migrate_pages(pages)
    p = pages / "dns.md"
    assert "reviews" not in p.read_text().split("---")[1]
    approve = sorted((pages / "dns.events").glob("*-review-human-*.yml"))
    assert len(approve) == 1 and check_pages(reg, pages, POLICY).ok()
    approve[0].unlink()  # the same page without its human approve event
    rep = check_pages(reg, pages, POLICY)
    assert any("dns.md: status reviewed needs human approve" in ln for ln in rep.lines())


def test_a_reviewed_page_missing_the_human_approve_fails(reg, pages):
    p = pages / "dns.md"
    text = p.read_text()
    i = text.index("- {by: 'human:example-operator'")
    j = text.index("---", i)
    p.write_text(text[:i] + text[j:])
    rep = check_pages(reg, pages, POLICY)
    assert not rep.ok()
    assert any("dns.md: status reviewed needs human approve" in ln for ln in rep.lines())


def test_editing_a_human_block_invalidates_its_reviews(reg, pages):
    p = pages / "dns.md"
    p.write_text(p.read_text().replace("Resolves internal names", "Resolves most internal names"))
    rep = check_pages(reg, pages, POLICY)
    assert not rep.ok()
    assert any("needs agent check, agent audit, human approve" in ln for ln in rep.lines())
    assert any("3 review(s) are of an earlier content" in ln for ln in rep.lines())


def test_regenerating_a_gen_block_keeps_the_reviews(reg, pages):
    p = pages / "dns.md"
    before = page_digest(p.read_text())
    stale = p.read_text().replace("- Owner: platform-team\n- Tags", "- Owner: someone-else\n- Tags")
    assert page_digest(stale) == before  # machine facts are not what a human reviewed
    p.write_text(stale)
    assert check_pages(reg, pages, POLICY).stale == ["dns.md"]
    generate_pages(reg, pages)
    assert page_digest(p.read_text()) == before
    rep = check_pages(reg, pages, POLICY)
    assert rep.ok(), rep.lines()
    assert "status: reviewed" in p.read_text() and "human:example-operator" in p.read_text()


def test_a_reviewed_page_with_todo_left_fails(reg, pages):
    p = pages / "dns.md"
    text = p.read_text()
    p.write_text(text.replace("status: draft", "status: reviewed"))
    events = pages / "events.md"
    events.write_text(events.read_text().replace("status: draft", "status: reviewed"))
    rep = check_pages(reg, pages, POLICY)
    assert any("events.md: status reviewed with TODO(human) left" in ln for ln in rep.lines())


def test_page_reviews_follow_the_same_identity_rules(reg, pages):
    p = pages / "dns.md"
    p.write_text(p.read_text().replace("author: unknown", "author: 'human:example-operator'"))
    rep = check_pages(reg, pages, POLICY)
    assert any("is the author; nobody reviews their own work" in ln for ln in rep.lines())
    p.write_text(
        p.read_text()
        .replace("author: 'human:example-operator'", "author: unknown")
        .replace("by: 'agent:example-auditor'", "by: 'agent:example-checker'")
    )
    assert any("must be a different agent" in ln for ln in check_pages(reg, pages, POLICY).lines())


def test_cli_prints_drafts_as_info_and_checks_reviewed_pages(reg, pages, capsys):
    rc = main(["systems", "check", str(REGISTRY), str(pages)])
    out = capsys.readouterr().out
    assert (
        rc == 0
        and "info: draft (needs agent check" in out
        and "dns.md" not in out.split("info:")[1].split("\n")[0]
    )
