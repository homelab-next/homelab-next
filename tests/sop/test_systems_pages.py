# SPDX-License-Identifier: Apache-2.0
"""Per-system SOP pages: prefill, regeneration keeps human text, missing/orphan/stale detection."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from homelabnext.cli import COMMANDS
from homelabnext.registry.model import load
from homelabnext.sop import SECTIONS, check_pages, generate_pages, render_page, render_template
from homelabnext.sop.cli import main

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
