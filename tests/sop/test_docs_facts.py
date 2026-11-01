# SPDX-License-Identifier: Apache-2.0
"""``hnx docs facts``: counts, names, tool classes and schema versions in the docs pages are
generated from their sources, so a page cannot state a stale one (docs/mcp-catalog.md once listed
seven tool classes after the table gained an eighth)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from homelabnext.agent.readers import DEFAULT_CLASSES
from homelabnext.cli import main
from homelabnext.conform.registry import CAPABILITIES, EXTENDED
from homelabnext.sop import facts

ROOT = Path(__file__).resolve().parents[2]
ID = facts.ID_PREFIX


def _root(tmp_path: Path, version: str = "1.2", draft: bool = False) -> Path:
    d = tmp_path / "schemas" / "widgets"
    d.mkdir(parents=True)
    doc = {"$id": f"{ID}widgets/gear/{version}", "title": "gear"}
    if draft:
        doc["x-draft"] = True
    (d / "gear.schema.json").write_text(json.dumps(doc))
    (tmp_path / "schemas" / "_frozen").mkdir()
    (tmp_path / "schemas" / "_frozen" / "old.schema.json").write_text("{}")
    (tmp_path / "docs").mkdir()
    return tmp_path


def test_the_repository_pages_are_current():
    pages = facts.files_with_facts(ROOT)
    names = {p.relative_to(ROOT).as_posix() for p in pages}
    assert {
        "docs/glossary.md",
        "docs/interfaces.md",
        "docs/agent.md",
        "docs/mcp-catalog.md",
    } <= names
    assert [line for p in pages for line in facts.check(p, ROOT, ROOT)] == []


def test_every_tool_class_is_named_on_the_catalog_page():
    import yaml

    classes = yaml.safe_load(DEFAULT_CLASSES.read_text(encoding="utf-8"))["classes"]
    text = (ROOT / "docs" / "mcp-catalog.md").read_text(encoding="utf-8")
    span = facts.SPAN.search(text[text.index("The classes are `tool_classes.yml`'s") :])
    assert span and span["name"] == "tool-classes"
    assert span["body"] == ", ".join(f"`{c}`" for c in classes)


def test_the_values_come_from_their_sources(tmp_path):
    got = facts.facts(_root(tmp_path, draft=True))
    assert got["capability-count"] == str(len(CAPABILITIES))
    assert got["capabilities"].count("`") == 2 * len(CAPABILITIES)
    assert got["extended-suites"] == ", ".join(f"`{e}`" for e in EXTENDED)
    assert got["schema-dirs"] == "`widgets`"
    assert got["schema-versions"].splitlines()[2] == (
        "| `widgets/gear` | 1.2 | `schemas/widgets/gear.schema.json` | draft |"
    )
    assert "| `codemode` |" in got["tool-class-table"]
    assert facts.number_word(18) == "eighteen" and facts.number_word(42) == "forty-two"


def test_a_stale_span_fails_the_check_and_generate_fixes_only_the_span(tmp_path):
    root = _root(tmp_path)
    page = root / "docs" / "p.md"
    text = (
        "Intro.\r\nThere are <!-- hnx:gen:fact:capability-count -->3<!-- /hnx:gen --> of them.\r\n"
        "<!-- hnx:gen:fact:schema-versions -->\r\n| old |\r\n<!-- /hnx:gen -->\r\nOutro.\r\n"
    )
    page.write_bytes(text.encode())
    assert facts.check(page, root, root) == [
        "stale: docs/p.md:2: capability-count",
        "stale: docs/p.md:3: schema-versions",
    ]
    assert main(["docs", "facts", "check", "--root", str(root), str(page)]) == 1
    assert main(["docs", "facts", "generate", "--root", str(root), str(page)]) == 0
    new = page.read_bytes().decode()
    assert new.startswith("Intro.\r\nThere are <!-- hnx:gen:fact:capability-count -->18<!--")
    assert "\r\n| `widgets/gear` | 1.2 |" in new and new.endswith("<!-- /hnx:gen -->\r\nOutro.\r\n")
    assert "\n" not in new.replace("\r\n", "")
    assert facts.check(page, root, root) == []
    (root / "schemas" / "widgets" / "gear.schema.json").write_text(
        json.dumps({"$id": f"{ID}widgets/gear/1.3"})
    )
    assert facts.check(page, root, root) == ["stale: docs/p.md:3: schema-versions"]


@pytest.mark.parametrize(
    ("body", "problem"),
    [
        ("<!-- hnx:gen:fact:nope -->x<!-- /hnx:gen -->", "unknown fact 'nope'"),
        ("<!-- hnx:gen:fact:capabilities -->\nx\n<!-- /hnx:gen -->", "must be written inline"),
        ("<!-- hnx:gen:fact:schema-versions -->x<!-- /hnx:gen -->", "must be written a block"),
        ("<!-- hnx:gen:fact:capabilities -->x", "malformed or unclosed fact marker"),
        ("<!-- hnx:gen:fact:capabilities-->x<!-- /hnx:gen -->", "malformed or unclosed"),
    ],
)
def test_a_bad_marker_fails_and_nothing_is_written(tmp_path, body, problem):
    root = _root(tmp_path)
    page = root / "docs" / "p.md"
    page.write_text(f"Text {body} end.\n")
    assert any(problem in line for line in facts.check(page, root, root)), facts.check(
        page, root, root
    )
    assert facts.generate(page, root, root)[0] is False
    assert page.read_text() == f"Text {body} end.\n"


def test_the_default_walk_finds_fact_pages_and_leaves_the_adrs_out(tmp_path):
    root = _root(tmp_path)
    (root / "docs" / "adr").mkdir()
    (root / "docs" / "adr" / "0001-x.md").write_text("<!-- hnx:gen:fact:nope -->x<!-- /hnx:gen -->")
    (root / "docs" / "sub").mkdir()
    (root / "docs" / "sub" / "q.md").write_text(
        "<!-- hnx:gen:fact:capability-count --><!-- /hnx:gen -->"
    )
    (root / "docs" / "plain.md").write_text("no facts here\n")
    assert facts.files_with_facts(root) == [root / "docs" / "sub" / "q.md"]


def test_a_schema_outside_the_id_namespace_is_refused(tmp_path):
    root = _root(tmp_path)
    (root / "schemas" / "widgets" / "odd.schema.json").write_text(json.dumps({"$id": "urn:x"}))
    with pytest.raises(ValueError, match=r"odd\.schema\.json"):
        facts.schemas(root)
