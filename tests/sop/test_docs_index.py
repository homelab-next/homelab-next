# SPDX-License-Identifier: Apache-2.0
"""``hnx docs index``: the descriptions in a docs index come from the pages' summaries."""

from __future__ import annotations

import pytest

from homelabnext.cli import main
from homelabnext.sop import index

INDEX = (
    "---\nsummary: Home.\n---\n# Home\n\nAuthored intro, kept [[a]] and [a](a.md).\n\n"
    "- [A](a.md) ([[a]]): <!-- hnx:gen:summary:a.md -->old<!-- /hnx:gen -->\n"
    "- [B](sub/b.md) ([[sub/b|B]]): <!-- hnx:gen:summary:sub/b.md -->Words b.<!-- /hnx:gen -->\n"
    "\nAuthored outro.\n"
)


@pytest.fixture
def docs(tmp_path):
    (tmp_path / "sub").mkdir()
    (tmp_path / "a.md").write_text("---\nsummary: Words a.\n---\n# A\n")
    (tmp_path / "sub" / "b.md").write_text("---\nsummary: Words b.\n---\n# B\n")
    (tmp_path / "README.md").write_text(INDEX)
    return tmp_path


def test_a_stale_span_fails_the_check(docs, capsys):
    assert index.check(docs / "README.md") == ["stale: a.md"]
    assert main(["docs", "index", "check", str(docs / "README.md")]) == 1
    assert "FAIL stale: a.md" in capsys.readouterr().out


def test_a_target_without_a_summary_fails_and_nothing_is_written(docs, capsys):
    (docs / "a.md").write_text("# A\n")
    assert index.check(docs / "README.md") == ["a.md: the page has no summary"]
    assert main(["docs", "index", "generate", str(docs / "README.md")]) == 1
    assert (docs / "README.md").read_text() == INDEX
    (docs / "a.md").unlink()
    assert index.check(docs / "README.md") == ["a.md: no such page"]
    capsys.readouterr()


def test_generate_is_idempotent_and_changes_only_the_spans(docs, capsys):
    path = docs / "README.md"
    assert main(["docs", "index", "generate", str(path)]) == 0
    first = path.read_text()
    assert first == INDEX.replace(">old<", ">Words a.<")
    assert main(["docs", "index", "generate", str(path)]) == 0
    assert path.read_text() == first
    assert "unchanged" in capsys.readouterr().out
    assert index.check(path) == []
    assert main(["docs", "index", "check", str(path)]) == 0


def test_a_path_outside_the_directory_is_refused(docs):
    (docs / "README.md").write_text("- <!-- hnx:gen:summary:../x.md -->t<!-- /hnx:gen -->\n")
    assert "not a Markdown page under" in index.check(docs / "README.md")[0]


def test_the_real_index_is_current():
    from pathlib import Path

    assert index.check(Path(__file__).resolve().parents[2] / "docs" / "README.md") == []


def test_generate_keeps_crlf_and_replaces_the_file_atomically(docs):
    path = docs / "README.md"
    path.write_bytes(INDEX.replace("\n", "\r\n").encode())
    assert main(["docs", "index", "generate", str(path)]) == 0
    data = path.read_bytes()
    assert data == INDEX.replace(">old<", ">Words a.<").replace("\n", "\r\n").encode()
    assert b"\n" not in data.replace(b"\r\n", b"")
    assert index.check(path) == []
    assert sorted(p.name for p in docs.iterdir()) == ["README.md", "a.md", "sub"]  # no temp file


@pytest.mark.parametrize(
    "line",
    [
        "- [A](a.md): <!-- hnx:gen:summary:a.md-->Words a.<!-- /hnx:gen -->",  # no space before -->
        "- [A](a.md): <!-- hnx:gen:summary:a.md -->Words a.",  # open marker, no close
        "- [A](a.md): <!-- hnx:gen:summary:a.md -->Words a.\n<!-- /hnx:gen -->",  # close elsewhere
        "- [A](a.md): Words a.<!-- /hnx:gen -->",  # stray close
        "- [A](a.md): <!-- hnx:gen:summary: a.md -->Words a.<!-- /hnx:gen -->",  # space in path
    ],
)
def test_a_malformed_or_unmatched_marker_fails(docs, line):
    path = docs / "README.md"
    path.write_text(
        INDEX.replace(
            "- [A](a.md) ([[a]]): <!-- hnx:gen:summary:a.md -->old<!-- /hnx:gen -->", line
        )
    )
    problems = index.check(path)
    assert any("malformed or unmatched" in p or "no summary span" in p for p in problems), problems


def test_a_list_entry_without_a_span_or_with_the_wrong_one_fails(docs):
    path = docs / "README.md"
    path.write_text(INDEX + "- [A again](a.md) ([[a]]): hand-written.\n")
    assert any("a.md but has no summary span" in p for p in index.check(path))
    path.write_text(
        INDEX + "- [C](a.md): <!-- hnx:gen:summary:sub/b.md -->Words b.<!-- /hnx:gen -->\n"
    )
    assert any("links a.md but its span is for sub/b.md" in p for p in index.check(path))
    path.write_text(
        INDEX.replace(">old<", ">Words a.<") + "Prose may link [A](a.md) freely.\n"
    )  # not a list entry
    assert index.check(path) == []


def test_a_top_level_page_missing_from_the_index_fails(docs):
    (docs / "README.md").write_text(INDEX.replace(">old<", ">Words a.<"))
    (docs / "new.md").write_text("---\nsummary: New.\n---\n# New\n")
    (docs / "_template.md").write_text("# template\n")
    assert index.check(docs / "README.md") == ["new.md: page is not listed in README.md"]


def test_text_after_the_closing_marker_is_authored_and_kept(docs):
    path = docs / "README.md"
    path.write_text(
        INDEX.replace("old<!-- /hnx:gen -->", "old<!-- /hnx:gen --> Proposed (ADR-0031).")
    )
    assert main(["docs", "index", "generate", str(path)]) == 0
    assert "Words a.<!-- /hnx:gen --> Proposed (ADR-0031)." in path.read_text()
