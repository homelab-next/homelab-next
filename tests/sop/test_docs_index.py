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
