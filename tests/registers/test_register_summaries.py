# SPDX-License-Identifier: Apache-2.0
"""The front-matter ``summary:`` of records and pages (ADR-0032): ``hnx registers summaries``
passes well-formed summaries, counts a missing one as a warning (exit 0), fails a too-long,
multi-line or control-character one (exit 1); the record validation refuses a malformed summary
too, and the write path keeps the field."""

from __future__ import annotations

import json
import re
import shutil

import pytest
from register_helpers import REPO, U, edit, f

from homelabnext.registers import RegisterError, build_all, load_register
from homelabnext.registers.__main__ import main
from homelabnext.registers.summaries import lint_summaries

KINDS = ("lessons", "runbooks")


@pytest.fixture
def src(tmp_path):
    d = tmp_path / "src"
    for kind in KINDS:
        shutil.copytree(REPO / "examples/registers" / kind, d / kind)
    shutil.copy(REPO / "examples/registers/invariants.yml", d / "invariants.yml")
    return d


def _summary_line(path) -> str:
    return next(ln for ln in path.read_text().splitlines() if ln.startswith("summary: "))


def test_every_example_record_carries_a_valid_summary():
    rep = lint_summaries([REPO / "examples/registers"], REPO)
    assert rep.ok and rep.records == 8 and rep.missing_records == []
    for kind in KINDS:
        for e in load_register(REPO / "examples/registers" / kind)[kind]:
            assert e["summary"] and len(e["summary"]) <= 160


def test_the_repository_lint_passes_and_only_warns(capsys):
    assert main(["summaries", str(REPO / "examples/registers"), str(REPO / "docs")]) == 0
    line = capsys.readouterr().out.strip().splitlines()[-1]
    assert re.fullmatch(
        r"\[registers\] summaries: 8 record\(s\), 0 without a summary; \d+ page\(s\), \d+ without "
        r"a summary( \(WARNING: a missing summary is not a failure yet\))?",
        line,
    )


def test_a_missing_summary_is_a_warning_not_a_failure(src, capsys):
    p = src / "lessons" / f("LL-001")
    edit(p, _summary_line(p) + "\n", "")
    assert main(["summaries", str(src)]) == 0
    out = capsys.readouterr().out
    assert "1 without a summary" in out and "WARNING" in out and "FAIL" not in out
    assert "missing" not in out.replace("missing summary", "")  # counts only, by default
    assert main(["summaries", str(src), "--missing"]) == 0
    listed = [ln for ln in capsys.readouterr().out.splitlines() if "] missing " in ln]
    assert len(listed) == 1 and listed[0].endswith(f("LL-001"))
    build_all(src, src.parent / "out")  # optional for the record validation too


@pytest.mark.parametrize(
    ("new", "needle"),
    [
        ("summary: " + "x" * 161, "summary is 161 characters (at most 160)"),
        ("summary: |\n  two\n  lines", "summary must be a single line"),
        ("summary: >\n  folded keeps a newline", "summary must be a single line"),
        ('summary: "a tab\\there"', "control or invisible"),
        ('summary: "right-to-left \\u202e override"', "control or invisible"),
        ("summary: ''", "non-empty"),
        ("summary: [not, text]", "non-empty"),
    ],
)
def test_a_malformed_summary_fails_the_lint_and_the_validation(src, tmp_path, capsys, new, needle):
    p = src / "runbooks" / f("RB-001")
    edit(p, _summary_line(p), new)
    assert main(["summaries", str(src)]) == 1
    out = capsys.readouterr().out
    (fail,) = [ln for ln in out.splitlines() if "FAIL" in ln]
    assert f"{p.name}: " in fail and needle in fail.split(f"{p.name}: ", 1)[1]
    with pytest.raises(RegisterError, match=re.escape(needle)):
        build_all(src, tmp_path / "out")


def test_pages_are_checked_and_templates_skipped(tmp_path):
    docs = tmp_path / "docs"
    docs.mkdir()
    (docs / "good.md").write_text("---\nsummary: A page with a summary.\n---\n# Good\n")
    (docs / "plain.md").write_text("# Plain\n\nNo front-matter.\n")
    (docs / "_TEMPLATE.md").write_text("---\nsummary: " + "x" * 300 + "\n---\n")
    rep = lint_summaries([docs], tmp_path)
    assert rep.ok and rep.pages == 2 and rep.missing_pages == ["docs/plain.md"]
    (docs / "bad.md").write_text('---\nsummary: "line\\nbreak"\n---\n# Bad\n')
    rep = lint_summaries([docs, docs / "bad.md"], tmp_path)  # a file named twice counts once
    assert rep.problems == ["docs/bad.md: summary must be a single line"] and rep.pages == 3


def test_json_output_is_deterministic(src, capsys):
    assert main(["summaries", str(src), "--json"]) == 0
    first = capsys.readouterr().out
    assert main(["summaries", str(src), "--json"]) == 0
    assert capsys.readouterr().out == first
    assert json.loads(first)["records"] == 8


def test_the_write_path_keeps_the_summary_in_front_order(src):
    from homelabnext.registers import join_register, split_register

    joined = src.parent / "lessons.yml"
    join_register(src / "lessons", joined)
    out = src.parent / "split" / "lessons"
    split_register(joined, out)
    text = (out / f("LL-001")).read_text()
    head = text.split("\n---\n", 1)[0].splitlines()
    assert head[3] == "title: Certificate expired on the internal reverse proxy"
    assert head[4].startswith("summary: A silent renewal failure")
    assert U["LL-001"] in head[1]
