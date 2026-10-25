# SPDX-License-Identifier: Apache-2.0
"""The front-matter ``summary:`` of records and pages (ADR-0032): ``hnx registers summaries``
passes well-formed summaries, fails a missing one, a too-long, multi-line or control-character
one (exit 1), and an authored page summary whose ``summary_of`` outline digest is absent or stale;
``--restamp`` rewrites only that line.  The record validation refuses a malformed summary too, and
the write path keeps the field."""

from __future__ import annotations

import json
import re
import shutil

import pytest
from register_helpers import REPO, U, edit, f

from homelabnext.context.levels import outline_digest
from homelabnext.registers import RegisterError, build_all, load_register
from homelabnext.registers.__main__ import main
from homelabnext.registers.summaries import RestampError, lint_summaries, restamp

KINDS = ("lessons", "runbooks")


@pytest.fixture
def src(tmp_path):
    d = tmp_path / "src"
    for kind in KINDS:
        shutil.copytree(REPO / "examples/registers" / kind, d / kind)
    shutil.copy(REPO / "examples/registers/invariants.yml", d / "invariants.yml")
    return d


def _page(summary: str, body: str, extra: str = "") -> str:
    """A stamped authored page: front matter with ``summary`` and the outline stamp of ``body``."""
    return f"---\nsummary: {summary}\nsummary_of: {outline_digest(body)}\n{extra}---\n{body}"


def _summary_line(path) -> str:
    return next(ln for ln in path.read_text().splitlines() if ln.startswith("summary: "))


def test_every_example_record_carries_a_valid_summary():
    rep = lint_summaries([REPO / "examples/registers"], REPO)
    assert rep.ok and rep.records == 8 and rep.missing_records == []
    for kind in KINDS:
        for e in load_register(REPO / "examples/registers" / kind)[kind]:
            assert e["summary"] and len(e["summary"]) <= 160


def test_the_repository_lint_passes(capsys):
    assert main(["summaries", str(REPO / "examples/registers"), str(REPO / "docs")]) == 0
    line = capsys.readouterr().out.strip().splitlines()[-1]
    assert re.fullmatch(
        r"\[registers\] summaries: 8 record\(s\), 0 without a summary; \d+ page\(s\), 0 without "
        r"a summary, \d+ with a generated one",
        line,
    )


def test_a_missing_summary_fails_the_lint(src, capsys):
    p = src / "lessons" / f("LL-001")
    edit(p, _summary_line(p) + "\n", "")
    assert main(["summaries", str(src)]) == 1
    out = capsys.readouterr().out
    assert "1 without a summary" in out and "WARNING" not in out
    (fail,) = [ln for ln in out.splitlines() if "FAIL" in ln]
    assert f("LL-001") in fail and "no front-matter summary" in fail
    build_all(src, src.parent / "out")  # optional for the record validation itself


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
    (docs / "good.md").write_text(_page("A page with a summary.", "# Good\n"))
    (docs / "plain.md").write_text("# Plain\n\nNo front-matter.\n")
    (docs / "_TEMPLATE.md").write_text("---\nsummary: " + "x" * 300 + "\n---\n")
    rep = lint_summaries([docs], tmp_path)
    assert rep.pages == 2 and rep.missing_pages == ["docs/plain.md"]
    assert [p.split(":")[0] for p in rep.problems] == ["docs/plain.md"]
    (docs / "plain.md").unlink()
    (docs / "bad.md").write_text('---\nsummary: "line\\nbreak"\n---\n# Bad\n')
    rep = lint_summaries([docs, docs / "bad.md"], tmp_path)  # a file named twice counts once
    assert rep.problems == ["docs/bad.md: summary must be a single line"] and rep.pages == 2


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


def test_generated_summaries_are_counted_apart_from_missing_and_authored(tmp_path):
    (tmp_path / "gen.md").write_text(
        "---\nsummary: Derived from data.\nsummary_generated: true\n---\n# G\n"
    )
    (tmp_path / "hand.md").write_text(_page("Written by a person.", "# H\n"))
    (tmp_path / "none.md").write_text("# N\n")
    (tmp_path / "bad.md").write_text(f"---\nsummary: {'x' * 200}\nsummary_generated: true\n---\n")
    rep = lint_summaries([tmp_path], tmp_path)
    assert rep.generated_pages == ["gen.md"]
    assert rep.missing_pages == ["none.md"] and len(rep.problems) == 2  # none + bad (too long)
    assert "1 with a generated one" in rep.lines()[-1]


def test_a_non_boolean_generated_marker_warns_but_does_not_fail(tmp_path):
    stamp = outline_digest("# S\n")
    (tmp_path / "s.md").write_text(
        f'---\nsummary: Words.\nsummary_of: {stamp}\nsummary_generated: "true"\n---\n# S\n'
    )
    stamp = outline_digest("# O\n")
    (tmp_path / "ok.md").write_text(
        f"---\nsummary: Words.\nsummary_of: {stamp}\nsummary_generated: false\n---\n# O\n"
    )
    rep = lint_summaries([tmp_path], tmp_path)
    assert rep.ok and rep.generated_pages == []
    assert len(rep.warnings) == 1 and rep.warnings[0].startswith("s.md: summary_generated")
    assert any(ln.startswith("WARN s.md") for ln in rep.lines())


# ---- summary_of: the outline stamp (ADR-0032) ------------------------------------------------

BODY = "# Title\n\nIntro prose.\n\n## One\n\ntext\n\n## Two\n\nmore\n"


def _docs(tmp_path, text, name="p.md"):
    p = tmp_path / name
    p.write_text(text)
    return p


def test_the_outline_digest_is_deterministic_and_named():
    d = outline_digest(BODY)
    assert d == outline_digest(BODY) == outline_digest("---\nsummary: x\n---\n" + BODY)
    assert re.fullmatch(r"outline:sha256:[0-9a-f]{16}", d)
    assert (
        d
        == "outline:sha256:"
        + __import__("hashlib").sha256(b"1 Title\n2 One\n2 Two").hexdigest()[:16]
    )


@pytest.mark.parametrize(
    "new",
    [
        BODY.replace("## Two", "## Three"),  # renamed
        BODY.replace("## Two", "### Two"),  # re-levelled
        BODY + "\n## Three\n",  # added
        BODY.replace("\n## Two\n\nmore\n", ""),  # removed
        BODY.replace("## One\n\ntext\n\n## Two", "## Two\n\ntext\n\n## One"),  # reordered
    ],
)
def test_an_outline_change_fails_the_lint(tmp_path, new, capsys):
    page = _docs(tmp_path, _page("Words.", BODY))
    assert lint_summaries([page], tmp_path).ok
    page.write_text(_page("Words.", BODY).replace(BODY, new))
    rep = lint_summaries([page], tmp_path)
    assert not rep.ok and len(rep.problems) == 1
    msg = rep.problems[0]
    assert msg.startswith("p.md: ") and "stale" in msg
    assert "reread the summary, then run" in msg
    assert "python3 -m homelabnext.registers summaries --restamp p.md" in msg


def test_body_edits_that_change_no_heading_pass(tmp_path):
    page = _docs(tmp_path, _page("Words.", BODY))
    edited = (
        _page("Words.", BODY)
        .replace("text", "entirely new text, # not a heading")
        .replace("more", "```\n# fenced is not a heading\n```")
    )
    page.write_text(edited)
    assert lint_summaries([page], tmp_path).ok


def test_an_authored_summary_without_summary_of_fails(tmp_path):
    page = _docs(tmp_path, "---\nsummary: Words.\n---\n" + BODY)
    (msg,) = lint_summaries([page], tmp_path).problems
    assert "has no summary_of" in msg and "--restamp p.md" in msg


def test_a_generated_summary_is_exempt_from_summary_of(tmp_path):
    page = _docs(tmp_path, "---\nsummary: Words.\nsummary_generated: true\n---\n" + BODY)
    rep = lint_summaries([page], tmp_path)
    assert rep.ok and rep.generated_pages == ["p.md"]


def test_register_records_are_exempt_from_summary_of(src):
    assert "summary_of" not in (src / "lessons" / f("LL-001")).read_text()
    assert lint_summaries([src]).ok


def test_a_missing_page_summary_fails(tmp_path):
    page = _docs(tmp_path, BODY)
    rep = lint_summaries([page], tmp_path)
    assert not rep.ok and rep.missing_pages == ["p.md"]


def _cli_restamp(*paths):
    return main(["summaries", "--restamp", *map(str, paths)])


def test_restamp_inserts_one_line_after_summary_and_changes_nothing_else(tmp_path):
    original = (
        "---\r\ntitle: T  # keep this comment\r\nsummary: 'It''s one line.'\r\n"
        "zeta: [1,   2]\r\nalpha: x\r\n---\r\n" + BODY.replace("\n", "\r\n")
    )
    page = tmp_path / "p.md"
    page.write_bytes(original.encode())
    assert restamp(page) is True
    new = page.read_bytes().decode()
    stamp = f"summary_of: {outline_digest(original)}\r\n"
    assert new == original.replace("zeta:", stamp + "zeta:")
    assert lint_summaries([page], tmp_path).ok
    assert restamp(page) is False  # idempotent
    assert page.read_bytes().decode() == new


def test_restamp_replaces_only_a_stale_summary_of_line(tmp_path):
    page = _docs(
        tmp_path,
        "---\nsummary: Words.\nsummary_of: outline:sha256:0000000000000000\nz: 1\n---\n" + BODY,
    )
    before = page.read_text()
    assert restamp(page) is True
    after = page.read_text()
    assert after == before.replace("0000000000000000", outline_digest(BODY).split(":")[2])
    assert restamp(page) is False and page.read_text() == after


def test_restamp_after_a_heading_edit_makes_the_lint_pass(tmp_path, capsys):
    page = _docs(tmp_path, _page("Words.", BODY, "other: kept\n"))
    page.write_text(page.read_text().replace("## Two", "## Deux"))
    assert main(["summaries", str(page)]) == 1
    capsys.readouterr()
    assert _cli_restamp(page) == 0
    assert "restamped" in capsys.readouterr().out
    assert main(["summaries", str(page)]) == 0
    assert "other: kept\n" in page.read_text()


@pytest.mark.parametrize(
    ("text", "needle"),
    [
        ("# No front matter\n", "no summary to stamp"),
        ("---\ntitle: T\n---\n# No summary\n", "no summary to stamp"),
        ("---\nsummary: Words.\nsummary_generated: true\n---\n# G\n", "generated"),
        ("---\nsummary: ''\n---\n# Empty\n", "non-empty"),
    ],
)
def test_restamp_refuses_a_page_without_an_authored_summary(tmp_path, capsys, text, needle):
    page = _docs(tmp_path, text)
    with pytest.raises(RestampError, match=needle):
        restamp(page)
    assert page.read_text() == text
    assert _cli_restamp(page) == 1
    assert needle in capsys.readouterr().err


def test_restamp_refuses_a_record_and_a_directory(src, tmp_path, capsys):
    rec = src / "lessons" / f("LL-001")
    before = rec.read_text()
    with pytest.raises(RestampError, match="exempt"):
        restamp(rec)
    assert rec.read_text() == before
    assert _cli_restamp(tmp_path) == 1
    assert "takes pages" in capsys.readouterr().err
    assert main(["summaries", "--restamp"]) == 1  # no restamp without explicit paths


def test_restamp_all_only_stamps_authored_pages(tmp_path):
    a = _docs(tmp_path, "---\nsummary: Words.\n---\n" + BODY, "a.md")
    g = _docs(tmp_path, "---\nsummary: Words.\nsummary_generated: true\n---\n" + BODY, "g.md")
    before = g.read_text()
    assert main(["summaries", "--restamp-all", str(tmp_path)]) == 0
    assert outline_digest(BODY) in a.read_text() and g.read_text() == before
    assert lint_summaries([tmp_path], tmp_path).ok


# ---- hardening of --restamp (review findings) ------------------------------------------------


def test_restamp_refuses_symlinks_dotdot_and_records(tmp_path, monkeypatch, src, capsys):
    docs = tmp_path / "docs"
    docs.mkdir()
    out = tmp_path / "out"
    out.mkdir()
    outside = out / "x.md"
    outside.write_text("---\nsummary: Words.\n---\n# X\n")
    secret = out / "secret.txt"
    secret.write_text("---\nsummary: Words.\n---\n# S\n")
    (docs / "link.md").symlink_to(outside)
    (docs / "secret.md").symlink_to(secret)
    (docs / "lessons").symlink_to(src / "lessons")
    monkeypatch.chdir(tmp_path)
    before = {p: p.read_bytes() for p in (outside, secret, *(src / "lessons").glob("*.md"))}
    for bad, needle in [
        ("docs/link.md", "symbolic link"),
        ("docs/secret.md", "symbolic link"),
        ("docs/lessons/" + f("LL-001"), "symbolic link"),
        ("docs/../out/x.md", "`..`"),
        ("out/secret.txt", "not a regular Markdown page"),
    ]:
        with pytest.raises(RestampError, match=needle):
            restamp(bad)
        assert main(["summaries", "--restamp", bad]) == 1
    capsys.readouterr()
    assert {p: p.read_bytes() for p in before} == before
    pages = tmp_path / "pages"
    pages.mkdir()
    (pages / "link.md").symlink_to(outside)
    assert main(["summaries", "--restamp-all", "pages"]) == 1  # restamp-all refuses it too
    assert {p: p.read_bytes() for p in before} == before


def test_restamp_refuses_a_real_record_path(src):
    rec = src / "runbooks" / f("RB-001")
    before = rec.read_bytes()
    with pytest.raises(RestampError, match="exempt"):
        restamp(rec)
    assert rec.read_bytes() == before


def test_restamp_keeps_crlf_for_a_one_line_front_matter(tmp_path):
    page = tmp_path / "p.md"
    original = b"---\r\nsummary: Words.\r\n---\r\n# H\r\n\r\nbody\r\n"
    page.write_bytes(original)
    assert restamp(page) is True
    stamp = b"summary_of: " + outline_digest("# H\n").encode() + b"\r\n"
    assert page.read_bytes() == original.replace(
        b"summary: Words.\r\n", b"summary: Words.\r\n" + stamp
    )


def test_restamp_keeps_comments_and_blank_lines_after_the_entries(tmp_path):
    page = tmp_path / "p.md"
    old = "outline:sha256:0000000000000000"
    page.write_text(
        f"---\nsummary: Words.\n# about the stamp\n\nsummary_of: {old}\n# trailing comment\nz: 1\n---\n# H\n"
    )
    assert restamp(page) is True
    text = page.read_text()
    assert (
        "# about the stamp\n\nsummary_of: "
        + outline_digest("# H\n")
        + "\n# trailing comment\nz: 1\n"
        in text
    )
    page.write_text("---\nsummary: Words.\n# c1\n\nz: 1\n---\n# H\n")
    assert restamp(page) is True
    assert page.read_text().startswith(
        "---\nsummary: Words.\nsummary_of: " + outline_digest("# H\n") + "\n# c1\n\nz: 1\n"
    )


def test_restamp_with_several_paths_writes_all_or_none(tmp_path, capsys):
    good = _docs(tmp_path, "---\nsummary: Words.\n---\n# G\n", "good.md")
    bad = _docs(tmp_path, "# no summary\n", "bad.md")
    before = good.read_bytes()
    assert main(["summaries", "--restamp", str(good), str(bad)]) == 1
    assert good.read_bytes() == before
    capsys.readouterr()


def test_restamp_writes_atomically_and_keeps_the_mode(tmp_path):
    page = _docs(tmp_path, "---\nsummary: Words.\n---\n# G\n")
    page.chmod(0o640)
    assert restamp(page) is True
    assert (page.stat().st_mode & 0o777) == 0o640
    assert [p.name for p in tmp_path.iterdir()] == ["p.md"]  # no temp file left behind


def test_a_duplicate_key_is_reported_as_invalid_yaml_not_a_missing_summary(tmp_path):
    page = _docs(tmp_path, "---\nsummary: Words.\nsummary: Other.\n---\n# D\n")
    (msg,) = lint_summaries([page], tmp_path).problems
    assert "not valid YAML" in msg and "duplicate" in msg.lower() and "no front-matter" not in msg
    with pytest.raises(RestampError, match="not valid YAML"):
        restamp(page)
    dup_of = _docs(tmp_path, "---\nsummary: W.\nsummary_of: a\nsummary_of: b\n---\n# D\n", "d.md")
    with pytest.raises(RestampError, match="not valid YAML"):
        restamp(dup_of)


def test_a_quoted_summary_key_can_be_restamped(tmp_path):
    page = _docs(tmp_path, '---\n"summary": Words.\ntitle: T\n---\n# Q\n')
    assert "has no summary_of" in lint_summaries([page], tmp_path).problems[0]
    assert restamp(page) is True
    assert lint_summaries([page], tmp_path).ok
    assert restamp(page) is False


def test_the_missing_flag_is_gone(capsys):
    with pytest.raises(SystemExit):
        main(["summaries", "docs", "--missing"])
    capsys.readouterr()
