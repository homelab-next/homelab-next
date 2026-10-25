# SPDX-License-Identifier: Apache-2.0
"""Authored Markdown in levels (ADR-0032): the front-matter, the summary and its fallback, ATX
headings outside fenced code, setext text left alone, unique slugs and heading paths, section
extents and exact naming, and the summary rule the lints share."""

from __future__ import annotations

import pytest

from homelabnext.context.levels import (
    MAX_SUMMARY_CHARS,
    check_summary,
    find_section,
    first_paragraph,
    front_matter,
    headings,
    is_markdown,
    summary_of,
)

DOC = """---
title: Example
summary: One reviewed line about the example.
---
<!-- SPDX-License-Identifier: Apache-2.0 -->
# Example page

The first paragraph
spans two lines.

## Decision

Text.

```yaml
# not a heading: inside a fence
## nor this
```

### Consequences

More.

## Alternatives

~~~
## still code
~~~
"""


def _paths(text: str) -> list[str]:
    return [h.path for h in headings(text)]


def test_front_matter_is_parsed_and_skipped():
    front, body = front_matter(DOC)
    assert front == {"title": "Example", "summary": "One reviewed line about the example."}
    assert DOC[body:].startswith("<!-- SPDX")
    assert front_matter("no block\n") == (None, 0)
    broken = "---\nkey: [unclosed\n---\n# Title\n"
    front, body = front_matter(broken)
    assert front is None and broken[body:] == "# Title\n"  # not YAML: still not body text
    assert front_matter("---\n---\nbody\n") == (None, 8)  # empty block: no mapping
    assert front_matter("---\n- a list\n---\n")[0] is None


def test_authored_summary_wins():
    assert summary_of(DOC, "docs/example.md") == (
        "One reviewed line about the example.",
        "authored",
    )


def test_first_paragraph_fallback_skips_front_matter_comments_headings_and_code():
    plain = DOC.replace("summary: One reviewed line about the example.\n", "")
    assert summary_of(plain, "docs/example.md") == (
        "The first paragraph spans two lines.",
        "first-paragraph",
    )
    fenced_first = "# T\n\n```\ncode first\n```\n\nThen prose.\n"
    assert first_paragraph(fenced_first) == "Then prose."


def test_a_long_first_paragraph_is_cut_at_a_word_and_marked():
    text = "# T\n\n" + " ".join(["word"] * 100) + "\n"
    s, src = summary_of(text, "a.md")
    assert src == "first-paragraph" and len(s) <= MAX_SUMMARY_CHARS and s.endswith("word...")
    one = "# T\n\n" + "x" * 400 + "\n"  # no space to cut at
    assert summary_of(one, "a.md")[0] == "x" * (MAX_SUMMARY_CHARS - 3) + "..."


def test_no_paragraph_and_non_markdown_give_none():
    assert summary_of("# Only a heading\n", "a.md") == ("", "none")
    assert summary_of("", "a.md") == ("", "none")
    assert summary_of("summary: looks like one\n\nprose\n", "script.py") == ("", "none")
    assert is_markdown("docs/A.MD") and not is_markdown("tools/x.py")


def test_a_malformed_authored_summary_is_not_served_as_authored():
    text = "---\nsummary: " + "y" * 200 + "\n---\nProse.\n"
    assert summary_of(text, "a.md") == ("Prose.", "first-paragraph")


def test_headings_inside_fenced_code_are_ignored():
    assert _paths(DOC) == [
        "Example page",
        "Example page/Decision",
        "Example page/Decision/Consequences",
        "Example page/Alternatives",
    ]
    unclosed = "# A\n\n```\n# inside, to the end\n"
    assert _paths(unclosed) == ["A"]
    shorter_close = "````\n```\n# still inside\n````\n# B\n"
    assert _paths(shorter_close) == ["B"]
    other_char = "```\n~~~\n# inside\n```\n# C\n"
    assert _paths(other_char) == ["C"]
    info_with_backtick = "``` a`b\n# D\n"  # not a fence: a backtick fence's info has none
    assert _paths(info_with_backtick) == ["D"]


def test_atx_rules_and_setext_text_is_not_a_heading():
    text = (
        "Setext title\n============\n\nSub title\n---------\n\n"
        "#no-space\n    # indented code\n   ### Three spaces ok ###\n####### seven\n#\n## C#\n"
    )
    hs = headings(text)
    assert [(h.level, h.title) for h in hs] == [(3, "Three spaces ok"), (2, "C#")]
    assert "Setext title" in first_paragraph(text)  # setext text stays paragraph text


def test_duplicate_titles_get_unique_slugs_and_paths_deterministically():
    text = (
        "## Steps\n### Verify\n### Verify\n## Steps\n### Verify\n## Steps 2\n## steps-2\n## A/B\n"
    )
    hs = headings(text)
    assert [h.slug for h in hs] == [
        "steps",
        "verify",
        "verify-2",
        "steps-2",
        "verify-3",
        "steps-2-2",
        "steps-2-3",
        "a-b",
    ]
    assert [h.path for h in hs] == [
        "Steps",
        "Steps/Verify",
        "Steps/Verify (2)",
        "Steps (2)",
        "Steps (2)/Verify",
        "Steps 2",
        "steps-2",
        "A\\/B",
    ]
    assert len({h.slug for h in hs}) == len({h.path for h in hs}) == len(hs)
    assert headings(text) == hs  # same text, same answer
    assert headings("# !!!\n")[0].slug == "heading"


def test_section_extent_runs_to_the_next_heading_of_the_same_or_higher_level():
    hs = {h.path: h for h in headings(DOC)}
    dec = hs["Example page/Decision"]
    sec = DOC[dec.start : dec.end]
    assert sec.startswith("## Decision\n") and "### Consequences" in sec
    assert "## Alternatives" not in sec and dec.chars == len(sec)
    alt = hs["Example page/Alternatives"]
    assert DOC[alt.start : alt.end].endswith("~~~\n") and alt.end == len(DOC)
    assert hs["Example page"].end == len(DOC)
    empty = headings("## A\ntext\n#\n## B\n")  # an empty heading still ends the section
    assert [h.title for h in empty] == ["A", "B"] and empty[0].chars == len("## A\ntext\n")


def test_find_section_is_exact_by_slug_or_full_path():
    hs = headings(DOC)
    assert [h.slug for h in find_section(hs, "decision")] == ["decision"]
    assert [h.slug for h in find_section(hs, "Example page/Decision")] == ["decision"]
    for near in ("Decision", "DECISION", "decis", " decision", "Example page/decision"):
        assert find_section(hs, near) == []
    clash = headings("## alpha\n## Beta\n### alpha\n")
    # "alpha" is the first heading's slug and path; the third's slug is alpha-2: one match
    assert [h.path for h in find_section(clash, "alpha")] == ["alpha"]
    same = headings("## x-y\n## X Y\n")  # slugs x-y, x-y-2: "x-y" is the first's slug and path
    assert [h.title for h in find_section(same, "x-y")] == ["x-y"]  # one heading, counted once
    nested = headings("## beta\n## gamma\n### Beta\n")
    assert [h.slug for h in find_section(nested, "gamma/Beta")] == ["beta-2"]
    # ambiguous: "one-x" is the nested heading's slug and the second top-level heading's path
    split = headings("## top\n### one-x\n## one-x\n")
    assert [h.path for h in find_section(split, "one-x")] == ["top/one-x", "one-x"]


@pytest.mark.parametrize(
    ("value", "problem"),
    [
        ("A fine summary.", None),
        ("x" * MAX_SUMMARY_CHARS, None),
        ("x" * (MAX_SUMMARY_CHARS + 1), "at most 160"),
        ("two\nlines", "single line"),
        ("carriage\rreturn", "single line"),
        ("tab\there", "control characters"),
        ("bell\x07", "control characters"),
        ("", "non-empty"),
        ("   ", "non-empty"),
        (None, "non-empty"),
        (42, "non-empty"),
        (" padded", "whitespace"),
    ],
)
def test_check_summary(value, problem):
    got = check_summary(value)
    assert (got is None) if problem is None else (problem in got)
