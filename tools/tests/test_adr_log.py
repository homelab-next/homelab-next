# SPDX-License-Identifier: Apache-2.0
"""The ADR log: five headings each, a status, sequential numbering apart from reserved numbers."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from homelabnext.context.levels import front_matter

ADR_DIR = Path(__file__).resolve().parents[2] / "docs" / "adr"
HEADINGS = ["Status", "Context", "Decision", "Consequences", "Alternatives"]
STATUSES = {"proposed", "accepted", "rejected"}
ADRS = sorted(p for p in ADR_DIR.glob("[0-9][0-9][0-9][0-9]-*.md"))


#: numbers held by open pull requests, so a later ADR does not take them (each reason names the
#: holder); an entry goes when its ADR merges, and one whose ADR exists is an error
RESERVED = {
    26: "the orchestrator as a component of this repository (planned with it)",
}


def test_sequential_adrs_apart_from_reserved_numbers():
    numbers = [int(p.name[:4]) for p in ADRS]
    assert not set(numbers) & set(RESERVED), "a reserved number now has its ADR: drop the entry"
    assert sorted(numbers + list(RESERVED)) == list(range(1, max(numbers) + 1))


@pytest.mark.parametrize("path", ADRS, ids=lambda p: p.name[:4])
def test_adr_has_five_headings_and_status(path: Path):
    raw = path.read_text()
    # a leading front-matter block (the L0 summary) is not the log
    text = raw[front_matter(raw)[1] :]
    assert re.match(rf"# ADR-{path.name[:4]}: \S", text), "title must be '# ADR-NNNN: ...'"
    status = re.search(r"^- \*\*Status:\*\* (.+)$", text, re.M)
    assert status, "missing Status line"
    assert status.group(1).split()[0] in STATUSES or status.group(1).startswith(
        "superseded by ADR-"
    )
    h2 = re.findall(r"^## (.+)$", text, re.M)
    assert h2 == HEADINGS[1:], f"expected sections {HEADINGS[1:]}, got {h2}"
    for name in HEADINGS[1:]:
        body = text.split(f"## {name}\n", 1)[1].split("\n## ", 1)[0]
        assert len(body.strip()) > 40, f"{name} is empty"


def test_every_adr_and_the_template_carry_an_l0_summary():
    """ADR-0032: an ADR opens with front-matter whose summary passes the lint, before its title;
    the template shows it, so a new ADR starts with one."""
    from homelabnext.context.levels import check_summary

    for path in [*ADRS, ADR_DIR / "_template.md"]:
        fm, body = front_matter(path.read_text())
        assert fm and check_summary(fm.get("summary")) is None, path.name
        assert path.read_text()[body:].startswith("# ADR-"), path.name


def test_negative_missing_heading_is_detected():
    broken = "# ADR-0099: x\n\n- **Status:** proposed\n\n## Context\n\nhello\n"
    assert re.findall(r"^## (.+)$", broken, re.M) != HEADINGS[1:]


def test_index_names_every_reserved_number():
    """A reader of the index sees why a number is missing, not only the test that holds it."""
    index = (ADR_DIR / "README.md").read_text()
    for n in RESERVED:
        assert f"**{n:04d}**" in index, f"docs/adr/README.md does not name reserved ADR-{n:04d}"


def test_index_lists_every_adr():
    index = (ADR_DIR / "README.md").read_text()
    for p in ADRS:
        assert p.name in index


# --------------------------------------------------------------------------- links between ADRs
#: header fields that link ADRs: each holds ADR ids only (``ADR-0017, ADR-0033``); ``Amends`` and
#: ``Amended-by`` are a reciprocal pair, ``Depends-on`` names the ADRs a decision rests on
LINK_FIELDS = ("Amends", "Amended-by", "Depends-on")
_FIELD = re.compile(r"^- \*\*(?P<name>[A-Za-z-]+)(?: \([^)]*\))?:\*\* ?(?P<value>.*)$")
_ADR_ID = re.compile(r"ADR-(\d{4})")


def header(text: str) -> dict[str, str]:
    """The header fields of an ADR (the bullets between the title and the first section), each
    value with its continuation lines joined."""
    text = text[front_matter(text)[1] :]
    fields: dict[str, str] = {}
    name = None
    for line in text.split("\n## ", 1)[0].splitlines()[1:]:
        if m := _FIELD.match(line):
            name = m["name"]
            fields[name] = m["value"].strip()
        elif name and line.startswith("  ") and line.strip():
            fields[name] += " " + line.strip()
        elif line.strip():
            name = None
    return fields


def link_problems(adrs: dict[int, dict[str, str]]) -> list[str]:
    """Every broken ADR link of ``adrs`` (number -> header fields)."""
    out = []
    links: dict[tuple[int, str], set[int]] = {}
    for n, fields in sorted(adrs.items()):
        for name in LINK_FIELDS:
            value = fields.get(name)
            if value is None:
                continue
            items = [v.strip() for v in value.split(",")]
            if not all(re.fullmatch(r"ADR-\d{4}", v) for v in items):
                out.append(f"ADR-{n:04d}: {name} holds ADR ids only, comma-separated: {value!r}")
                continue
            ids = {int(v[4:]) for v in items}
            for t in sorted(ids - set(adrs)):
                out.append(f"ADR-{n:04d}: {name} names ADR-{t:04d}, which does not exist")
            if n in ids:
                out.append(f"ADR-{n:04d}: {name} names itself")
            links[(n, name)] = ids & set(adrs) - {n}
        # the prose Amended line names its amending ADRs; each is listed in Amended-by
        prose = {int(x) for x in _ADR_ID.findall(fields.get("Amended", ""))} - {n}
        for t in sorted(prose - links.get((n, "Amended-by"), set())):
            out.append(f"ADR-{n:04d}: its Amended line names ADR-{t:04d}, missing from Amended-by")
    for (n, name), ids in sorted(links.items()):
        back = {"Amends": "Amended-by", "Amended-by": "Amends"}.get(name)
        for t in sorted(ids):
            if back and n not in links.get((t, back), set()):
                out.append(
                    f"ADR-{n:04d}: {name} ADR-{t:04d}, but ADR-{t:04d} has no {back} ADR-{n:04d}"
                )
            if (
                name == "Depends-on"
                and _state(adrs[n]) == "accepted"
                and _state(adrs[t]) != "accepted"
            ):
                out.append(
                    f"ADR-{n:04d} is accepted but depends on ADR-{t:04d}, which is "
                    f"{_state(adrs[t])}: accept that one first, or drop the dependency"
                )
    return out


def _state(fields: dict[str, str]) -> str:
    return (fields.get("Status") or "").split(" ", 1)[0]


def test_adr_links_are_reciprocal_and_rest_on_accepted_decisions():
    adrs = {int(p.name[:4]): header(p.read_text()) for p in ADRS}
    assert link_problems(adrs) == []


def test_the_amendments_are_linked_both_ways():
    """The amendments the ADRs record in prose carry the machine-readable pair."""
    adrs = {int(p.name[:4]): header(p.read_text()) for p in ADRS}
    assert adrs[13]["Amended-by"] == "ADR-0017, ADR-0033"
    assert adrs[19]["Amends"] == "ADR-0014, ADR-0015"


@pytest.mark.parametrize(
    ("adrs", "problem"),
    [
        ({1: {"Amended-by": "ADR-0002"}, 2: {}}, "ADR-0002 has no Amends ADR-0001"),
        ({1: {"Amends": "ADR-0002"}, 2: {}}, "ADR-0002 has no Amended-by ADR-0001"),
        ({1: {"Amends": "ADR-0009"}}, "names ADR-0009, which does not exist"),
        ({1: {"Depends-on": "ADR-0001"}}, "Depends-on names itself"),
        ({1: {"Depends-on": "the broker"}}, "holds ADR ids only"),
        ({1: {"Amended": "2026-10-21 by ADR-0002"}, 2: {}}, "missing from Amended-by"),
        (
            {1: {"Status": "accepted", "Depends-on": "ADR-0002"}, 2: {"Status": "proposed"}},
            "ADR-0001 is accepted but depends on ADR-0002, which is proposed",
        ),
    ],
)
def test_a_broken_link_is_refused(adrs, problem):
    assert any(problem in p for p in link_problems(adrs)), link_problems(adrs)


def test_links_that_hold_pass_and_the_header_parser_joins_continuations():
    text = (
        "---\nsummary: x\n---\n# ADR-0001: x\n\n- **Status:** accepted (by the operator)\n"
        "- **Amended (2026-11-01):** by ADR-0002, see\n  the amendment\n"
        "- **Amended-by:** ADR-0002\n- **Depends-on:** ADR-0002\n\n## Context\n\nx\n"
    )
    fields = header(text)
    assert fields["Amended"] == "by ADR-0002, see the amendment"
    other = {"Status": "accepted (2026-10-31)", "Amends": "ADR-0001"}
    assert link_problems({1: fields, 2: other}) == []
