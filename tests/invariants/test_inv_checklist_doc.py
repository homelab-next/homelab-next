# SPDX-License-Identifier: Apache-2.0
import pathlib
import re

from homelabnext.invariants.plugins.pillar_x import SERVER_ONLY

DOC = pathlib.Path(__file__).resolve().parents[2] / "docs" / "checklist.md"
ROW = re.compile(r"^\| ([A-Z]-\d{2}) \| (.+?) \| (.+) \| (PUBLIC-NOW|SERVER) \|$")


def rows():
    return [m.groups() for line in DOC.read_text().splitlines() if (m := ROW.match(line))]


def test_checklist_is_complete_and_well_formed():
    rs = rows()
    ids = [r[0] for r in rs]
    assert len(ids) >= 130 and len(ids) == len(set(ids))
    assert all(len(r[2]) > 15 for r in rs), "every row needs a real observable"
    assert {i[0] for i in ids} >= set("FCTSDOPRQMAGKELX")


def test_every_non_header_table_line_parses():
    bad = [
        line
        for line in DOC.read_text().splitlines()
        if line.startswith("| ") and not ROW.match(line) and not line.startswith("| ID ")
    ]
    assert bad == []


def test_pillar_x_rows_match_plugins():
    by_id = {r[0]: r[3] for r in rows()}
    assert sorted(i for i in by_id if i.startswith("X-")) == [f"X-0{n}" for n in range(1, 9)]
    for i, tag in by_id.items():
        if i.startswith("X-"):
            assert (tag == "SERVER") == (i in SERVER_ONLY), i


def test_totals_line_matches_rows():
    rs = rows()
    m = re.search(
        r"\*\*Totals:\*\* (\d+) criteria across (\d+) pillars; (\d+) PUBLIC-NOW, (\d+) SERVER",
        DOC.read_text(),
    )
    assert m and (int(m[1]), int(m[3]), int(m[4])) == (
        len(rs),
        sum(r[3] == "PUBLIC-NOW" for r in rs),
        sum(r[3] == "SERVER" for r in rs),
    )
