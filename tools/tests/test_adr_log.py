# SPDX-License-Identifier: Apache-2.0
"""The ADR log: twenty-two records, five headings each, a status, sequential numbering."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ADR_DIR = Path(__file__).resolve().parents[2] / "docs" / "adr"
HEADINGS = ["Status", "Context", "Decision", "Consequences", "Alternatives"]
STATUSES = {"proposed", "accepted", "rejected"}
ADRS = sorted(p for p in ADR_DIR.glob("[0-9][0-9][0-9][0-9]-*.md"))


def test_adrs_are_numbered_in_sequence():
    # 0024 is taken by the MCP catalog ADR (on its own branch); this branch adds 0025
    assert [int(p.name[:4]) for p in ADRS] == [*range(1, 24), 25]


@pytest.mark.parametrize("path", ADRS, ids=lambda p: p.name[:4])
def test_adr_has_five_headings_and_status(path: Path):
    text = path.read_text()
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


def test_negative_missing_heading_is_detected():
    broken = "# ADR-0099: x\n\n- **Status:** proposed\n\n## Context\n\nhello\n"
    assert re.findall(r"^## (.+)$", broken, re.M) != HEADINGS[1:]


def test_index_lists_every_adr():
    index = (ADR_DIR / "README.md").read_text()
    for p in ADRS:
        assert p.name in index
