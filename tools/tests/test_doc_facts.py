# SPDX-License-Identifier: Apache-2.0
"""Counts and paths the docs state are held to their source of truth, so they cannot go stale.

README once said "Twelve architecture decision records" while docs/adr/ held 24, and
docs/conformance.md cited a test file that had been renamed. A number or a path written into
prose is a second copy of a fact; these tests fail the moment the two disagree.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
ADRS = sorted((ROOT / "docs" / "adr").glob("[0-9][0-9][0-9][0-9]-*.md"))
CODE_PATH = re.compile(r"`((?:tests|tools|conformance|homelabnext)/[\w/.-]+\.py)(?:::[\w\[\]-]+)?`")


def _tracked_docs() -> list[Path]:
    out = subprocess.run(
        ["git", "ls-files", "-z", "--", "README.md", "CONTRIBUTING.md", "docs"],
        cwd=ROOT,
        capture_output=True,
        check=False,
    )
    if out.returncode == 0 and out.stdout:
        names = [n for n in out.stdout.decode().split("\0") if n.endswith(".md")]
        return [ROOT / n for n in names]
    # an export without .git: the same files from the directory walk
    return [ROOT / "README.md", ROOT / "CONTRIBUTING.md", *sorted((ROOT / "docs").rglob("*.md"))]


def test_the_readme_counts_the_adrs():
    text = (ROOT / "README.md").read_text()
    m = re.search(r"^(\d+) architecture decision records live in", text, re.M)
    assert m, "README's Decisions section states how many ADRs there are"
    assert int(m[1]) == len(ADRS)


def test_the_readme_counts_the_capabilities():
    caps = yaml.safe_load((ROOT / "capabilities.yml").read_text())["capabilities"]
    text = (ROOT / "README.md").read_text()
    counts = [int(n) for n in re.findall(r"\b(\d+) capabilit", text)]
    assert counts and set(counts) == {len(caps)}, counts


def test_the_adr_index_reserves_no_number_that_has_its_adr():
    index = (ROOT / "docs" / "adr" / "README.md").read_text()
    taken = {p.name[:4] for p in ADRS}
    for m in re.finditer(r"numbers? ([\d ,and]+?) (?:is|are) reserved", index):
        assert not set(re.findall(r"\d{4}", m[1])) & taken, m[0]


def test_code_paths_named_in_the_docs_exist():
    missing = []
    for doc in _tracked_docs():
        for n, line in enumerate(doc.read_text().splitlines(), 1):
            for m in CODE_PATH.finditer(line):
                if not (ROOT / m[1]).is_file():
                    missing.append(f"{doc.relative_to(ROOT)}:{n}: {m[1]}")
    assert missing == []
