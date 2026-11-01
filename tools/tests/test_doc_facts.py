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


def _rows(text: str, prefix: str) -> dict[str, list[str]]:
    """The cells of each table row whose first cell starts with ``prefix``, by that cell."""
    out = {}
    for line in text.splitlines():
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if line.startswith("| ") and re.fullmatch(prefix + r"\d+", cells[0]):
            out[cells[0]] = cells
    return out


def test_every_public_phase_names_where_it_lives():
    phases = _rows((ROOT / "docs" / "build-order.md").read_text(), "P")
    assert len(phases) >= 9
    for phase, cells in phases.items():
        where = re.findall(r"`([^`]+)`", cells[4])
        assert where, f"{phase}: the Where cell names no path ({cells[4]!r})"
        for path in where:
            assert (ROOT / path.split(" ")[0]).exists(), f"{phase}: {path} does not exist"


def test_the_server_phases_carry_the_tlp_exit_criteria():
    """Data is copied only after the label backfill (S-09) and the agent window closes only with
    every model role and profile under a TLP ceiling (O-12), as docs/checklist.md says."""
    checklist = (ROOT / "docs" / "checklist.md").read_text()
    phases = _rows((ROOT / "docs" / "build-order.md").read_text(), "S")
    for phase, row in (("S3", "S-09"), ("S6", "O-12")):
        assert f"| {row} |" in checklist
        assert row in phases[phase][1] and row in phases[phase][-1], (phase, row)


#: the module manifest's overview and its reference pages (docs/modules.md, "Reference pages")
MODULE_PAGES = [ROOT / "docs" / "modules.md", *sorted((ROOT / "docs" / "modules").glob("*.md"))]
#: a page of the module specification is read whole, by people and in agent context packs
MODULE_PAGE_LINES = 250
_MODULE_CITE = re.compile(r"""docs/modules\.md(?:'s)?,? "([A-Za-z`][^"]{1,100})\"""")


def test_module_pages_stay_short():
    assert len(MODULE_PAGES) > 10
    long = {
        p.relative_to(ROOT).as_posix(): n
        for p in MODULE_PAGES
        if (n := len(p.read_text().splitlines())) > MODULE_PAGE_LINES
    }
    assert long == {}, f"split a page over {MODULE_PAGE_LINES} lines: {long}"


def _module_targets() -> list[str]:
    out = []
    for p in MODULE_PAGES:
        for line in p.read_text().splitlines():
            if m := re.match(r"#{1,6} (.+)", line):
                out.append(m[1])
            out += [m[1] for m in re.finditer(r"\*\*([^*]{2,100}?)\.?\*\*", line)]
    return [t.replace("`", "").lower() for t in out]


def _citing_files() -> list[Path]:
    out = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, check=False)
    if out.returncode == 0 and out.stdout:
        names = [n for n in out.stdout.decode().split("\0") if n]
    else:  # an export without .git
        names = [
            p.relative_to(ROOT).as_posix()
            for d in ("docs", "homelabnext", "tools", "tests", "examples", "schemas")
            for p in (ROOT / d).rglob("*")
            if p.is_file()
        ]
    return [ROOT / n for n in names if n != "CHANGELOG.md" and (ROOT / n).is_file()]


def test_module_section_citations_name_a_section_that_exists():
    """``docs/modules.md, "What the loader checks"`` in code, tests and pages resolves to a heading
    (or a paragraph's bold lead) on the overview or one of its reference pages; the citation is a
    second copy of the heading, so a renamed or moved section cannot leave it dangling."""
    targets = _module_targets()
    dangling, seen = [], 0
    for f in _citing_files():
        try:
            text = f.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        if "docs/modules.md" not in text:
            continue
        # citations wrap across lines, inside comments, docstrings and quotes
        flat = re.sub(r"\n[ \t]*(?:#+|//|\*|>)?[ \t]*", " ", text)
        for m in _MODULE_CITE.finditer(flat):
            seen += 1
            cited = m[1].replace("`", "").rstrip(".,;").lower()
            if not any(t.startswith(cited) for t in targets):
                dangling.append(f"{f.relative_to(ROOT)}: {m[1]!r}")
    assert seen > 20
    assert dangling == []
