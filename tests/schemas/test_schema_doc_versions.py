# SPDX-License-Identifier: Apache-2.0
"""A schema version a page states as current is the schema's ``$id`` version.

Pages name schemas two ways: by file (``model_roles.json`` (1.4)) and by ``$id`` name
(``agent/profile`` (1.5)).  Either one followed by ``(X.Y)``, ``(X.Y, ...`` or ``(version X.Y,``
is a claim about the live schema; a minor bump that leaves it behind is caught here, not by a
reader.  History is written as "1.2 adds ..." in prose, outside that form."""

import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
#: every page but the ADRs: an ADR is append-only and names the version its decision was made on
PAGES = sorted(
    [*(ROOT / "schemas").glob("*/README.md"), *(ROOT / "docs").rglob("*.md")],
    key=lambda p: p.as_posix(),
)
PAGES = [p for p in PAGES if (ROOT / "docs" / "adr") not in p.parents]
BY_FILE = re.compile(
    r"`(?:[a-z_]+/)*([a-z_.-]+\.(?:schema\.)?json)` \((?:version )?(\d+\.\d+)[,;)]"
)
BY_NAME = re.compile(r"`([a-z_]+)/([a-z_.-]+)` \((?:version )?(\d+\.\d+)[,;)]")


def _version(path: Path) -> str:
    return json.loads(path.read_text(encoding="utf-8"))["$id"].rsplit("/", 1)[-1]


def _live_by_file() -> dict[str, list[Path]]:
    out: dict[str, list[Path]] = {}
    for p in (ROOT / "schemas").glob("*/*.json"):
        if not p.parent.name.startswith("_"):
            out.setdefault(p.name, []).append(p)
    return out


def claims(page: Path):
    """``(line, text, schema file, stated version)`` for every version claim on ``page``."""
    files = _live_by_file()
    for n, line in enumerate(page.read_text(encoding="utf-8").splitlines(), 1):
        for m in BY_FILE.finditer(line):
            found = files.get(m.group(1), [])
            if page.parent.parent == ROOT / "schemas":  # a schema README: its own directory first
                found = [p for p in found if p.parent == page.parent] or found
            if len(found) == 1:
                yield n, m.group(0), found[0], m.group(2)
        for m in BY_NAME.finditer(line):
            d = ROOT / "schemas" / m.group(1)
            for p in (d / f"{m.group(2)}.schema.json", d / f"{m.group(2)}.json"):
                if p.is_file():
                    yield n, m.group(0), p, m.group(3)
                    break


@pytest.mark.parametrize("page", PAGES, ids=lambda p: p.relative_to(ROOT).as_posix())
def test_a_stated_schema_version_is_the_live_one(page):
    wrong = [
        f"{page.relative_to(ROOT)}:{n}: {text} but the schema is {_version(p)}"
        for n, text, p, stated in claims(page)
        if _version(p) != stated
    ]
    assert wrong == []


def test_the_claim_forms_are_recognised():
    """The two forms this test reads, on lines like the ones it once missed."""
    assert BY_FILE.search("| `model_roles.json` (1.3) | alias table")
    assert BY_FILE.search("`schemas/platform/guest.schema.json` (version 1.4, additive")
    assert BY_NAME.search("except `agent/profile` (1.1, additive: `reads_untrusted`")
    assert not BY_NAME.search("`agent/profile` 1.2 adds an include")
