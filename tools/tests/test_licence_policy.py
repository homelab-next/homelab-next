# SPDX-License-Identifier: Apache-2.0
"""ADR-0011 decision 4 and CI's dependency review say the same thing: every copyleft family the
ADR refuses for linked code (GPL, AGPL, SSPL) is denied, LGPL is not, and each package exempted
from the licence check is a separately run tool that ``NOTICE`` names and ``homelabnext/`` never
imports."""

from __future__ import annotations

import ast
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
ADR = ROOT / "docs" / "adr" / "0011-public-private-split-and-licensing.md"
#: the import name of each exempted PyPI package (``pkg:pypi/<name>``)
IMPORT_NAME = {"ansible-core": "ansible"}


def _review_step() -> dict:
    ci = yaml.safe_load((ROOT / ".github" / "workflows" / "ci.yml").read_text())
    (step,) = [
        s
        for s in ci["jobs"]["dependency-review"]["steps"]
        if str(s.get("uses", "")).startswith("actions/dependency-review-action@")
    ]
    return step["with"]


def _listed(value) -> list[str]:
    return [x.strip() for x in str(value or "").split(",") if x.strip()]


def _refused_families() -> list[str]:
    """The licence families the ADR's linked-code rule names: ``(GPL, AGPL, SSPL)``."""
    m = re.search(r"copyleft licence \(([^)]+)\) is\s+refused", ADR.read_text())
    assert m, "ADR-0011 decision 4 no longer names the refused copyleft families"
    return [x.strip() for x in m.group(1).split(",")]


def test_every_family_the_adr_refuses_is_denied_and_lgpl_is_not():
    denied = _listed(_review_step().get("deny-licenses"))
    families = _refused_families()
    assert set(families) >= {"GPL", "AGPL", "SSPL"}
    for fam in families:
        assert any(d.startswith(f"{fam}-") for d in denied), f"{fam} is not in deny-licenses"
    assert not [d for d in denied if d.startswith("LGPL")], "LGPL is allowed unmodified"


def test_each_exempted_package_is_a_separately_run_tool_named_in_notice():
    notice = (ROOT / "NOTICE").read_text()
    section = notice.split("Separately run software", 1)
    assert len(section) == 2, "NOTICE has no 'Separately run software' section"
    allowed = _listed(_review_step().get("allow-dependencies-licenses"))
    for purl in allowed:
        assert purl.startswith("pkg:pypi/"), purl
        name = purl.removeprefix("pkg:pypi/")
        assert name in section[1], f"{name} is exempted in CI but not named in NOTICE"
        assert name in ADR.read_text(), f"{name} is exempted in CI but not named in ADR-0011"
        mod = IMPORT_NAME[name]
        for path in (ROOT / "homelabnext").rglob("*.py"):
            for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
                names = (
                    [a.name for a in node.names]
                    if isinstance(node, ast.Import)
                    else [node.module or ""]
                    if isinstance(node, ast.ImportFrom) and node.level == 0
                    else []
                )
                assert not [n for n in names if n == mod or n.startswith(mod + ".")], (
                    f"{path.relative_to(ROOT)} imports {mod}: a linked copyleft dependency"
                )
