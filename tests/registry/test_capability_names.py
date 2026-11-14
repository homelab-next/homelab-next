# SPDX-License-Identifier: Apache-2.0
"""The platform's capability names live in one small module (``homelabnext.capability_names``):
registry validation reads them without importing the MCP catalog or the conformance harness, and
every capability package code reaches by a literal name is one of them, so an ``eval`` or
``retiring`` row can never take a name some consumer resolves (ADR-0039 decision 2)."""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest

from homelabnext import capability_names as cn
from homelabnext.conform import registry as conform_registry
from homelabnext.mcp.servers import known_capabilities
from homelabnext.registry.model import env_var_name, platform_capabilities

ROOT = Path(__file__).resolve().parents[2]
PACKAGE = ROOT / "homelabnext"
#: ``HNX_ENDPOINT_<CAPABILITY>`` written out (a default endpoint variable)
ENDPOINT_VAR = re.compile(r"\bHNX_ENDPOINT_([A-Z0-9]+(?:_[A-Z0-9]+)*)\b")
#: ``resolve("<cap>")``, ``.resolve("<cap>")`` and ``by_capability("<cap>")`` with a literal name
LITERAL_LOOKUP = re.compile(r"\b(?:resolve|by_capability)\(\s*[\"']([a-z][a-z0-9-]*)[\"']")


def _package_sources() -> list[Path]:
    return sorted(p for p in PACKAGE.rglob("*.py") if "__pycache__" not in p.parts)


def test_the_shared_list_is_the_one_the_catalog_and_the_harness_read():
    assert conform_registry.CAPABILITIES is cn.CAPABILITIES
    assert conform_registry.EXTENDED is cn.EXTENDED
    assert platform_capabilities() == cn.platform_capabilities()
    assert platform_capabilities() == {c.removeprefix("cap:") for c in known_capabilities()}


def test_registry_validation_imports_neither_the_catalog_nor_the_harness():
    code = (
        "import sys\n"
        "from homelabnext.registry.model import load\n"
        f"load({str(ROOT / 'examples' / 'services.yml')!r})\n"
        "bad = sorted(m for m in sys.modules if m.startswith(('homelabnext.mcp', "
        "'homelabnext.conform')))\n"
        "print(','.join(bad))\n"
    )
    res = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, check=True, cwd=ROOT
    )
    assert res.stdout.strip() == ""


def test_every_endpoint_variable_written_in_package_code_is_a_platform_capability():
    known = {env_var_name(c): c for c in platform_capabilities()}
    found = {
        (p.relative_to(ROOT).as_posix(), f"HNX_ENDPOINT_{m.group(1)}")
        for p in _package_sources()
        for m in ENDPOINT_VAR.finditer(p.read_text(encoding="utf-8"))
    }
    assert found, "the scan found no HNX_ENDPOINT_* literal: the pattern is broken"
    assert sorted(f"{path}: {var}" for path, var in found if var not in known) == []


def test_every_literal_capability_lookup_in_package_code_is_a_platform_capability():
    known = platform_capabilities()
    found = {
        (p.relative_to(ROOT).as_posix(), m.group(1))
        for p in _package_sources()
        for m in LITERAL_LOOKUP.finditer(p.read_text(encoding="utf-8"))
    }
    assert found, "the scan found no literal lookup: the pattern is broken"
    assert sorted(f"{path}: {cap}" for path, cap in found if cap not in known) == []


@pytest.mark.parametrize(
    ("text", "hit"),
    [
        ('resolve("object-store", resolver=r)', "object-store"),
        ("reg.by_capability('agent-audit')", "agent-audit"),
        ("Resolver(reg).resolve( 'nowhere' )", "nowhere"),
        ("resolve(cap)", None),
    ],
)
def test_the_lookup_pattern(text, hit):
    m = LITERAL_LOOKUP.search(text)
    assert (m.group(1) if m else None) == hit
