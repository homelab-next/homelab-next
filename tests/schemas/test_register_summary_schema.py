# SPDX-License-Identifier: Apache-2.0
"""The `summary` field of registers/lesson 2.1 and registers/runbook 2.2 (ADR-0032): one line of
at most 160 characters, ordinary non-ASCII text accepted, control and invisible format
characters refused, and a final newline refused even by a validator whose ``$`` matches before
one (Python's ``re``, which jsonschema uses)."""

import json
from pathlib import Path

import pytest
import schema_check as sc

from homelabnext.context.levels import check_summary

ROOT = Path(__file__).resolve().parents[2]
REG = sc.build_registry(ROOT)
SCHEMAS = {
    name: json.loads((ROOT / f"schemas/registers/{name}.schema.json").read_text())
    for name in ("lesson", "runbook")
}
EXAMPLES = {
    "lesson": json.loads((ROOT / "schemas/registers/examples/lesson.controlled.json").read_text()),
    "runbook": json.loads((ROOT / "schemas/registers/examples/runbook.valid.json").read_text()),
}


def _errors(kind: str, summary) -> list[str]:
    return sc.errors_for(SCHEMAS[kind], {**EXAMPLES[kind], "summary": summary}, REG)


@pytest.mark.parametrize("kind", ["lesson", "runbook"])
@pytest.mark.parametrize(
    "ok", ["Plain ASCII summary.", "Café and a no-break\xa0space", "x" * 160, "日本"]
)
def test_ordinary_text_is_accepted_by_schema_and_lint(kind, ok):
    assert _errors(kind, ok) == [] and check_summary(ok) is None


@pytest.mark.parametrize("kind", ["lesson", "runbook"])
@pytest.mark.parametrize(
    "bad",
    [
        "esc\x1b[0m",
        "nul\x00",
        "del\x7f",
        "c1\x85",
        "soft\xadhyphen",
        "alm\u061c",
        "zwsp\u200b",
        "rlm\u200f",
        "ls\u2028x",
        "ps\u2029x",
        "rlo\u202eevil",
        "wj\u2060",
        "lri\u2066",
        "bom\ufeff",
        "trailing newline\n",
        "x" * 161,
        "",
    ],
)
def test_control_invisible_and_multi_line_summaries_are_refused_by_schema_and_lint(kind, bad):
    assert _errors(kind, bad) != []
    assert check_summary(bad) is not None


def test_the_newline_guard_is_needed_under_the_python_validator():
    """``$`` in Python's ``re`` matches before a final newline: without ``(?!\\n)`` the same
    character class would accept ``"x\\n"``.  The guard is what refuses it."""
    pattern = SCHEMAS["lesson"]["properties"]["summary"]["pattern"]
    assert pattern.endswith("$(?!\\n)")
    unguarded = {"type": "string", "pattern": pattern.removesuffix("(?!\\n)")}
    assert sc.errors_for(unguarded, "x\n", REG) == []
    assert sc.errors_for({"type": "string", "pattern": pattern}, "x\n", REG) != []
