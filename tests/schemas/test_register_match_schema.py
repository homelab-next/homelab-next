# SPDX-License-Identifier: Apache-2.0
"""registers/lesson 2.2 and registers/runbook 2.3 (additive): an optional ``match``, the bounded
matcher the orchestrator matches a job's task against (orchestrator/internal/lessons).  Each is
frozen at its own version and additive over the version before it."""

import json
from pathlib import Path

import pytest
import schema_check as sc

ROOT = Path(__file__).resolve().parents[2]
REG = sc.build_registry(ROOT)


@pytest.mark.parametrize(
    ("name", "old", "new"), [("lesson", "2.1", "2.2"), ("runbook", "2.2", "2.3")]
)
def test_match_is_additive_and_frozen(name, old, new):
    current = json.loads((ROOT / f"schemas/registers/{name}.schema.json").read_text())
    assert current["$id"].endswith(f"/registers/{name}/{new}")
    frozen = json.loads((ROOT / f"schemas/_frozen/{new}/registers/{name}.schema.json").read_text())
    assert frozen == current
    before = json.loads((ROOT / f"schemas/_frozen/{old}/registers/{name}.schema.json").read_text())
    assert "match" not in before["properties"] and "match" in current["properties"]
    assert sc.is_additive(before, current) == []


@pytest.mark.parametrize(
    ("match", "ok"),
    [
        ({"keywords": ["stale cache"]}, True),
        ({"paths": ["roles/web_proxy/", ".github/"]}, True),
        ({"keywords": ["stale cache"], "paths": ["roles/"]}, True),
        ({}, False),
        ({"regex": "stale.*"}, False),
        ({"keywords": ["ab"]}, False),
        ({"keywords": ["abc"]}, False),
        ({"keywords": ["stale\ncache"]}, False),
        ({"keywords": ["a" * 81]}, False),
        ({"paths": ["/abs/"]}, False),
        ({"paths": ["../up/"]}, False),
        ({"paths": ["a/../b"]}, False),
        ({"paths": ["./a"]}, False),
        ({"paths": ["a//b"]}, False),
        ({"paths": ["a\\b"]}, False),
    ],
)
def test_match_is_bounded(match, ok):
    lesson = json.loads((ROOT / "schemas/registers/examples/lesson.open.json").read_text())
    schema = json.loads((ROOT / "schemas/registers/lesson.schema.json").read_text())
    errors = sc.errors_for(schema, {**lesson, "match": match}, REG)
    assert (errors == []) == ok, errors
