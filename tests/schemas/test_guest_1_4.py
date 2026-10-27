# SPDX-License-Identifier: Apache-2.0
"""platform/guest 1.4 (additive): ``status`` (planned, live or retired; default live) and a
one-line ``description``, both informational for the generated maps (ADR-0018).  1.4-only
documents live in ``fixtures/`` (see the 1.1 test)."""

import json
from pathlib import Path

import pytest
import schema_check as sc
import yaml

ROOT = Path(__file__).resolve().parents[2]
REG = sc.build_registry(ROOT)
CURRENT = json.loads((ROOT / "schemas/platform/guest.schema.json").read_text())
FROZEN_13 = json.loads((ROOT / "schemas/_frozen/1.3/platform/guest.schema.json").read_text())
FROZEN_14 = json.loads((ROOT / "schemas/_frozen/1.4/platform/guest.schema.json").read_text())
FIXTURES = sorted((Path(__file__).parent / "fixtures").glob("guest.1_4.*.yml"))


def test_1_4_is_frozen_and_current_is_additive_over_it():
    assert FROZEN_14["$id"].endswith("/platform/guest/1.4")
    assert sc.is_additive(FROZEN_13, FROZEN_14) == []
    assert sc.is_additive(FROZEN_14, CURRENT) == []


def test_fixtures_exist():
    assert len(FIXTURES) >= 2


@pytest.mark.parametrize("path", FIXTURES, ids=lambda p: p.name)
def test_1_4_documents_validate_against_1_4_only(path):
    doc = yaml.safe_load(path.read_text())
    assert sc.errors_for(CURRENT, doc, REG) == []
    assert sc.errors_for(FROZEN_13, doc, REG) != []


def test_status_defaults_to_live_and_both_fields_are_optional():
    props = CURRENT["properties"]
    assert props["status"]["default"] == "live"
    assert props["status"]["enum"] == ["planned", "live", "retired"]
    assert "status" not in CURRENT["required"] and "description" not in CURRENT["required"]


@pytest.mark.parametrize(
    "extra",
    [{"status": "maybe"}, {"description": ""}, {"description": "two\nlines"}, {"status": None}],
    ids=["status-unknown", "description-empty", "description-newline", "status-null"],
)
def test_bad_status_or_description_is_refused(extra):
    doc = yaml.safe_load((Path(__file__).parent / "fixtures" / "guest.1_4.planned.yml").read_text())
    doc.update(extra)
    assert sc.errors_for(CURRENT, doc, REG) != []
