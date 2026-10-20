# SPDX-License-Identifier: Apache-2.0
"""platform/baseline_set 1.1 (additive): a control's ``apply`` (``guest`` | ``central``) and the
``group`` of its central product host (ADR-0016 decision 7). 1.1-only documents live in
``fixtures/`` (see the guest 1.1 test); the cross-field rules are semantic
(homelabnext.compute.baselines)."""

import json
from pathlib import Path

import pytest
import schema_check as sc
import yaml

ROOT = Path(__file__).resolve().parents[2]
REG = sc.build_registry(ROOT)
CURRENT = json.loads((ROOT / "schemas/platform/baseline_set.schema.json").read_text())
FROZEN_10 = json.loads((ROOT / "schemas/_frozen/1.0/platform/baseline_set.schema.json").read_text())
FROZEN_11 = json.loads((ROOT / "schemas/_frozen/1.1/platform/baseline_set.schema.json").read_text())
FIXTURES = sorted((Path(__file__).parent / "fixtures").glob("baseline_set.1_1.*.yml"))


def test_version_is_1_1_frozen_and_additive():
    assert CURRENT["$id"].endswith("/platform/baseline_set/1.1")
    assert CURRENT == FROZEN_11
    assert sc.is_additive(FROZEN_10, CURRENT) == []


def test_fixtures_exist():
    assert len(FIXTURES) >= 2


@pytest.mark.parametrize("path", FIXTURES, ids=lambda p: p.name)
def test_1_1_documents_validate_against_1_1_only(path):
    doc = yaml.safe_load(path.read_text())
    assert sc.errors_for(CURRENT, doc, REG) == []
    assert sc.errors_for(FROZEN_10, doc, REG) != []


def test_apply_defaults_to_guest_and_is_optional():
    control = CURRENT["$defs"]["control"]
    assert control["properties"]["apply"]["default"] == "guest"
    assert "apply" not in control["required"] and "group" not in control["required"]
