# SPDX-License-Identifier: Apache-2.0
"""platform/guest 1.3 (additive): ``baseline`` (named defense baselines, per-guest ``add`` and
``remove``, or a documented ``exemption``; ADR-0016).  1.3-only documents live in ``fixtures/``
(see the 1.1 test), and the baseline set itself is ``platform/baseline_set`` 1.0."""

import json
from pathlib import Path

import pytest
import schema_check as sc
import yaml

ROOT = Path(__file__).resolve().parents[2]
REG = sc.build_registry(ROOT)
CURRENT = json.loads((ROOT / "schemas/platform/guest.schema.json").read_text())
FROZEN_12 = json.loads((ROOT / "schemas/_frozen/1.2/platform/guest.schema.json").read_text())
FROZEN_13 = json.loads((ROOT / "schemas/_frozen/1.3/platform/guest.schema.json").read_text())
FIXTURES = sorted((Path(__file__).parent / "fixtures").glob("guest.1_3.*.yml"))


def test_1_3_is_frozen_and_current_is_additive_over_it():
    assert FROZEN_13["$id"].endswith("/platform/guest/1.3")
    assert sc.is_additive(FROZEN_12, FROZEN_13) == []
    assert sc.is_additive(FROZEN_13, CURRENT) == []


def test_fixtures_exist():
    assert len(FIXTURES) >= 2


@pytest.mark.parametrize("path", FIXTURES, ids=lambda p: p.name)
def test_1_3_documents_validate_against_1_3_only(path):
    doc = yaml.safe_load(path.read_text())
    assert sc.errors_for(CURRENT, doc, REG) == []
    assert sc.errors_for(FROZEN_12, doc, REG) != []


def test_baseline_is_optional_in_the_schema():
    # the requirement "every guest has one" holds only when a baseline set exists, so it is a
    # semantic rule (homelabnext.compute.baselines), never a schema `required`
    assert "baseline" not in CURRENT["required"]
