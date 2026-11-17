# SPDX-License-Identifier: Apache-2.0
"""platform/guest 1.8 (additive): a ``shared_dirs`` item's ``mapping``, the PVE directory mapping
that shares it into a VM by virtiofs.  1.8-only documents live in ``fixtures/``."""

import json
from pathlib import Path

import pytest
import schema_check as sc
import yaml

ROOT = Path(__file__).resolve().parents[2]
REG = sc.build_registry(ROOT)
CURRENT = json.loads((ROOT / "schemas/platform/guest.schema.json").read_text())
FROZEN_17 = json.loads((ROOT / "schemas/_frozen/1.7/platform/guest.schema.json").read_text())
FROZEN_18 = json.loads((ROOT / "schemas/_frozen/1.8/platform/guest.schema.json").read_text())
FIXTURES = sorted((Path(__file__).parent / "fixtures").glob("guest.1_8.*.yml"))


def test_version_is_1_8_and_frozen():
    assert CURRENT["$id"].endswith("/platform/guest/1.8")
    assert sc.same_version_problems(FROZEN_18, CURRENT) == []
    assert sc.is_additive(FROZEN_17, CURRENT) == []


def test_fixtures_exist():
    assert FIXTURES


@pytest.mark.parametrize("path", FIXTURES, ids=lambda p: p.name)
def test_1_8_documents_validate_against_1_8_only(path):
    doc = yaml.safe_load(path.read_text())
    assert sc.errors_for(CURRENT, doc, REG) == []
    assert sc.errors_for(FROZEN_17, doc, REG) != []


@pytest.mark.parametrize("mapping", ["Share", "1share", "a b", "", None, 3])
def test_bad_mapping_is_refused(mapping):
    doc = yaml.safe_load(FIXTURES[0].read_text())
    doc["shared_dirs"][0]["mapping"] = mapping
    assert sc.errors_for(CURRENT, doc, REG) != []
