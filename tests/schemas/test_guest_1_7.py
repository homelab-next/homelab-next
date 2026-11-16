# SPDX-License-Identifier: Apache-2.0
"""platform/guest 1.7 (additive): ``gpu.count``, how many devices of the one resource mapping a
guest takes.  The schema holds the range; validation (``homelabnext.compute.validate``) holds
``tensor_parallel <= count``.  1.7-only documents live in ``fixtures/``."""

import json
from pathlib import Path

import pytest
import schema_check as sc
import yaml

ROOT = Path(__file__).resolve().parents[2]
REG = sc.build_registry(ROOT)
CURRENT = json.loads((ROOT / "schemas/platform/guest.schema.json").read_text())
FROZEN_16 = json.loads((ROOT / "schemas/_frozen/1.6/platform/guest.schema.json").read_text())
FROZEN_17 = json.loads((ROOT / "schemas/_frozen/1.7/platform/guest.schema.json").read_text())
FIXTURES = sorted((Path(__file__).parent / "fixtures").glob("guest.1_7.*.yml"))


def test_version_is_1_7_and_frozen():
    assert CURRENT["$id"].endswith("/platform/guest/1.7")
    assert sc.same_version_problems(FROZEN_17, CURRENT) == []
    assert sc.is_additive(FROZEN_16, CURRENT) == []


def test_fixtures_exist():
    assert FIXTURES


@pytest.mark.parametrize("path", FIXTURES, ids=lambda p: p.name)
def test_1_7_documents_validate_against_1_7_only(path):
    doc = yaml.safe_load(path.read_text())
    assert sc.errors_for(CURRENT, doc, REG) == []
    assert sc.errors_for(FROZEN_16, doc, REG) != []


@pytest.mark.parametrize("count", [1, 2, 4, 16])
def test_count_in_range_validates(count):
    doc = yaml.safe_load(FIXTURES[0].read_text())
    doc["gpu"] = {"profile": "accel-a", "resource_mapping": "gpu-a", "count": count}
    assert sc.errors_for(CURRENT, doc, REG) == []


@pytest.mark.parametrize("count", [0, -1, 17, 2.5, "4", None, True])
def test_count_out_of_range_or_not_an_integer_is_refused(count):
    doc = yaml.safe_load(FIXTURES[0].read_text())
    doc["gpu"] = {"profile": "accel-a", "resource_mapping": "gpu-a", "count": count}
    assert sc.errors_for(CURRENT, doc, REG) != []
