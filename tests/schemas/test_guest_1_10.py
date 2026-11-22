# SPDX-License-Identifier: Apache-2.0
"""platform/guest 1.10 (additive): ``cloudinit.instance_id``, the instance-id a running VM already
has, so re-rendering its meta-data never presents cloud-init a new instance (LL-570)."""

import json
from pathlib import Path

import pytest
import schema_check as sc
import yaml

ROOT = Path(__file__).resolve().parents[2]
REG = sc.build_registry(ROOT)
CURRENT = json.loads((ROOT / "schemas/platform/guest.schema.json").read_text())
FROZEN_19 = json.loads((ROOT / "schemas/_frozen/1.9/platform/guest.schema.json").read_text())
FROZEN_110 = json.loads((ROOT / "schemas/_frozen/1.10/platform/guest.schema.json").read_text())
FIXTURE = Path(__file__).parent / "fixtures" / "guest.1_10.instance-id.yml"


def test_version_is_1_10_and_frozen():
    assert CURRENT["$id"].endswith("/platform/guest/1.10")
    assert sc.same_version_problems(FROZEN_110, CURRENT) == []
    assert sc.is_additive(FROZEN_19, CURRENT) == []


def test_a_1_10_document_validates_against_1_10_only():
    doc = yaml.safe_load(FIXTURE.read_text())
    assert sc.errors_for(CURRENT, doc, REG) == []
    assert sc.errors_for(FROZEN_19, doc, REG) != []


@pytest.mark.parametrize("value", ["", "a b", "-x", 7, None, "x" * 129])
def test_a_bad_instance_id_is_refused(value):
    doc = yaml.safe_load(FIXTURE.read_text())
    doc["cloudinit"]["instance_id"] = value
    assert sc.errors_for(CURRENT, doc, REG) != []
