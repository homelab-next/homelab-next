# SPDX-License-Identifier: Apache-2.0
"""platform/guest 1.9 (additive): ``network.vlan_tag_mode: native``, a NIC on the bridge's native
(untagged) VLAN.  The node's ``native_vlans`` and the one-native-VLAN-per-bridge rule are semantic
(``homelabnext.compute.validate``; tests/compute/test_native_vlan.py).  1.9-only documents live in
``fixtures/``."""

import json
from pathlib import Path

import pytest
import schema_check as sc
import yaml

ROOT = Path(__file__).resolve().parents[2]
REG = sc.build_registry(ROOT)
CURRENT = json.loads((ROOT / "schemas/platform/guest.schema.json").read_text())
FROZEN_18 = json.loads((ROOT / "schemas/_frozen/1.8/platform/guest.schema.json").read_text())
FROZEN_19 = json.loads((ROOT / "schemas/_frozen/1.9/platform/guest.schema.json").read_text())
FIXTURES = sorted((Path(__file__).parent / "fixtures").glob("guest.1_9.*.yml"))


def test_version_is_1_9_and_frozen():
    assert CURRENT["$id"].endswith("/platform/guest/1.9")
    assert sc.same_version_problems(FROZEN_19, CURRENT) == []
    assert sc.is_additive(FROZEN_18, CURRENT) == []


def test_fixtures_exist():
    assert FIXTURES


@pytest.mark.parametrize("path", FIXTURES, ids=lambda p: p.name)
def test_1_9_documents_validate_against_1_9_only(path):
    doc = yaml.safe_load(path.read_text())
    assert sc.errors_for(CURRENT, doc, REG) == []
    assert sc.errors_for(FROZEN_18, doc, REG) != []


@pytest.mark.parametrize("mode", ["tagged", "Native", "", None, 1])
def test_an_unknown_tag_mode_is_refused(mode):
    doc = yaml.safe_load(FIXTURES[0].read_text())
    doc["network"]["vlan_tag_mode"] = mode
    assert sc.errors_for(CURRENT, doc, REG) != []
