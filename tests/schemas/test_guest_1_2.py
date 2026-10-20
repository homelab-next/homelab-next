# SPDX-License-Identifier: Apache-2.0
"""platform/guest 1.2 (additive): ``cloudinit.sudo``, ``firewall_rules.policy_out`` and
``firewall_rules.outbound_allow``.  1.2-only documents live in ``fixtures/`` (see the 1.1 test)."""

import json
from pathlib import Path

import pytest
import schema_check as sc
import yaml

ROOT = Path(__file__).resolve().parents[2]
REG = sc.build_registry(ROOT)
CURRENT = json.loads((ROOT / "schemas/platform/guest.schema.json").read_text())
FROZEN_11 = json.loads((ROOT / "schemas/_frozen/1.1/platform/guest.schema.json").read_text())
FROZEN_12 = json.loads((ROOT / "schemas/_frozen/1.2/platform/guest.schema.json").read_text())
FIXTURES = sorted((Path(__file__).parent / "fixtures").glob("guest.1_2.*.yml"))


def test_1_2_is_frozen_and_current_is_additive_over_it():
    assert FROZEN_12["$id"].endswith("/platform/guest/1.2")
    assert sc.is_additive(FROZEN_11, FROZEN_12) == []
    assert sc.is_additive(FROZEN_12, CURRENT) == []


@pytest.mark.parametrize("path", FIXTURES, ids=lambda p: p.name)
def test_1_2_documents_validate_against_1_2_only(path):
    doc = yaml.safe_load(path.read_text())
    assert sc.errors_for(FROZEN_12, doc, REG) == []
    assert sc.errors_for(CURRENT, doc, REG) == []
    assert sc.errors_for(FROZEN_11, doc, REG) != []


def test_safe_defaults():
    ci = CURRENT["properties"]["cloudinit"]["properties"]
    assert ci["sudo"]["default"] == "none"
    fw = CURRENT["properties"]["firewall_rules"]["properties"]
    assert fw["policy_out"]["default"] == "ACCEPT"  # unchanged; DROP is the opt-in
