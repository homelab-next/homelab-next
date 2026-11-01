# SPDX-License-Identifier: Apache-2.0
"""status/agents 1.4 (additive): the viewer and approver groups come from the hub's registry
row (ADR-0034), so ``private.viewer_group`` and ``approvals.approver_group`` are optional."""

import json
from pathlib import Path

import schema_check as sc
import yaml

ROOT = Path(__file__).resolve().parents[2]
REG = sc.build_registry(ROOT)
CURRENT = json.loads((ROOT / "schemas/status/agents.schema.json").read_text())
FROZEN_13 = json.loads((ROOT / "schemas/_frozen/1.3/status/agents.schema.json").read_text())
FROZEN_14 = json.loads((ROOT / "schemas/_frozen/1.4/status/agents.schema.json").read_text())
DOC = yaml.safe_load((ROOT / "examples/status/agents.yml").read_text())


def test_version_is_1_4_frozen_and_additive():
    assert CURRENT["$id"].endswith("/status/agents/1.4")
    assert CURRENT == FROZEN_14
    assert sc.is_additive(FROZEN_13, CURRENT) == []


def test_the_example_names_no_group_and_validates_in_1_4_only():
    assert "viewer_group" not in DOC["private"] and "approver_group" not in DOC["approvals"]
    assert sc.errors_for(CURRENT, DOC, REG) == []
    assert sc.errors_for(FROZEN_13, DOC, REG) != []
