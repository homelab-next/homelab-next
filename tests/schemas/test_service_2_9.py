# SPDX-License-Identifier: Apache-2.0
"""platform/service 2.9 (additive): a row's ``standing`` and a replica's ``replica_of``
(ADR-0039 decisions 1 and 4). Absent ``standing`` means ``primary``, so every 2.8 registry still
validates; the rules (one primary per capability, until and why, the suffix rule) are in
``tests/registry/test_registry_model.py``."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import schema_check as sc
import yaml

from homelabnext.registry.model import build_registry

ROOT = Path(__file__).resolve().parents[2]
REG = sc.build_registry(ROOT)
CURRENT = json.loads((ROOT / "schemas/platform/service.json").read_text())
FROZEN_28 = json.loads((ROOT / "schemas/_frozen/2.8/platform/service.json").read_text())
FROZEN_29 = json.loads((ROOT / "schemas/_frozen/2.9/platform/service.json").read_text())
DOC = yaml.safe_load((ROOT / "examples/services.yml").read_text())
FOUR_BOX = yaml.safe_load((ROOT / "examples/four-box-lab/services.yml").read_text())


def test_version_is_2_9_frozen_and_additive():
    assert CURRENT["$id"].endswith("/platform/service/2.9")
    assert CURRENT == FROZEN_29
    assert sc.is_additive(FROZEN_28, CURRENT) == []


def test_standing_validates_in_2_9_only_and_reaches_the_model():
    doc = copy.deepcopy(DOC)
    doc["services"]["metrics"]["standing"] = {"tier": "primary", "why": "the decided product"}
    assert sc.errors_for(CURRENT, doc, REG) == []
    assert sc.errors_for(FROZEN_28, doc, REG) != []
    assert build_registry(doc).services["metrics"].standing == "primary"
    assert build_registry(DOC).services["metrics"].standing == "primary"  # absent: primary


def test_replica_of_validates_in_2_9_only_and_reaches_the_model():
    assert sc.errors_for(CURRENT, FOUR_BOX, REG) == []
    assert sc.errors_for(FROZEN_28, FOUR_BOX, REG) != []
    row = build_registry(FOUR_BOX).services["dns-secondary"]
    assert (row.capability, row.replica_of, row.standing) == ("dns-secondary", "dns", "primary")


def test_a_non_primary_standing_needs_until_and_why_in_the_schema():
    doc = copy.deepcopy(DOC)
    doc["services"]["metrics"]["standing"] = {"tier": "eval"}
    errors = sc.errors_for(CURRENT, doc, REG)
    assert errors and any("until" in e for e in errors), errors
