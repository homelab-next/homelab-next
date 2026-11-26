# SPDX-License-Identifier: Apache-2.0
"""platform/service 2.16 (additive): a status source's ``tlp`` (ADR-0033 decisions 2 and 3).  The
hub's side (the label on the menu, the views checked against it) is in
``tests/status/test_status_tlp.py``."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import schema_check as sc
import yaml

ROOT = Path(__file__).resolve().parents[2]
REG = sc.build_registry(ROOT)
CURRENT = json.loads((ROOT / "schemas/platform/service.json").read_text())
FROZEN_215 = json.loads((ROOT / "schemas/_frozen/2.15/platform/service.json").read_text())
FROZEN_216 = json.loads((ROOT / "schemas/_frozen/2.16/platform/service.json").read_text())
DOC = yaml.safe_load((ROOT / "examples/services.yml").read_text())


def test_version_is_2_16_frozen_and_additive():
    assert CURRENT["$id"].endswith("/platform/service/2.16")
    assert FROZEN_216 == CURRENT
    assert sc.is_additive(FROZEN_215, CURRENT) == []


def _with_tlp(value):
    doc = copy.deepcopy(DOC)
    svc = next(s for s in doc["services"].values() if s.get("status_sources"))
    svc["status_sources"][0]["tlp"] = value
    return doc


def test_a_source_declares_one_of_the_five_labels_and_only_those():
    for label in ("clear", "green", "amber", "amber+strict", "red"):
        assert sc.errors_for(CURRENT, _with_tlp(label), REG) == []
    for bad in ("white", "TLP:RED", "amber-strict", "amber strict", "", None, 3):
        assert sc.errors_for(CURRENT, _with_tlp(bad), REG) != [], bad


def test_a_2_15_registry_still_validates_and_2_15_does_not_know_the_field():
    assert sc.errors_for(CURRENT, DOC, REG) == []
    assert sc.errors_for(FROZEN_215, _with_tlp("red"), REG) != []
