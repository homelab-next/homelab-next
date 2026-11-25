# SPDX-License-Identifier: Apache-2.0
"""platform/service 2.14 (additive): the execution-history kind's built-in ``automation-shadow``,
the shadow evidence per rule of the rendered workflow pack.  The mapper and the registry rules are
in ``tests/status/test_status_products.py``."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import schema_check as sc
import yaml

ROOT = Path(__file__).resolve().parents[2]
REG = sc.build_registry(ROOT)
CURRENT = json.loads((ROOT / "schemas/platform/service.json").read_text())
FROZEN_213 = json.loads((ROOT / "schemas/_frozen/2.13/platform/service.json").read_text())
FROZEN_214 = json.loads((ROOT / "schemas/_frozen/2.14/platform/service.json").read_text())
DOC = yaml.safe_load((ROOT / "examples/services.yml").read_text())


def _with_shadow(mapping):
    doc = copy.deepcopy(DOC)
    row = next(s for s in doc["services"].values() if s.get("capability") == "automation")
    source = copy.deepcopy(row["status_sources"][0])
    source.update(id="automation-shadow", interval_s=900, timeout_s=30, mapping=mapping)
    row["status_sources"].append(source)
    return doc


def test_version_is_2_14_frozen_and_additive():
    assert FROZEN_214["$id"].endswith("/platform/service/2.14")
    assert sc.is_additive(FROZEN_213, FROZEN_214) == []
    assert sc.is_additive(FROZEN_214, CURRENT) == []


def test_the_shadow_builtin_validates_in_2_14_only():
    doc = _with_shadow({"builtin": "automation-shadow", "window_s": 604800, "limit": 100})
    assert sc.errors_for(CURRENT, doc, REG) == []
    assert sc.errors_for(FROZEN_213, doc, REG) != []
    assert sc.errors_for(CURRENT, DOC, REG) == []  # every 2.13 registry still validates


def test_the_window_keeps_its_bounds():
    for window in (59, 604801, "7d"):
        doc = _with_shadow({"builtin": "automation-shadow", "window_s": window})
        assert sc.errors_for(CURRENT, doc, REG) != [], window
