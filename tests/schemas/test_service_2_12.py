# SPDX-License-Identifier: Apache-2.0
"""platform/service 2.12: the data-freshness status mapping built-ins and their limits."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import schema_check as sc
import yaml

ROOT = Path(__file__).resolve().parents[2]
REG = sc.build_registry(ROOT)
CURRENT = json.loads((ROOT / "schemas/platform/service.json").read_text())
FROZEN_211 = json.loads((ROOT / "schemas/_frozen/2.11/platform/service.json").read_text())
DOC = yaml.safe_load((ROOT / "examples/services.yml").read_text())


def test_version_is_2_12_frozen_and_additive():
    assert CURRENT["$id"].endswith("/platform/service/2.12")
    assert json.loads((ROOT / "schemas/_frozen/2.12/platform/service.json").read_text()) == CURRENT
    assert sc.is_additive(FROZEN_211, CURRENT) == []


def _with_source(mapping):
    doc = copy.deepcopy(DOC)
    svc = next(iter(doc["services"].values()))
    svc["status_sources"] = [
        {
            "id": "freshness-probe",
            "kind": "poll-http-json",
            "target": {"path": "/v1/probe"},
            "interval_s": 60,
            "timeout_s": 10,
            "mapping": mapping,
            "what": "A freshness probe for the schema test.",
        }
    ]
    return doc


def test_the_two_freshness_builtins_validate_with_their_limits():
    for builtin in ("table-snapshot-age", "backup-snapshot-age"):
        doc = _with_source({"builtin": builtin, "warn_after_s": 60, "fail_after_s": 120})
        assert sc.errors_for(CURRENT, doc, REG) == []


def test_a_limit_must_be_a_positive_integer_and_the_builtin_must_exist():
    for mapping in (
        {"builtin": "table-snapshot-age", "fail_after_s": 0},
        {"builtin": "table-snapshot-age", "fail_after_s": "soon"},
        {"builtin": "no-such-builtin"},
    ):
        assert sc.errors_for(CURRENT, _with_source(mapping), REG) != []
