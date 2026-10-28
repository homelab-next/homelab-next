# SPDX-License-Identifier: Apache-2.0
"""events/swap.step 1.1: the swap record's nine step names are accepted; 1.0 documents stay valid.

The 1.1-only documents live here rather than in ``schemas/events/examples/`` because every
published example must also validate against the frozen 1.0 baseline (additive evolution).
"""

import json
from pathlib import Path

import pytest
import schema_check as sc

ROOT = Path(__file__).resolve().parents[2]
REG = sc.build_registry(ROOT)
CURRENT = json.loads((ROOT / "schemas/events/swap.step.schema.json").read_text())
FROZEN_10 = json.loads((ROOT / "schemas/_frozen/1.0/events/swap.step.schema.json").read_text())
FROZEN_12 = json.loads((ROOT / "schemas/_frozen/1.2/events/swap.step.schema.json").read_text())
FROZEN_11 = json.loads((ROOT / "schemas/_frozen/1.1/events/swap.step.schema.json").read_text())
FIXTURES = sorted((Path(__file__).parent / "fixtures").glob("swap.step.*.json"))
RECORD_STEPS = (
    "declare",
    "shadow-start",
    "dual-write",
    "parity-compare",
    "soak",
    "cutover",
    "rollback-window",
    "decommission-check",
    "close",
)


def _event(name: str, step: int = 1) -> dict:
    return {
        "specversion": "1.0",
        "id": f"evt-{step}",
        "source": "cap:lake-query",
        "type": "homelabnext.swap.step",
        "time": "2026-01-01T00:00:00Z",
        "data": {
            "swap_id": "swap-0001",
            "capability": "cap:lake-query",
            "step": step,
            "step_name": name,
            "status": "passed",
        },
    }


def test_version_is_1_2_and_1_1_and_1_2_are_frozen():
    """1.2 only retargets the envelope ref to envelope 1.1; 1.1 is what added the step names."""
    assert CURRENT["$id"].endswith("/events/swap.step/1.2")
    assert CURRENT == FROZEN_12
    assert FROZEN_11["$id"].endswith("/events/swap.step/1.1")
    assert FROZEN_10["$id"].endswith("/events/swap.step/1.0")


@pytest.mark.parametrize("path", FIXTURES, ids=lambda p: p.name)
def test_1_1_documents_validate_against_1_1_only(path):
    doc = json.loads(path.read_text())
    assert sc.errors_for(CURRENT, doc, REG) == []
    assert sc.errors_for(FROZEN_10, doc, REG) != []  # the reason they are not published examples


@pytest.mark.parametrize("name", RECORD_STEPS)
def test_every_record_step_name_is_accepted(name):
    assert sc.errors_for(CURRENT, _event(name, RECORD_STEPS.index(name) + 1), REG) == []


@pytest.mark.parametrize("name", ["inventory", "contract", "fake", "conform-old", "shadow"])
def test_1_0_step_names_stay_valid(name):
    assert sc.errors_for(CURRENT, _event(name), REG) == []
    assert sc.errors_for(FROZEN_10, _event(name), REG) == []


def test_a_misspelt_step_name_is_still_rejected():
    assert sc.errors_for(CURRENT, _event("decomission-check"), REG) != []
