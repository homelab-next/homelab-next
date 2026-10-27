# SPDX-License-Identifier: Apache-2.0
"""platform/guest 1.5 (additive): ``network.firewall_exemption.filtered_by``, where a NIC whose
firewall is off is filtered instead (a guest that runs its firewall, or a zone's router).
Validation resolves it, and a model runtime with its NIC firewall off needs it (docs/compute-
model.md, "Model runtimes").  1.5-only documents live in ``fixtures/``."""

import json
from pathlib import Path

import pytest
import schema_check as sc
import yaml

ROOT = Path(__file__).resolve().parents[2]
REG = sc.build_registry(ROOT)
CURRENT = json.loads((ROOT / "schemas/platform/guest.schema.json").read_text())
FROZEN_14 = json.loads((ROOT / "schemas/_frozen/1.4/platform/guest.schema.json").read_text())
FROZEN_15 = json.loads((ROOT / "schemas/_frozen/1.5/platform/guest.schema.json").read_text())
FIXTURES = sorted((Path(__file__).parent / "fixtures").glob("guest.1_5.*.yml"))


def test_1_5_is_frozen_and_current_is_additive_over_it():
    assert FROZEN_15["$id"].endswith("/platform/guest/1.5")
    assert sc.is_additive(FROZEN_14, FROZEN_15) == []
    assert sc.is_additive(FROZEN_15, CURRENT) == []


def test_fixtures_exist():
    assert FIXTURES


@pytest.mark.parametrize("path", FIXTURES, ids=lambda p: p.name)
def test_1_5_documents_validate_against_1_5_only(path):
    doc = yaml.safe_load(path.read_text())
    assert sc.errors_for(CURRENT, doc, REG) == []
    assert sc.errors_for(FROZEN_14, doc, REG) != []


@pytest.mark.parametrize(
    "value",
    ["hv-a", "guest:", "zone:", "guest:HV", "zone:mgmt extra", 7],
    ids=["bare", "guest-empty", "zone-empty", "uppercase", "trailing", "not-string"],
)  # a trailing newline is refused before the schema, by the loader's control-character check
def test_a_bad_pointer_is_refused(value):
    doc = yaml.safe_load(FIXTURES[0].read_text())
    doc["network"]["firewall_exemption"]["filtered_by"] = value
    assert sc.errors_for(CURRENT, doc, REG) != []
