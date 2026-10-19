# SPDX-License-Identifier: Apache-2.0
"""platform/guest 1.1 (additive): `scope`, `network.firewall_exemption`, `firewall_rules`.

1.1-only documents live in ``fixtures/`` rather than ``schemas/platform/examples/`` because every
published example must also validate against the frozen 1.0 baseline.  The old default of
``network.firewall`` ("inherit") changed to "enabled"; an `inherit` file stays valid.
"""

import json
from pathlib import Path

import pytest
import schema_check as sc
import yaml

ROOT = Path(__file__).resolve().parents[2]
REG = sc.build_registry(ROOT)
CURRENT = json.loads((ROOT / "schemas/platform/guest.schema.json").read_text())
FROZEN_10 = json.loads((ROOT / "schemas/_frozen/1.0/platform/guest.schema.json").read_text())
FROZEN_11 = json.loads((ROOT / "schemas/_frozen/1.1/platform/guest.schema.json").read_text())
FIXTURES = sorted((Path(__file__).parent / "fixtures").glob("guest.1_1.*.yml"))


def test_1_1_is_frozen_and_current_is_additive_over_it():
    assert FROZEN_11["$id"].endswith("/platform/guest/1.1")
    assert FROZEN_10["$id"].endswith("/platform/guest/1.0")
    assert sc.is_additive(FROZEN_11, CURRENT) == []


@pytest.mark.parametrize("path", FIXTURES, ids=lambda p: p.name)
def test_1_1_documents_validate_against_1_1_only(path):
    doc = yaml.safe_load(path.read_text())
    assert sc.errors_for(CURRENT, doc, REG) == []
    assert sc.errors_for(FROZEN_10, doc, REG) != []


def test_every_published_1_0_example_stays_valid():
    for f in sc.instances_for(ROOT / "schemas/platform/guest.schema.json", "examples"):
        assert sc.errors_for(CURRENT, sc.load_instance(f), REG) == [], f.name


def test_firewall_default_is_enabled():
    props = CURRENT["properties"]["network"]["properties"]
    assert props["firewall"]["default"] == "enabled"
    assert "inherit" in props["firewall"]["enum"]  # old files keep working
