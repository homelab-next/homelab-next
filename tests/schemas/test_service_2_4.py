# SPDX-License-Identifier: Apache-2.0
"""platform/service 2.4 (additive): a service's one-line ``description`` (the generated maps
show it, ADR-0018); the registry model keeps it."""

import json
from pathlib import Path

import schema_check as sc
import yaml

from homelabnext.registry.model import build_registry

ROOT = Path(__file__).resolve().parents[2]
REG = sc.build_registry(ROOT)
CURRENT = json.loads((ROOT / "schemas/platform/service.json").read_text())
FROZEN_23 = json.loads((ROOT / "schemas/_frozen/2.3/platform/service.json").read_text())
FROZEN_24 = json.loads((ROOT / "schemas/_frozen/2.4/platform/service.json").read_text())

DOC = yaml.safe_load(
    (Path(__file__).parent / "fixtures" / "service.2_4.description.yml").read_text()
)


def test_version_2_4_is_frozen_and_additive():
    assert FROZEN_24["$id"].endswith("/platform/service/2.4")
    assert sc.is_additive(FROZEN_23, FROZEN_24) == []
    assert sc.is_additive(FROZEN_24, CURRENT) == []


def test_description_validates_in_2_4_only_and_reaches_the_model():
    assert sc.errors_for(CURRENT, DOC, REG) == []
    assert sc.errors_for(FROZEN_23, DOC, REG) != []
    assert build_registry(DOC).services["events"].description.startswith("The event bus")


def test_a_multiline_description_is_refused():
    bad = json.loads(json.dumps(DOC))
    bad["services"]["events"]["description"] = "one\ntwo"
    assert sc.errors_for(CURRENT, bad, REG) != []
