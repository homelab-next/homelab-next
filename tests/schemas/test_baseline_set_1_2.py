# SPDX-License-Identifier: Apache-2.0
"""platform/baseline_set 1.2 (additive): a baseline lists a control as its id or as ``{id, with}``,
and a control may name the ``settings`` a baseline may set.  1.2-only documents live in
``fixtures/``; keys, types, merge order and conflicts are semantic
(homelabnext.compute.baselines, tests/compute/test_settings.py)."""

import json
from pathlib import Path

import pytest
import schema_check as sc
import yaml

ROOT = Path(__file__).resolve().parents[2]
REG = sc.build_registry(ROOT)
CURRENT = json.loads((ROOT / "schemas/platform/baseline_set.schema.json").read_text())
FROZEN_11 = json.loads((ROOT / "schemas/_frozen/1.1/platform/baseline_set.schema.json").read_text())
FROZEN_12 = json.loads((ROOT / "schemas/_frozen/1.2/platform/baseline_set.schema.json").read_text())
FIXTURES = sorted((Path(__file__).parent / "fixtures").glob("baseline_set.1_2.*.yml"))


def test_version_is_1_2_frozen_and_additive():
    assert CURRENT["$id"].endswith("/platform/baseline_set/1.2")
    assert CURRENT == FROZEN_12
    assert sc.is_additive(FROZEN_11, CURRENT) == []


@pytest.mark.parametrize("path", FIXTURES, ids=lambda p: p.name)
def test_1_2_documents_validate_against_1_2_only(path):
    doc = yaml.safe_load(path.read_text())
    assert sc.errors_for(CURRENT, doc, REG) == []
    assert sc.errors_for(FROZEN_11, doc, REG) != []


def test_a_1_1_document_is_still_a_1_2_document():
    for p in sorted((Path(__file__).parent / "fixtures").glob("baseline_set.1_1.*.yml")):
        assert sc.errors_for(CURRENT, yaml.safe_load(p.read_text()), REG) == [], p.name


@pytest.mark.parametrize(
    "entry",
    [{"id": "package-scan"}, {"id": "package-scan", "with": {}}, {"with": {"severity": "HIGH"}},
     {"id": "package-scan", "with": {"severity": "HIGH"}, "extra": 1}, "Package-Scan"],
)  # fmt: skip
def test_bad_control_entries_are_refused(entry):
    doc = yaml.safe_load(
        (Path(__file__).parent / "fixtures" / "baseline_set.1_2.settings.yml").read_text()
    )
    doc["baselines"]["server"]["controls"] = [entry]
    assert sc.errors_for(CURRENT, doc, REG) != []


def test_widening_a_reference_into_an_any_of_is_additive_and_nothing_else_is():
    """The additive check accepts ``$ref S -> anyOf[$ref S, T]`` (every S document stays valid):
    without the rule a removed ``$ref`` always reads as a break.  A branch list that drops S, or
    an anyOf beside another constraint, is still refused."""
    ref = {"$ref": "#/$defs/name"}
    obj = {"$ref": "#/$defs/control_entry"}
    assert sc.is_additive(ref, {"anyOf": [ref, obj]}) == []
    assert sc.is_additive(ref, {"anyOf": [{"$ref": "#/$defs/other"}, obj]}) != []
    assert sc.is_additive(ref, {"anyOf": [ref, obj], "maxLength": 3}) != []
    assert sc.is_additive({"anyOf": [ref]}, {"anyOf": [ref, obj]}) != []  # length change
