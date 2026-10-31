# SPDX-License-Identifier: Apache-2.0
"""The OCSF subsets: the examples are accepted and the negatives rejected by BOTH the JSON Schema
and the lake's own validator (so the library cannot drift from the contract)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from homelabnext import tlp
from homelabnext.lake import RowRejected, load_schemas
from homelabnext.lake.validate import normalize_rows

ROOT = Path(__file__).resolve().parents[2] / "schemas" / "ocsf"
SCHEMAS = load_schemas()
EXAMPLES = sorted((ROOT / "examples").glob("*.json"))
NEGATIVES = sorted((ROOT / "negative").glob("*.json"))


def _table(p: Path) -> str:
    return p.name.split(".v1.")[0]


def test_every_schema_has_examples_and_negatives():
    for name in SCHEMAS:
        assert [p for p in EXAMPLES if _table(p) == name], name
        assert len([p for p in NEGATIVES if _table(p) == name]) >= 2, name


@pytest.mark.parametrize("path", EXAMPLES, ids=lambda p: p.name)
def test_example_accepted_by_jsonschema_and_lake(path):
    jsonschema = pytest.importorskip("jsonschema")
    doc = json.loads(path.read_text())
    schema = json.loads((ROOT / f"{_table(path)}.v1.json").read_text())
    jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker()).validate(doc)
    rows = normalize_rows(SCHEMAS[_table(path)], [doc])
    assert rows[0]["time"].tzinfo is not None


@pytest.mark.parametrize("path", NEGATIVES, ids=lambda p: p.name)
def test_negative_rejected_by_lake_validator(path):
    doc = json.loads(path.read_text())
    schema = SCHEMAS[_table(path)]
    # the lake validator is a type/shape gate; value-range and pattern rules are the JSON Schema's
    shape_only = {
        "negative-bytes",
        "bad-port",
        "bad-cve",
        "cvss-too-high",
        "rule-number-id",
        "bad-technique",
        "wrong-class",
    }
    label = path.name.split(".v1.")[1].rsplit(".", 1)[0]
    if label in shape_only:
        jsonschema = pytest.importorskip("jsonschema")
        full = json.loads((ROOT / f"{_table(path)}.v1.json").read_text())
        assert not jsonschema.Draft202012Validator(full).is_valid(doc)
    else:
        with pytest.raises(RowRejected):
            normalize_rows(schema, [doc])


def test_schema_files_declare_the_lake_block_and_pin_version():
    for name, s in SCHEMAS.items():
        doc = json.loads((ROOT / f"{name}.v1.json").read_text())
        # 1.1 adds the row's TLP label (ADR-0033 decision 5); 1.0 stays frozen beside it
        assert doc["$id"].endswith(f"/ocsf/{name}/1.1")
        assert doc["additionalProperties"] is False
        assert s.labelled and s.column("tlp").enum == tlp.LABELS
        assert s.key == ("uid",) and s.partition == "day(time)"


def test_detection_id_is_logical_never_a_rule_number():
    doc = json.loads((ROOT / "detection_finding.v1.json").read_text())
    assert doc["properties"]["detection_id"]["pattern"].startswith("^det:")
