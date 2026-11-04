# SPDX-License-Identifier: Apache-2.0
"""``homelabnext.novelty.spec``: the schema and the rules it cannot state."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
from novelty_support import SPEC

from homelabnext.lake import load_schemas
from homelabnext.novelty import SpecError, load_spec, parse_spec

ROOT = Path(__file__).resolve().parents[2]
SCHEMAS = load_schemas()


def _with(**over):
    doc = copy.deepcopy(SPEC)
    doc["profiles"][0].update(over)
    return doc


def test_defaults_are_applied():
    (p,) = parse_spec(SPEC, SCHEMAS).profiles
    assert p.time_column == "time" and dict(p.where) == {}
    assert p.min_history_days == p.learn_days == 4


def test_the_example_spec_loads():
    spec = load_spec(ROOT / "examples/novelty/spec.yml", SCHEMAS)
    assert [p.id for p in spec.profiles] == ["host-dst-port", "user-src-ip"]
    assert spec.profiles[1].min_history_days == 14 and spec.profiles[1].where == {"auth_protocol": "ssh"}  # fmt: skip


def test_a_json_spec_loads(tmp_path):
    path = tmp_path / "spec.json"
    path.write_text(json.dumps(SPEC))
    assert load_spec(path, SCHEMAS).digest == parse_spec(SPEC, SCHEMAS).digest


@pytest.mark.parametrize(
    "over, match",
    [
        ({"table": "no_such_table"}, "unknown table"),
        ({"entity": "src_endpoint.nope"}, "not a column of network_activity"),
        ({"entity": "src_endpoint"}, "is a struct"),
        ({"values": ["time"]}, "is a timestamp"),
        ({"values": ["src_endpoint.ip"]}, "also a value"),
        ({"where": {"nope": 1}}, "where column"),
        ({"where": {"activity_id": "6"}}, "is not a long"),
        ({"where": {"activity_id": True}}, "is not a long"),
        ({"where": {"protocol_name": 6}}, "is not a string"),
        ({"where": {"time": "2026-03-01"}}, "is a timestamp"),
        ({"entity_kind": "mac"}, "entity_kind"),
        ({"time_column": "protocol_name"}, "time_column"),
        ({"min_history_days": 5}, "min_history_days 5 > learn_days 4"),
        ({"emit_at": 0}, "emit_at"),
        ({"learn_dayz": 4}, "learn_dayz"),
    ],
)
def test_a_bad_profile_is_refused(over, match):
    with pytest.raises(SpecError, match=match):
        parse_spec(_with(**over), SCHEMAS)


def test_profile_ids_are_unique():
    doc = copy.deepcopy(SPEC)
    doc["profiles"].append(doc["profiles"][0])
    with pytest.raises(SpecError, match="listed twice"):
        parse_spec(doc, SCHEMAS)


def test_a_duplicate_yaml_key_is_refused(tmp_path):
    path = tmp_path / "spec.yml"
    path.write_text('schema_version: "1.0"\nschema_version: "1.0"\nprofiles: []\n')
    with pytest.raises(SpecError):
        load_spec(path, SCHEMAS)


def test_the_profile_digest_changes_with_any_parameter():
    a = parse_spec(SPEC, SCHEMAS).profiles[0].digest
    assert a == parse_spec(copy.deepcopy(SPEC), SCHEMAS).profiles[0].digest
    assert a != parse_spec(_with(emit_at=0.3), SCHEMAS).profiles[0].digest
    # an explicit default is the same profile
    assert a == parse_spec(_with(min_history_days=4, time_column="time"), SCHEMAS).profiles[0].digest  # fmt: skip
