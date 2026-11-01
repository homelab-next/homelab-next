# SPDX-License-Identifier: Apache-2.0
"""RoleTable.load validates the file against schemas/platform/model_roles.json first."""

import json
from pathlib import Path

import pytest

from homelabnext import paths
from homelabnext.registry.models import RoleTable, RoleTableError, schema_problems

REPO = Path(__file__).resolve().parents[2]
SCHEMAS = paths.schemas_dir() / "platform"

ROLES = {
    "version": 1,
    "roles": {
        "triage": {
            "tier": "fast",
            "bindings": [{"backend": "svc:engine-a", "model_id": "small-chat"}],
        }
    },
}


def _write(tmp_path, doc) -> Path:
    p = tmp_path / "model_roles.json"
    p.write_text(json.dumps(doc), encoding="utf-8")
    return p


def test_a_valid_table_loads(tmp_path):
    assert sorted(RoleTable.load(_write(tmp_path, ROLES)).roles) == ["triage"]


@pytest.mark.parametrize(
    ("mutate", "where"),
    [
        (lambda d: d["roles"]["triage"].update(tier="huge"), "roles/triage/tier"),
        (lambda d: d["roles"]["triage"].pop("tier"), "roles/triage"),
        (lambda d: d["roles"]["triage"]["bindings"][0].update(priority=-1), "bindings/0/priority"),
        (lambda d: d["roles"]["triage"]["bindings"][0].update(model_id="a b"), "model_id"),
        (lambda d: d["roles"]["triage"].update(logprobs="false"), "roles/triage/logprobs"),
        (lambda d: d["roles"]["triage"].update(params={"temperature": 5}), "temperature"),
        (
            lambda d: d["roles"]["triage"].update(limits={"window_s": 60, "max_requests": 1.5}),
            "limits/max_requests",
        ),
        (lambda d: d.pop("version"), "$"),
    ],
)
def test_a_value_the_schema_refuses_is_an_error_not_ignored(tmp_path, mutate, where):
    doc = json.loads(json.dumps(ROLES))
    mutate(doc)
    RoleTable.from_dict(doc)  # the hand checks alone accept it
    with pytest.raises(RoleTableError) as exc:
        RoleTable.load(_write(tmp_path, doc))
    assert any(where in p for p in exc.value.problems), exc.value.problems


def test_every_shipped_table_and_example_satisfies_the_schema():
    tables = [*REPO.glob("examples/**/model_roles.json"), *SCHEMAS.glob("examples/model_roles.*")]
    assert tables
    for p in tables:
        RoleTable.load(p)


def test_every_negative_is_refused_by_load():
    negatives = sorted(SCHEMAS.glob("negative/model_roles.*.json"))
    assert negatives
    for p in negatives:
        assert schema_problems(json.loads(p.read_text(encoding="utf-8"))), p.name
        with pytest.raises(RoleTableError):
            RoleTable.load(p)
