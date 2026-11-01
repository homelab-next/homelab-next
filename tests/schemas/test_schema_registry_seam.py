# SPDX-License-Identifier: Apache-2.0
"""homelabnext.schema_registry is the one schema-registry loader every validator uses."""

import json

import pytest

from homelabnext import paths
from homelabnext.schema_registry import registry_of, schema_registry, validator

pytest.importorskip("referencing")

COMMON = "https://schemas.example.internal/homelabnext/ids/common/1.0"


def test_registry_of_adds_only_documents_with_a_string_id():
    reg = registry_of([{"$id": "urn:example:a", "type": "string"}, {"$id": 3}, [], "x", None])
    assert reg.contents("urn:example:a") == {"$id": "urn:example:a", "type": "string"}
    assert len(list(reg)) == 1


def test_registry_of_extends_a_base_and_reads_draft_2020_12_by_default():
    base = registry_of([{"$id": "urn:example:a"}])
    reg = registry_of([{"$id": "urn:example:b"}], base)
    assert {"urn:example:a", "urn:example:b"} <= set(reg)
    from referencing import Resource
    from referencing.jsonschema import DRAFT202012

    want = Resource.from_contents({"$id": "urn:example:b"}, default_specification=DRAFT202012)
    assert reg["urn:example:b"] == want


def test_the_packaged_registry_skips_frozen_and_instance_folders():
    ids = set(schema_registry())
    assert COMMON in ids
    for p in paths.schemas_dir().rglob("*.json"):
        parts = set(p.relative_to(paths.schemas_dir()).parts)
        if parts & {"examples", "negative"}:
            doc = json.loads(p.read_text(encoding="utf-8"))
            if isinstance(doc, dict) and isinstance(doc.get("$id"), str):
                assert schema_registry().contents(doc["$id"]) != doc


def test_validator_resolves_refs_across_families():
    # a status schema $refs the shared ids; the validator resolves them offline
    v = validator("status", "observation.schema.json")
    assert v.schema["$id"].startswith("https://schemas.example.internal/homelabnext/status/")
    for ex in sorted((paths.schemas_dir() / "status" / "examples").glob("observation.*.json")):
        assert not list(v.iter_errors(json.loads(ex.read_text(encoding="utf-8")))), ex.name
    errors = list(v.iter_errors({"observed_at": "not a time"}))
    assert errors, "an invalid observation is refused"
