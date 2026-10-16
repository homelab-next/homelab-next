# SPDX-License-Identifier: Apache-2.0
"""Additive-evolution: a v1.0 document must validate against every v1.x schema."""

import copy
import json
from pathlib import Path

import pytest
import schema_check as sc

ROOT = Path(__file__).resolve().parents[2]
REG = sc.build_registry(ROOT)
OWNED = ["ids", "events", "records", "registers", "platform"]
SCHEMAS = [
    p
    for p in sc.schema_files(ROOT, OWNED)
    if p.relative_to(ROOT / "schemas").as_posix() != "platform/service.json"
]


@pytest.mark.parametrize("path", SCHEMAS, ids=lambda p: p.relative_to(ROOT / "schemas").as_posix())
def test_current_schema_is_additive_over_frozen_v1_0(path):
    frozen = sc.frozen_path(ROOT, path, 1, 0)
    assert frozen.is_file(), f"missing baseline {frozen}"
    old, new = json.loads(frozen.read_text()), json.loads(path.read_text())
    assert sc.is_additive(old, new) == []


@pytest.mark.parametrize("path", SCHEMAS, ids=lambda p: p.relative_to(ROOT / "schemas").as_posix())
def test_v1_0_examples_validate_against_current_schema(path):
    """The frozen v1.0 schema accepted these examples; the current v1.x must still accept them."""
    frozen = json.loads(sc.frozen_path(ROOT, path, 1, 0).read_text())
    current = json.loads(path.read_text())
    for f in sc.instances_for(path, "examples"):
        doc = sc.load_instance(f)
        assert sc.errors_for(frozen, doc, REG) == [], f.name
        assert sc.errors_for(current, doc, REG) == [], f.name


# ----- the evolution rules themselves, on a worked v1.0 -> v1.1 example -----
V10 = {
    "$id": "https://schemas.example.internal/homelabnext/events/demo/1.0",
    "type": "object",
    "properties": {"a": {"type": "string", "maxLength": 10}, "kind": {"enum": ["x", "y"]}},
    "required": ["a"],
}
DOC10 = {"a": "hello", "kind": "x"}


def v11(mutator):
    s = copy.deepcopy(V10)
    s["$id"] = s["$id"].replace("1.0", "1.1")
    mutator(s)
    return s


def test_worked_example_additive_changes_pass_and_old_document_still_validates():
    def add(s):
        s["properties"]["b"] = {"type": "integer"}  # new optional property
        s["properties"]["kind"]["enum"].append("z")  # widened enum
        s["properties"]["a"]["maxLength"] = 20  # relaxed bound
        s["properties"]["a"]["description"] = "documented"  # annotation

    new = v11(add)
    assert sc.is_additive(V10, new) == []
    assert sc.errors_for(new, DOC10, REG) == []
    assert sc.errors_for(new, {**DOC10, "b": 3, "kind": "z"}, REG) == []


@pytest.mark.parametrize(
    "label,mutator",
    [
        ("new required", lambda s: s["required"].append("b")),
        ("removed property", lambda s: s["properties"].pop("kind")),
        ("narrowed enum", lambda s: s["properties"]["kind"].__setitem__("enum", ["x"])),
        ("tightened bound", lambda s: s["properties"]["a"].__setitem__("maxLength", 3)),
        ("narrowed type", lambda s: s["properties"]["a"].__setitem__("type", "integer")),
        ("closed object", lambda s: s.__setitem__("additionalProperties", False)),
        ("new pattern", lambda s: s["properties"]["a"].__setitem__("pattern", "^z")),
        ("new minLength", lambda s: s["properties"]["a"].__setitem__("minLength", 2)),
    ],
)
def test_breaking_changes_are_detected(label, mutator):
    assert sc.is_additive(V10, v11(mutator)), label


def test_breaking_change_really_breaks_a_v1_document():
    broken = v11(lambda s: s["required"].append("b"))
    assert sc.errors_for(broken, DOC10, REG)  # proves the detector is guarding something real


def test_checker_flags_non_additive_schema_in_repo(tmp_path):
    import shutil

    shutil.copytree(ROOT / "schemas", tmp_path / "schemas")
    p = tmp_path / "schemas/registers/lesson.schema.json"
    s = json.loads(p.read_text())
    s["required"].append("owner")
    p.write_text(json.dumps(s))
    probs = sc.check_repo(tmp_path, ["registers"])
    assert any("not additive" in x.message and "owner" in x.message for x in probs)


def test_major_bump_is_allowed_to_break(tmp_path):
    import shutil

    shutil.copytree(ROOT / "schemas", tmp_path / "schemas")
    p = tmp_path / "schemas/registers/lesson.schema.json"
    s = json.loads(p.read_text())
    s["required"].append("owner")
    s["$id"] = s["$id"].replace("/1.0", "/2.0")
    p.write_text(json.dumps(s))
    probs = [
        x
        for x in sc.check_repo(tmp_path, ["registers"])
        if "lesson.schema.json" in x.where and "additive" in x.message
    ]
    assert probs == []
