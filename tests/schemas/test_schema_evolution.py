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


def _major(path) -> int:
    return sc.parse_id(json.loads(path.read_text()))[1]


@pytest.mark.parametrize("path", SCHEMAS, ids=lambda p: p.relative_to(ROOT / "schemas").as_posix())
def test_current_schema_is_additive_over_frozen_v1_0(path):
    """Additive over the x.0 baseline of its own major; a major bump (a breaking change, ADR-0001:
    the registers' lesson and runbook 2.0 require a uid, ADR-0019) keeps every earlier major's
    baseline frozen, for the migration that reads it."""
    major = _major(path)
    for m in range(1, major + 1):
        assert sc.frozen_path(ROOT, path, m, 0).is_file(), f"missing baseline {m}.0 of {path}"
    old = json.loads(sc.frozen_path(ROOT, path, major, 0).read_text())
    assert sc.is_additive(old, json.loads(path.read_text())) == []


# examples of a feature added after the 1.0 freeze (1.0 rightly refuses them)
NEWER_THAN_1_0 = {
    "note.register-transition.md": "records/note 1.1: type register-transition",
    "note.strategy-transition.md": "records/note 1.3: type strategy-transition",
    "note.strategy-rfi.md": "records/note 1.3: type strategy-rfi",
    "register_event.value.yml": "registers/register_event 1.1: event value",
    "register_event.value-finding.yml": "registers/register_event 1.1: event value",
    "register_event.review-audit.yml": "registers/register_event 1.2: review role audit",
    "register_event.rekey.yml": "registers/register_event 1.3: event rekey",
    "note.register-transition-legacy-code.md": "records/note 1.1: type register-transition",
    "site.tailnet-deploy.yml": "platform/site 1.2: tailnet.deploy",
    "decision.returned.agent-approved.json": "events/decision.returned 1.1: tier_used agent",
}


@pytest.mark.parametrize("name", sorted(NEWER_THAN_1_0))
def test_an_example_newer_than_1_0_names_a_version_its_schema_really_has(name):
    """Excusing an example from the 1.0 check claims a later minor added its feature: the schema
    must carry that version (its $id at or past it) and a frozen copy of it, or the excuse hides an
    additive change that never bumped the id."""
    ref, _, _ = NEWER_THAN_1_0[name].partition(":")
    schema_ref, ver = ref.split()
    major, minor = (int(x) for x in ver.split("."))
    path = ROOT / "schemas" / f"{schema_ref}.schema.json"
    _, cur_major, cur_minor = sc.parse_id(json.loads(path.read_text()))
    assert (cur_major, cur_minor) >= (major, minor), f"{path.name} is {cur_major}.{cur_minor}"
    assert sc.frozen_path(ROOT, path, major, minor).is_file(), f"no frozen {ver} of {path.name}"


@pytest.mark.parametrize("path", SCHEMAS, ids=lambda p: p.relative_to(ROOT / "schemas").as_posix())
def test_v1_0_examples_validate_against_current_schema(path):
    """The frozen v1.0 schema accepted these examples; the current v1.x must still accept them."""
    frozen = json.loads(sc.frozen_path(ROOT, path, 1, 0).read_text())
    current = json.loads(path.read_text())
    for f in sc.instances_for(path, "examples"):
        doc = sc.load_instance(f)
        if f.name not in NEWER_THAN_1_0 and _major(path) == 1:
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
    base, _, ver = s["$id"].rpartition("/")
    s["$id"] = f"{base}/{int(ver.split('.')[0]) + 1}.0"  # the next major
    p.write_text(json.dumps(s))
    probs = [
        x
        for x in sc.check_repo(tmp_path, ["registers"])
        if "lesson.schema.json" in x.where and "additive" in x.message
    ]
    assert probs == []


@pytest.mark.parametrize(
    ("old", "new", "additive"),
    [
        ("^[a-z]+$", "^[a-z]+$(?!\\n)", True),  # ECMA-262 `$` is end of input: same language
        ("^a$|^b$", "^a$|^b$(?!\\n)", True),
        ("^[a-z]+\\$", "^[a-z]+\\$(?!\\n)", False),  # an escaped dollar is a literal
        ("^[a-z]+$", "^[a-z]+$(?!\\r)", False),
        ("^[a-z]+$", "^[a-y]+$(?!\\n)", False),
        ("^[a-z]+", "^[a-z]+(?!\\n)", False),  # no closing anchor: a real tightening
    ],
)
def test_a_trailing_newline_guard_is_the_only_pattern_change_proved_compatible(old, new, additive):
    s_old = {"type": "string", "pattern": old}
    assert (sc.is_additive(s_old, {**s_old, "pattern": new}) == []) is additive


def test_the_newline_guard_rejects_what_python_alone_accepted():
    """Python's ``$`` matches before a trailing newline; the guard closes that, nothing else."""
    old, new = {"pattern": "^[a-z]+$"}, {"pattern": "^[a-z]+$(?!\\n)"}
    assert sc.errors_for(old, "abc\n", REG) == []  # the defect, under Python's re
    assert sc.errors_for(new, "abc\n", REG) and sc.errors_for(new, "abc", REG) == []
