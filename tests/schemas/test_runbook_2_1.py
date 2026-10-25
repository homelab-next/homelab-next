# SPDX-License-Identifier: Apache-2.0
"""registers/runbook 2.1 (additive over 2.0): ``lessons`` items are lesson uids (ADR-0019), as
every other record link is.  A 2.0
document (``lessons: [LL-042]``, the numbered codes of records written before uids) still
validates, so 2.0 stays readable; a legacy code inside a record is refused by the record
validation (homelabnext.registers.schema), not by the contract.

The sweep below holds every current schema to the same rule: a pattern written for a legacy
numbered code (``^LL-\\d{3,}$``, ``^(?:SO|OO|...)-\\d{3,}$``) only ever appears as an ``anyOf``
branch beside a uid branch, never as the only form a record reference may take."""

import json
import re
from pathlib import Path

import pytest
import schema_check as sc

from homelabnext.identity import is_uid
from homelabnext.identity.types import LEGACY_PREFIX

ROOT = Path(__file__).resolve().parents[2]
REG = sc.build_registry(ROOT)
CURRENT = json.loads((ROOT / "schemas/registers/runbook.schema.json").read_text())
FROZEN_20 = json.loads((ROOT / "schemas/_frozen/2.0/registers/runbook.schema.json").read_text())
FROZEN_21 = ROOT / "schemas/_frozen/2.1/registers/runbook.schema.json"
LESSON = "01a15e4e-758c-7314-ba7d-8691599bb269"  # a lesson uid (UUIDv7)


def doc(**extra):
    base = {
        "uid": "01a15e4e-0000-7000-8000-000000000003",
        "type": "runbook",
        "title": "Deploy a web service",
        "systems": ["web-proxy"],
        "steps": [{"n": 1, "text": "Apply the role", "verify": "Canary path returns 200"}],
    }
    return {**base, **extra}


def test_version_2_1_is_frozen_and_the_current_one_additive_over_it_and_2_0():
    # 2.2 added `summary` (ADR-0032); 2.1's rule on `lessons` stands unchanged
    assert CURRENT["$id"].endswith("/registers/runbook/2.2")
    assert FROZEN_21.is_file()
    frozen_21 = json.loads(FROZEN_21.read_text())
    assert frozen_21["properties"]["lessons"] == CURRENT["properties"]["lessons"]
    assert sc.is_additive(frozen_21, CURRENT) == []
    assert sc.is_additive(FROZEN_20, CURRENT) == []


def test_lessons_are_uids():
    assert sc.errors_for(CURRENT, doc(lessons=[LESSON]), REG) == []


@pytest.mark.parametrize(
    "ref",
    [
        "lesson-42",
        "01a15e4e-758c-4314-ba7d-8691599bb269",  # a UUIDv4, not v7
        "01A15E4E-758C-7314-BA7D-8691599BB269",  # not the canonical lowercase form
        LESSON + "\n",
        "LL-42",
    ],
)
def test_a_lesson_that_is_not_a_uid_is_refused(ref):
    assert sc.errors_for(CURRENT, doc(lessons=[ref]), REG) != []


def test_a_2_0_document_stays_readable():
    legacy = doc(lessons=["LL-042"])
    assert sc.errors_for(FROZEN_20, legacy, REG) == []
    assert sc.errors_for(CURRENT, legacy, REG) == []
    # the uid form is what 2.0 refused: the reason for 2.1
    assert sc.errors_for(FROZEN_20, doc(lessons=[LESSON]), REG) != []


def test_the_shipped_example_links_its_lessons_by_uid():
    ex = json.loads((ROOT / "schemas/registers/examples/runbook.valid.json").read_text())
    assert ex["lessons"] and all(is_uid(x) for x in ex["lessons"])
    assert sc.errors_for(FROZEN_20, ex, REG) != []  # not a 2.0 document any more
    assert sc.errors_for(CURRENT, ex, REG) == []


# --- the sweep: no current schema requires a legacy numbered code ---------------------------

_PREFIXES = "|".join(sorted(LEGACY_PREFIX, key=len, reverse=True))
# a pattern written for a legacy code names a prefix literally right before its hyphen
_LEGACY_PATTERN = re.compile(rf"(?:^\^|\(|\|)\(?(?:\?:)?(?:{_PREFIXES})(?:\||\)|-)")
_UID_SAMPLE = "01a15e4e-758c-7314-ba7d-8691599bb269"


def _accepts_uid(sub, root) -> bool:
    if not isinstance(sub, dict):
        return False
    if "$ref" in sub:
        ref = sub["$ref"]
        if ref.startswith("#/"):  # a local definition of the schema being swept
            for part in ref[2:].split("/"):
                root = root[part]
            return _accepts_uid(root, root)
        return sc.errors_for({"$ref": ref}, _UID_SAMPLE, REG) == []
    return isinstance(sub.get("pattern"), str) and bool(re.search(sub["pattern"], _UID_SAMPLE))


def _legacy_only(node, path="$", parent_any_of=None, root=None):
    root = node if root is None else root
    out = []
    if isinstance(node, dict):
        pat = node.get("pattern")
        uid_beside = parent_any_of and any(_accepts_uid(b, root) for b in parent_any_of)
        if isinstance(pat, str) and _LEGACY_PATTERN.search(pat) and not uid_beside:
            out.append(f"{path}: {pat}")
        for k, v in node.items():
            branches = v if k == "anyOf" and isinstance(v, list) else None
            if branches is not None:
                for i, b in enumerate(branches):
                    out += _legacy_only(b, f"{path}.anyOf[{i}]", branches, root)
            else:
                out += _legacy_only(v, f"{path}.{k}", None, root)
    elif isinstance(node, list):
        for i, v in enumerate(node):
            out += _legacy_only(v, f"{path}[{i}]", None, root)
    return out


def _current_schemas():
    return [
        p
        for p in sorted((ROOT / "schemas").rglob("*.json"))
        if not {"_frozen", "examples", "negative"} & set(p.parts)
    ]


def test_the_sweep_detects_a_legacy_only_pattern():
    assert _legacy_only(FROZEN_20) == ["$.properties.lessons.items: ^LL-\\d{3,}$"]
    assert _legacy_only({"anyOf": [{"pattern": "^(LL|RB)-\\d{3,}$"}, {"pattern": "^x$"}]})


@pytest.mark.parametrize("path", _current_schemas(), ids=lambda p: p.relative_to(ROOT).as_posix())
def test_no_schema_requires_a_legacy_record_code(path):
    assert _legacy_only(json.loads(path.read_text())) == []
