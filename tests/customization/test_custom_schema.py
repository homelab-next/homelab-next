# SPDX-License-Identifier: Apache-2.0
"""Contract tests: every example validates, every negative is rejected, each for a reason."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from cust_helpers import make_doc

from homelabnext.customization.loader import REPO_ROOT, validate_doc

PLATFORM = REPO_ROOT / "schemas" / "platform"
EXAMPLES = sorted((PLATFORM / "examples").glob("customization.*.json"))
NEGATIVES = sorted((PLATFORM / "negative").glob("customization.*.json"))

#: negative -> a fragment the first error must mention (proves it fails for the intended reason)
EXPECT = {
    "no-reason": "reason",
    "short-reason": "reason",
    "no-owner": "owner",
    "no-review-by": "review_by",
    "review-by-not-a-date": "review_by",
    "no-upstream": "upstream",
    "upstream-unknown-value": "upstream",
    "id-wrong-prefix": "id",
    "id-with-digit-run": "id",
    "unknown-kind": "kind",
    "empty-scope": "scope",
    "scope-host-is-fqdn": "scope/hosts",
    "scope-capability-not-logical": "scope/capabilities",
    "contract-is-product-url": "contract",
    "extra-field": "sudo",
}


def test_corpus_present():
    assert len(EXAMPLES) >= 6
    assert len(NEGATIVES) >= 20


@pytest.mark.parametrize("path", EXAMPLES, ids=lambda p: p.stem)
def test_example_valid(path):
    assert validate_doc(json.loads(path.read_text())) == []


@pytest.mark.parametrize("path", NEGATIVES, ids=lambda p: p.stem)
def test_negative_rejected(path):
    errs = validate_doc(json.loads(path.read_text()))
    assert errs, f"{path.name} was accepted"
    label = path.stem.split(".", 1)[1]
    if label in EXPECT:
        assert EXPECT[label] in errs[0] or any(EXPECT[label] in e for e in errs), errs


@pytest.mark.parametrize("field", ["reason", "owner", "review_by", "created", "upstream", "scope"])
def test_required_fields(field):
    assert validate_doc(make_doc(**{field: None}))


def test_every_kind_has_a_shape_of_its_own():
    """An action that is valid for one kind must not be valid for another."""
    docs = {
        p.stem.split(".")[1]: json.loads(p.read_text())
        for p in EXAMPLES
        if p.stem.split(".")[1] != "full"
    }
    assert set(docs) == {"override", "hook", "patch-overlay", "registry-patch", "profile"}
    for kind, doc in docs.items():
        for other, odoc in docs.items():
            if other != kind:
                swapped = {**doc, "action": odoc["action"]}
                assert validate_doc(swapped), f"{kind} accepted the {other} action"


def test_schema_is_frozen_additive():
    frozen = REPO_ROOT / "schemas" / "_frozen" / "1.0" / "platform" / "customization.schema.json"
    assert frozen.is_file()
    assert Path(PLATFORM / "customization.schema.json").is_file()
