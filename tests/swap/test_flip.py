# SPDX-License-Identifier: Apache-2.0
import difflib

import pytest
from support import check_golden, registry_text

from homelabnext.registry import loads
from homelabnext.swap import FlipError, flip_text, plan_flip
from homelabnext.swap.flip import load_doc

TARGET = {"host": "lake-core-2", "impl": "duckdb", "version": "1.5"}


def plan():
    return plan_flip(load_doc(registry_text()), "lake-query", **TARGET)


def test_plan_diff_inverse_and_text_goldens():
    p = plan()
    text = registry_text()
    new_text = flip_text(text, p)
    check_golden("flip.plan.txt", p.diff())
    check_golden("flip.inverse.txt", p.inverse().diff())
    check_golden(
        "flip.text.diff",
        "".join(
            difflib.unified_diff(
                text.splitlines(True),
                new_text.splitlines(True),
                "services.yml",
                "services.yml",
                n=1,
            )
        ),
    )
    # the flipped text is a valid registry and the alias now resolves to the candidate
    reg = loads(new_text)
    assert reg.services["lake-query"].host == "lake-core-2"
    assert reg.alias("lake-query") == "lake-query.svc.example.internal"


def test_inverse_restores_the_document_and_the_text_exactly():
    p = plan()
    text = registry_text()
    new_text = flip_text(text, p)
    assert new_text != text
    assert load_doc(new_text) == p.apply(load_doc(text))
    assert p.inverse().apply(load_doc(new_text)) == load_doc(text)
    assert flip_text(new_text, p.inverse()) == text  # byte-identical, comments included
    assert p.inverse().inverse() == p


def test_plan_is_pure_and_serialisable():
    doc = load_doc(registry_text())
    snapshot = load_doc(registry_text())
    p = plan_flip(doc, "lake-query", **TARGET)
    assert doc == snapshot
    from homelabnext.swap import FlipPlan

    assert FlipPlan.from_dict(p.to_dict()) == p


def test_noop_plan_is_empty_and_text_unchanged():
    p = plan_flip(load_doc(registry_text()), "lake-query", host="lake-core")
    assert p.empty
    assert flip_text(registry_text(), p) == registry_text()


def test_invalid_flips_are_refused():
    doc = load_doc(registry_text())
    with pytest.raises(FlipError, match="not in the registry"):
        plan_flip(doc, "lake-query", host="no-such-host")
    with pytest.raises(FlipError, match="invalid"):  # lake-catalog already listens on 8181 there
        plan_flip(doc, "lake-query", port=8181)


def test_unknown_service_and_stale_plan():
    doc = load_doc(registry_text())
    with pytest.raises(FlipError, match="no service"):
        plan_flip(doc, "nope", host="lake-core-2")
    p = plan_flip(doc, "lake-query", **TARGET)
    other = plan_flip(doc, "lake-query", impl="other")
    moved = other.apply(doc)
    with pytest.raises(FlipError, match="changed since the plan"):
        p.apply(moved)
