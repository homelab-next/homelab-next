# SPDX-License-Identifier: Apache-2.0
"""``homelabnext.tlp_egress``: the label an item leaves under (ADR-0033 decision 13)."""

import pytest

from homelabnext.tlp import Label
from homelabnext.tlp_egress import (
    analyzers_for,
    egress_check,
    egress_label,
    job_label,
    markers,
)


@pytest.mark.parametrize(
    "text, want",
    [
        ("nothing here", []),
        ("TLP:RED summary", [Label.RED]),
        ("tlp: amber, then TLP:GREEN", [Label.AMBER, Label.GREEN]),
        ("TLP:AMBER+STRICT", [Label.AMBER_STRICT]),
        ("TLP : Amber + Strict", [Label.AMBER_STRICT]),
        ("marked TLP:WHITE", [Label.CLEAR]),
        ("TLP:BLACK", [Label.RED]),  # an unknown word is red
        ("(TLP:CLEAR)", [Label.CLEAR]),
        ("XTLP:RED", []),  # inside a word is not a marker
        (None, []),
        (b"TLP:RED", []),
    ],
)
def test_markers(text, want):
    assert markers(text) == want


@pytest.mark.parametrize(
    "claimed, recorded, body, want",
    [
        ("clear", "clear", "", Label.CLEAR),
        ("clear", "amber", "", Label.AMBER),  # a claim never loosens the record
        ("clear", "clear", "see TLP:RED", Label.RED),  # a stricter marker wins
        ("amber", "clear", "TLP:GREEN", Label.AMBER),
        (None, "clear", "", Label.RED),  # no claim is red
        ("clear", None, "", Label.RED),  # a recorded label that is missing is red
        ("gren", "clear", "", Label.RED),
    ],
)
def test_egress_label(claimed, recorded, body, want):
    assert egress_label(claimed, recorded, body) is want


def test_without_a_record_the_claim_and_body_decide():
    assert egress_label("green") is Label.GREEN
    assert egress_label("green", body="TLP:AMBER") is Label.AMBER


def test_egress_check():
    ok = egress_check(Label.GREEN, "clear", "green", "fine")
    assert ok.allowed and ok.label is Label.GREEN and ok.reason is None
    no = egress_check(Label.CLEAR, "clear", "clear", "TLP:AMBER detail")
    assert not no.allowed and no.label is Label.AMBER and "above" in no.reason
    with pytest.raises(TypeError):
        egress_check("clear", "clear")


def test_job_label():
    assert job_label(["clear", "clear"], Label.CLEAR) is Label.CLEAR
    assert job_label(["clear", "red"], Label.CLEAR) is Label.RED  # a lab sighting
    assert job_label([], Label.CLEAR) is Label.RED  # no records: unlabelled
    assert job_label(["clear"], Label.AMBER) is Label.AMBER  # raised to the submitter
    with pytest.raises(TypeError):
        job_label(["clear"], "clear")


def test_analyzers_for():
    maxima = {
        "a-open": "clear",
        "b-community": "green",
        "c-partner": "amber",
        "d-local": "red",
        "e-undeclared": None,
        "f-odd": "TLP:AMBER",
    }
    assert analyzers_for(Label.CLEAR, maxima) == ["a-open", "b-community", "c-partner", "d-local"]
    assert analyzers_for(Label.GREEN, maxima) == ["b-community", "c-partner", "d-local"]
    assert analyzers_for(Label.RED, maxima) == ["d-local"]
    assert analyzers_for(Label.AMBER, {}) == []
    with pytest.raises(TypeError):
        analyzers_for("clear", maxima)
