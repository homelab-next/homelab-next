# SPDX-License-Identifier: Apache-2.0
"""``homelabnext.tlp``: ADR-0033 decision 1 (labels, order, spellings) and its read rules."""

import json
from pathlib import Path

import pytest

from homelabnext import tlp
from homelabnext.tlp import Label

ROOT = Path(__file__).resolve().parents[2]


def test_five_labels_in_restriction_order():
    assert tlp.LABELS == ("clear", "green", "amber", "amber+strict", "red")
    assert list(Label) == sorted(Label)
    assert [str(label) for label in Label] == list(tlp.LABELS)
    assert Label.CLEAR < Label.GREEN < Label.AMBER < Label.AMBER_STRICT < Label.RED


@pytest.mark.parametrize(
    "spelling, label",
    [
        ("clear", Label.CLEAR),
        ("green", Label.GREEN),
        ("amber", Label.AMBER),
        ("amber+strict", Label.AMBER_STRICT),
        ("red", Label.RED),
        ("TLP:AMBER+STRICT", Label.AMBER_STRICT),
        ("tlp:green", Label.GREEN),
        ("  Amber  ", Label.AMBER),
        ("\ttlp:Clear\n", Label.CLEAR),
        ("white", Label.CLEAR),
        ("TLP:WHITE", Label.CLEAR),
        (Label.AMBER, Label.AMBER),
    ],
)
def test_accepted_spellings(spelling, label):
    assert tlp.read(spelling) is label
    assert tlp.parse(spelling) is label


@pytest.mark.parametrize(
    "value",
    [
        "",
        "   ",
        "amber-strict",
        "amber strict",
        "amber_strict",
        "amberstrict",
        "tlp: red",  # a space after the prefix is not an accepted spelling
        "tlp:",
        "tlp:tlp:red",
        "black",
        "secret",
        "public",
        "redd",
        "gr" + chr(0x435) + "en",  # Cyrillic e
        chr(0xFF47) + "reen",  # fullwidth g
        None,
        0,
        4,
        True,
        1.0,
        ["red"],
        {"tlp": "clear"},
    ],
)
def test_anything_else_reads_red_and_does_not_parse(value):
    assert tlp.read(value) is Label.RED
    with pytest.raises(ValueError, match="not a TLP label"):
        tlp.parse(value)


def test_read_never_lowers_a_damaged_label():
    # a misspelt loose label must not come back looser than red
    for broken in ("clea r", "gren", "ambr", "CLEAR!", "clear\x00"):
        assert tlp.read(broken) is Label.RED


def test_strictest_takes_the_most_restrictive_input():
    assert tlp.strictest(["clear", "green"]) is Label.GREEN
    assert tlp.strictest(["clear", "tlp:amber+strict", "amber"]) is Label.AMBER_STRICT
    assert tlp.strictest([Label.CLEAR, "white"]) is Label.CLEAR
    # an unreadable input is red, and red wins
    assert tlp.strictest(["clear", "typo"]) is Label.RED
    assert tlp.strictest(["clear", None]) is Label.RED
    # no inputs: unlabelled, so red
    assert tlp.strictest([]) is Label.RED
    assert tlp.strictest(iter(())) is Label.RED


def test_allows_is_at_or_below_the_ceiling():
    assert tlp.allows(Label.GREEN, "clear")
    assert tlp.allows(Label.GREEN, "green")
    assert not tlp.allows(Label.GREEN, "amber")
    assert tlp.allows(Label.RED, "red")
    assert tlp.allows(Label.AMBER_STRICT, "amber")
    assert not tlp.allows(Label.AMBER, "amber+strict")
    # a damaged label reads red: only a red ceiling receives it
    assert not tlp.allows(Label.AMBER_STRICT, "amber-strict")
    assert tlp.allows(Label.RED, "amber-strict")
    assert not tlp.allows(Label.CLEAR, None)


@pytest.mark.parametrize("ceiling", ["green", "red", 4, None])
def test_allows_refuses_a_ceiling_that_was_not_parsed(ceiling):
    with pytest.raises(TypeError, match="ceiling must be a Label"):
        tlp.allows(ceiling, "clear")


def test_bool_is_not_a_label():
    # True == 1 == Label.GREEN numerically; it must still not be accepted as a label
    assert tlp.read(True) is Label.RED
    with pytest.raises(TypeError):
        tlp.allows(True, "clear")


def test_publishing_sidecar_uses_the_canonical_enum():
    path = ROOT / "examples/modules/publishing/interfaces/publishable-item.schema.json"
    schema = json.loads(path.read_text(encoding="utf-8"))
    assert tuple(schema["properties"]["tlp"]["enum"]) == tlp.LABELS
