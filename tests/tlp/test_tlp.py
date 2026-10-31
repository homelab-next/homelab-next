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
        ("tlp:white", Label.CLEAR),
        (" \r\nred\t", Label.RED),
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
        "tlp:tlp:clear",  # the prefix is taken once
        "\x0bclear",  # only spaces, tabs, CR and LF are stripped
        "\x1cclear",
        "\x0cgreen\x0c",
        "\u00a0clear",  # no-break space
        "clear\u3000",
        "tlp:clear\x00",
        b"clear",
        bytearray(b"clear"),
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
    # a single string is one input, not its characters; a non-iterable is unreadable
    assert tlp.strictest("clear") is Label.CLEAR
    assert tlp.strictest("amber+strict") is Label.AMBER_STRICT
    assert tlp.strictest(Label.GREEN) is Label.GREEN
    assert tlp.strictest(b"clear") is Label.RED
    assert tlp.strictest(None) is Label.RED
    assert tlp.strictest(3) is Label.RED


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


def test_numbers_are_not_labels():
    assert tlp.read(True) is Label.RED
    assert tlp.read(0) is Label.RED
    with pytest.raises(TypeError):
        tlp.allows(True, "clear")
    with pytest.raises(TypeError):
        tlp.allows(0, "clear")


def test_a_label_compares_only_with_a_label_and_is_always_truthy():
    assert all(bool(label) for label in Label)
    assert Label.CLEAR != 0
    assert Label.GREEN != 1
    with pytest.raises(TypeError):
        _ = Label.RED >= 4
    with pytest.raises(TypeError):
        _ = Label.CLEAR < 1
    assert [label.rank for label in Label] == [0, 1, 2, 3, 4]
    assert max(Label) is Label.RED and min(Label) is Label.CLEAR


def test_parse_and_allows_take_a_label_as_is():
    for label in Label:
        assert tlp.parse(label) is label
        assert tlp.read(label) is label
        assert tlp.allows(Label.RED, label)
    assert tlp.allows(Label.AMBER, Label.AMBER)
    assert not tlp.allows(Label.AMBER, Label.AMBER_STRICT)


class _Lying(str):
    def strip(self, *args):
        return "clear"

    def lower(self):
        return "clear"

    def startswith(self, *args):
        return False


class _Equal(str):
    def __eq__(self, other):
        return True

    def __hash__(self):
        return hash("clear")


class _Raising(str):
    def isascii(self):
        raise RuntimeError("boom")

    def __str__(self):
        raise RuntimeError("boom")


@pytest.mark.parametrize("cls", [_Lying, _Equal, _Raising])
def test_a_str_subclass_is_read_as_the_str_it_holds(cls):
    assert tlp.read(cls("red")) is Label.RED
    assert tlp.read(cls("typo")) is Label.RED
    assert tlp.read(cls("green")) is Label.GREEN
    assert tlp.strictest(["clear", cls("red")]) is Label.RED
    assert not tlp.allows(Label.AMBER, cls("red"))


def test_the_spelling_tables_are_read_only():
    with pytest.raises(TypeError):
        tlp._SPELLINGS["red"] = Label.CLEAR  # type: ignore[index]


def test_publishing_sidecar_uses_the_canonical_enum():
    path = ROOT / "examples/modules/publishing/interfaces/publishable-item.schema.json"
    schema = json.loads(path.read_text(encoding="utf-8"))
    assert tuple(schema["properties"]["tlp"]["enum"]) == tlp.LABELS


@pytest.mark.parametrize(
    "declared, item, honour, want",
    [
        # a null label field is not a missing one: it reads red
        (Label.CLEAR, None, False, Label.RED),
        (Label.GREEN, None, True, Label.RED),
        # stricter carried labels are always kept
        (Label.GREEN, "amber", False, Label.AMBER),
        (Label.CLEAR, "tlp:red", False, Label.RED),
        # looser carried labels are raised to the declaration unless the source is honoured
        (Label.AMBER, "clear", False, Label.AMBER),
        (Label.AMBER, "clear", True, Label.CLEAR),
        (Label.RED, "green", True, Label.GREEN),
        # an unreadable carried label is red, whatever the declaration and the trust
        (Label.CLEAR, "amber-strict", True, Label.RED),
        (Label.GREEN, "", False, Label.RED),
        # only True honours: a string that looks true does not
        (Label.AMBER, "clear", "yes", Label.AMBER),
        (Label.AMBER, "clear", 1, Label.AMBER),
    ],
)
def test_item_label(declared, item, honour, want):
    assert tlp.item_label(declared, item, honour_item_labels=honour) is want


@pytest.mark.parametrize("declared", ["amber", None, 2])
def test_item_label_needs_a_parsed_declaration(declared):
    with pytest.raises(TypeError, match="declared must be a Label"):
        tlp.item_label(declared, "clear")


def test_an_item_that_carried_no_label_takes_the_declaration():
    for label in Label:
        assert tlp.item_label(label) is label
        assert tlp.item_label(label, honour_item_labels=True) is label
