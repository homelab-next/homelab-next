# SPDX-License-Identifier: Apache-2.0
"""The label spellings real feeds and reports use, and what each reader of ``homelabnext.tlp``
makes of them: the corpus every reader is held to, so a spelling cannot be read one way on
arrival and another at egress or in storage (ADR-0033 decision 1)."""

import pytest

from homelabnext import tlp, tlp_egress
from homelabnext.logpipeline import tlp_labels
from homelabnext.tlp import Label

C, G, A, S, R = Label.CLEAR, Label.GREEN, Label.AMBER, Label.AMBER_STRICT, Label.RED

#: (spelling, as an incoming label: read(), as a tag: tag_label(), as a stored value)
CORPUS = [
    # canonical: every reader agrees
    ("clear", C, None, C),
    ("green", G, None, G),
    ("amber", A, None, A),
    ("amber+strict", S, None, S),
    ("red", R, None, R),
    # the prefixed and capitalised forms feeds and tag vocabularies use: lenient readers only
    ("TLP:CLEAR", C, C, R),
    ("tlp:white", C, C, R),
    ("TLP:WHITE", C, C, R),
    ("TLP:GREEN", G, G, R),
    ("tlp:amber", A, A, R),
    ("TLP:AMBER+STRICT", S, S, R),
    ("tlp:amber+strict", S, S, R),
    ("TLP:RED", R, R, R),
    ("Green", G, None, R),
    ("white", C, None, R),
    ("  red\n", R, None, R),
    # report-header and file-name spellings: markers, not incoming labels
    ("TLP: AMBER", R, A, R),
    ("TLP : RED", R, R, R),
    ("TLP AMBER", R, A, R),
    ("TLP_RED", R, R, R),
    ("TLP-GREEN", R, G, R),
    ("[TLP:GREEN]", R, G, R),
    ("TLP:AMBER + STRICT", R, S, R),
    # not labels anywhere: red wherever they are read as one
    ("amber-strict", R, None, R),
    ("tlp:amber-strict", R, R, R),
    ("TLP:AMBER STRICT", R, R, R),
    ("tlp:unclear", R, R, R),
    ("tlp:ex:chr", R, R, R),
    ("tlp:", R, R, R),
    ("", R, None, R),
]


@pytest.mark.parametrize("text, incoming, tag, stored", CORPUS)
def test_the_corpus(text, incoming, tag, stored):
    assert tlp.read(text) is incoming
    assert tlp.tag_label(text) is tag
    assert tlp.read_stored(text) is stored


@pytest.mark.parametrize("text, incoming, tag, stored", CORPUS)
def test_a_body_marker_and_a_tag_are_one_grammar(text, incoming, tag, stored):
    found = tlp_egress.markers(text)
    assert (max(found) if found else None) is tag


@pytest.mark.parametrize("text, incoming, tag, stored", CORPUS)
def test_parse_stored_refuses_exactly_what_read_stored_reads_as_red(text, incoming, tag, stored):
    if text in tlp.LABELS:
        assert tlp.parse_stored(text) is stored
    else:
        with pytest.raises(ValueError, match="canonical"):
            tlp.parse_stored(text)


@pytest.mark.parametrize("value", [None, 3, b"red", Label.RED, ["red"]])
def test_a_stored_value_that_is_not_text_is_red(value):
    assert tlp.read_stored(value) is R
    with pytest.raises(ValueError):
        tlp.parse_stored(value)


def test_a_stix_marking_is_read_in_one_place():
    ref = "marking-definition--939a9414-2ddd-4d32-a0cd-375ea402b003"
    assert tlp.stix_marking_label(ref) is S
    assert tlp.stix_marking_label("  " + ref.upper() + " ") is S
    assert (
        tlp.stix_marking_label("marking-definition--00000000-0000-4000-8000-000000000000") is None
    )
    assert tlp.stix_marking_label(None) is None
    assert not hasattr(tlp_labels, "STIX_TLP_MARKINGS")  # no second copy of the table
