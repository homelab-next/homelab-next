# SPDX-License-Identifier: Apache-2.0
"""``fast-classifier``: labels come only from the offered set, deterministically, with a confidence."""

from __future__ import annotations

from conformance.fakes.keyword_classifier import InventingClassifier, KeywordClassifier
from homelabnext.conform.core import Mutant, Suite

from ._util import raises

SUITE = Suite(
    "fast-classifier",
    "small text classifier: label from the offered set, confidence in [0, 1], deterministic",
    "conformance.protocols.classifier:Classifier",
)

POS = "This is wonderful, excellent work. Thank you!"
NEG = "Terrible failure: everything is broken and awful."
NEUTRAL = "The quarterly meeting is scheduled for the third floor room."
LABELS = ["positive", "negative"]


@SUITE.check("label-from-offered-set", "the answer is always one of the labels the caller offered")
def _(c):
    for text in (POS, NEG, NEUTRAL, "zzzz qqqq 0000", "☃ ☃"):
        got = c.classify(text, LABELS)
        assert got.label in LABELS, f"{text[:30]!r} -> invented label {got.label!r}"


@SUITE.check("confidence-in-unit-interval", "confidence is a number in [0, 1]")
def _(c):
    for text in (POS, NEG, NEUTRAL):
        conf = c.classify(text, LABELS).confidence
        assert isinstance(conf, int | float) and 0.0 <= conf <= 1.0, f"confidence {conf!r}"


@SUITE.check("deterministic", "the same input gives the same answer")
def _(c):
    a, b = c.classify(POS, LABELS), c.classify(POS, LABELS)
    assert a == b, f"{a} != {b}"


@SUITE.check(
    "obvious-cases-are-right", "unmistakable positive and negative texts get the right label"
)
def _(c):
    assert c.classify(POS, LABELS).label == "positive", "wonderful text not positive"
    assert c.classify(NEG, LABELS).label == "negative", "awful text not negative"


@SUITE.check("single-label-returns-it", "with one label offered, that label is the answer")
def _(c):
    assert c.classify(NEUTRAL, ["only-label"]).label == "only-label"


@SUITE.check("no-labels-rejected", "an empty label list is an error, not a guess")
def _(c):
    raises(lambda: c.classify(POS, []), "empty labels", ValueError)


@SUITE.check("empty-text-handled", "empty text still yields an offered label")
def _(c):
    assert c.classify("", LABELS).label in LABELS


@SUITE.check(
    "label-order-does-not-matter",
    "offering the labels in another order does not change the answer",
    severity="should",
)
def _(c):
    assert c.classify(POS, LABELS).label == c.classify(POS, LABELS[::-1]).label


@SUITE.check(
    "duplicate-labels-tolerated", "a repeated label in the offer is harmless", severity="should"
)
def _(c):
    assert c.classify(POS, ["positive", "positive", "negative"]).label in LABELS


@SUITE.check("long-input-handled", "a 50 kB input does not crash the classifier", severity="should")
def _(c):
    assert c.classify((POS + " ") * 1000, LABELS).label in LABELS


@SUITE.check(
    "confidence-tracks-decisiveness",
    "an obvious text is at least as confident as a vacuous one",
    severity="should",
)
def _(c):
    assert c.classify(POS, LABELS).confidence >= c.classify(NEUTRAL, LABELS).confidence


def make_fake():
    return KeywordClassifier()


MUTANTS = {
    "invents-label": Mutant(
        InventingClassifier,
        "label-from-offered-set",
        "answers 'unknown' when nothing matches",
    ),
}
