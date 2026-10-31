# SPDX-License-Identifier: Apache-2.0
"""Model requests carry their context label (ADR-0033 decision 11): ``homelabnext.registry.
model_tlp``, the gateway-side rule as a library function."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from homelabnext.registry import model_tlp as mt
from homelabnext.tlp import Label

ROOT = Path(__file__).resolve().parents[2]
EXAMPLES = ROOT / "schemas" / "platform" / "examples"


def _roles(name: str) -> dict:
    return json.loads((EXAMPLES / f"model_roles.{name}.json").read_text())["roles"]


CLOUD = _roles("cloud-bound")  # remote-reasoner leaves the lab; local-reasoner falls back to it
RAISED = _roles("cloud-terms")  # both roles raised to green with the provider's terms
LOCAL = _roles("valid")  # nothing leaves the lab
CLOUD_SENDER = mt.send_ceiling(data_tier="cloud-allowed")


# ------------------------------------------------------------------- the ADR's verification


def test_a_cloud_role_is_refused_an_amber_context():
    a = mt.admit(CLOUD, "mdl:remote-reasoner", "amber", sender=CLOUD_SENDER)
    assert not a and a.reason == mt.ABOVE_CEILING and a.label is Label.AMBER
    assert a.ceiling is Label.CLEAR and a.leaves_lab


def test_a_cloud_role_is_refused_an_unlabelled_request():
    a = mt.admit(CLOUD, "remote-reasoner", sender=CLOUD_SENDER)
    assert not a and a.reason == mt.UNLABELLED and a.label is Label.RED
    assert "unlabelled, read as red" in a.message


def test_a_clear_claim_from_an_amber_ceiling_profile_is_refused():
    """The caller asserts its label, so the sender's own ceiling bounds it from below."""
    a = mt.admit(CLOUD, "mdl:remote-reasoner", "clear", sender=Label.AMBER)
    assert not a and a.reason == mt.ABOVE_CEILING and a.label is Label.AMBER


def test_a_role_with_a_local_primary_and_a_cloud_fallback_has_the_cloud_ceiling():
    a = mt.admit(CLOUD, "mdl:local-reasoner", "green", sender=CLOUD_SENDER)
    assert not a and a.ceiling is Label.CLEAR and a.leaves_lab


# ------------------------------------------------------------------- the rest of the rule


def test_a_clear_request_from_a_clear_profile_reaches_a_cloud_role():
    a = mt.admit(CLOUD, "mdl:remote-reasoner", "tlp:CLEAR", sender=CLOUD_SENDER)
    assert a and a.reason == mt.WITHIN_CEILING and a.label is Label.CLEAR
    assert a.record() == {
        "role": "mdl:remote-reasoner",
        "allowed": True,
        "reason": "within-ceiling",
        "label": "clear",
        "ceiling": "clear",
        "leaves_lab": True,
    }
    assert a.message.startswith("allowed: ")


def test_a_raised_role_takes_green_and_never_amber():
    assert mt.admit(RAISED, "remote-summariser", "green", sender=CLOUD_SENDER)
    assert mt.admit(RAISED, "local-summariser", "green", sender=Label.GREEN)
    assert not mt.admit(RAISED, "remote-summariser", "amber", sender=CLOUD_SENDER)
    assert not mt.admit(RAISED, "remote-summariser", "clear", sender=Label.AMBER)


@pytest.mark.parametrize("claim", ["red", "amber+strict", None, "", "amber-strict", 3, b"clear"])
def test_a_local_role_takes_anything_and_the_sender_does_not_raise_it(claim):
    a = mt.admit(LOCAL, "mdl:main-reasoner", claim, sender=Label.RED)
    assert a and a.ceiling is Label.RED and not a.leaves_lab
    assert "stays in the lab" in a.message


@pytest.mark.parametrize("claim", [None, "", "amber-strict", "black", 0, ["clear"]])
def test_a_label_that_is_not_one_is_red(claim):
    a = mt.admit(CLOUD, "mdl:remote-reasoner", claim, sender=CLOUD_SENDER)
    assert not a and a.label is Label.RED and a.reason == mt.ABOVE_CEILING


def test_a_role_the_table_does_not_hold_is_refused():
    a = mt.admit(CLOUD, "mdl:gone", "clear", sender=CLOUD_SENDER)
    assert not a and a.reason == mt.UNKNOWN_ROLE
    assert a.record()["role"] == "mdl:gone" and "not in the role table" in a.message


def test_request_label_raises_to_the_sender_only_for_a_role_that_leaves_the_lab():
    assert mt.request_label("clear", leaves_lab=True, sender=Label.GREEN) is Label.GREEN
    assert mt.request_label("clear", leaves_lab=False, sender=Label.GREEN) is Label.CLEAR
    assert mt.request_label(leaves_lab=False, sender=Label.CLEAR) is Label.RED
    assert mt.request_label("amber", leaves_lab=True, sender=Label.CLEAR) is Label.AMBER


@pytest.mark.parametrize("sender", ["clear", None, 0])
def test_the_sender_ceiling_is_a_label_never_a_default(sender):
    with pytest.raises(TypeError, match="sender must be a Label"):
        mt.admit(CLOUD, "remote-reasoner", "clear", sender=sender)


@pytest.mark.parametrize(
    "ceiling, tier, want",
    [
        ("amber", "local-only", Label.AMBER),
        ("clear", "cloud-allowed", Label.CLEAR),
        ("not-a-label", "cloud-allowed", Label.RED),  # read as data
        (None, "cloud-allowed", Label.CLEAR),
        (None, "local-only", Label.RED),
        (None, None, Label.RED),
        (None, "anything", Label.RED),
    ],
)
def test_send_ceiling(ceiling, tier, want):
    assert mt.send_ceiling(ceiling, tier) is want


def test_send_ceiling_without_a_declaration_reads_the_data_tier():
    assert mt.send_ceiling(data_tier="cloud-allowed") is Label.CLEAR
    assert mt.send_ceiling() is Label.RED


# ------------------------------------------------------------------- data_tier is derived


@pytest.mark.parametrize(
    "label, tier",
    [
        (Label.CLEAR, "cloud-allowed"),
        (Label.GREEN, "local-only"),
        (Label.AMBER, "local-only"),
        (Label.AMBER_STRICT, "local-only"),
        (Label.RED, "local-only"),
    ],
)
def test_data_tier_of_a_label(label, tier):
    assert mt.data_tier_of(label) == tier
    assert mt.tier_disagreement(tier, label, "x") is None
    other = "local-only" if tier == "cloud-allowed" else "cloud-allowed"
    msg = mt.tier_disagreement(other, label, f"tlp_ceiling {label}")
    assert msg and f"data_tier {other} disagrees with tlp_ceiling {label}" in msg


def test_data_tier_of_needs_a_label():
    with pytest.raises(TypeError):
        mt.data_tier_of("clear")
    assert mt.tier_disagreement(None, Label.RED, "x")  # a missing tier never agrees
