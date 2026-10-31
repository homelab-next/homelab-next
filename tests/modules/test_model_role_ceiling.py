# SPDX-License-Identifier: Apache-2.0
"""A model role's TLP ceiling (ADR-0033 decision 10): ``rules.role_ceiling`` and the validation
that refuses what would read as a ceiling other than the one declared."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from homelabnext.modules import rules
from homelabnext.modules import swap_evidence as se
from homelabnext.tlp import Label

ROOT = Path(__file__).resolve().parents[2]
EXAMPLES = ROOT / "schemas" / "platform" / "examples"
TERMS = {"retention": "none", "training": "none", "ref": "the provider's terms, 2026-09"}
LOCAL = {"backend": "svc:inference", "model_id": "example-local-1"}
REMOTE = {"backend": "svc:cloud-inference", "model_id": "example-remote-1", "leaves_lab": True}


def _roles(name: str) -> dict:
    return json.loads((EXAMPLES / f"model_roles.{name}.json").read_text())["roles"]


def test_a_local_role_is_red_and_a_role_that_leaves_the_lab_is_clear():
    roles = _roles("cloud-bound")
    assert rules.role_ceiling(roles, "mdl:remote-reasoner") is Label.CLEAR
    # a local primary whose fallback leaves the lab has the cloud ceiling (the ADR's fixture)
    assert rules.role_ceiling(roles, "local-reasoner") is Label.CLEAR
    assert rules.role_ceiling(_roles("valid"), "main-reasoner") is Label.RED
    assert rules.role_ceilings(roles) == {
        "mdl:local-reasoner": Label.CLEAR,
        "mdl:remote-reasoner": Label.CLEAR,
    }
    assert rules.role_ceiling_problems(roles) == []


def test_a_role_the_table_does_not_hold_is_red():
    assert rules.role_ceiling(_roles("cloud-bound"), "mdl:no-such-role") is Label.RED


def test_the_provider_terms_raise_a_cloud_role_to_green_and_no_further():
    roles = _roles("cloud-terms")
    assert rules.role_ceilings(roles) == {
        "mdl:local-summariser": Label.GREEN,
        "mdl:remote-summariser": Label.GREEN,
    }
    assert rules.role_ceiling_problems(roles) == []


@pytest.mark.parametrize(
    "mutate, want",
    [
        # the terms missing, partial or not "none": the role stays clear, and validation says so
        (lambda r: r["remote-summariser"]["bindings"][0].pop("provider_terms"), "records no"),
        (
            lambda r: r["remote-summariser"]["bindings"][0]["provider_terms"].update(
                training="opt-out"
            ),
            "records no",
        ),
        # a raised primary whose fallback is not raised stays clear
        (lambda r: r["remote-summariser"].pop("tlp_ceiling"), "raise mdl:remote-summariser"),
    ],
)
def test_a_raise_without_the_terms_on_every_binding_stays_clear_and_is_refused(mutate, want):
    roles = _roles("cloud-terms")
    mutate(roles)
    assert rules.role_ceiling(roles, "local-summariser") is Label.CLEAR
    probs = rules.role_ceiling_problems(roles)
    assert any(p.startswith("mdl:local-summariser") and want in p for p in probs), probs


def test_a_terms_record_down_the_chain_is_needed_too():
    roles = {
        "a": {"tlp_ceiling": "green", "bindings": [{**REMOTE, "provider_terms": TERMS}],
              "fallback": "mdl:b"},
        "b": {"tlp_ceiling": "green", "bindings": [REMOTE]},
    }  # fmt: skip
    assert rules.role_ceiling(roles, "a") is Label.CLEAR
    probs = rules.role_ceiling_problems(roles)
    assert any("mdl:a" in p and "(down its fallback chain, mdl:b)" in p for p in probs), probs
    roles["b"]["bindings"] = [{**REMOTE, "provider_terms": TERMS}]
    assert rules.role_ceiling(roles, "a") is Label.GREEN
    assert rules.role_ceiling_problems(roles) == []


@pytest.mark.parametrize("value", ["amber", "amber+strict", "red"])
def test_amber_and_above_are_never_allowed_for_a_role_that_leaves_the_lab(value):
    roles = _roles("cloud-terms")
    roles["remote-summariser"]["tlp_ceiling"] = value
    probs = rules.role_ceiling_problems(roles)
    assert any("never granted" in p for p in probs), probs
    assert rules.role_ceiling(roles, "remote-summariser") is Label.CLEAR


@pytest.mark.parametrize("value", ["Green", "tlp:green", "amber-strict", "", None, 1])
def test_a_ceiling_that_is_not_a_canonical_label_is_refused(value):
    roles = _roles("cloud-terms")
    roles["remote-summariser"]["tlp_ceiling"] = value
    probs = rules.role_ceiling_problems(roles)
    assert any(p.startswith("mdl:remote-summariser: tlp_ceiling") for p in probs), probs


def test_a_local_role_declares_no_ceiling_and_records_no_terms():
    roles = {"a": {"tlp_ceiling": "clear", "bindings": [{**LOCAL, "provider_terms": TERMS}]}}
    probs = rules.role_ceiling_problems(roles)
    assert any("a local role's ceiling is red" in p for p in probs), probs
    assert any("records provider_terms but does not leave the lab" in p for p in probs), probs
    assert rules.role_ceiling(roles, "a") is Label.RED


def test_the_ceiling_is_in_addition_to_grants_cloud_models():
    """A raised role still leaves the lab: a module requiring it still needs the grant."""
    roles = _roles("cloud-terms")
    assert rules.cloud_roles(roles) == {"mdl:local-summariser", "mdl:remote-summariser"}


def test_a_dangling_or_looping_chain_is_read_as_cloud_roles_reads_it():
    roles = {
        "a": {"bindings": [REMOTE], "fallback": "mdl:a"},
        "b": {"bindings": [LOCAL], "fallback": "mdl:gone"},
    }
    assert rules.role_ceiling(roles, "a") is Label.CLEAR
    assert rules.role_ceiling(roles, "b") is Label.RED


@pytest.mark.parametrize(
    "mutate, field",
    [
        (lambda r: r["main-reasoner"].update(tlp_ceiling="green"), "tlp_ceiling"),
        (
            lambda r: r["main-reasoner"]["bindings"][0].update(provider_terms=TERMS),
            "bindings[].provider_terms",
        ),
    ],
)
def test_raising_a_ceiling_is_a_trust_change_the_swap_gate_needs_a_record_for(mutate, field):
    """Neither field is in a pin, so the swap gate reads them as a trust change of the role (a
    record naming it, on top of the human approve every change to the table already is)."""
    base = {"version": 1, "roles": _roles("valid")}
    head = copy.deepcopy(base)
    mutate(head["roles"])
    assert se._trust_changes(base, head) == {"main-reasoner": [field]}


@pytest.mark.parametrize("value", [" TLP:GREEN ", "tlp:green", "GREEN", "green\n", "Green"])
def test_only_the_canonical_spelling_raises_a_role(value):
    """Validation refuses a non-canonical ceiling, so it must raise nothing either: the role
    stays clear in role_ceiling and in admit."""
    from homelabnext.registry import model_tlp as mt

    roles = _roles("cloud-terms")
    for r in roles.values():
        r["tlp_ceiling"] = value
    assert rules.role_ceiling(roles, "remote-summariser") is Label.CLEAR
    assert rules.role_ceiling(roles, "local-summariser") is Label.CLEAR
    a = mt.admit(roles, "remote-summariser", "green", sender=Label.CLEAR)
    assert not a and a.ceiling is Label.CLEAR
    assert rules.role_ceiling_problems(roles)
