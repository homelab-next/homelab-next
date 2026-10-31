# SPDX-License-Identifier: Apache-2.0
"""An agent profile's TLP ceiling (ADR-0033 decision 12): attested by the ceiling policy where it
attests ``data_tier``, agreeing with it, and bounding the ``tlp`` of every MCP server granted."""

from __future__ import annotations

import copy

import pytest
import yaml
from agent_support import library, spec

from homelabnext.agent import (
    CatalogViolation,
    CeilingPolicy,
    CeilingViolation,
    SpecError,
    compile_profile,
    verify_profile,
)
from homelabnext.agent.readers import (
    DEFAULT_CLASSES,
    ToolClasses,
    grant_problems,
    profile_problems,
    receive_ceiling,
    server_label,
)
from homelabnext.tlp import Label

ENTRY = {
    "mcp": ["lake"],
    "capabilities": ["cap:lake-query"],
    "tier": "read",
    "data_tier": "local-only",
    "budgets": {
        "max_input_tokens": 64000,
        "max_output_tokens": 4000,
        "max_runtime_s": 900,
        "max_tool_calls": 40,
    },
}


def _policy(**entry) -> CeilingPolicy:
    return CeilingPolicy.from_mapping({"ceilings": {"profile:reader": {**ENTRY, **entry}}})


def _spec(**over) -> dict:
    s = {k: v for k, v in spec().items() if k != "ceiling"}
    s.update(over)
    return s


def _table(label: str | None) -> ToolClasses:
    """The packaged class table with one server, ``lake``, whose data is labelled ``label``."""
    doc = yaml.safe_load(DEFAULT_CLASSES.read_text())
    meta = {"lake": {"status": "active", "data_tier": "local-only", "tlp": label}}
    return ToolClasses({**doc, "mcp": {"lake": ["read"]}}, catalog=meta)


# ------------------------------------------------------------------- the policy's attestation


@pytest.mark.parametrize(
    "entry, words",
    [
        ({"tlp_ceiling": "amber-strict"}, "not a TLP label"),
        ({"tlp_ceiling": "TLP:RED"}, "is not written as 'red'"),
        ({"tlp_ceiling": "clear"}, "data_tier local-only disagrees with tlp_ceiling clear"),
        (
            {"tlp_ceiling": "amber", "data_tier": "cloud-allowed"},
            "data_tier cloud-allowed disagrees with tlp_ceiling amber",
        ),
    ],
)
def test_the_policy_refuses_a_ceiling_that_is_not_a_label_or_disagrees_with_its_tier(entry, words):
    with pytest.raises(SpecError, match=words.replace("+", r"\+")):
        _policy(**entry)


def test_a_policy_ceiling_attests_the_tier_it_derives():
    """Without data_tier on the entry, an attested ceiling above clear attests local-only: the
    local-only server is granted, and a spec that calls itself cloud-allowed is refused."""
    entry = {k: v for k, v in ENTRY.items() if k != "data_tier"}
    pol = CeilingPolicy.from_mapping(
        {"ceilings": {"profile:reader": {**entry, "tlp_ceiling": "red"}}}
    )
    assert pol.tlp_ceiling("profile:reader") is Label.RED
    p = compile_profile(_spec(), library(), policy=pol)
    assert p["tlp_ceiling"] == "red" and verify_profile(p, policy=pol) == []
    with pytest.raises(CeilingViolation, match="attests data_tier local-only"):
        compile_profile(_spec(data_tier="cloud-allowed"), library(), policy=pol)


def test_the_compiled_profile_carries_the_attested_ceiling_and_a_spec_may_not_differ():
    pol = _policy(tlp_ceiling="amber")
    p = compile_profile(_spec(), library(), policy=pol, classes=_table("amber"))
    assert p["tlp_ceiling"] == "amber"
    assert (
        compile_profile(_spec(tlp_ceiling="amber"), library(), policy=pol, classes=_table("amber"))
        == p
    )
    with pytest.raises(CeilingViolation, match="attests tlp_ceiling amber for profile:reader"):
        compile_profile(_spec(tlp_ceiling="red"), library(), policy=pol, classes=_table("amber"))


def test_a_profile_without_an_attested_or_declared_ceiling_compiles_as_before():
    p = compile_profile(_spec(), library(), policy=_policy())
    assert "tlp_ceiling" not in p
    assert _policy().tlp_ceiling("profile:reader") is None
    (note,) = _policy().tlp_notes()
    assert "attest no tlp_ceiling" in note and "profile:reader" in note
    assert _policy(tlp_ceiling="red").tlp_notes() == []


def test_a_server_above_the_attested_ceiling_is_refused():
    """The ADR's fixture: a profile is refused a server whose label is above its ceiling."""
    pol = _policy(tlp_ceiling="green")
    with pytest.raises(CeilingViolation) as exc:
        compile_profile(_spec(), library(), policy=pol, classes=_table("amber"))
    assert any(
        "MCP server(s) ['lake'], whose data is labelled above the TLP ceiling green" in p
        for p in exc.value.problems
    ), exc.value.problems
    assert (
        compile_profile(_spec(), library(), policy=pol, classes=_table("green"))["tlp_ceiling"]
        == "green"
    )


def test_a_server_with_no_label_reads_from_its_data_tier():
    """A local-only server without tlp reads red, so a green ceiling refuses it."""
    with pytest.raises(CeilingViolation, match="labelled above the TLP ceiling green"):
        compile_profile(
            _spec(), library(), policy=_policy(tlp_ceiling="green"), classes=_table(None)
        )
    assert server_label({"data_tier": "cloud-allowed"}) is Label.CLEAR
    assert server_label({"data_tier": "local-only"}) is Label.RED
    assert server_label({"tlp": "not-a-label"}) is Label.RED


def test_verify_refuses_a_compiled_profile_edited_to_another_ceiling():
    pol = _policy(tlp_ceiling="red")
    p = compile_profile(_spec(), library(), policy=pol)
    t = copy.deepcopy(p)
    t["tlp_ceiling"] = "green"
    problems = verify_profile(t, policy=pol)
    assert any(
        "attests tlp_ceiling red for profile:reader; the profile says green" in x for x in problems
    )


# ------------------------------------------------------------------- without a policy


def test_a_declared_ceiling_bounds_the_grants_without_a_policy():
    s = spec()
    s["tlp_ceiling"] = "green"
    with pytest.raises(
        CatalogViolation, match="returns data labelled amber, above the profile's TLP ceiling green"
    ):
        compile_profile(s, library(), classes=_table("amber"))
    assert compile_profile(s, library(), classes=_table("green"))["tlp_ceiling"] == "green"


@pytest.mark.parametrize(
    "ceiling, tier, words",
    [
        ("green", "cloud-allowed", "disagrees with tlp_ceiling green"),
        ("clear", "local-only", "disagrees with tlp_ceiling clear"),
        ("white", "cloud-allowed", "is not written as 'clear'"),
        ("black", "local-only", "is not a TLP label"),
    ],
)
def test_a_profile_ceiling_must_agree_with_its_data_tier(ceiling, tier, words):
    s = spec()
    s.update(tlp_ceiling=ceiling, data_tier=tier)
    with pytest.raises(SpecError, match=words):
        compile_profile(s, library())
    lean = {"id": "profile:reader", "data_tier": tier, "tlp_ceiling": ceiling, "mcp": []}
    assert any(words in p for p in profile_problems(lean))


@pytest.mark.parametrize(
    "ceiling, tier, want",
    [
        (None, "local-only", Label.RED),  # what a local-only profile already receives
        (None, "cloud-allowed", Label.CLEAR),
        (None, None, Label.CLEAR),  # nothing attested or declared: the least
        ("amber", "local-only", Label.AMBER),
        ("nonsense", "local-only", Label.RED),  # read as data; refused by tlp_ceiling_problems
    ],
)
def test_receive_ceiling(ceiling, tier, want):
    assert receive_ceiling(ceiling, tier) is want


def test_a_manifest_is_judged_by_no_ceiling():
    """grant_problems without data_tier or tlp_ceiling (a context manifest) applies no TLP rule."""
    assert grant_problems({"mcp": ["lake"]}, _table("red"), "manifest m") == []
