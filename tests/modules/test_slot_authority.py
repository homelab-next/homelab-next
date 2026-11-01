# SPDX-License-Identifier: Apache-2.0
"""The authority slots have one source (homelabnext.modules.authority): the manifest and
selection schema generator and the loader's rules read it, and the slot registry's
``authority`` and ``granted_upstream`` flags must agree with it."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import yaml

import homelabnext.modules.authority as authority
from homelabnext.modules import cli as mcli
from homelabnext.modules import rules as mr
from homelabnext.schemas import module_manifest as mm

ROOT = Path(__file__).resolve().parents[2]
SLOTS = yaml.safe_load((ROOT / "examples/modules/slots.yml").read_text())["slots"]


def test_the_schema_generator_and_the_rules_read_the_one_list():
    assert tuple("cap:" + s for s in authority.AUTHORITY_SLOTS) == mm.AUTHORITY_SLOTS
    assert tuple("cap:" + s for s in authority.NEVER_SHARED) == mm.NEVER_SHARED
    assert mr.AUTHORITY_SLOTS is authority.AUTHORITY_SLOTS
    assert mr.GRANTED_UPSTREAMS is authority.GRANTED_UPSTREAMS
    assert {"cap:" + s for s in authority.SHARED_CONFIG_GRANTS} == mr.PRIVILEGED_SHARED_CONFIG


def test_the_generated_selection_schema_grants_exactly_the_derived_sets():
    sel = json.loads((ROOT / "schemas/platform/module_selection.schema.json").read_text())
    grants = sel["properties"]["grants"]["properties"]

    def enum(kind):
        return grants[kind]["additionalProperties"]["items"]["enum"]

    assert enum("upstreams") == ["cap:" + s for s in authority.GRANTED_UPSTREAMS]
    assert enum("shared_config") == ["cap:" + s for s in authority.SHARED_CONFIG_GRANTS]


def test_every_authority_slot_is_closed_to_shared_config_or_needs_a_grant():
    for s in authority.AUTHORITY_SLOTS:
        assert (s in authority.NEVER_SHARED) != (s in authority.SHARED_CONFIG_GRANTS), s
    assert set(authority.GRANTED_UPSTREAMS) <= set(authority.AUTHORITY_SLOTS)


def test_the_shipped_registry_flags_agree_with_the_list():
    assert authority.slot_flag_problems(SLOTS) == []
    flagged = {s for s, d in SLOTS.items() if d.get("authority")}
    assert flagged == set(authority.AUTHORITY_SLOTS) & set(SLOTS)
    assert {"broker", "secrets", "idp", "edge"} <= flagged


def test_a_registry_that_drops_or_adds_an_authority_flag_is_a_problem():
    """Negative: either direction of disagreement is reported by the loader, so a registry can
    neither demote a trust root to ordinary nor flag one the rules do not know."""
    slots = copy.deepcopy(SLOTS)
    del slots["edge"]["authority"]
    slots["dns"]["authority"] = True
    slots["broker"]["granted_upstream"] = False
    good, probs = mcli._slot_entries({"slots": slots})
    text = [p.message for p in probs]
    assert any(t.startswith("edge: an authority slot") for t in text), text
    assert any(t.startswith("dns: flagged authority") for t in text), text
    assert any(t.startswith("broker: a granted-upstream slot") for t in text), text
    assert "dns" in good  # the entry still validates: the disagreement is the problem


def test_the_slot_schema_refuses_a_granted_upstream_that_is_not_an_authority():
    slots = copy.deepcopy(SLOTS)
    slots["dns"]["granted_upstream"] = True
    good, probs = mcli._slot_entries({"slots": slots})
    assert "dns" not in good
    assert any(p.message.startswith("dns: schema:") for p in probs), probs
