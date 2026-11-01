# SPDX-License-Identifier: Apache-2.0
"""homelabnext.grants is the one definition of the broker tiers and the grant lookup: the broker,
the profile compiler, the handoff, the access block and the playbook validator all read it."""

import json
from pathlib import Path

import pytest

import homelabnext.grants as grants

REPO = Path(__file__).resolve().parents[2]
MANIFEST = json.loads((REPO / "schemas/broker/examples/manifest.example.json").read_text())


def test_the_tiers_are_the_broker_schemas_in_rank_order():
    schema = json.loads((REPO / "schemas/broker/manifest.schema.json").read_text())
    enums = []

    def walk(node):
        if isinstance(node, dict):
            if set(node.get("enum") or ()) == set(grants.TIERS):
                enums.append(node["enum"])
            for v in node.values():
                walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)

    walk(schema)
    assert enums, "the broker manifest schema names no tier enum"
    assert grants.TIER_RANK == {"read": 0, "write": 1, "execute": 2, "privileged": 3}


def test_every_reader_uses_the_one_definition():
    from homelabnext import broker
    from homelabnext.agent import TIER_RANK, compiler

    assert broker.TIER_RANK is grants.TIER_RANK is compiler.TIER_RANK is TIER_RANK


def test_grant_for_finds_the_grant_naming_actor_and_action():
    g = MANIFEST["grants"][0]
    action = g["actions"][0]
    assert grants.grant_for(MANIFEST, g["profile"], action) is g
    assert grants.grant_for(MANIFEST, g["profile"], "no.such-action") is None
    assert grants.grant_for(MANIFEST, "profile:nobody", action) is None
    assert grants.grant_for({}, g["profile"], action) is None


def test_tier_exceeds():
    assert grants.tier_exceeds("execute", "write")
    assert not grants.tier_exceeds("write", "write")
    assert not grants.tier_exceeds("read", "privileged")
    with pytest.raises(KeyError):
        grants.tier_exceeds("admin", "read")
