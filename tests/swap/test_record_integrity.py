# SPDX-License-Identifier: Apache-2.0
"""The swap record's steps, route and status must agree with its transition log.

Regression tests for the security review: a step marked passed without its transition, a
truncated log, a keyed chain recomputed without the key, and an anchored head.
"""

from __future__ import annotations

import copy
import json

import pytest
from support import ROOT

from homelabnext.swap import record as R

EX = ROOT / "schemas" / "platform" / "examples"


def _doc(label="active"):
    return json.loads((EX / f"swap_record.{label}.json").read_text())


@pytest.fixture(autouse=True)
def _no_env_key(monkeypatch):
    monkeypatch.delenv(R.KEY_ENV, raising=False)


def test_forged_steps_without_transitions_are_reported():
    t = _doc()
    for name in ("soak", "cutover"):
        s = next(x for x in t["steps"] if x["name"] == name)
        s.update(
            status="passed",
            attempts=1,
            started_at="2026-04-01T09:00:00Z",
            finished_at="2026-04-01T09:00:00Z",
            evidence=[
                {"kind": "x", "ref": "fake.json", "sha256": "sha256:" + "a" * 64, "summary": "fake"}
            ],
            gates=[],
        )
    t["current_step"] = "rollback-window"
    t["route"]["flipped"] = True
    probs = R.problems(t)
    assert any("step-passed transitions" in p for p in probs), probs
    assert any("differ from the state the last transition recorded" in p for p in probs), probs


def test_truncated_chain_is_reported():
    t = _doc()
    t["transitions"] = t["transitions"][:2]
    t["updated_at"] = t["transitions"][-1]["at"]
    probs = R.problems(t)
    assert any("step-passed transitions" in p for p in probs), probs


def test_route_flip_alone_is_reported():
    t = _doc("closed")
    t["route"]["after"]["port"] = 1
    assert any("state" in p for p in R.problems(t))


def test_finished_at_and_evidence_must_match_the_transition():
    t = _doc()
    t["steps"][0]["finished_at"] = "2026-04-02T09:00:00Z"
    assert any("finished_at" in p for p in R.record_problems(t))
    t = _doc()
    t["steps"][1]["evidence"][0]["summary"] = "something else"
    assert any("names no evidence" in p for p in R.record_problems(t))


def test_status_needs_its_transition():
    t = _doc("closed")
    t["transitions"] = [x for x in t["transitions"] if x["event"] != "closed"]
    assert any("'closed' transition is absent" in p for p in R.record_problems(t))


def _keyed_record(key):
    return R.new_record(
        swap_id="s-keyed",
        capability="cap:lake-query",
        from_adapter="a",
        to_adapter="b",
        service="lake-query",
        before={"host": "h1", "port": 1},
        after={"host": "h2", "port": 1},
        now="2026-04-01T09:00:00Z",
        actor="op",
        key=key,
    )


def test_keyed_chain_needs_the_key_and_cannot_be_recomputed_without_it():
    doc = _keyed_record(b"k1")
    assert doc["chain"] == {"alg": "hmac-sha256"}
    R.append_transition(
        doc, at="2026-04-01T09:01:00Z", event="note", step="declare", actor="op", key=b"k1"
    )
    assert R.problems(doc, key=b"k1") == []
    assert any("set" in p for p in R.problems(doc))  # no key: cannot verify
    assert any("hash does not match" in p for p in R.problems(doc, key=b"other"))
    # an attacker without the key edits the note and recomputes with plain sha256
    forged = copy.deepcopy(doc)
    forged["transitions"][-1]["note"] = "forged"
    for t in forged["transitions"]:
        t["hash"] = R.chain_hash(t["prev"], t)
    assert any("hash does not match" in p for p in R.problems(forged, key=b"k1"))


def test_downgrade_to_unkeyed_is_refused_when_a_key_is_configured(monkeypatch):
    doc = _keyed_record(b"k1")
    del doc["chain"]
    prev = R.GENESIS
    for t in doc["transitions"]:
        t["prev"] = prev
        t["hash"] = prev = R.chain_hash(prev, t)
    assert R.problems(doc) == []  # unkeyed and no key: consistent
    monkeypatch.setenv(R.KEY_ENV, "k1")
    assert any("unkeyed" in p for p in R.problems(doc))


def test_anchor_catches_a_consistent_older_copy():
    doc = _doc("closed")
    anchor = R.head(doc)
    assert R.verify_anchor(doc, anchor) == []
    older = _doc("active")  # internally consistent, but not the record that was anchored
    assert R.problems(older) == []
    assert R.verify_anchor(older, anchor)
    assert R.verify_anchor(doc, {"seq": 2, "hash": "sha256:" + "0" * 64})
