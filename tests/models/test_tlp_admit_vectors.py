# SPDX-License-Identifier: Apache-2.0
"""The shared TLP admission vectors (ADR-0038 decision 5) are what the Python rule says: another
implementation of the rule (the gateway's) is held to this file, so the file must not drift."""

from __future__ import annotations

import json
from pathlib import Path

from homelabnext import tlp
from homelabnext.registry.model_tlp import _ABSENT, request_label

VECTORS = Path(__file__).resolve().parents[2] / "conformance/fixtures/tlp_admit_vectors.json"


def test_the_vectors_match_the_python_rule():
    doc = json.loads(VECTORS.read_text(encoding="utf-8"))
    assert doc["labels"] == list(tlp.LABELS)
    assert len(doc["vectors"]) >= 100
    for v in doc["vectors"]:
        header = _ABSENT if v["header"] is None else v["header"]
        label = request_label(
            header, leaves_lab=v["role_leaves_lab"], sender=tlp.parse_stored(v["sender_ceiling"])
        )
        allowed = label <= tlp.parse_stored(v["role_ceiling"])
        reason = (
            "within-ceiling"
            if allowed
            else "unlabelled"
            if v["header"] is None
            else "above-ceiling"
        )
        assert (label.value, allowed, reason) == (v["label"], v["allowed"], v["reason"]), v


def test_the_vectors_cover_every_outcome_and_the_lenient_spellings():
    vs = json.loads(VECTORS.read_text(encoding="utf-8"))["vectors"]
    assert {v["reason"] for v in vs} == {"within-ceiling", "above-ceiling", "unlabelled"}
    headers = {v["header"] for v in vs}
    assert {None, "white", "TLP:GREEN", "purple", ""} <= headers
