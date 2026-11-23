# SPDX-License-Identifier: Apache-2.0
"""The manager-log benign list (modules/source-census/data/manager-benign.yml) is a ratchet: every
entry hides a class of error line from a verdict, so it grows only by a reviewed change.

The count below is the reviewed baseline.  Adding an entry means raising it in the same change, with
the reason the entry carries in front of the reviewer; removing one lowers it.  Each entry must carry
a reason and be scoped (a site value or a specific phrase), and the list must load.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from homelabnext import logbursts as lb

BENIGN = (
    Path(__file__).resolve().parents[2]
    / "modules"
    / "source-census"
    / "data"
    / "manager-benign.yml"
)
REVIEWED_COUNT = 4


def test_the_benign_list_has_not_grown_past_its_reviewed_count():
    entries = yaml.safe_load(BENIGN.read_text())["benign"]
    assert len(entries) == REVIEWED_COUNT, (
        "the benign list changed: it grows only by a reviewed change (raise REVIEWED_COUNT with it)"
    )


def test_every_entry_carries_a_real_reason_and_the_list_loads():
    entries = yaml.safe_load(BENIGN.read_text())["benign"]
    assert all(len(e["reason"].split()) >= 8 for e in entries), "a reason says why, in a sentence"
    loaded = lb.load_benign(BENIGN, {"scanner_address": "scanner-host-7"})
    assert [b.reason for b in loaded] == [e["reason"] for e in entries]


def test_no_entry_hides_every_line_of_a_class_of_source():
    # an entry without a site value must name a specific phrase (at least 3 words)
    for e in yaml.safe_load(BENIGN.read_text())["benign"]:
        if "{" not in e["match"]:
            assert len(e["match"].split()) >= 3, e["match"]
