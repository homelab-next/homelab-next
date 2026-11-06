# SPDX-License-Identifier: Apache-2.0
"""An entity noisy in both windows, and the doc fact that names the signal set (ADR-0036
decision 6, docs/novelty.md)."""

from __future__ import annotations

import re
from pathlib import Path

from novelty_support import AS_OF, SITE, SPEC, net, rows

from homelabnext.lake import FakeLake, load_schemas
from homelabnext.lake.ceiling import reader_for
from homelabnext.novelty import READER, corroborate, parse_spec, run
from homelabnext.novelty.corroborate import SIGNALS

SCHEMAS = load_schemas()
REPO = Path(__file__).resolve().parents[2]


def _lake_with_both_windows_noisy() -> FakeLake:
    # 192.0.2.88 touches 4 ports on each learning day (16 distinct, above max_values_per_entity 3)
    # and 60 ports on the scoring day: noisy in both windows
    extra = []
    i = 0
    for day in (5, 6, 7, 8):
        for port in range(4):
            extra.append(net(900 + i, day=day, src="192.0.2.88", port=3000 + port))
            i += 1
    for p in range(60):
        extra.append(net(1000 + p, day=9, src="192.0.2.88", port=4000 + p))
    lake = FakeLake(SCHEMAS)
    lake.write_batch("network_activity", rows() + extra, idempotency_key="seed")
    return lake


def test_an_entity_noisy_in_both_windows_is_high_cardinality_once_and_not_a_signal():
    lake = _lake_with_both_windows_noisy()
    reader = reader_for(lake, READER, SITE["tlp_readers"], SCHEMAS)
    (result,) = run(reader, parse_spec(SPEC, SCHEMAS), AS_OF, writer=None)
    assert result.status == "ok", result.error
    mine = [r for r in result.rows if r["entity"] == "192.0.2.88"]
    # one row, not one per value, and not a burst: learning-window noise takes precedence
    assert len(mine) == 1
    (row,) = mine
    assert row["status"] == "high_cardinality" and row["value"] is None
    assert row["score"] is None
    assert "learned values" in row["reasons"][-1] and "(a signal)" not in row["reasons"][-1]
    # high_cardinality is not a corroboration signal: a second source does not corroborate it
    base = {
        "entity_kind": row["entity_kind"],
        "entity": row["entity"],
        "time": row["time"],
        "tlp": row["tlp"],
    }
    as_rows = [
        dict(
            base, uid="x1", source="lake-novelty", profile=row["profile"], status="high_cardinality"
        ),
        dict(base, uid="x2", source="host-kernel", profile="process-lineage", status="finding"),
    ]
    assert corroborate(as_rows) == []


def test_the_documented_signal_set_is_corroborate_signals():
    text = (REPO / "docs" / "novelty.md").read_text(encoding="utf-8")
    section = text.split("## Corroboration", 1)[1].split("\n## ", 1)[0]
    listed = re.search(r"groups (.+?) rows by", section, re.DOTALL)
    assert listed, "docs/novelty.md Corroboration must name the statuses it groups"
    documented = re.findall(r"`([a-z_]+)`", listed.group(1))
    assert sorted(documented) == sorted(SIGNALS)
