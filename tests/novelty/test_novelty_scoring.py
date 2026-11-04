# SPDX-License-Identifier: Apache-2.0
"""The scoring rule of ADR-0035 decision 3, checked against hand-computed cases.

The profile below scores ``[2026-03-09, 2026-03-10)`` and learns from ``[2026-03-05,
2026-03-09)``: days 03-05..03-08 are 4..1 days old, and with ``half_life_days: 2`` weigh
0.25, 2**-1.5, 0.5 and 2**-0.5.  Counts are chosen so the arithmetic is exact in binary.
"""

from __future__ import annotations

import dataclasses
from datetime import UTC, date, datetime

import pytest

from homelabnext.lake.ceiling import GroupCount
from homelabnext.novelty import batch_id, score_profile, windows
from homelabnext.novelty.spec import Profile
from homelabnext.tlp import Label

AS_OF = datetime(2026, 3, 10, tzinfo=UTC)
D = {n: date(2026, 3, n) for n in range(1, 11)}
P = Profile(
    id="host-dst-port",
    table="network_activity",
    entity="src_endpoint.ip",
    values=("dst_endpoint.port",),
    where={},
    time_column="time",
    learn_days=4,
    half_life_days=2,
    score_hours=24,
    min_support=2,
    entity_min_samples=4,
    max_values_per_entity=3,
    emit_at=0.25,
    max_findings=10,
    min_history_days=4,
)
#: the table holds the whole learning window (oldest day 03-05: four days of history)
FULL = [GroupCount(None, (), D[5], Label.CLEAR, 1)]


def g(entity, value, day, count=1, label=Label.GREEN):
    return GroupCount(entity, (value,), D[day], label, count)


def score(learn, scoring, history=FULL, profile=P, as_of=AS_OF):
    return score_profile(profile, as_of, learn, scoring, history, spec_digest="sha256:spec")


def by_entity(result):
    return {(r["entity"], r["value"]): r for r in result.rows}


def test_windows_are_adjacent_and_never_overlap():
    w = windows(P, AS_OF)
    assert w.learn_since == datetime(2026, 3, 5, tzinfo=UTC)
    assert w.learn_until == w.score_since == datetime(2026, 3, 9, tzinfo=UTC)
    assert w.score_until == AS_OF


def test_decay_halves_support_every_half_life():
    # 22: 2 rows two days old = 2 * 0.5 = 1.0;  443: 4 rows four days old = 4 * 0.25 = 1.0
    r = score([g("h1", 22, 7, 2), g("h1", 443, 5, 4)], [g("h1", 22, 9), g("h1", 443, 9)])
    rows = by_entity(r)
    for v in ("22", "443"):
        assert rows[("h1", v)]["support"] == 1.0
        assert rows[("h1", v)]["entity_total"] == 2.0
        # surprise 1 - 1/2 = 0.5, confidence 2/4 = 0.5, score 0.25 >= emit_at 0.25
        assert rows[("h1", v)]["score"] == 0.25 and rows[("h1", v)]["confidence"] == 0.5


def test_a_value_at_min_support_is_normal_and_just_below_is_not():
    p = dataclasses.replace(P, emit_at=0.2)
    at = score([g("h1", 22, 7, 4), g("h1", 80, 7, 4)], [g("h1", 22, 9)], profile=p)  # s = 2.0
    assert at.rows == []
    below = score([g("h1", 22, 7, 3), g("h1", 80, 7, 4)], [g("h1", 22, 9)], profile=p)  # 1.5
    (row,) = below.rows
    # surprise 1 - 1.5/2 = 0.25, confidence min(1, 3.5/4) = 0.875, score 0.21875
    assert (row["status"], row["support"], row["score"]) == ("finding", 1.5, 0.21875)


def test_emit_at_is_inclusive():
    learn = [g("h1", 22, 7, 2), g("h1", 80, 7, 6)]  # s(22) = 1, T = 4
    # surprise 0.5 * confidence 1 = 0.5
    assert by_entity(score(learn, [g("h1", 22, 9)], profile=dataclasses.replace(P, emit_at=0.5)))
    assert not score(learn, [g("h1", 22, 9)], profile=dataclasses.replace(P, emit_at=0.5000001)).rows  # fmt: skip


@pytest.mark.parametrize(
    "rows_of_other, confidence",
    [(0, 0.0), (2, 0.25), (6, 0.75), (8, 1.0), (100, 1.0)],
)
def test_confidence_ramps_with_the_entity_total(rows_of_other, confidence):
    # a never-seen value (s = 0, surprise 1) of an entity with T = rows * 0.5
    learn = [g("h1", 80, 7, rows_of_other)] if rows_of_other else []
    r = score(learn, [g("h1", 22, 9)], profile=dataclasses.replace(P, emit_at=0.01))
    (row,) = r.rows
    if confidence == 0.0:
        assert row["status"] == "unlearned"
    else:
        assert row["confidence"] == confidence and row["score"] == confidence


def test_an_entity_with_no_learned_support_is_unlearned_never_scored_zero():
    r = score([g("h1", 22, 7, 8)], [g("h2", 22, 9, 3), g("h2", 23, 9)])
    assert [(x["entity"], x["value"], x["status"]) for x in r.rows] == [
        ("h2", "22", "unlearned"),
        ("h2", "23", "unlearned"),
    ]
    assert all(x["score"] is None and x["confidence"] is None for x in r.rows)
    assert by_entity(r)[("h2", "22")]["count"] == 3


def test_a_high_cardinality_entity_is_reported_once_and_not_scored():
    learn = [g("h1", port, 7) for port in (1, 2, 3, 4)]  # 4 distinct > max 3
    r = score(learn, [g("h1", 22, 9), g("h1", 23, 9), g("h1", 1, 9)])
    (row,) = r.rows
    assert row["status"] == "high_cardinality" and row["value"] is None
    assert row["count"] == 3 and row["score"] is None
    exactly = score([g("h1", port, 7) for port in (1, 2, 3)], [g("h1", 22, 9)])
    assert [x["status"] for x in exactly.rows] == ["finding"]


def test_the_cap_keeps_the_highest_scores_and_reports_what_it_dropped():
    learn = [g(f"h{i}", 80, 7, 8) for i in range(5)] + [g(f"h{i}", 22, 7, i) for i in range(5)]
    scoring = [g(f"h{i}", 22, 9) for i in range(5)] + [g("new", 1, 9), g("new", 2, 9)]
    p = dataclasses.replace(P, max_findings=3, emit_at=0.01)
    r = score(learn, scoring, profile=p)
    # s(h_i, 22) = i * 0.5; T = 4 + i*0.5 >= 4 so confidence 1; scores 1, .75, .5, .25, 0
    assert [(x["entity"], x["score"]) for x in r.rows] == [("h0", 1.0), ("h1", 0.75), ("h2", 0.5)]
    s = r.summary()
    assert s["candidates"] == {"finding": 4, "high_cardinality": 0, "unlearned": 2}
    assert s["dropped"] == 3
    assert s["dropped_by_status"] == {"finding": 1, "high_cardinality": 0, "unlearned": 2}


def test_the_label_is_the_strictest_contributing_row_learning_window_included():
    learn = [g("h1", 22, 7, 1, Label.CLEAR), g("h1", 80, 8, 8, Label.AMBER)]
    r = score(learn, [g("h1", 22, 9, 1, Label.GREEN)])
    (row,) = r.rows
    assert row["tlp"] == "amber"  # the entity's other value makes T(e), so its label counts
    unlearned = score([], [g("h9", 22, 9, 1, Label.GREEN), g("h9", 22, 9, 1, Label.CLEAR)])
    assert [x["tlp"] for x in unlearned.rows] == ["green"]


def test_the_scoring_window_is_never_learned_from():
    # a value seen many times only inside the scoring window is still new
    r = score([g("h1", 80, 7, 8)], [g("h1", 22, 9, 50)])
    (row,) = r.rows
    assert row["support"] == 0.0 and row["count"] == 50 and row["score"] == 1.0


def test_same_inputs_same_rows_whatever_the_input_order():
    learn = [g("h1", 22, 7, 3), g("h1", 80, 6, 5), g("h2", 22, 8, 1), g("h2", 9, 5, 7)]
    scoring = [g("h1", 22, 9), g("h2", 23, 9), g("h3", 1, 9)]
    a = score(learn, scoring)
    b = score(learn[::-1], scoring[::-1])
    assert a.rows == b.rows and a.rows
    assert len({r["uid"] for r in a.rows}) == len(a.rows)
    assert all(r["uid"].startswith("nov-") for r in a.rows)
    other = score(learn, scoring, as_of=datetime(2026, 3, 10, 1, tzinfo=UTC))
    assert {r["uid"] for r in other.rows}.isdisjoint(r["uid"] for r in a.rows)


def test_every_row_is_heuristic_and_names_its_source_and_windows():
    (row,) = score([g("h1", 80, 7, 8)], [g("h1", 22, 9)]).rows
    assert row["source_kind"] == "heuristic" and row["source"] == "lake-novelty"
    assert row["profile"] == "host-dst-port" and row["time"] == row["as_of"] == AS_OF
    assert row["learn_until"] == row["score_since"] and row["spec_digest"] == P.digest
    assert row["message"] and row["reasons"]


def test_batch_id_is_a_digest_of_profile_spec_and_as_of():
    a = batch_id(P, "sha256:spec", AS_OF)
    assert a == batch_id(P, "sha256:spec", AS_OF.astimezone(UTC))
    assert a != batch_id(P, "sha256:other", AS_OF)
    assert a != batch_id(P, "sha256:spec", datetime(2026, 3, 11, tzinfo=UTC))


def test_as_of_must_be_aware():
    with pytest.raises(ValueError, match="timezone-aware"):
        score([], [], as_of=datetime(2026, 3, 10))


# ---------------------------------------------------------------- cold start (warming)
@pytest.mark.parametrize(
    "oldest, min_history, status, history, remaining",
    [
        (None, 4, "warming", 0, 4),  # an empty lake
        (8, 4, "warming", 1, 3),
        (6, 4, "warming", 3, 1),  # the day before the boundary
        (5, 4, "ok", 4, None),  # the boundary: the learning window's first day
        (6, 3, "ok", 3, None),  # a shorter cold start
        (None, 0, "ok", 0, None),  # min_history_days 0 never warms
    ],
)
def test_a_profile_warms_until_the_table_holds_min_history_days(
    oldest, min_history, status, history, remaining
):
    hist = [] if oldest is None else [GroupCount(None, (), D[oldest], Label.RED, 1)]
    p = dataclasses.replace(P, min_history_days=min_history)
    r = score([g("h1", 80, 8, 8)], [g("h1", 22, 9)], history=hist, profile=p)
    s = r.summary()
    assert (s["status"], s["history_days"]) == (status, history)
    assert s["oldest_day"] == (None if oldest is None else D[oldest].isoformat())
    if status == "warming":
        assert r.rows == [] and s["days_remaining"] == remaining
        assert "emitted" not in s and "batch_id" not in s
    else:
        assert "days_remaining" not in s and s["emitted"]["finding"] == 1


def test_warming_is_the_same_for_the_same_as_of_and_moves_with_it():
    hist = [GroupCount(None, (), D[7], Label.RED, 1)]
    one = score([], [], history=hist).summary()
    assert one == score([], [], history=hist).summary()
    assert one["days_remaining"] == 2
    later = score([], [], history=hist, as_of=datetime(2026, 3, 11, tzinfo=UTC)).summary()
    assert later["days_remaining"] == 1
