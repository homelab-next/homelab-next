# SPDX-License-Identifier: Apache-2.0
"""``corroborate``: only entities flagged by two distinct sources (ADR-0035 decision 6)."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from homelabnext.novelty import corroborate
from homelabnext.tlp import Label

T0 = datetime(2026, 3, 10, tzinfo=UTC)


def f(entity, source, *, profile="p", status="finding", hour=1, tlp="green", uid=None):
    return {
        "uid": uid or f"{source}-{profile}-{entity}-{hour}",
        "entity": entity,
        "source": source,
        "profile": profile,
        "status": status,
        "time": T0.replace(hour=hour),
        "tlp": tlp,
    }


def test_two_distinct_sources_corroborate_one_does_not():
    got = corroborate(
        [
            f("192.0.2.10", "lake-novelty", profile="host-dst-port"),
            f("192.0.2.10", "host-kernel", profile="process-lineage", tlp="amber"),
            f("192.0.2.11", "lake-novelty", profile="host-dst-port"),
            f("192.0.2.11", "lake-novelty", profile="user-src-ip"),  # same source twice
        ]
    )
    (c,) = got
    assert c.entity == "192.0.2.10" and c.sources == ("host-kernel", "lake-novelty")
    assert c.profiles == ("host-kernel/process-lineage", "lake-novelty/host-dst-port")
    assert c.label is Label.AMBER and c.findings == 2 and len(c.uids) == 2


def test_the_window_is_half_open():
    rows = [f("e", "a", hour=1), f("e", "b", hour=3)]
    since, until = T0.replace(hour=1), T0.replace(hour=3)
    assert corroborate(rows, since=since, until=until) == []
    assert corroborate(rows, since=since, until=T0.replace(hour=4))


def test_unlearned_counts_high_cardinality_does_not():
    assert corroborate([f("e", "a", status="unlearned"), f("e", "b")])
    assert corroborate([f("e", "a", status="high_cardinality"), f("e", "b")]) == []


def test_count_by_groups_count_as_many_findings():
    rows = [
        {
            "entity": "e",
            "source": "a",
            "profile": "p",
            "status": "finding",
            "tlp": "red",
            "rows": 3,
        },
        {"entity": "e", "source": "b", "profile": "q", "status": "finding", "tlp": "clear"},
    ]
    (c,) = corroborate(rows)
    assert c.findings == 4 and c.label is Label.RED and c.uids == ()


def test_sorted_by_number_of_sources_then_entity():
    rows = [f("b", "x"), f("b", "y"), f("a", "x"), f("a", "y"), f("c", "x"), f("c", "y"), f("c", "z")]  # fmt: skip
    assert [c.entity for c in corroborate(rows)] == ["c", "a", "b"]
    assert [c.entity for c in corroborate(rows, min_sources=3)] == ["c"]


@pytest.mark.parametrize(
    "kwargs, match",
    [
        ({"min_sources": 1}, "never corroborates"),
        ({"since": datetime(2026, 3, 10)}, "timezone-aware"),
    ],
)
def test_bad_arguments_are_refused(kwargs, match):
    with pytest.raises(ValueError, match=match):
        corroborate([], **kwargs)


def test_a_windowed_row_needs_a_time():
    row = f("e", "a")
    del row["time"]
    with pytest.raises(ValueError, match="aware time"):
        corroborate([row], since=T0)
