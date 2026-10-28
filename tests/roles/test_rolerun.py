# SPDX-License-Identifier: Apache-2.0
"""How many role tests' first runs ``rolerun`` starts at once."""

from __future__ import annotations

import pytest
from rolerun import MAX_WORKERS, workers


@pytest.mark.parametrize(
    ("cpus", "expected"),
    [(1, 1), (4, 4), (MAX_WORKERS, MAX_WORKERS), (64, MAX_WORKERS), (0, 1)],
)
def test_first_runs_start_one_per_cpu_up_to_the_cap(cpus, expected):
    assert workers(env={}, cpus=cpus) == expected


@pytest.mark.parametrize(("raw", "expected"), [("1", 1), ("3", 3), ("32", 32), (" 2 ", 2)])
def test_the_environment_sets_the_count(raw, expected):
    assert workers(env={"HNX_ROLERUN_WORKERS": raw}, cpus=64) == expected


@pytest.mark.parametrize("raw", ["0", "-1", "two", "", "1.5", "10000"])
def test_a_count_that_is_not_a_positive_integer_is_refused(raw):
    with pytest.raises(ValueError, match="HNX_ROLERUN_WORKERS is a positive integer"):
        workers(env={"HNX_ROLERUN_WORKERS": raw}, cpus=4)
