# SPDX-License-Identifier: Apache-2.0
"""How many role tests' first runs ``rolerun`` starts at once."""

from __future__ import annotations

import types

import pytest
import rolerun
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


def test_the_first_runs_are_started_by_as_many_workers_as_workers_says(
    monkeypatch, tmp_path_factory
):
    started = []

    class Pool(rolerun.ThreadPoolExecutor):
        def __init__(self, max_workers):
            started.append(max_workers)
            super().__init__(max_workers=max_workers)

    monkeypatch.setattr(rolerun, "ThreadPoolExecutor", Pool)
    monkeypatch.setattr(rolerun, "workers", lambda: 3)

    def case(tmp):
        return {"runner": lambda _tmp: "ran"}

    module = types.ModuleType("m")
    node = types.SimpleNamespace(
        nodeid="m::t", name="t", module=module, function=types.SimpleNamespace(hnx_first_run=case)
    )
    node.session = types.SimpleNamespace(items=[node])
    run = rolerun.prefetch_first_runs(types.SimpleNamespace(node=node), tmp_path_factory)
    assert started == [3]
    assert run[0] == "ran"


def test_a_very_large_explicit_count_is_allowed():
    # an override is the operator's call: only the default is capped at MAX_WORKERS
    assert workers(env={"HNX_ROLERUN_WORKERS": "9999"}, cpus=4) == 9999
