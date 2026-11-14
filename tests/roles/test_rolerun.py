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


def test_one_pool_starts_the_first_runs_of_every_module(monkeypatch, tmp_path_factory):
    """The first test to ask starts every module's marked first runs in one pool, not one pool per
    module: a module with one marked test used to run it alone, the other workers idle."""
    pools = []

    class Pool(rolerun.ThreadPoolExecutor):
        def __init__(self, max_workers):
            pools.append([])
            super().__init__(max_workers=max_workers)

        def map(self, fn, jobs):
            jobs = list(jobs)
            pools[-1].extend(nid for nid, _, _ in jobs)
            return super().map(fn, jobs)

    monkeypatch.setattr(rolerun, "ThreadPoolExecutor", Pool)
    monkeypatch.setattr(rolerun, "_FIRST_RUNS", {})

    def node(mod, name):
        def case(tmp):
            return {"runner": lambda _tmp: f"ran {mod.__name__}::{name}"}

        return types.SimpleNamespace(
            nodeid=f"{mod.__name__}::{name}", name=name, module=mod,
            function=types.SimpleNamespace(hnx_first_run=case),
            get_closest_marker=lambda _name: None, iter_markers=lambda _name: [],
        )  # fmt: skip

    a, b = types.ModuleType("a"), types.ModuleType("b")
    items = [node(a, "t1"), node(b, "t2"), node(b, "t3")]
    session = types.SimpleNamespace(items=items)
    for it in items:
        it.session = session
    got = [rolerun.prefetch_first_runs(types.SimpleNamespace(node=it), tmp_path_factory)[0]
           for it in items]  # fmt: skip
    assert pools == [["a::t1", "b::t2", "b::t3"]]
    assert got == ["ran a::t1", "ran b::t2", "ran b::t3"]


def test_parallel_cases_are_split_in_order_and_put_back_in_order(monkeypatch, tmp_path):
    chunks = []

    def chunk(tmp, tag, role, tasks_from, base_vars, overrides, env):
        chunks.append((tag, [o["i"] for o in overrides]))
        return [(o["i"] % 2 == 0, f"case {o['i']}") for o in overrides]

    monkeypatch.setattr(rolerun, "_run_case_chunk", chunk)
    monkeypatch.setattr(rolerun, "workers", lambda: 3)
    cases = [{"i": i} for i in range(7)]
    got = rolerun.run_cases(tmp_path, "r", "health", {}, cases, parallel=True)
    assert got == [(i % 2 == 0, f"case {i}") for i in range(7)]
    assert sorted(chunks) == [("-0", [0, 1, 2]), ("-1", [3, 4, 5]), ("-2", [6])]
    chunks.clear()
    assert rolerun.run_cases(tmp_path, "r", "health", {}, cases) == got  # one process by default
    assert chunks == [("", list(range(7)))]
