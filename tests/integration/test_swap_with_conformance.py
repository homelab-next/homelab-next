# SPDX-License-Identifier: Apache-2.0
"""Wave-3 coherence: the swap runner drives a swap between two conformance fakes.

The incumbent and the candidate are both the ``lake-query`` conformance fake (the built-in
``fake`` target of the harness).  ``hnx conform run lake-query --target fake`` is run before the
swap starts and again after the cutover; the swap's own conformance gates call the same suite; and
the swap record is turned into ``homelabnext.swap.step`` events that validate against the events
schema (envelope included).
"""

from __future__ import annotations

import json
import re
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
for _p in (ROOT, ROOT / "tools", ROOT / "tests" / "lake" / "fixtures", ROOT / "tests" / "parity"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

import lakes
import schema_check as sc

from conformance.suites import lake_query
from homelabnext import cli
from homelabnext.conform import run_capability
from homelabnext.parity import ParityQuery, RowRules
from homelabnext.swap import GateFailed, LakeBackend, Outcome, SwapRunner, record
from homelabnext.swap.events import EVENT_TYPE, step_events

pytest.importorskip("yaml")
pytest.importorskip("jsonschema")


class Clock:
    def __init__(self):
        self.now = datetime(2026, 4, 1, 9, 0, 0, tzinfo=UTC)

    def __call__(self):
        return self.now

    def advance(self, **kw):
        self.now += timedelta(**kw)


def _registry_with_candidate_host() -> str:
    text = (ROOT / "examples" / "services.yml").read_text(encoding="utf-8")
    m = re.search(r"^  lake-core: .*address: (\d+\.\d+\.\d+)\.(\d+),.*$", text, re.M)
    assert m
    twin = (
        m.group(0)
        .replace("lake-core:", "lake-core-2:")
        .replace(f"{m.group(1)}.{m.group(2)},", f"{m.group(1)}.{int(m.group(2)) + 1},")
    )
    return text.replace(m.group(0), m.group(0) + "\n" + twin, 1)


def _conform_fake(capsys) -> int:
    code = cli.main(["conform", "run", "lake-query", "--target", "fake"])
    capsys.readouterr()
    return code


def _smoke(_client, role) -> Outcome:
    """The swap's conformance gate: the harness's own lake-query suite, on the fake target."""
    run = run_capability("lake-query", "fake")
    return Outcome(run.passing, f"{role}: lake-query suite on target fake", {"role": role})


@pytest.fixture
def swap(tmp_path):
    old = lake_query.make_fake()  # the conformance fake IS the incumbent
    new = lake_query.make_fake()  # ... and the candidate
    for t in lakes.TABLES:
        old.write_batch(t, lakes.rows_for(t), idempotency_key=f"seed-{t}")
    registry = tmp_path / "services.yml"
    registry.write_text(_registry_with_candidate_host(), encoding="utf-8")
    clock = Clock()
    backend = LakeBackend(
        old,
        new,
        tables=list(lakes.TABLES),
        registry_path=registry,
        service="lake-query",
        new_host="lake-core-2",
        queries=[
            ParityQuery(
                "auth-by-user",
                sql="SELECT user_name, count(*) AS n FROM authentication GROUP BY user_name",
                rules=RowRules(key=("user_name",)),
                min_rows=1,
            )
        ],
        smoke=_smoke,
    )
    runner = SwapRunner.create(
        tmp_path / "s.swap.json",
        backend,
        swap_id="swap-conform-0001",
        capability="cap:lake-query",
        from_adapter="fake-a",
        to_adapter="fake-b",
        service="lake-query",
        before={"host": "lake-core", "port": 8443, "impl": "trino", "version": "450.0"},
        after={"host": "lake-core-2", "port": 8443, "impl": "duckdb", "version": "1.5"},
        plan={
            "soak_hours": 48,
            "rollback_window_hours": 72,
            "max_divergences": 0,
            "min_parity_rows": 50,
        },
        registry="services.yml",
        clock=clock,
        actor="platform-team",
    )
    return runner, backend, clock


def test_conformance_passes_before_and_after_a_swap(swap, capsys):
    runner, _backend, clock = swap
    assert _conform_fake(capsys) == 0  # before: the contract holds for the incumbent
    for _ in range(4):  # declare .. parity-compare
        assert runner.advance().passed
    clock.advance(hours=49)
    assert runner.advance().passed  # soak
    assert runner.advance().passed  # cutover
    doc = runner.record()
    assert doc["route"]["flipped"] is True and record.problems(doc) == []
    assert _conform_fake(capsys) == 0  # after: still green
    # both conformance gates of the swap ran the harness suite
    names = [s["name"] for s in doc["steps"] if s["status"] == "passed"]
    assert names[:2] == ["declare", "shadow-start"]


def test_swap_record_becomes_valid_events(swap):
    runner, _backend, clock = swap
    for _ in range(4):
        runner.advance()
    clock.advance(hours=49)
    runner.advance()
    runner.advance()
    runner.rollback("canary regression, exercising the event mapping")
    events = step_events(runner.record())
    assert events, "a record with transitions yields events"
    schema_path = ROOT / "schemas" / "events" / "swap.step.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    registry = sc.build_registry(ROOT)
    for ev in events:
        assert ev["type"] == EVENT_TYPE
        assert sc.errors_for(schema, ev, registry) == [], ev
    assert len({e["id"] for e in events}) == len(events)  # idempotency keys are unique
    kinds = [(e["data"]["step_name"], e["data"]["status"]) for e in events]
    assert kinds[0] == ("declare", "started")
    assert ("cutover", "passed") in kinds
    assert kinds[-1][1] == "rolled_back"
    # republishing the same record yields byte-identical events (redelivery is harmless)
    assert step_events(runner.record()) == events


def test_event_for_a_failed_gate(swap):
    runner, backend, _clock = swap
    runner.advance()  # declare
    backend.old.down = True  # the incumbent dies: the next gate cannot pass
    with pytest.raises(GateFailed):
        runner.advance()
    doc = runner.record()
    events = step_events(doc)
    assert events[-1]["data"]["status"] == "failed"
    assert events[-1]["data"]["step_name"] == doc["current_step"]
    schema = json.loads((ROOT / "schemas/events/swap.step.schema.json").read_text())
    assert sc.errors_for(schema, events[-1], sc.build_registry(ROOT)) == []
