# SPDX-License-Identifier: Apache-2.0
"""The telemetry store: agent.job.finished consumed idempotently (by event id and by run id), only
from the controller, purged by age; the rollup's numbers per profile, backend and lane."""

from __future__ import annotations

import copy
import json

import pytest
from orch_helpers import CONTROLLER_EXAMPLE, DOTTED_EXAMPLE, EXAMPLES, T0, body, examples

from homelabnext.events.envelope import EventError
from homelabnext.orchestration import ROLLUP_SCHEMA, percentile, rollup
from homelabnext.orchestration.store import TelemetryStore
from homelabnext.status.model import parse_iso


def test_each_example_is_stored_once_and_a_redelivery_is_a_duplicate(store):
    evs = examples()
    assert [store.consume(body(e)).status for e in evs] == ["processed"] * 4
    assert [store.consume(body(e)).status for e in evs] == ["duplicate"] * 4
    assert [j["run_id"] for j in store.jobs()] == ["run-0004", "run-0003", "run-0002", "run-0001"]
    assert store.job("run-0002") == evs[1]["data"]  # the record is the event's data, as sent


@pytest.mark.parametrize(
    "mutate, why",
    [
        (lambda e: e["data"].update(output_bytes=7), "already consumed with another body"),
        (lambda e: e.update(id="evt-other"), "already recorded under event 'evt-0001'"),
        (lambda e: e.update(id="evt-other", source="svc:status-hub"), "only svc:llm-orchestrator"),
        (lambda e: e["data"].update(prompt="fake task text"), "invalid"),
        (lambda e: e.update(type="homelabnext.agent.job.failed"), ""),
    ],
)
def test_a_conflicting_foreign_or_invalid_record_is_refused(filled, mutate, why):
    ev = copy.deepcopy(examples()[0])
    mutate(ev)
    with pytest.raises(EventError) as err:
        filled.consume(body(ev))
    assert why in str(err.value)
    assert filled.job("run-0001") == examples()[0]["data"]  # the stored record is untouched


@pytest.mark.parametrize(
    "key, value",
    [
        ("finished_at", "2026-02-30T00:00:00Z"),  # no such day
        ("queued_at", "2026-01-01T24:00:00Z"),  # no such hour
        ("started_at", "2026-01-01T00:00:00+99:00"),  # no such offset
        ("finished_at", "0000-01-01T00:00:00Z"),  # no year 0
    ],
)
def test_a_pattern_valid_but_impossible_timestamp_is_refused_as_poison(store, key, value):
    ev = copy.deepcopy(examples()[0])
    ev["data"][key] = value
    with pytest.raises(EventError) as err:
        store.consume(body(ev))
    assert f"data.{key}" in str(err.value) and "not a real date and time" in str(err.value)
    assert store.jobs() == []


def test_jobs_and_turns_past_retention_are_purged(tmp_path):
    now = [T0]
    store = TelemetryStore(tmp_path / "t.db", clock=lambda: now[0], retention_days=1)
    store.consume(body(examples()[0]))
    store.add_turns(
        [{"turn_id": "req-a1", "gateway_tag": "run-0001", "started_at": "2026-01-01T00:00:13Z"}]
    )
    assert store.job("run-0001") and store.turns()
    now[0] = parse_iso("2026-01-02T00:05:13Z")  # a day and a second after it finished
    assert store.purge() == 2
    assert store.job("run-0001") is None and store.turns() == {}


def test_percentile_is_nearest_rank_over_known_values():
    assert percentile([], 50) is None and percentile([None], 95) is None
    assert percentile([300.0, 570.0], 50) == 300.0
    assert percentile([300.0, None, 570.0], 95) == 570.0
    assert percentile(range(1, 101), 95) == 95


def test_rollup_per_profile_backend_and_lane(filled):
    filled.add_turns(
        [
            {"turn_id": "t1", "gateway_tag": "run-0001", "started_at": "2026-01-01T00:00:13Z",
             "input_tokens": 20000, "output_tokens": 1500, "cache_read_tokens": 12000,
             "cost_usd": 0.0, "status": "success", "ttft_ms": 400, "duration_ms": 2100},
            {"turn_id": "t2", "gateway_tag": "hnx-run-0002", "started_at": "2026-01-01T01:00:40Z",
             "input_tokens": 9000, "output_tokens": 400, "status": "failure"},
        ]
    )  # fmt: skip
    roll = filled.rollup(days=7)
    assert roll["schema"] == ROLLUP_SCHEMA and roll["window"]["days"] == 7
    by = {(g["profile"], g["backend"], g["lane"]): g for g in roll["groups"]}
    assert sorted(by) == [
        ("profile:triage", "-", "real"),
        ("profile:triage", "local-large", "real"),
        ("profile:triage", "local-small", "shadow"),
    ]
    g = by["profile:triage", "local-large", "real"]  # run-0001 (completed), run-0002 (failed)
    assert g["jobs"] == 2
    assert g["outcomes"] == {"completed": 1, "failed": 1, "cancelled": 0, "timeout": 0}
    assert g["failure_classes"] == {"backend-down": 1}
    assert g["wall_s"] == {"p50": 300.0, "p95": 570.0, "n": 2}
    assert g["queue_wait_s"] == {"p50": 12.0, "p95": 30.0, "n": 2}
    assert g["tokens"] == {
        "input": 50000, "output": 3600, "reasoning": 0, "cache_read": 28000, "jobs_unknown": 0,
    }  # fmt: skip
    # run-0002 did not report cache reads: the share is over run-0001 alone, never diluted
    assert g["cache_read_share"] == round(28000 / 41000, 4)
    assert g["cost_usd"] == {"total": 0.0, "jobs_unknown": 1}
    assert g["retries"] == {"of_earlier_run": 0, "auto_scheduled": 1}
    assert g["bytes"]["input"] == {"p50": 2048, "total": 4096}
    assert g["bytes"]["output"] == {"p50": 6144, "total": 6144, "n": 1}
    assert g["api_calls_per_job"] == {"p50": 3, "p95": 9, "n": 2}
    t = g["turns"]
    assert (t["count"], t["jobs_with_turns"], t["failures"]) == (2, 2, 1)
    assert (t["input_tokens"], t["output_tokens"], t["cache_read_tokens"]) == (29000, 1900, 12000)
    never = by["profile:triage", "-", "real"]  # run-0004: cancelled in the queue, no usage file
    assert never["wall_s"] == {"p50": None, "p95": None, "n": 0}
    assert never["tokens"]["jobs_unknown"] == 1 and never["cost_usd"]["jobs_unknown"] == 1
    assert never["cache_read_share"] is None and never["retries"]["of_earlier_run"] == 1
    assert roll["days"] == [
        {"day": "2026-01-01", "profile": "profile:triage", "jobs": 4, "completed": 2,
         "not_completed": 2, "wall_s_p50": 300.0, "input_tokens": 89000, "output_tokens": 6500,
         "cost_usd": 0.0},
    ]  # fmt: skip


def test_rollup_window_leaves_out_older_jobs():
    jobs = [e["data"] for e in examples()]
    assert rollup(jobs, {}, now=parse_iso("2026-01-01T02:59:00Z"), days=1)["days"][0]["jobs"] == 3
    assert rollup(jobs, {}, now=parse_iso("2026-01-09T00:00:00Z"), days=7)["groups"] == []


#: the controller's own test event (llm-orchestrator), byte for byte; values fictional
CONTROLLER_EVENT = (
    '{"specversion":"1.0","id":"evt-0db579c95c808da59500536064c11648","source":"svc:llm-orchestrator",'
    '"type":"homelabnext.agent.job.finished","time":"2026-10-22T12:02:00Z","subject":"run-c1",'
    '"correlationid":"run-c1","data":{"run_id":"run-c1","profile":"profile:pipeline-health-analyst",'
    '"profile_revision":"rev-9","lane":"real","outcome":"completed","failure_class":null,'
    '"retry_of_run_id":null,"auto_retry_scheduled":false,"local_attempts":1,'
    '"cloud_fallback_used":false,"backend":"local-gateway","model":"custom/hermes-agent",'
    '"queued_at":"2026-10-22T12:00:00Z","started_at":"2026-10-22T12:00:30Z",'
    '"finished_at":"2026-10-22T12:02:00Z","queue_wait_s":30,"wall_s":90,"input_bytes":4,'
    '"output_bytes":10,"usage":{"input_tokens":1200,"output_tokens":0,"reasoning_tokens":null,'
    '"cache_read_tokens":800,"api_calls":3,"cost_usd":0.0125},"turn_exit_reason":"text_response",'
    '"gateway_tag":"run-c1"}}'
)


def test_the_controllers_own_event_is_accepted_as_sent(store):
    """The controller side's test event validates unchanged and is stored; the schema's
    ``controller`` example is the same event, so the contract tests publish and consume it too."""
    assert (EXAMPLES / CONTROLLER_EXAMPLE).read_text().strip() == CONTROLLER_EVENT
    assert store.consume(CONTROLLER_EVENT).status == "processed"
    assert store.job("run-c1")["model"] == "custom/hermes-agent"
    # a vLLM backend's model is its path: an opaque name, accepted as such
    path_model = CONTROLLER_EVENT.replace("custom/hermes-agent", "/srv/models/example-27b")
    path_model = path_model.replace("evt-0db5", "evt-1db5").replace('"run-c1"', '"run-c2"')
    assert store.consume(path_model).status == "processed"
    # a configured prefix may hold '/', the run id after it may not
    prefixed = CONTROLLER_EVENT.replace('"gateway_tag":"run-c1"', '"gateway_tag":"lab/hnx:run-c1"')
    prefixed = prefixed.replace("evt-0db5", "evt-2db5").replace('"run-c1"', '"run-c3"')
    assert store.consume(prefixed).status == "processed"


@pytest.mark.parametrize("backend", [".lab-gateway", "lab9", "node.7_gw-a"])
def test_a_backend_name_is_stored_as_the_controller_emits_it(store, backend):
    """Regression: the controller emits local_backend_used verbatim, and real names start with a
    dot or digits; a pattern that refused them sent every such record to the dead-letter stream.
    A ':' or '/' (a host:port or a URL) is still refused."""
    ev = json.loads((EXAMPLES / DOTTED_EXAMPLE).read_text())
    assert store.consume(body(ev)).status == "processed"
    ev = copy.deepcopy(ev) | {"id": f"evt-b-{len(backend)}"}
    ev["data"].update(run_id=f"run-b-{len(backend)}", backend=backend)
    assert store.consume(body(ev)).status == "processed"
    assert store.job(f"run-b-{len(backend)}")["backend"] == backend
    for bad in ("gw.example.com:8000", "https://gw.example.com/v1", "a" * 65, ""):
        ev = copy.deepcopy(ev) | {"id": "evt-bad"}
        ev["data"].update(run_id="run-bad", backend=bad)
        with pytest.raises(EventError):
            store.consume(body(ev))
