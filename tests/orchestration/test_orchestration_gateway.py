# SPDX-License-Identifier: Apache-2.0
"""Per-turn records from the gateway's spend log: the allow-list (nothing else in a row is ever
kept), the read-only viewer key by secret name over a guarded transport, paging, the join by tag
and settling.  The gateway is a loopback fake serving a recorded-shape fixture."""

from __future__ import annotations

import pytest
from orch_helpers import KEY_ENV, NEVER, T0, FakeSpendLogs, pages

from homelabnext.orchestration.gateway import (
    GatewayError,
    SpendLogReader,
    sync_turns,
    turn_from_row,
)
from homelabnext.status.model import parse_iso

ROWS = [r for p in pages() for r in p["data"]]
TAGS = {"run-0001", "hnx-run-0002", "run-0003", "run-0004"}


def test_a_turn_keeps_only_the_allow_listed_names_and_numbers():
    by_id = {r["request_id"]: r for r in ROWS}
    turn = turn_from_row(by_id["req-a1"], TAGS)
    assert turn == {
        "turn_id": "req-a1", "gateway_tag": "run-0001", "started_at": "2026-01-01T00:00:13Z",
        "duration_ms": 2100, "ttft_ms": 400, "model_group": "mdl:triage-large",
        "model": "example-27b", "call_type": "acompletion", "status": "success",
        "error_code": None, "input_tokens": 20000, "output_tokens": 1500,
        "cache_read_tokens": 12000, "cache_hit": False, "cost_usd": 0.0,
    }  # fmt: skip
    for row in ROWS:
        text = repr(turn_from_row(row, TAGS))
        assert [n for n in NEVER if n in text] == [], row["request_id"]


def test_a_turn_reads_every_shape_the_spend_log_uses():
    by_id = {r["request_id"]: r for r in ROWS}
    a2 = turn_from_row(by_id["req-a2"], TAGS)  # naive UTC times, cache_read_input_tokens
    assert (a2["started_at"], a2["ttft_ms"], a2["cache_read_tokens"], a2["cache_hit"]) == (
        "2026-01-01T00:02:00Z", 250, 16000, True,
    )  # fmt: skip
    b1 = turn_from_row(by_id["req-b1"], TAGS)  # tags as JSON text, a failure, a mangled name
    assert (b1["gateway_tag"], b1["status"], b1["error_code"]) == ("hnx-run-0002", "failure", "503")
    assert b1["model_group"] is None and b1["ttft_ms"] is None and b1["cache_hit"] is None
    assert turn_from_row(by_id["req-x9"], TAGS) is None  # another job's turn
    assert turn_from_row({**by_id["req-a1"], "request_id": "a b"}, TAGS) is None
    assert turn_from_row({**by_id["req-a1"], "startTime": "yesterday"}, TAGS) is None


def test_the_reader_pages_through_the_window_with_the_viewer_key():
    with FakeSpendLogs() as gw:
        reader = SpendLogReader(gw.url, env=KEY_ENV, page_size=3)
        got = list(reader.rows(parse_iso("2026-01-01T00:00:00Z"), parse_iso("2026-01-01T03:00Z")))
    assert [r["request_id"] for r in got] == ["req-a1", "req-a2", "req-x9", "req-b1", "req-c1"]
    assert [(r["path"], r["page"]) for r in gw.requests] == [
        ("/spend/logs/v2", "1"),
        ("/spend/logs/v2", "2"),
    ]
    first = gw.requests[0]
    assert (first["start_date"], first["end_date"]) == (
        "2026-01-01 00:00:00",
        "2026-01-01 03:00:00",
    )
    assert (first["page_size"], first["sort_by"], first["sort_order"]) == ("3", "startTime", "asc")


@pytest.mark.parametrize(
    "env, status, needle",
    [
        ({}, 200, "is not set: HNX_SECRET_LLM_GATEWAY_KEY_TELEMETRY_READER"),
        ({"HNX_SECRET_LLM_GATEWAY_KEY_TELEMETRY_READER": "fake-wrong"}, 200, "proxy_admin_viewer"),
        (KEY_ENV, 500, "answered HTTP 500"),
    ],
)
def test_a_refused_or_failing_read_is_a_gateway_error(env, status, needle):
    with FakeSpendLogs(status=status) as gw, pytest.raises(GatewayError, match=needle):
        list(SpendLogReader(gw.url, env=env).rows(0, 60))


def test_a_runaway_window_stops_at_max_pages():
    endless = [{"data": [{"request_id": f"r{n}"}], "total_pages": 99} for n in range(5)]
    with FakeSpendLogs(endless) as gw, pytest.raises(GatewayError, match="more than 2 pages"):
        list(SpendLogReader(gw.url, env=KEY_ENV, max_pages=2).rows(0, 60))


@pytest.mark.parametrize(
    "url, key, needle",
    [
        ("http://gateway.example.com", "secret:llm-gateway/key-telemetry-reader", "plaintext http"),
        ("https://fake:fake@gateway.example.com", "secret:llm-gateway/key-x", "no credentials"),
        ("https://gateway.example.com", "fake-literal-key", "secret name"),
        ("https://gateway.example.com", "secret:llm-gateway/master-key", "master key"),
        ("gateway.example.com", "secret:llm-gateway/key-x", "absolute https URL"),
    ],
)
def test_the_reader_refuses_an_unsafe_configuration_before_any_connection(url, key, needle):
    with pytest.raises(GatewayError, match=needle):
        SpendLogReader(url, key)


def test_sync_joins_turns_by_tag_and_settles_only_finished_jobs(filled):
    just_after = parse_iso("2026-01-01T03:01:00Z")  # run-0004 finished a minute ago
    with FakeSpendLogs() as gw:
        got = sync_turns(filled, SpendLogReader(gw.url, env=KEY_ENV).rows, now=just_after)
    assert got == {"jobs": 4, "turns": 4, "settled": 3}
    # the four jobs sit within an hour of each other: one window from the first queue time
    # (less the slack) to now
    assert {(r["start_date"], r["end_date"]) for r in gw.requests} == {
        ("2025-12-31 23:58:00", "2026-01-01 03:01:00")
    }
    turns = filled.turns()
    assert {t: [x["turn_id"] for x in v] for t, v in turns.items()} == {
        "run-0001": ["req-a1", "req-a2"], "hnx-run-0002": ["req-b1"], "run-0003": ["req-c1"],
    }  # fmt: skip
    assert [j["run_id"] for j in filled.unsettled()] == ["run-0004"]
    with FakeSpendLogs() as gw:  # reading again rewrites the same rows; now run-0004 settles too
        again = sync_turns(filled, SpendLogReader(gw.url, env=KEY_ENV).rows, now=T0)
    assert again == {"jobs": 1, "turns": 0, "settled": 1} and filled.unsettled() == []
    assert filled.turns() == turns
    stored = filled.path.read_bytes() + b"".join(
        p.read_bytes() for p in filled.path.parent.glob("*-wal")
    )
    assert [n for n in NEVER if n.encode() in stored] == []


def test_a_failed_read_settles_nothing(filled):
    with FakeSpendLogs(status=503) as gw, pytest.raises(GatewayError):
        sync_turns(filled, SpendLogReader(gw.url, env=KEY_ENV).rows, now=T0)
    assert len(filled.unsettled()) == 4 and filled.turns() == {}
