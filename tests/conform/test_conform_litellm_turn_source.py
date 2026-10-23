# SPDX-License-Identifier: Apache-2.0
"""The first turn source adapter (``inference`` feature ``turn-records``) on its gateway's
recorded-shape spend log: the conformance checks pass, each check fails on the defect it exists
for, and the adapter's own rules hold -- the allow-list (nothing else in a row is ever kept), the
read-only viewer key by secret name over a guarded transport, paging."""

from __future__ import annotations

import pytest

from conformance.fakes.inference_target import FakeTurnSource, fake_turns
from conformance.fakes.litellm_spend_log_api import KEY_ENV, NEVER, TAGS, WINDOW, FakeSpendLogs
from conformance.fakes.litellm_spend_log_api import pages as fixture_pages
from conformance.protocols.inference import TurnRecordsGateway, TurnSource, turn_problems
from conformance.suites.inference import SUITE
from homelabnext.conform.adapters.litellm_spend_log import (
    SpendLogError,
    SpendLogReader,
    SpendLogTurnSource,
    make,
    turn_from_row,
)
from homelabnext.conform.core import run_checks
from homelabnext.status.model import parse_iso

ROWS = [r for p in fixture_pages() for r in p["data"]]
TAGS_SET = set(TAGS)
TURN_CHECKS = [s.id for s in SUITE.specs if "turn-records" in s.requires]


class Subject:
    """An ``inference`` subject that only offers feature ``turn-records``: ``source`` on a window
    and tags (the fixture's by default)."""

    features = ("turn-records",)

    def __init__(self, source, window=WINDOW, tags=TAGS):
        self.source, self.window, self.tags = source, window, list(tags)

    def turn_records(self):
        return self.source, *map(parse_iso, self.window), self.tags


def _failed(source, **kw) -> list[str]:
    results = run_checks(SUITE, lambda: Subject(source, **kw), only=TURN_CHECKS)
    assert {r.check for r in results} == set(TURN_CHECKS)
    return sorted(r.check for r in results if not r.ok)


def test_the_adapter_passes_the_turn_records_checks_on_the_recorded_spend_log():
    with FakeSpendLogs() as gw:
        source = make(base_url=gw.url, env=KEY_ENV)
        assert isinstance(source, TurnSource) and isinstance(Subject(source), TurnRecordsGateway)
        results = run_checks(SUITE, lambda: Subject(source), only=TURN_CHECKS)
    assert [(r.check, r.status) for r in results if r.status != "pass"] == []
    assert len(results) == len(TURN_CHECKS) >= 4


class Widened(FakeTurnSource):
    def turns(self, start, end, tags):
        return [
            t | {"api_base": "https://upstream.example.com/v1"}
            for t in super().turns(start, end, tags)
        ]


class SmuggledName(FakeTurnSource):
    """Widening inside allowed fields: a URL in model, an address in call_type."""

    def turns(self, start, end, tags):
        return [
            t
            | {
                "model": "https://gateway.example.com/v1",
                "call_type": "alice@example.com",
            }
            for t in super().turns(start, end, tags)
        ]


class EveryTag(FakeTurnSource):
    def turns(self, start, end, tags):
        return super().turns(start, end, {t["gateway_tag"] for t in self.log})


class Unwindowed(FakeTurnSource):
    def turns(self, start, end, tags):
        return super().turns(0, 4e9, tags)


class FreshIds(FakeTurnSource):
    calls = 0

    def turns(self, start, end, tags):
        FreshIds.calls += 1
        return [
            t | {"turn_id": f"{t['turn_id']}-{self.calls}"} for t in super().turns(start, end, tags)
        ]


@pytest.mark.parametrize(
    "source, fails",
    [
        (FakeTurnSource(fake_turns()), []),
        (Widened(fake_turns()), ["turn-records-are-neutral"]),
        (SmuggledName(fake_turns()), ["turn-records-are-neutral"]),
        (EveryTag(fake_turns()), ["turn-records-only-the-asked-tags"]),
        (Unwindowed(fake_turns()), ["turn-records-in-the-window"]),
        (FreshIds(fake_turns()), ["turn-records-stable-ids"]),
    ],
    ids=["conforming", "widened", "smuggled-name", "every-tag", "unwindowed", "fresh-ids"],
)
def test_each_turn_records_check_fails_on_its_defect(source, fails):
    from conformance.fakes.inference_target import TURN_TAGS, TURN_WINDOW
    from homelabnext.status.model import iso

    window = tuple(iso(t) for t in TURN_WINDOW)
    tags = TURN_TAGS[:1] if isinstance(source, EveryTag) else TURN_TAGS
    failed = _failed(source, window=window, tags=tags)
    assert failed == fails if not fails else set(fails) <= set(failed), failed


def test_every_turn_the_adapter_maps_is_a_neutral_record():
    for row in ROWS:
        turn = turn_from_row(row, TAGS_SET)
        assert turn is None or turn_problems(turn) == [], row["request_id"]


def test_make_needs_a_gateway_url_before_any_connection(monkeypatch):
    monkeypatch.delenv("HNX_ENDPOINT_LLM_GATEWAY", raising=False)
    with pytest.raises(SpendLogError, match="HNX_ENDPOINT_LLM_GATEWAY"):
        make()
    assert isinstance(make(base_url="https://gateway.example.com"), SpendLogTurnSource)


def test_a_turn_keeps_only_the_allow_listed_names_and_numbers():
    by_id = {r["request_id"]: r for r in ROWS}
    turn = turn_from_row(by_id["req-a1"], TAGS_SET)
    assert turn == {
        "turn_id": "req-a1", "gateway_tag": "run-0001", "started_at": "2026-01-01T00:00:13Z",
        "duration_ms": 2100, "ttft_ms": 400, "model_role": "mdl:triage-large",
        "model": "example-27b", "call_type": "acompletion", "status": "success",
        "error_code": None, "input_tokens": 20000, "output_tokens": 1500,
        "cache_read_tokens": 12000, "cache_hit": False, "cost_usd": 0.0,
    }  # fmt: skip
    for row in ROWS:
        text = repr(turn_from_row(row, TAGS_SET))
        assert [n for n in NEVER if n in text] == [], row["request_id"]


def test_a_turn_reads_every_shape_the_spend_log_uses():
    by_id = {r["request_id"]: r for r in ROWS}
    a2 = turn_from_row(by_id["req-a2"], TAGS_SET)  # naive UTC times, cache_read_input_tokens
    assert (a2["started_at"], a2["ttft_ms"], a2["cache_read_tokens"], a2["cache_hit"]) == (
        "2026-01-01T00:02:00Z", 250, 16000, True,
    )  # fmt: skip
    b1 = turn_from_row(by_id["req-b1"], TAGS_SET)  # tags as JSON text, a failure, a mangled name
    assert (b1["gateway_tag"], b1["status"], b1["error_code"]) == ("hnx-run-0002", "failure", "503")
    assert b1["model_role"] is None and b1["ttft_ms"] is None and b1["cache_hit"] is None
    assert turn_from_row(by_id["req-x9"], TAGS_SET) is None  # another job's turn
    assert turn_from_row({**by_id["req-a1"], "request_id": "a b"}, TAGS_SET) is None
    assert turn_from_row({**by_id["req-a1"], "startTime": "yesterday"}, TAGS_SET) is None


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
    with FakeSpendLogs(status=status) as gw, pytest.raises(SpendLogError, match=needle):
        list(SpendLogReader(gw.url, env=env).rows(0, 60))


def test_a_runaway_window_stops_at_max_pages():
    endless = [{"data": [{"request_id": f"r{n}"}], "total_pages": 99} for n in range(5)]
    with FakeSpendLogs(endless) as gw, pytest.raises(SpendLogError, match="more than 2 pages"):
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
    with pytest.raises(SpendLogError, match=needle):
        SpendLogReader(url, key)


@pytest.mark.parametrize(
    "key",
    [
        "secret:llm-gateway/master_key",
        "secret:llm-gateway/master.key",
        "secret:llm_gateway/master-key",
        "secret:llm.gateway/master/key",
    ],
)
def test_every_spelling_of_the_master_key_is_refused(key):
    """Each of these is delivered in the master key's own variable, so each is the master key."""
    with pytest.raises(SpendLogError, match="master key"):
        SpendLogReader("https://gateway.example.com", key)


@pytest.mark.parametrize(
    "key, value, ok",
    [
        ("model", "meta-llama/Llama-3.1-8B-Instruct", True),
        ("model", "llama3:8b", True),
        ("model", "claude-3-5-sonnet-v2@20241022", True),
        ("model", "custom/hermes-agent", True),
        ("model_role", "smart", True),
        ("call_type", "acompletion", True),
        ("model", "https://gateway.example.com/v1", False),
        ("model", "gateway.example.com//v1", False),
        ("model", "alice@example.com", False),
        ("model_role", "smart@example", False),
        ("call_type", "alice@example.com", False),
        ("call_type", "http://x", False),
    ],
)
def test_a_name_is_never_a_url_or_an_address(key, value, ok):
    from conformance.fakes.inference_target import fake_turns
    from conformance.protocols.inference import turn_problems

    probs = turn_problems(fake_turns()[0] | {key: value})
    assert probs == [] if ok else probs == [f"{key} is not a name"], probs
