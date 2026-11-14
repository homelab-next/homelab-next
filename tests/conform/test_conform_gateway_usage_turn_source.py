# SPDX-License-Identifier: Apache-2.0
"""The own gateway's turn source (``inference`` feature ``turn-records``) on its recorded-shape
``GET /v1/usage``: the conformance checks pass, and the adapter's own rules hold -- the
allow-list (``model`` from the deployment, never the key, owner or TLP verdict), status and error
code from the HTTP status, cache figures null when not reported, ``count`` expanded into turns,
paging by time with turn-id de-duplication at the cap, and the read-only key over a guarded
transport."""

from __future__ import annotations

import json

import pytest

from conformance.fakes.gateway_usage_api import (
    KEY_ENV,
    NEVER,
    READER_KEY,
    TAGS,
    WINDOW,
    FakeUsage,
    records,
)
from conformance.protocols.inference import TurnRecordsGateway, TurnSource, turn_problems
from conformance.suites.inference import SUITE
from homelabnext.conform.adapters.gateway_usage import (
    MAX_COUNT,
    MAX_RECORDS,
    UsageError,
    UsageReader,
    make,
    turn_from_record,
)
from homelabnext.conform.core import run_checks
from homelabnext.status.model import parse_iso

TURN_CHECKS = [s.id for s in SUITE.specs if "turn-records" in s.requires]
PLAIN = "http://gateway.example.internal:4100"  # no-raw-endpoint: allow a URL the reader refuses
LO, HI = map(parse_iso, WINDOW)


class Subject:
    features = ("turn-records",)

    def __init__(self, source, window=WINDOW, tags=TAGS):
        self.source, self.window, self.tags = source, window, list(tags)

    def turn_records(self):
        return self.source, *map(parse_iso, self.window), self.tags


def test_the_adapter_passes_the_turn_records_checks_on_the_recorded_usage_log():
    with FakeUsage() as gw:
        source = make(base_url=gw.url, env=KEY_ENV)
        assert isinstance(source, TurnSource) and isinstance(Subject(source), TurnRecordsGateway)
        results = run_checks(SUITE, lambda: Subject(source), only=TURN_CHECKS)
    assert [(r.check, r.status) for r in results if r.status != "pass"] == []
    assert len(results) == len(TURN_CHECKS) >= 4


def test_each_turn_is_the_neutral_record_and_nothing_else_of_the_usage_log():
    with FakeUsage() as gw:
        got = list(make(base_url=gw.url, env=KEY_ENV).turns(LO, HI, TAGS))
        asked = {(r["path"], r["tag"]) for r in gw.requests}
    assert asked == {("/v1/usage", t) for t in TAGS}  # one read per tag
    assert all(turn_problems(t) == [] for t in got)
    text = json.dumps(got)
    assert not [v for v in NEVER if v in text]
    by_id = {t["turn_id"]: t for t in got}
    served = by_id["req-000000000000000000000004"]
    # model is the deployment that served the call (a fallback role's), the role the one asked for
    assert served["model"] == "fast-classifier-1" and served["model_role"] == "main-reasoner"
    assert (served["cache_read_tokens"], served["cache_hit"]) == (4, True)
    assert (served["status"], served["error_code"]) == ("success", None)
    stream = by_id["req-000000000000000000000002"]
    assert stream["ttft_ms"] == 12 and stream["cost_usd"] == pytest.approx(0.000074)
    # no cache figure reported: null, never 0 or False
    assert (stream["cache_read_tokens"], stream["cache_hit"]) == (None, None)
    assert by_id["req-000000000000000000000003"]["call_type"] == "embedding"
    failed = by_id["req-000000000000000000000006"]
    assert (failed["status"], failed["error_code"], failed["model"]) == ("failure", "502", None)
    assert failed["started_at"] == "2026-01-01T00:05:00Z"


def test_an_aggregated_refusal_becomes_count_turns_with_stable_ids():
    with FakeUsage() as gw:
        source = make(base_url=gw.url, env=KEY_ENV)
        first = [t for t in source.turns(LO, HI, ["run-0002"]) if t["status"] == "failure"]
        again = [t for t in source.turns(LO, HI, ["run-0002"]) if t["status"] == "failure"]
    refused = [t for t in first if t["turn_id"].startswith("req-000000000000000000000005")]
    assert [t["turn_id"] for t in refused] == [
        "req-000000000000000000000005",
        "req-000000000000000000000005.2",
        "req-000000000000000000000005.3",
    ]
    assert {(t["error_code"], t["model"], t["input_tokens"], t["cost_usd"]) for t in refused} == {
        ("403", None, None, None)
    }
    assert first == again


def test_an_untagged_overflow_record_and_another_tag_give_no_turns():
    with FakeUsage() as gw:
        got = list(make(base_url=gw.url, env=KEY_ENV).turns(LO, LO + 4 * 3600, TAGS))
    ids = {t["turn_id"] for t in got}
    assert "req-000000000000000000000008" not in ids  # gateway_tag null (aggregated_overflow)
    assert "req-000000000000000000000009" not in ids  # run-9999 was not asked for
    assert {t["gateway_tag"] for t in got} == set(TAGS)


def test_a_name_the_record_refuses_is_null_and_the_turn_is_kept():
    rec = next(r for r in records() if r["turn_id"] == "req-000000000000000000000007")
    (turn,) = turn_from_record(rec, ["run-0003"])
    assert turn["model"] is None and turn_problems(turn) == []
    assert (turn["cache_read_tokens"], turn["cache_hit"]) == (0, False)


@pytest.mark.parametrize(
    "change",
    [
        {"turn_id": "not an id"},
        {"ts": "yesterday"},
        {"ts": "2026-01-01T00:01:00"},  # no zone
        {"status": "200"},
        {"status": True},
        {"gateway_tag": None},
    ],
)
def test_a_record_without_a_usable_id_time_status_or_tag_gives_no_turn(change):
    rec = records()[0] | change
    assert turn_from_record(rec, ["run-0001"]) == []


@pytest.mark.parametrize("count", [0, -1, MAX_COUNT + 1, True, 1.5, "3"])
def test_a_count_that_is_not_the_gateways_is_refused(count):
    with pytest.raises(UsageError, match="count"):
        turn_from_record(records()[0] | {"count": count}, ["run-0001"])


def test_paging_at_the_cap_asks_again_from_the_last_second_and_drops_repeats():
    base = records()[0]
    recs = [
        base | {"turn_id": f"req-{i:024d}", "ts": f"2026-01-01T00:00:{i // 3:02d}.{i % 3}Z"}
        for i in range(30)
    ]
    with FakeUsage(recs, cap=7) as gw:
        got = list(make(base_url=gw.url, env=KEY_ENV).turns(LO, HI, ["run-0001"]))
        starts = [int(r["start"]) for r in gw.requests]
    assert sorted(t["turn_id"] for t in got) == sorted(r["turn_id"] for r in recs)
    assert len(got) == len({t["turn_id"] for t in got})
    assert starts == sorted(starts) and len(starts) > 1 and starts[0] == int(LO)


def test_more_records_in_one_second_than_the_cap_is_an_error():
    base = records()[0]
    recs = [base | {"turn_id": f"req-{i:024d}"} for i in range(5)]
    with FakeUsage(recs, cap=3) as gw, pytest.raises(UsageError, match="in the second"):
        list(make(base_url=gw.url, env=KEY_ENV).turns(LO, HI, ["run-0001"]))


def test_a_runaway_window_is_bounded_by_max_pages():
    base = records()[0]
    recs = [
        base | {"turn_id": f"req-{i:024d}", "ts": f"2026-01-01T00:{i:02d}:00Z"} for i in range(9)
    ]
    with FakeUsage(recs, cap=2) as gw, pytest.raises(UsageError, match="pages"):
        list(make(base_url=gw.url, env=KEY_ENV, max_pages=2).turns(LO, HI, ["run-0001"]))


@pytest.mark.parametrize(
    ("status", "needle"), [(401, "refused the key"), (403, "refused the key"), (500, "HTTP 500")]
)
def test_a_refusal_or_failure_of_the_route_is_a_usage_error(status, needle):
    with FakeUsage(status=status) as gw, pytest.raises(UsageError, match=needle):
        list(make(base_url=gw.url, env=KEY_ENV).turns(LO, HI, TAGS))


def test_a_wrong_key_is_a_usage_error_naming_no_value():
    env = {"HNX_SECRET_LLM_GATEWAY_KEY_TELEMETRY_READER": "fake-wrong-reader-key-0002"}
    with FakeUsage() as gw, pytest.raises(UsageError) as exc:
        list(make(base_url=gw.url, env=env).turns(LO, HI, TAGS))
    assert "fake-wrong-reader-key" not in str(exc.value)


@pytest.mark.parametrize(
    ("kw", "needle"),
    [
        ({"key": "secret:llm-gateway/master-key"}, "admin key"),
        ({"key": "secret:llm_gateway/master.key"}, "admin key"),
        ({"key": "sk-a-literal-value"}, "secret name"),
        ({"base_url": "ftp://gateway.example.internal"}, "absolute https"),
        ({"base_url": "https://u:p@gateway.example.internal"}, "no credentials"),
        ({"base_url": PLAIN}, "plaintext"),
        ({"timeout": 0}, "timeout"),
        ({"timeout": True}, "timeout"),
        ({"max_pages": 0}, "max_pages"),
    ],
)
def test_unsafe_settings_are_refused_before_any_connection(kw, needle):
    kw = {"base_url": "https://gateway.example.internal"} | kw
    with pytest.raises(UsageError, match=needle):
        make(env=KEY_ENV, **kw)


def test_the_url_comes_from_the_endpoint_override_and_is_required():
    with pytest.raises(UsageError, match="HNX_ENDPOINT_LLM_GATEWAY"):
        make(env=KEY_ENV)
    source = make(env=KEY_ENV | {"HNX_ENDPOINT_LLM_GATEWAY": "https://gw.example.internal"})
    assert source.reader.url == "https://gw.example.internal/v1/usage"
    assert "fake-telemetry" not in repr(source)


def test_a_missing_key_is_named_by_its_variable():
    reader = UsageReader("https://gw.example.internal", env={})
    with pytest.raises(UsageError, match="HNX_SECRET_LLM_GATEWAY_KEY_TELEMETRY_READER"):
        reader.page(0, 1, "run-0001")


@pytest.mark.parametrize(
    "change",
    [
        {"status": 200},  # a served call is never aggregated
        {"status": 204},
        {"input_tokens": 6},
        {"output_tokens": 1},
        {"cache_read_tokens": 4},
        {"cost_usd": 0.001},
        {"input_tokens": False},  # a boolean is no count, even though False == 0
        {"cost_usd": False},
        {"output_tokens": True},
        {"cache_read_tokens": "0"},
    ],
)
def test_an_aggregated_record_that_is_not_a_spendless_refusal_is_refused(change):
    rec = next(r for r in records() if r["count"] == 3) | change
    with pytest.raises(UsageError, match="not a refusal"):
        turn_from_record(rec, ["run-0002"])


def test_an_aggregated_refusal_with_zero_spend_is_expanded():
    rec = next(r for r in records() if r["count"] == 3) | {"input_tokens": 0, "cost_usd": 0}
    assert len(turn_from_record(rec, ["run-0002"])) == 3


def test_a_page_over_the_gateways_cap_is_refused():
    base = records()[0]
    recs = [base | {"turn_id": f"req-{i:024d}"} for i in range(MAX_RECORDS + 1)]
    with FakeUsage(recs, cap=MAX_RECORDS + 1) as gw, pytest.raises(UsageError, match="cap of"):
        list(make(base_url=gw.url, env=KEY_ENV).turns(LO, HI, ["run-0001"]))


def test_one_read_yields_at_most_a_full_windows_turns():
    base = next(r for r in records() if r["count"] == 3)
    recs = [
        base | {"turn_id": f"req-{i:024d}", "gateway_tag": "run-0001", "count": MAX_COUNT}
        for i in range(2)
    ]
    with FakeUsage(recs) as gw:
        source = make(base_url=gw.url, env=KEY_ENV, max_pages=1)
        with pytest.raises(UsageError, match=f"more than {MAX_RECORDS} turns"):
            list(source.turns(LO, HI, ["run-0001"]))


def test_a_reader_key_whose_value_is_the_admin_keys_is_refused():
    env = KEY_ENV | {"HNX_SECRET_LLM_GATEWAY_MASTER_KEY": READER_KEY}
    with FakeUsage() as gw, pytest.raises(UsageError, match="admin key") as exc:
        list(make(base_url=gw.url, env=env).turns(LO, HI, TAGS))
    assert READER_KEY not in str(exc.value)
    assert not gw.requests  # refused before the key was sent
