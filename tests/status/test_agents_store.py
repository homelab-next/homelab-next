# SPDX-License-Identifier: Apache-2.0
"""Agent activity: the two schemas, redaction and caps before storage, retention, sessions."""

from __future__ import annotations

import json

import pytest
from agent_helpers import FAKE_BEARER, detail, summary
from status_helpers import ROOT, T0

from homelabnext.events.consumer import decode_event
from homelabnext.status.agents import (
    DETAIL_KEYS,
    ActivityError,
    ActivityStore,
    Redactor,
    Thresholds,
    bus_event,
    derive_sessions,
    detail_problems,
    summary_problems,
)
from homelabnext.status.agents.model import session_state

SCHEMAS = ROOT / "schemas" / "status"


@pytest.fixture
def store(tmp_path, clock):
    return ActivityStore(tmp_path / "activity.db", clock=clock, retention_days=1)


def _disk(tmp_path) -> bytes:
    """Every byte the store has on disk (the database, its WAL and shared memory)."""
    return b"".join(p.read_bytes() for p in tmp_path.glob("activity.db*"))


# ---------------------------------------------------------------- schemas
@pytest.mark.parametrize(
    "name", sorted(p.name for p in (SCHEMAS / "examples").glob("agent_activity.*"))
)
def test_summary_examples_validate(name):
    assert summary_problems(json.loads((SCHEMAS / "examples" / name).read_text())) == []


@pytest.mark.parametrize(
    "name", sorted(p.name for p in (SCHEMAS / "negative").glob("agent_activity.*"))
)
def test_summary_negatives_fail(name):
    assert summary_problems(json.loads((SCHEMAS / "negative" / name).read_text()))


@pytest.mark.parametrize(
    "name", sorted(p.name for p in (SCHEMAS / "examples").glob("agent_activity_detail.*"))
)
def test_detail_examples_validate(name):
    assert detail_problems(json.loads((SCHEMAS / "examples" / name).read_text())) == []


@pytest.mark.parametrize(
    "name", sorted(p.name for p in (SCHEMAS / "negative").glob("agent_activity_detail.*"))
)
def test_detail_negatives_fail(name):
    assert detail_problems(json.loads((SCHEMAS / "negative" / name).read_text()))


@pytest.mark.parametrize("key", sorted(DETAIL_KEYS))
def test_summary_tier_never_carries_a_detail_field(key):
    doc = summary(**{key: "x"})
    assert any(key in p for p in summary_problems(doc))
    with pytest.raises(ValueError, match="never go on the bus"):
        bus_event(doc, "svc:status-hub")


def test_bus_event_is_the_summary_tier_and_validates():
    ev = bus_event(summary(), "svc:status-hub")
    assert decode_event(json.dumps(ev), types=["homelabnext.agent.activity"])["data"] == summary()
    assert not DETAIL_KEYS & set(ev["data"])
    assert bus_event(summary(), "svc:status-hub")["id"] == ev["id"]  # a re-send is a duplicate


# ---------------------------------------------------------------- redaction before storage
def test_bearer_token_in_a_command_never_reaches_disk(tmp_path, store):
    cmd = f'curl -H "Authorization: Bearer {FAKE_BEARER}" https://api.example.invalid/v1'
    res = store.add(
        [summary(has_detail=True)],
        [
            detail(
                command=cmd,
                tool_input=json.dumps({"command": cmd}),
                tool_output=f"Authorization: Bearer {FAKE_BEARER}",
            )
        ],
        via="test",
    )
    assert res.added == 1 and res.details == 1 and res.redactions["token"] >= 2
    stored = store.detail("ev-s-1-1")
    assert "[REDACTED:token:1]" in stored["command"] and FAKE_BEARER not in json.dumps(stored)
    assert FAKE_BEARER.encode() not in _disk(tmp_path)
    assert stored["redactions"]["token"] >= 2


def test_secret_in_a_summary_name_is_replaced(store):
    token = "gh" + "p_" + "fake0123456789abcdefghijklmnopqrstuv"  # built: no literal token shape
    store.add([summary(project=token)], via="test")
    assert store.event("ev-s-1-1")["project"] == "redacted"


def test_personal_data_redaction_is_a_switch(tmp_path, clock):
    text = "mail someone@example.org about it"
    off = ActivityStore(tmp_path / "a" / "activity.db", clock=clock)
    on = ActivityStore(
        tmp_path / "b" / "activity.db", clock=clock, redactor=Redactor(personal=True)
    )
    for s in (off, on):
        s.add([summary()], [detail(prompt=text)], via="test")
    assert off.detail("ev-s-1-1")["prompt"] == text
    assert on.detail("ev-s-1-1")["prompt"] == "mail [REDACTED:email:1] about it"


def test_caps_apply_after_redaction(tmp_path, clock):
    store = ActivityStore(
        tmp_path / "activity.db", clock=clock, redactor=Redactor(caps={"command": 40})
    )
    # cut first, the token would be half there and unrecognisable; redacted first, it is a label
    cmd = "x" * 10 + f" Authorization: Bearer {FAKE_BEARER} " + "y" * 100
    store.add([summary()], [detail(command=cmd, tool_output="z" * 20)], via="test")
    d = store.detail("ev-s-1-1")
    assert len(d["command"]) == 40 and d["truncated"] == ["command"]
    assert FAKE_BEARER[:8] not in d["command"]
    assert FAKE_BEARER.encode()[:12] not in _disk(tmp_path)


def test_an_invalid_record_stores_nothing(store):
    with pytest.raises(ActivityError) as exc:
        store.add([summary(), summary(2, kind="thinking")], via="test")
    assert "summary[1]" in str(exc.value)
    with pytest.raises(ActivityError):
        store.add([summary(3)], [{"session_id": "s-1"}], via="test")
    assert store.events() == []


def test_detail_tier_can_be_switched_off(tmp_path, clock):
    store = ActivityStore(tmp_path / "activity.db", clock=clock, keep_detail=False)
    assert store.add([summary()], [detail(prompt="p")], via="test").details == 0
    assert store.detail("ev-s-1-1") is None


def test_duplicates_are_counted_not_rewritten(store):
    assert store.add([summary()], via="test").added == 1
    res = store.add([summary(outcome="error")], via="test")
    assert (res.added, res.duplicates) == (0, 1)
    assert store.event("ev-s-1-1")["outcome"] == "success"


# ---------------------------------------------------------------- retention
def test_retention_purges_on_ingest_and_on_open(tmp_path, clock):
    store = ActivityStore(tmp_path / "activity.db", clock=clock, retention_days=1)
    store.add([summary(1)], [detail(1, prompt="old")], via="test")
    clock.advance(86400 - 10)
    store.add([summary(2, t=clock())], via="test")
    assert {e["event_id"] for e in store.events()} == {"ev-s-1-1", "ev-s-1-2"}
    clock.advance(20)  # event 1 is past one day now; the next write purges it
    store.add([summary(3, t=clock())], via="test")
    assert {e["event_id"] for e in store.events()} == {"ev-s-1-2", "ev-s-1-3"}
    assert store.detail("ev-s-1-1") is None
    clock.advance(2 * 86400)  # nothing written: reopening the store purges
    reopened = ActivityStore(tmp_path / "activity.db", clock=clock, retention_days=1)
    assert reopened.events() == []


def test_an_event_dated_beyond_retention_is_purged_at_once(store, clock):
    store.add([summary(t=clock() - 3 * 86400)], via="test")
    assert store.events() == []


# ---------------------------------------------------------------- sessions
def test_session_states_and_counts(clock):
    evs = [
        summary(1, session="a", kind="session_start", outcome="info", t=T0, host="devbox"),
        summary(2, session="a", kind="tool_start", t=T0 + 1, outcome=None),
        summary(
            3, session="a", kind="tool_end", t=T0 + 2, tokens_in=10, tokens_out=5, cost_usd=0.5
        ),
        summary(1, session="b", kind="tool_end", outcome="error", t=T0),
        summary(1, session="c", kind="stop", outcome=None, t=T0),
        summary(1, session="d", kind="session_end", outcome="info", t=T0),
        summary(1, session="e", kind="approval_request", outcome="pending", t=T0),
        summary(2, session="e", kind="tool_end", outcome="denied", t=T0 - 1),
    ]
    rows = {r["session_id"]: r for r in derive_sessions(evs, T0 + 60)}
    assert {k: r["state"] for k, r in rows.items()} == {
        "a": "working", "b": "errored", "c": "waiting", "d": "done", "e": "waiting",
    }  # fmt: skip
    a = rows["a"]
    assert (a["tool_calls"], a["tokens_in"], a["tokens_out"], a["cost_usd"]) == (1, 10, 5, 0.5)
    assert a["host"] == "devbox" and a["last_tool"] == "Bash" and a["idle_s"] == 58
    assert rows["e"]["denials"] == 1 and rows["e"]["approvals"] == 1
    assert next(r["session_id"] for r in derive_sessions(evs, T0 + 60)) == "b"  # worst first


def test_stuck_after_the_threshold_with_an_injected_clock():
    evs = [summary(1, session="a", kind="tool_start", outcome=None)]
    t = Thresholds(default=900)
    assert derive_sessions(evs, T0 + 899, t)[0]["state"] == "working"
    assert derive_sessions(evs, T0 + 900, t)[0]["state"] == "stuck"


def test_threshold_model_beats_runtime_beats_default():
    t = Thresholds(default=900, runtimes={"codex": 300}, models={"slow-model": 3000})
    assert t.for_session("claude-code", None) == 900
    assert t.for_session("codex", None) == 300
    assert t.for_session("codex", "slow-model") == 3000
    ev = summary(1, runtime="codex", kind="tool_start", outcome=None)
    assert derive_sessions([ev], T0 + 400, t)[0]["state"] == "stuck"
    ev = {**ev, "model": "slow-model"}
    assert derive_sessions([ev], T0 + 400, t)[0]["state"] == "working"


def test_errored_beats_stuck_and_waiting_is_never_stuck():
    assert session_state({"kind": "tool_end", "outcome": "error"}, 10**6, 60) == "errored"
    assert session_state({"kind": "stop"}, 10**6, 60) == "waiting"
    assert session_state({"kind": "session_end"}, 10**6, 60) == "done"
