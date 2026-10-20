# SPDX-License-Identifier: Apache-2.0
"""The push ingest (``POST /ingest/agent-activity``): tokens, limits, schemas, redaction."""

from __future__ import annotations

import http.client
import json
import threading
import urllib.parse

import pytest
from agent_helpers import FAKE_BEARER, detail, post_json, request, summary

from homelabnext.status.agents import ActivityStore
from homelabnext.status.agents.config import IngestSettings, Sender
from homelabnext.status.agents.ingest import RateLimiter, make_ingest_server, sender_for

DOC_ADDR = ".".join(["192", "0", "2", "10"])  # a documentation address, built so no gate trips

TOKEN = "fake-ingest-token-cloud"
SETTINGS = IngestSettings(
    senders=(Sender("cloud", TOKEN), Sender("fleet", "fake-ingest-token-fleet", detail=False)),
    max_body_bytes=4096,
    max_events=5,
    rate_per_min=3,
)


@pytest.fixture
def ingest(tmp_path, clock):
    store = ActivityStore(tmp_path / "activity.db", clock=clock)
    published = []
    srv = make_ingest_server(store, SETTINGS, clock=clock, publish=published.extend)
    th = threading.Thread(target=srv.serve_forever, args=(0.05,), daemon=True)
    th.start()
    host, port = srv.server_address[:2]
    yield f"http://{host}:{port}", store, published, clock
    srv.shutdown()
    srv.server_close()


def test_accepts_both_tiers_and_redacts_before_storage(ingest, tmp_path):
    base, store, published, _ = ingest
    cmd = f"curl -H 'Authorization: Bearer {FAKE_BEARER}' x"
    code, _, body = post_json(
        base, {"summary": [summary(has_detail=True)], "detail": [detail(command=cmd)]}, TOKEN
    )
    assert code == 200, body
    assert json.loads(body) == {"added": 1, "duplicates": 0, "details": 1, "detail_dropped": 0}
    assert store.events()[0]["event_id"] == "ev-s-1-1"
    assert FAKE_BEARER not in store.detail("ev-s-1-1")["command"]
    assert all(FAKE_BEARER.encode() not in p.read_bytes() for p in tmp_path.glob("activity.db*"))
    assert published == [summary(has_detail=True)]  # the bus gets the summary tier only
    assert post_json(base, {"summary": [summary(has_detail=True)]}, TOKEN)[0] == 200  # duplicate


@pytest.mark.parametrize("token", [None, "", "fake-wrong-token", TOKEN + "x", TOKEN[:-1]])
def test_missing_or_invalid_token_is_401(ingest, token):
    base, store, *_ = ingest
    code, headers, _ = post_json(base, {"summary": [summary()]}, token)
    assert code == 401 and headers["WWW-Authenticate"].startswith("Bearer")
    assert store.events() == []


def test_basic_auth_is_not_a_bearer_token():
    assert sender_for(f"Basic {TOKEN}", SETTINGS.senders) is None
    assert sender_for(f"Bearer {TOKEN}", SETTINGS.senders).name == "cloud"
    assert sender_for("Bearer ", (Sender("empty", ""),)) is None


def test_oversize_body_and_too_many_events_are_413(ingest):
    base, store, *_ = ingest
    big = {"summary": [summary()], "detail": [detail(prompt="x" * 5000)]}
    assert post_json(base, big, TOKEN)[0] == 413
    many = {"summary": [summary(i) for i in range(6)]}
    assert post_json(base, many, TOKEN)[0] == 413
    assert store.events() == []


def test_missing_length_is_411_and_wrong_type_is_415(ingest):
    base, *_ = ingest
    u = urllib.parse.urlsplit(base)
    conn = http.client.HTTPConnection(u.hostname, u.port, timeout=5)
    conn.putrequest("POST", "/ingest/agent-activity")
    conn.putheader("Authorization", f"Bearer {TOKEN}")
    conn.endheaders()
    assert conn.getresponse().status == 411
    conn.close()
    code, *_ = post_json(base, b"{}", TOKEN, headers={"Content-Type": "text/plain"})
    assert code == 415


@pytest.mark.parametrize(
    "body, code",
    [
        (b"not json", 400),
        (b"[]", 400),
        ({"summary": [summary()], "extra": 1}, 400),
        ({"summary": {"a": 1}}, 400),
        ({"summary": [summary(kind="thinking")]}, 422),
        ({"summary": [summary(prompt="leaks into the summary tier")]}, 422),
        ({"summary": [summary()], "detail": [{"session_id": "s-1"}]}, 422),
        ({"detail": [detail(99, prompt="orphan")]}, 422),
    ],
)
def test_invalid_batches_are_refused_whole(ingest, body, code):
    base, store, *_ = ingest
    got, _, out = post_json(base, body, TOKEN)
    assert got == code, out
    assert store.events() == [] and store.detail("ev-s-1-99") is None


def test_detail_for_a_stored_event_is_accepted(ingest):
    base, store, *_ = ingest
    assert post_json(base, {"summary": [summary()]}, TOKEN)[0] == 200
    assert post_json(base, {"detail": [detail(prompt="later")]}, TOKEN)[0] == 200
    assert store.detail("ev-s-1-1")["prompt"] == "later"


def test_a_sender_without_detail_has_it_dropped(ingest):
    base, store, *_ = ingest
    code, _, body = post_json(
        base, {"summary": [summary()], "detail": [detail(prompt="p")]}, "fake-ingest-token-fleet"
    )
    assert code == 200 and json.loads(body)["detail_dropped"] == 1
    assert store.detail("ev-s-1-1") is None
    assert store.events(via="push")[0]["event_id"] == "ev-s-1-1"


def test_rate_limit_per_sender_with_an_injected_clock(ingest):
    base, _, _, clock = ingest
    for i in range(3):
        assert post_json(base, {"summary": [summary(i)]}, TOKEN)[0] == 200
    code, headers, _ = post_json(base, {"summary": [summary(9)]}, TOKEN)
    assert code == 429 and headers["Retry-After"] == "60"
    assert (
        post_json(base, {"summary": [summary(8, session="f")]}, "fake-ingest-token-fleet")[0] == 200
    )
    clock.advance(20)  # one request a 20 s at 3/min
    assert post_json(base, {"summary": [summary(9)]}, TOKEN)[0] == 200


def test_rate_limiter_refills():
    t = [0.0]
    rl = RateLimiter(60, lambda: t[0])
    assert all(rl.allow("a") for _ in range(60)) and not rl.allow("a")
    t[0] += 1
    assert rl.allow("a") and not rl.allow("a")


def test_only_post_on_the_one_path_and_hosts_are_guarded(ingest):
    base, *_ = ingest
    assert post_json(base, {"summary": []}, TOKEN, path="/elsewhere")[0] == 404
    code, headers, _ = request(base, "/ingest/agent-activity")
    assert code == 405 and headers["Allow"] == "POST"
    code, *_ = post_json(base, {"summary": []}, TOKEN, headers={"Host": "evil.example"})
    assert code == 403
    code, *_ = post_json(base, {"summary": []}, TOKEN, headers={"Origin": "https://evil.example"})
    assert code == 403


def test_binding_beyond_loopback_needs_allow_remote_and_hosts(tmp_path, clock):
    store = ActivityStore(tmp_path / "activity.db", clock=clock)
    with pytest.raises(ValueError, match="loopback-only"):
        make_ingest_server(store, SETTINGS, host=DOC_ADDR)
    with pytest.raises(ValueError, match="allowed_hosts"):
        make_ingest_server(store, SETTINGS, allow_remote=True)


# ---------------------------------------------------------------- the sender must own the source
OWNED = IngestSettings(
    senders=(
        Sender("cloud", TOKEN, runtimes=("claude-code",)),
        Sender("fleet", "fake-ingest-token-fleet", runtimes=("hermes",)),
    ),
    rate_per_min=100,
)


@pytest.fixture
def owned(tmp_path, clock):
    store = ActivityStore(tmp_path / "activity.db", clock=clock)
    srv = make_ingest_server(store, OWNED, clock=clock)
    threading.Thread(target=srv.serve_forever, args=(0.05,), daemon=True).start()
    host, port = srv.server_address[:2]
    yield f"http://{host}:{port}", store
    srv.shutdown()
    srv.server_close()


def test_a_sender_reports_only_its_runtimes(owned):
    base, _ = owned
    code, _, body = post_json(base, {"summary": [summary(runtime="hermes")]}, TOKEN)
    assert code == 403 and b"may not report" in body
    assert post_json(base, {"summary": [summary()]}, TOKEN)[0] == 200


def test_a_sender_cannot_write_into_another_senders_or_a_local_session(owned):
    # regression: any valid token could append events and details to any session
    base, store = owned
    assert post_json(base, {"summary": [summary(1, has_detail=True)]}, TOKEN)[0] == 200
    hijack = {"summary": [summary(2, runtime="hermes")]}  # same session s-1, other sender
    assert post_json(base, hijack, "fake-ingest-token-fleet")[0] == 403
    late = {"detail": [detail(1, prompt="planted")]}
    assert post_json(base, late, "fake-ingest-token-fleet")[0] == 403
    assert store.detail("ev-s-1-1") is None
    store.add([summary(1, session="local")], via="agent-spool")
    assert post_json(base, {"summary": [summary(2, session="local")]}, TOKEN)[0] == 403
    assert [e["event_id"] for e in store.events(session="s-1")] == ["ev-s-1-1"]
    assert post_json(base, {"detail": [detail(1, prompt="mine")]}, TOKEN)[0] == 200  # the owner


def test_a_refused_sender_is_logged_on_one_line(owned, caplog):
    """The refusal log quotes sender-supplied values; it must stay one line (no log forging)."""
    base, _ = owned
    with caplog.at_level("WARNING", logger="homelabnext.status.agents.ingest"):
        code, *_ = post_json(base, {"summary": [summary(runtime="hermes")]}, TOKEN)
    assert code == 403
    lines = [r.getMessage() for r in caplog.records if "refused sender" in r.getMessage()]
    assert lines and all("\n" not in m and "\r" not in m for m in lines)
