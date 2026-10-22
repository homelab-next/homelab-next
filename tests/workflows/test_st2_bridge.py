# SPDX-License-Identifier: Apache-2.0
"""The StackStorm event bridge (``homelabnext.workflows.st2_bridge``, docs/stackstorm.md).

Hermetic: the bus is the in-memory fake (and, once, the JetStream adapter over its in-process wire
fake), the webhook a loopback HTTP server that records what it was sent.
"""

from __future__ import annotations

import copy
import http.server
import json
import threading
import time

import pytest
from wf_support import ROOT

from conformance.fakes.event_bus import FakeEventBus
from conformance.fakes.jetstream_wire import FakeJetStreamWire
from homelabnext.conform.adapters import nats_jetstream as nj
from homelabnext.events.envelope import canonical_body
from homelabnext.workflows import st2_bridge as sb

BRIDGE = ROOT / "workflows" / "stackstorm" / "bridge.json"
KEY = "fake-st2-webhook-key-0001"  # scrub-allow: fake placeholder
ENV = {"HNX_SECRET_STACKSTORM_WEBHOOK_KEY": KEY}
EXAMPLE = json.loads((ROOT / "schemas/events/examples/proposal.created.valid.json").read_text())


def proposal(i: int = 1, **over) -> dict:
    ev = copy.deepcopy(EXAMPLE)
    ev |= {"id": f"evt-bridge-{i}", "source": "svc:broker"}
    return ev | over


class Clock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t


# ---------------------------------------------------------------- a loopback StackStorm webhook
class Hook:
    """A loopback server: answers each POST with the next scripted status (default 202)."""

    def __init__(self):
        self.requests: list[dict] = []
        self.script: list[int] = []
        self.redirect_hits = 0
        hook = self

        class H(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
                if self.path != "/api/v1/webhooks/homelabnext":
                    hook.redirect_hits += 1
                hook.requests.append(
                    {"path": self.path, "headers": dict(self.headers), "body": body}
                )
                code = hook.script.pop(0) if hook.script else 202
                self.send_response(code)
                if code in (301, 302, 307, 308):
                    self.send_header("Location", "/elsewhere")
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"{}")

            def log_message(self, *_a):
                pass

        self.server = http.server.ThreadingHTTPServer(("localhost", 0), H)
        host, port = self.server.server_address[:2]
        self.url = f"http://{host}:{port}"
        threading.Thread(
            target=self.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True
        ).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def hook():
    h = Hook()
    yield h
    h.close()


def bridge(bus, poster, **kw):
    kw.setdefault("clock", Clock())
    b = sb.Bridge(bus, sb.load_bridge(BRIDGE), poster, **kw)
    b.open()
    return b


def webhook(h: Hook, **kw) -> sb.Webhook:
    cfg = sb.load_bridge(BRIDGE)
    return sb.Webhook(h.url, cfg.webhook, cfg.api_key, env=kw.pop("env", ENV), **kw)


def publish(bus, ev: dict, subject: str | None = None, msg_id: str | None = "same") -> None:
    data = ev if isinstance(ev, bytes) else canonical_body(ev)
    mid = (ev["id"] if isinstance(ev, dict) else None) if msg_id == "same" else msg_id
    bus.publish(subject or "homelabnext.proposal.created", data, msg_id=mid)


# ---------------------------------------------------------------- bridge.json
def test_the_committed_bridge_file_loads_and_pins_each_subjects_producers():
    cfg = sb.load_bridge(BRIDGE)
    assert cfg.api_key == "secret:stackstorm/webhook-key"
    by = {s.subject: s for s in cfg.subscriptions}
    assert by["homelabnext.proposal.created"].sources == {"svc:broker"}
    assert by["homelabnext.agent.job.failed"].sources == {"svc:orchestration"}


@pytest.mark.parametrize(
    "change",
    [
        {"api_key": "fake-literal-key"},
        {"webhook": "/elsewhere"},
        {"content_type": "application/cloudevents+json"},
        {"subscriptions": []},
    ],
)
def test_a_malformed_bridge_file_is_refused(change):
    doc = json.loads(BRIDGE.read_text()) | change
    with pytest.raises(sb.BridgeError):
        sb.load_bridge(doc)


def test_a_subscription_without_pinned_producers_is_refused():
    doc = json.loads(BRIDGE.read_text())
    doc["subscriptions"][0].pop("sources")
    with pytest.raises(sb.BridgeError, match="sources"):
        sb.load_bridge(doc)


# ---------------------------------------------------------------- the webhook client
def test_the_webhook_posts_json_with_the_key_by_name_and_the_event_id(hook):
    ev = proposal()
    assert webhook(hook).post(ev) == 202
    [req] = hook.requests
    assert req["path"] == "/api/v1/webhooks/homelabnext"
    assert req["headers"]["Content-Type"] == "application/json"
    assert req["headers"]["St2-Api-Key"] == KEY
    assert req["headers"]["Idempotency-Key"] == ev["id"]
    assert json.loads(req["body"]) == ev
    assert KEY not in repr(webhook(hook))


def test_the_webhook_follows_no_redirect(hook):
    hook.script = [302]
    assert webhook(hook).post(proposal()) == 302
    assert hook.redirect_hits == 0 and len(hook.requests) == 1  # the key went nowhere else


def test_the_webhook_refuses_plaintext_values_and_paths():
    cfg = sb.load_bridge(BRIDGE)
    with pytest.raises(sb.BridgeError, match="plaintext"):
        sb.Webhook("http://st2.example.invalid", cfg.webhook, cfg.api_key)
    sb.Webhook("http://st2.example.invalid", cfg.webhook, cfg.api_key, allow_plaintext=True)
    sb.Webhook("https://st2.example.invalid", cfg.webhook, cfg.api_key)
    with pytest.raises(sb.BridgeError, match="secret name"):
        sb.Webhook("https://st2.example.invalid", cfg.webhook, "fake-literal-key")
    with pytest.raises(sb.BridgeError, match="credentials"):
        sb.Webhook("https://u:fake@st2.example.invalid", cfg.webhook, cfg.api_key)
    with pytest.raises(sb.BridgeError, match="path"):
        sb.Webhook("https://st2.example.invalid/api", cfg.webhook, cfg.api_key)


def test_a_missing_key_sends_nothing(hook):
    with pytest.raises(sb.WebhookUnavailable, match="HNX_SECRET_STACKSTORM_WEBHOOK_KEY"):
        webhook(hook, env={}).post(proposal())
    assert hook.requests == []


# ---------------------------------------------------------------- forwarding
def test_a_valid_event_is_forwarded_once_and_acked(hook):
    bus = FakeEventBus()
    b = bridge(bus, webhook(hook))
    publish(bus, proposal(1))
    assert b.poll() == 1
    assert b.poll() == 0  # acked: nothing is redelivered
    assert [json.loads(r["body"])["id"] for r in hook.requests] == ["evt-bridge-1"]
    assert b.stats()["subjects"]["homelabnext.proposal.created"]["forwarded"] == 1
    assert b.stats()["state"] == "ok"


def test_a_failed_post_is_nacked_and_retried_after_a_backoff(hook):
    bus, clock = FakeEventBus(), Clock()
    b = bridge(bus, webhook(hook), clock=clock, backoff_base_s=2.0)
    hook.script = [503, 429]
    publish(bus, proposal(1))
    assert b.poll() == 1  # 503: nacked
    assert b.poll() == 0 and b.stats()["state"] == "warn"  # backing off: nothing is fetched
    clock.t = 2.0
    assert b.poll() == 1  # 429: nacked, the backoff doubles
    clock.t = 5.9
    assert b.poll() == 0
    clock.t = 6.0
    assert b.poll() == 1
    st = b.stats()["subjects"]["homelabnext.proposal.created"]
    assert (st["forwarded"], st["retried"], b.failures) == (1, 2, 0)
    ids = [r["headers"]["Idempotency-Key"] for r in hook.requests]
    assert ids == ["evt-bridge-1"] * 3  # the same id each time: admit drops a second run


def test_an_unreachable_webhook_retries_until_the_bus_dead_letters_it():
    class Down:
        def post(self, _ev):
            raise sb.WebhookUnavailable("ConnectionRefusedError")

    bus, clock = FakeEventBus(), Clock()
    b = bridge(bus, Down(), clock=clock, max_deliver=3)
    publish(bus, proposal(1))
    for _ in range(3):
        b.poll()
        clock.t += 120
    [cons] = [c for s, c in b._consumers if s.subject == "homelabnext.proposal.created"]
    assert [d.msg_id for d in cons.dead_letters()] == ["evt-bridge-1"]
    st = b.stats()
    assert st["subjects"]["homelabnext.proposal.created"]["dead_lettered"] == 1
    assert st["state"] == "fail"


@pytest.mark.parametrize(
    ("body", "subject", "reason"),
    [
        (b"not json {", None, "not-json"),
        (proposal(2, data={"note": "x"}), None, "invalid-event"),  # schema-invalid data
        (proposal(3, source="profile:triage"), None, "wrong-source"),  # not the pinned producer
        (proposal(4, source="svc:orchestration"), None, "wrong-source"),  # another subject's
        (
            json.loads((ROOT / "schemas/events/examples/agent.job.failed.valid.json").read_text()),
            "homelabnext.proposal.created",
            "wrong-type",
        ),
    ],
)
def test_poison_is_quarantined_counted_and_never_forwarded(hook, body, subject, reason):
    bus = FakeEventBus()
    b = bridge(bus, webhook(hook))
    publish(bus, body, subject, msg_id=None)
    assert b.poll() == 1
    assert b.poll() == 0  # never redelivered
    assert hook.requests == []
    subj = subject or "homelabnext.proposal.created"
    assert b.stats()["subjects"][subj]["quarantined"] == {reason: 1}
    [cons] = [c for s, c in b._consumers if s.subject == subj]
    assert len(cons.dead_letters()) == 1  # terminated: the DLQ is the quarantine


def test_a_msg_id_that_is_not_the_event_id_is_poison(hook):
    bus = FakeEventBus()
    b = bridge(bus, webhook(hook))
    publish(bus, proposal(5), msg_id="evt-something-else")
    b.poll()
    assert hook.requests == []
    q = b.stats()["subjects"]["homelabnext.proposal.created"]["quarantined"]
    assert q == {"id-mismatch": 1}


def test_stackstorm_refusing_the_body_is_poison_not_a_retry(hook):
    bus = FakeEventBus()
    b = bridge(bus, webhook(hook))
    hook.script = [400]
    publish(bus, proposal(6))
    b.poll()
    assert b.poll() == 0 and len(hook.requests) == 1
    q = b.stats()["subjects"]["homelabnext.proposal.created"]["quarantined"]
    assert q == {"rejected-400": 1} and b.failures == 0


def test_in_flight_posts_are_bounded():
    class Slow:
        def __init__(self):
            self.now = self.peak = 0
            self.lock = threading.Lock()

        def post(self, _ev):
            with self.lock:
                self.now += 1
                self.peak = max(self.peak, self.now)
            time.sleep(0.02)
            with self.lock:
                self.now -= 1
            return 202

    bus, slow = FakeEventBus(), Slow()
    b = bridge(bus, slow, max_in_flight=3)
    for i in range(10):
        publish(bus, proposal(i))
    handled = [b.poll() for _ in range(5)]
    assert handled == [3, 3, 3, 1, 0] and slow.peak == 3


def test_sigterm_stops_fetching_and_settles_what_is_in_flight(tmp_path, hook):
    bus = FakeEventBus()
    stop = threading.Event()
    stats = tmp_path / "bridge.json"

    class StopAfterTwo:
        def __init__(self, inner):
            self.inner, self.n = inner, 0

        def post(self, ev):
            self.n += 1
            if self.n == 2:
                stop.set()  # SIGTERM arrives while this POST is in flight
            return self.inner.post(ev)

    b = sb.Bridge(
        bus, sb.load_bridge(BRIDGE), StopAfterTwo(webhook(hook)), max_in_flight=1, stats_file=stats
    )
    b.open()
    for i in range(4):
        publish(bus, proposal(i))
    t = threading.Thread(target=b.run, args=(stop,), kwargs={"idle_s": 0.01})
    t.start()
    t.join(5)
    assert not t.is_alive()
    assert len(hook.requests) == 2  # stopped fetching; the in-flight POST was settled
    doc = json.loads(stats.read_text())
    assert doc["subjects"]["homelabnext.proposal.created"]["forwarded"] == 2
    b2 = bridge(bus, webhook(hook))  # a restart resumes the durable consumer
    while b2.poll():
        pass
    rest = sorted(r["headers"]["Idempotency-Key"] for r in hook.requests[2:])
    assert rest == ["evt-bridge-2", "evt-bridge-3"]  # posted concurrently: in any order


def test_the_bridge_over_the_jetstream_adapter(hook):
    """The subject the broker publishes (the event type) is the subject the bridge consumes."""
    bus = nj.make(
        wire=FakeJetStreamWire(), scratch=False, stream="HNX", subject_prefix="hnx", ack_wait=0.2
    )
    b = bridge(bus, webhook(hook))
    publish(bus, proposal(7))
    publish(bus, proposal(8, source="profile:triage"))
    assert b.poll() == 2
    assert [r["headers"]["Idempotency-Key"] for r in hook.requests] == ["evt-bridge-7"]
    assert b.poll() == 0
