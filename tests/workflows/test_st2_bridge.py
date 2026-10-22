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
from conformance.protocols.events import EventsError
from homelabnext.conform.adapters import nats_jetstream as nj
from homelabnext.events.envelope import canonical_body
from homelabnext.workflows import st2
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
    assert by["homelabnext.agent.job.failed"].sources == {st2.ORCHESTRATOR_SOURCE}


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


def test_the_webhook_never_goes_through_a_proxy(hook, monkeypatch):
    """The reviewer's proxy.py: urllib's default ProxyHandler sent the loopback plain-http POST,
    St2-Api-Key and all, to whatever HTTP_PROXY named.  The bridge uses no proxy."""

    hits: list[str] = []

    class Proxy(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            hits.append(self.headers.get("St2-Api-Key", ""))
            self.send_response(202)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *_a):
            pass

    proxy = http.server.ThreadingHTTPServer(("localhost", 0), Proxy)
    threading.Thread(
        target=proxy.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True
    ).start()
    try:
        url = f"http://localhost:{proxy.server_address[1]}"
        for var in ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy"):
            monkeypatch.setenv(var, url)
        for var in ("NO_PROXY", "no_proxy"):
            monkeypatch.delenv(var, raising=False)
        assert webhook(hook).post(proposal()) == 202
    finally:
        proxy.shutdown()
        proxy.server_close()
    assert hits == [] and len(hook.requests) == 1


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


def test_one_failing_subject_backs_off_alone():
    """A subject whose POSTs fail is paused on its own; every other subject keeps flowing."""
    failed = json.loads((ROOT / "schemas/events/examples/agent.job.failed.valid.json").read_text())
    failed["source"] = st2.ORCHESTRATOR_SOURCE

    class PickyHook:
        def __init__(self):
            self.ok: list[str] = []

        def post(self, ev):
            if ev["type"] == "homelabnext.proposal.created":
                return 503
            self.ok.append(ev["id"])
            return 202

    bus, clock, picky = FakeEventBus(), Clock(), PickyHook()
    b = bridge(bus, picky, clock=clock, backoff_base_s=30.0)
    publish(bus, proposal(1))
    publish(bus, failed | {"id": "evt-failed-1"}, "homelabnext.agent.job.failed")
    b.poll()
    publish(bus, failed | {"id": "evt-failed-2"}, "homelabnext.agent.job.failed")
    clock.t = 1.0  # the proposal subject is backing off; the other one is not
    b.poll()
    assert picky.ok == ["evt-failed-1", "evt-failed-2"]
    subjects = b.stats()["subjects"]
    assert subjects["homelabnext.proposal.created"]["consecutive_failures"] == 1
    assert subjects["homelabnext.agent.job.failed"]["consecutive_failures"] == 0
    assert b.pause_until == 30.0


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


def test_dead_letters_count_by_the_durables_limit_and_fail_clears_after_a_window():
    """An existing durable keeps the max_deliver it was created with: a dead letter is counted at
    that limit.  ``fail`` holds for the window after the latest one, then the state recovers (the
    counter keeps the history)."""

    class Switch:
        up = False

        def post(self, _ev):
            if not self.up:
                raise sb.WebhookUnavailable("ConnectionRefusedError")
            return 202

    bus, clock, hook = FakeEventBus(), Clock(), Switch()
    b = bridge(bus, hook, clock=clock, max_deliver=100, dead_letter_window_s=3600.0)
    [cons] = [c for s, c in b._consumers if s.subject == "homelabnext.proposal.created"]
    cons.max_deliver = 2  # what the server reports for a durable created with a lower limit
    publish(bus, proposal(1))
    for _ in range(2):
        b.poll()
        clock.t += 120
    assert [d.msg_id for d in cons.dead_letters()] == ["evt-bridge-1"]
    st = b.stats()
    assert st["subjects"]["homelabnext.proposal.created"]["dead_lettered"] == 1
    assert st["state"] == "fail" and st["dead_lettered"] == 1 and st["last_dead_letter"]
    hook.up = True
    clock.t += 3600
    publish(bus, proposal(2))
    assert b.poll() == 1
    st = b.stats()
    assert st["state"] == "ok" and st["dead_lettered"] == 1


def test_a_dead_letter_is_not_a_warning_forever():
    """The reviewer's r1: after a dead letter the subject's failure count never reset (its
    fetches came back empty), so state stayed warn long after fail had cleared."""

    class Down:
        def post(self, _ev):
            raise sb.WebhookUnavailable("ConnectionRefusedError")

    bus, clock = FakeEventBus(), Clock()
    b = bridge(bus, Down(), clock=clock, max_deliver=2, dead_letter_window_s=3600.0)
    publish(bus, proposal(1))
    for _ in range(4):
        b.poll()
        clock.t += 120
    assert b.stats()["state"] == "fail" and b.stats()["dead_lettered"] == 1
    clock.t += 10_000  # past the dead-letter window, nothing pending
    for _ in range(3):
        b.poll()
        clock.t += 120
    st = b.stats()
    assert (st["state"], st["consecutive_failures"], st["dead_lettered"]) == ("ok", 0, 1)


@pytest.mark.parametrize(
    ("body", "subject", "reason"),
    [
        (b"not json {", None, "not-json"),
        (proposal(2, data={"note": "x"}), None, "invalid-event"),  # schema-invalid data
        (proposal(3, source="profile:triage"), None, "wrong-source"),  # not the pinned producer
        (proposal(4, source=st2.ORCHESTRATOR_SOURCE), None, "wrong-source"),  # another subject's
        (
            json.loads((ROOT / "schemas/events/examples/agent.job.failed.valid.json").read_text()),
            "homelabnext.proposal.created",
            "wrong-type",
        ),
        (b"[" * 100_000, None, "not-json"),  # nested past the parser's stack
        (b'{"a":' * 20_000 + b"1" + b"}" * 20_000, None, "not-json"),
        (b'{"pad": "' + b"x" * (256 << 10) + b'"}', None, "too-large"),
    ],
    ids=lambda v: v if isinstance(v, str) else type(v).__name__,
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


def test_the_size_cap_is_the_one_the_poison_case_exceeds():
    assert sb.MAX_EVENT_BYTES == 256 << 10


def test_a_defect_in_a_check_or_the_bus_costs_one_delivery_not_the_bridge(hook):
    """Any exception while checking a delivery quarantines that delivery; a settlement the bus
    fails is logged and left to redelivery; the bridge keeps forwarding the rest."""
    bus = FakeEventBus()
    b = bridge(bus, webhook(hook))
    real = b.classify

    def flaky(sub, d):
        if d.msg_id == "evt-bridge-1":
            raise RuntimeError("a defect in a check")
        return real(sub, d)

    b.classify = flaky
    publish(bus, proposal(1))
    publish(bus, proposal(2))
    assert b.poll() == 2
    assert [r["headers"]["Idempotency-Key"] for r in hook.requests] == ["evt-bridge-2"]
    q = b.stats()["subjects"]["homelabnext.proposal.created"]["quarantined"]
    assert q == {"unprocessable": 1}

    class BrokenAck:
        def __init__(self, d):
            self.d, self.subject, self.data = d, d.subject, d.data
            self.msg_id, self.seq, self.attempt = d.msg_id, d.seq, d.attempt

        def ack(self):
            raise ConnectionError("the bus went away")

        def nack(self):
            self.d.nack()

        def term(self):
            self.d.term()

    [(sub, cons)] = [(s, c) for s, c in b._consumers if s.subject == "homelabnext.proposal.created"]

    class Wrapped:
        def fetch(self, n):
            return [BrokenAck(d) for d in cons.fetch(n)]

    b._consumers = [(sub, Wrapped())]
    publish(bus, proposal(3))
    assert b.poll() == 1  # posted, the ack failed: logged, not raised
    assert "ack failed" in b.stats()["last_error"]


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


def test_sigterm_fetches_no_further_subject_in_the_same_pass():
    """The reviewer's r3: a SIGTERM during one subject's POST still fetched (and posted) every
    later subject of that pass."""
    bus, stop, posted = FakeEventBus(), threading.Event(), []

    class StopOnFirst:
        def post(self, ev):
            posted.append(ev["type"])
            stop.set()
            return 202

    b = sb.Bridge(bus, sb.load_bridge(BRIDGE), StopOnFirst(), max_in_flight=1)
    b.open()
    job = json.loads((ROOT / "schemas/events/examples/agent.job.failed.valid.json").read_text())
    publish(bus, job, subject="homelabnext.agent.job.failed")
    publish(bus, proposal(1))
    b.run(stop, idle_s=0.01)
    assert posted == ["homelabnext.agent.job.failed"]


class Flaky:
    """A bus whose fetches fail (a transport error, or a permanent one) while ``down``."""

    def __init__(self, inner, *, permanent: bool = False):
        self.inner, self.down, self.permanent, self.closed = inner, False, permanent, 0

    def consumer(self, *a, **kw):
        cons = self.inner.consumer(*a, **kw)
        bus = self

        class C:
            max_deliver = getattr(cons, "max_deliver", 100)

            def fetch(self, n=1):
                if bus.down:
                    raise nj.WireError("connection closed", permanent=bus.permanent)
                return cons.fetch(n)

        return C()

    def close(self):
        self.closed += 1


def test_a_failed_fetch_backs_off_one_subject_and_never_ends_the_bridge(hook):
    """SEC4: a WireError from one fetch escaped poll() and run(), and the CLI exited.  Now that
    subject backs off and the others go on."""
    inner, clock = FakeEventBus(), Clock()
    bus = Flaky(inner, permanent=True)
    b = bridge(bus, webhook(hook), clock=clock, backoff_base_s=5.0)
    bus.down = True
    publish(inner, proposal(1))
    assert b.poll() == 0
    st = b.stats()
    assert st["state"] == "warn" and "fetch failed: WireError" in st["last_error"]
    assert all(v["consecutive_failures"] == 1 for v in st["subjects"].values())
    bus.down = False
    assert b.poll() == 0  # backing off
    clock.t = 5.0
    assert b.poll() == 1 and b.stats()["state"] == "ok"
    assert [r["headers"]["Idempotency-Key"] for r in hook.requests] == ["evt-bridge-1"]


def test_a_transport_failure_reconnects_and_reopens_the_durables(hook):
    inner, clock = FakeEventBus(), Clock()
    first, made = Flaky(inner), []

    def connect():
        if len(made) == 0:
            made.append("refused")
            raise nj.WireError("connection refused")
        made.append("ok")
        return Flaky(inner)

    b = bridge(first, webhook(hook), clock=clock, backoff_base_s=1.0, connect=connect)
    first.down = True
    publish(inner, proposal(1))
    assert b.poll() == 0 and first.closed == 0  # the first subject failed: no more this pass
    assert b.poll() == 0 and first.closed == 1 and made == ["refused"]  # dropped; refused
    assert b.stats()["state"] == "warn" and "reconnect failed" in b.stats()["last_error"]
    assert b.poll() == 0 and made == ["refused"]  # backing off the reconnect
    clock.t = 10.0
    assert b.poll() == 1 and made == ["refused", "ok"] and b.bus is not first
    assert [r["headers"]["Idempotency-Key"] for r in hook.requests] == ["evt-bridge-1"]
    assert b.stats()["state"] == "ok"


def provisioned(limits: bool = True) -> FakeJetStreamWire:
    """A server where the operator created the stream and its DLQ (docs/stackstorm.md)."""
    wire = FakeJetStreamWire()
    cap = {"max_bytes": 1 << 30, "max_age": 30 * 86400 * 10**9} if limits else {}
    adv = "$JS.EVENT.ADVISORY.CONSUMER"
    for name, subjects in (
        ("HNX", ["hnx.>"]),
        ("HNX_DLQ", [f"{adv}.MAX_DELIVERIES.HNX.*", f"{adv}.MSG_TERMINATED.HNX.*"]),
    ):
        body = {"name": name, "subjects": subjects, "retention": "limits", **cap}
        wire.request(f"$JS.API.STREAM.CREATE.{name}", json.dumps(body).encode(), timeout=1)
    return wire


def standing(wire: FakeJetStreamWire, ack_wait: float = sb.ACK_WAIT_S):
    return nj.make(
        wire=wire,
        scratch=False,
        provision=False,
        stream="HNX",
        subject_prefix="hnx",
        ack_wait=ack_wait,
    )


def test_the_bridge_creates_no_stream_and_refuses_an_unbounded_one():
    """It reads the stream and manages its durables, nothing else: a missing stream, or one a
    poison flood could grow without bound, is a configuration error, never created."""
    with pytest.raises(EventsError, match="does not exist"):
        standing(FakeJetStreamWire())
    with pytest.raises(EventsError, match="max_bytes"):
        standing(provisioned(limits=False))
    wire = provisioned()
    before = len(wire.log)
    standing(wire)
    assert not [s for s, _p, _h in wire.log[before:] if ".STREAM.CREATE." in s]


def test_the_lease_outlasts_a_post(hook):
    """A delivery leased for less than the POST timeout would be handed out again mid-POST."""
    hook = webhook(hook)
    assert hook.timeout + sb.LEASE_MARGIN_S <= sb.ACK_WAIT_S
    wire = provisioned()
    with pytest.raises(sb.BridgeError, match="ack_wait 3s"):
        bridge(standing(wire, ack_wait=3.0), hook)
    # the durable keeps the lease it was created with: a reopen with a longer one still refuses
    with pytest.raises(sb.BridgeError, match="nats consumer edit"):
        bridge(standing(wire), hook)
    bridge(standing(provisioned()), hook)


def test_reopening_several_durables_waits_out_one_lease_not_one_each():
    """A restarted bridge (a new bus) whose three durables each hold an unsettled delivery: their
    leases were all granted before the new bus existed, so it waits one lease in all."""
    wire, clock, slept = provisioned(), Clock(), []
    old = standing(wire)
    cfg = sb.load_bridge(BRIDGE)
    for s in cfg.subscriptions:
        cons = old.consumer(s.durable, s.subject, max_deliver=5)
        old.publish(s.subject, b"{}", msg_id=f"m-{s.durable}")
        assert len(cons.fetch(1)) == 1  # leased, never settled: the process died

    def sleep(t):
        slept.append(t)
        clock.t += t

    new = nj.JetStreamBus(
        wire, stream="HNX", subject_prefix="hnx", ack_wait=sb.ACK_WAIT_S, provision=False,
        clock=clock, sleep=sleep,
    )  # fmt: skip
    for s in cfg.subscriptions:
        new.consumer(s.durable, s.subject, max_deliver=5)
    assert len(cfg.subscriptions) == 3 and len(slept) == 1
    assert sb.ACK_WAIT_S < sum(slept) <= sb.ACK_WAIT_S + 1.0


class Wall:
    def __init__(self, t: float = 1_800_000_000.0):
        self.t = t

    def __call__(self) -> float:
        return self.t


def test_a_new_durable_forwards_what_was_published_before_it_existed(hook):
    """The reviewer's r4: durables were created deliver_policy new, so whatever the relay
    published before the bridge's first start (or after a durable was recreated) was skipped for
    good.  A durable the bridge creates now starts REPLAY_S back: no further, so a
    long-retention stream does not replay its history."""
    wall = Wall()
    wire = FakeJetStreamWire(wall=wall)
    for name, subjects in (
        ("HNX", ["hnx.>"]),
        ("HNX_DLQ", ["$JS.EVENT.ADVISORY.CONSUMER.MAX_DELIVERIES.HNX.*",
                     "$JS.EVENT.ADVISORY.CONSUMER.MSG_TERMINATED.HNX.*"]),
    ):  # fmt: skip
        body = {"name": name, "subjects": subjects, "retention": "limits", "max_bytes": 1 << 30}
        wire.request(f"$JS.API.STREAM.CREATE.{name}", json.dumps(body).encode(), timeout=1)
    bus = nj.JetStreamBus(
        wire, stream="HNX", subject_prefix="hnx", ack_wait=sb.ACK_WAIT_S, provision=False,
        replay_s=sb.REPLAY_S, wall=wall,
    )  # fmt: skip
    publish(bus, proposal(0))  # ancient: older than admit's memory
    wall.t += sb.REPLAY_S + 3600
    publish(bus, proposal(1))  # the relay published it before the bridge's first start
    wall.t += 60
    b = bridge(bus, webhook(hook))
    publish(bus, proposal(2))
    while b.poll():
        pass
    # one fetch is POSTed concurrently, so the two may land in either order
    got = sorted(r["headers"]["Idempotency-Key"] for r in hook.requests)
    assert got == ["evt-bridge-1", "evt-bridge-2"]


def test_the_bridge_creates_pull_durables_through_the_filtered_create_only():
    """SEC5: CONSUMER.CREATE.<stream>.<durable> takes any config, a push deliver_subject or
    another filter included.  The adapter creates pull durables only, through the 2.9+ form whose
    subject carries the filter, so the bus ACL can grant exactly that."""
    wire = provisioned()
    before = len(wire.log)
    bridge(standing(wire), lambda _ev: 202)
    creates = [(s, json.loads(p)) for s, p, _h in wire.log[before:] if ".CONSUMER.CREATE." in s]
    assert len(creates) == 3
    for subject, body in creates:
        cfg = body["config"]
        assert (
            subject == f"$JS.API.CONSUMER.CREATE.HNX.{cfg['durable_name']}.{cfg['filter_subject']}"
        )
        assert "deliver_subject" not in cfg and cfg["ack_policy"] == "explicit"
    with pytest.raises(EventsError, match="did not match filtered subject"):
        nj._api(
            wire,
            "CONSUMER.CREATE.HNX.x.hnx.homelabnext.other",
            {"stream_name": "HNX", "config": {"durable_name": "x", "filter_subject": "hnx.>"}},
            timeout=1,
        )


def test_the_bridge_over_the_jetstream_adapter(hook):
    """The subject the broker publishes (the event type) is the subject the bridge consumes."""
    bus = standing(provisioned())
    b = bridge(bus, webhook(hook))
    publish(bus, proposal(7))
    publish(bus, proposal(8, source="profile:triage"))
    assert b.poll() == 2
    assert [r["headers"]["Idempotency-Key"] for r in hook.requests] == ["evt-bridge-7"]
    assert b.poll() == 0


def test_the_bridge_command_passes_its_bus_credentials(monkeypatch):
    """On an authenticated bus the bridge connects as its own user, with the password by name."""
    from homelabnext.workflows import cli

    seen = {}

    def fake_make(**kw):
        seen.update(kw)
        raise EventsError("stop here")

    monkeypatch.setattr(nj, "make", fake_make)
    rc = cli.main(
        [
            "st2",
            "bridge",
            "--bridge-file",
            str(ROOT / "workflows" / "stackstorm" / "bridge.json"),
            "--st2-url",
            "https://st2.example.internal",
            "--stream",
            "HOMELABNEXT",
            "--subject-prefix",
            "lab",
            "--events-user",
            "hnx-st2-bridge",
            "--events-password-secret",
            "secret:events/st2-bridge-password",
            "--events-ca-file",
            "/etc/fake/nats-ca.pem",
        ]
    )
    assert rc == 2  # the fake connect refused, as a configuration error
    assert seen["user"] == "hnx-st2-bridge"
    assert seen["password_secret"] == "secret:events/st2-bridge-password"
    assert seen["ca_file"] == "/etc/fake/nats-ca.pem"
    assert seen["allow_plaintext"] is False
    assert seen["provision"] is False
    assert seen["replay_s"] == sb.REPLAY_S == 86400.0  # what admit remembers, no more
