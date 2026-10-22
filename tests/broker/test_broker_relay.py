# SPDX-License-Identifier: Apache-2.0
"""The broker's outbox relay (``hnx broker relay``, :mod:`homelabnext.broker.relay`).

Hermetic: the bus is the JetStream adapter over its in-process wire fake
(:class:`conformance.fakes.jetstream_wire.FakeJetStreamWire`), wrapped where a test needs the bus
to be down, to lose a PubAck, or the relay to crash between the publish and the mark.
"""

from __future__ import annotations

import json
import logging
import textwrap
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from conformance.fakes.jetstream_wire import FakeJetStreamWire
from homelabnext.broker import cli as broker_cli
from homelabnext.broker.relay import BROKER_SOURCE, OutboxRelay, RelayBusy
from homelabnext.broker.service import BrokerService
from homelabnext.broker.state import StateDir
from homelabnext.conform.adapters import nats_jetstream as nj
from homelabnext.conform.adapters._env import AdapterConfigError
from homelabnext.events.envelope import build_event

ROOT = Path(__file__).resolve().parents[2]
EXAMPLE = ROOT / "examples" / "broker" / "manifest.yml"
STREAM, PREFIX = "HNX", "hnx"
SECRET = "fake-nats-broker-password-7c1"  # scrub-allow: fake placeholder
MARKER = "fake-body-marker-should-never-be-logged"


class Clock:
    def __init__(self) -> None:
        self.t = 100.0

    def __call__(self) -> float:
        return self.t


class Wire:
    """The fake server behind a switch: ``down`` refuses everything, ``lose_acks`` stores a
    publish and then loses its PubAck.  Closing this wire never closes the server."""

    def __init__(self, server: FakeJetStreamWire) -> None:
        self.server, self.down, self.lose_acks = server, False, 0

    def request(self, subject, payload=b"", *, headers=None, timeout):
        if self.down:
            url = f"nats://{SECRET}@bus.invalid:4222"  # no-raw-endpoint: allow must not leak
            raise nj.WireError(f"connection refused to {url}")
        msg = self.server.request(subject, payload, headers=headers, timeout=timeout)
        if headers and "Nats-Msg-Id" in headers and self.lose_acks:
            self.lose_acks -= 1
            raise nj.WireError("no reply within 5.0s")
        return msg

    def pull(self, *a, **kw):
        return self.server.pull(*a, **kw)

    def close(self) -> None:
        pass


class Bus:
    """A connect() for the relay: a fresh adapter over the switchable wire, counted."""

    def __init__(self) -> None:
        self.server = FakeJetStreamWire()
        self.wire = Wire(self.server)
        self.connects = 0

    def __call__(self):
        self.connects += 1
        if self.wire.down:
            raise nj.WireError(f"cannot connect: nats://hnx-broker:{SECRET}@bus.invalid:4222")
        return nj.make(wire=self.wire, scratch=False, stream=STREAM, subject_prefix=PREFIX)

    def stored(self) -> list[tuple[str, dict, str]]:
        """(subject, event, Nats-Msg-Id) of every message in the stream, in sequence order."""
        st = self.server.streams.get(STREAM)
        if st is None:
            return []
        return [
            (m.subject, json.loads(m.data), m.headers.get("Nats-Msg-Id"))
            for _, m in sorted(st.msgs.items())
        ]


def event(i: int, etype: str = "homelabnext.decision.requested") -> dict:
    data = {
        "decision_id": f"req-{i:04d}",
        "spec": "broker-approval",
        "subject": f"requests/req-{i:04d}.json",
        "action": "service.restart",
        "actor": "profile:triage",
        "request_digest": "sha256:" + "0" * 64,
    }
    if etype == "homelabnext.decision.returned":
        data = {"decision_id": f"req-{i:04d}", "verdict": "accept", "confidence": 1.0,
                "tier_used": "human"}  # fmt: skip
    return build_event(etype, BROKER_SOURCE, data, dedupe_key=f"k{i}", subject=f"req-{i:04d}")


def emit(state: StateDir, n: int) -> list[str]:
    """``n`` events whose ids sort in the *opposite* order of emission."""
    evs = [event(i) for i in range(n)]
    evs.sort(key=lambda e: e["id"], reverse=True)
    for ev in evs:
        assert state.put_outbox(ev)
    return [e["id"] for e in evs]


def relay(state: StateDir, bus: Bus, clock: Clock | None = None, **kw) -> OutboxRelay:
    return OutboxRelay(state, bus, clock=clock or Clock(), **kw)


# ---------------------------------------------------------------- order and dedupe
def test_publishes_in_emit_order_with_the_event_id_as_msg_id(tmp_path):
    state, bus = StateDir(tmp_path / "state"), Bus()
    ids = emit(state, 5)
    assert [e["id"] for e in state.outbox()] == ids  # emit order, not file-name order
    assert relay(state, bus).drain() == 5
    stored = bus.stored()
    assert [ev["id"] for _, ev, _ in stored] == ids
    assert all(mid == ev["id"] for _, ev, mid in stored)
    assert {s for s, _, _ in stored} == {f"{PREFIX}.homelabnext.decision.requested"}
    assert all(ev["source"] == "svc:broker" for _, ev, _ in stored)
    assert state.outbox_pending() == [] and state.delivered(ids[0])["seq"] == 1
    assert relay(state, bus).drain() == 0 and len(bus.stored()) == 5  # delivered stays delivered


def test_bounded_batch(tmp_path):
    state, bus = StateDir(tmp_path / "state"), Bus()
    ids = emit(state, 5)
    r = relay(state, bus, batch=2)
    assert r.pass_once() == 2 and [ev["id"] for _, ev, _ in bus.stored()] == ids[:2]
    assert r.pass_once() == 2 and r.pass_once() == 1 and r.pass_once() == 0


def test_a_lost_puback_is_republished_and_deduplicated(tmp_path):
    state, bus, clock = StateDir(tmp_path / "state"), Bus(), Clock()
    ids = emit(state, 3)
    bus.wire.lose_acks = 1  # the server stores the first event, the PubAck never arrives
    r = relay(state, bus, clock)
    assert r.pass_once() == 0 and r.failures == 1
    assert [e["id"] for e in state.outbox_pending()] == ids  # nothing marked, order kept
    assert r.pass_once() == 0  # backing off
    clock.t += 1.0
    assert r.pass_once() == 3
    assert [ev["id"] for _, ev, _ in bus.stored()] == ids  # stored once each
    assert state.delivered(ids[0])["seq"] == 1


def test_crash_between_publish_and_mark_republishes_under_the_same_id(tmp_path, monkeypatch):
    state, bus = StateDir(tmp_path / "state"), Bus()
    ids = emit(state, 2)

    class Crash(BaseException):
        pass

    def crash(*_a, **_kw):
        raise Crash

    monkeypatch.setattr(state, "mark_delivered", crash)
    with pytest.raises(Crash):  # the process dies after the PubAck, before the marker
        relay(state, bus).pass_once()
    monkeypatch.undo()
    after = StateDir(tmp_path / "state")  # a restarted relay over the same directory
    assert [e["id"] for e in after.outbox_pending()] == ids
    assert relay(after, bus).drain() == 2
    assert [ev["id"] for _, ev, _ in bus.stored()] == ids  # the republish was a duplicate
    assert after.delivered(ids[0])["seq"] == 1 and after.outbox_pending() == []


def test_bus_down_then_up_keeps_order_and_backs_off(tmp_path):
    state, bus, clock = StateDir(tmp_path / "state"), Bus(), Clock()
    ids = emit(state, 3)
    bus.wire.down = True
    r = relay(state, bus, clock, backoff_base_s=1.0, backoff_max_s=4.0)
    waits = []
    for _ in range(4):
        assert r.pass_once() == 0
        waits.append(r.pause_until - clock.t)
        clock.t = r.pause_until
    assert waits == [1.0, 2.0, 4.0, 4.0] and bus.stored() == []
    bus.wire.down = False
    assert r.pass_once() == 3 and r.failures == 0
    assert [ev["id"] for _, ev, _ in bus.stored()] == ids


def test_a_failed_event_holds_back_the_ones_after_it(tmp_path):
    state, bus, clock = StateDir(tmp_path / "state"), Bus(), Clock()
    ids = emit(state, 3)
    r = relay(state, bus, clock)
    real = bus.wire.request
    calls = {"n": 0}

    def flaky(subject, payload=b"", *, headers=None, timeout):
        if headers and "Nats-Msg-Id" in headers:
            calls["n"] += 1
            if calls["n"] == 2:
                raise nj.WireError("connection reset")
        return real(subject, payload, headers=headers, timeout=timeout)

    bus.wire.request = flaky
    assert r.pass_once() == 1
    assert [ev["id"] for _, ev, _ in bus.stored()] == ids[:1]
    assert [e["id"] for e in state.outbox_pending()] == ids[1:]
    clock.t = r.pause_until
    assert r.pass_once() == 2 and [ev["id"] for _, ev, _ in bus.stored()] == ids


def test_nothing_secret_or_from_the_body_is_logged(tmp_path, caplog, monkeypatch):
    monkeypatch.setenv("HNX_SECRET_EVENTS_BROKER", SECRET)
    state, bus, clock = StateDir(tmp_path / "state"), Bus(), Clock()
    ev = event(1)
    ev["data"]["action"] = MARKER
    ev = build_event(ev["type"], ev["source"], ev["data"], dedupe_key="m", subject="req-0001")
    state.put_outbox(ev)
    stats = tmp_path / "relay-stats.json"
    r = relay(state, bus, clock, stats_file=stats)
    caplog.set_level(logging.DEBUG, logger="homelabnext.broker.relay")
    bus.wire.lose_acks = 1  # the publish fails with a message naming the endpoint
    r.pass_once()
    clock.t = r.pause_until
    bus.wire.down = True  # and the reconnect fails with one carrying the secret
    r.pass_once()
    clock.t = r.pause_until
    bus.wire.down = False
    assert r.pass_once() == 1
    r.close()
    text = caplog.text + stats.read_text()
    assert ev["id"] in caplog.text and "WireError" in text
    assert SECRET not in text and MARKER not in text and "bus.invalid" not in text
    doc = json.loads(stats.read_text())
    assert doc["pending"] == 0 and doc["published"] == 1 and doc["state"] == "ok"


def test_one_relay_per_state_directory(tmp_path):
    state = StateDir(tmp_path / "state")
    a, b = relay(state, Bus()), relay(StateDir(tmp_path / "state"), Bus())
    a.acquire()
    with pytest.raises(RelayBusy):
        b.acquire()
    a.close()
    b.acquire()
    b.close()


def test_an_outbox_file_from_before_the_order_field_is_still_relayed(tmp_path):
    state, bus = StateDir(tmp_path / "state"), Bus()
    old = event(9)
    (state.root / "outbox" / f"{old['id']}.json").write_text(json.dumps(old))
    assert state.outbox() == [old]
    assert relay(state, bus).drain() == 1 and bus.stored()[0][1] == old


# ---------------------------------------------------------------- the broker through to the bridge
def test_the_broker_decision_reaches_the_st2_bridge(tmp_path):
    """A gated request's approval is in the outbox; the relay publishes it; the StackStorm bridge
    (consuming before the relay runs) forwards it, source pin included."""
    from homelabnext.workflows import st2_bridge as sb
    from homelabnext.workflows.st2_runtime import BROKER_SOURCE as A03_SOURCE

    assert BROKER_SOURCE == A03_SOURCE
    t = datetime(2026, 1, 15, 10, 0, tzinfo=UTC)
    svc = BrokerService.from_manifest(
        EXAMPLE,
        tmp_path / "state",
        data_root=tmp_path / "data",
        clock=lambda: t,
        resolve_secret={"DEMO_API_TOKEN": "fake-demo-token-4b1d"}.__getitem__,
    )
    assert svc.source == BROKER_SOURCE
    bus = Bus()
    config = sb.load_bridge(ROOT / "workflows" / "stackstorm" / "bridge.json")
    sub = next(s for s in config.subscriptions if s.subject == "homelabnext.decision.returned")
    assert BROKER_SOURCE in sub.sources

    class Poster:
        def __init__(self):
            self.events = []

        def post(self, ev):
            self.events.append(ev)
            return 202

    poster = Poster()
    bridge = sb.Bridge(bus(), config, poster)
    bridge.open()
    rid = svc.submit("profile:triage", "service.restart", {"grace_s": 30}, target="svc:queue")
    t += timedelta(seconds=30)
    svc.approve(rid, "sso:operator-one")
    assert relay(svc.state, bus).drain() == 2
    assert [ev["type"] for _, ev, _ in bus.stored()] == [
        "homelabnext.decision.requested",
        "homelabnext.decision.returned",
    ]
    while bridge.poll():
        pass
    [fwd] = poster.events
    assert fwd["type"] == "homelabnext.decision.returned" and fwd["subject"] == rid
    assert fwd["data"]["verdict"] == "accept" and fwd["source"] == BROKER_SOURCE


# ---------------------------------------------------------------- the CLI and the adapter's credential
def test_relay_cli_once(tmp_path, monkeypatch, capsys):
    shared = FakeJetStreamWire()
    mod = tmp_path / "mods" / "relay_fake_bus.py"
    mod.parent.mkdir()
    mod.write_text(
        textwrap.dedent(
            """
            from homelabnext.conform.adapters import nats_jetstream as nj

            WIRE = None
            DOWN = False

            def make(**config):
                if DOWN:
                    raise nj.WireError("cannot connect")
                return nj.make(wire=WIRE, **config)
            """
        )
    )
    monkeypatch.syspath_prepend(str(mod.parent))
    import relay_fake_bus

    relay_fake_bus.WIRE = Wire(shared)
    target = tmp_path / "events-target.yml"
    target.write_text(
        "name: relay-test\ncapabilities:\n  events:\n    adapter: relay_fake_bus:make\n"
        "    config: {duplicate_window: 60.0}\n"
    )
    state = StateDir(tmp_path / "state")
    ids = emit(state, 2)
    argv = ["relay", "--state", str(state.root), "--events-target", str(target),
            "--stream", STREAM, "--subject-prefix", PREFIX, "--once"]  # fmt: skip
    relay_fake_bus.DOWN = True
    assert broker_cli.main(argv) == 1
    assert "published 0, 2 pending" in capsys.readouterr().out
    relay_fake_bus.DOWN = False
    assert broker_cli.main(argv) == 0
    assert "published 2, 0 pending" in capsys.readouterr().out
    stored = shared.streams[STREAM]
    assert [json.loads(m.data)["id"] for _, m in sorted(stored.msgs.items())] == ids
    assert stored.config["duplicate_window"] == 60 * 10**9
    held = OutboxRelay(state, relay_fake_bus.make)
    held.acquire()
    try:
        assert broker_cli.main(argv) == 2
        assert "another relay" in capsys.readouterr().err
    finally:
        held.close()


def test_the_adapter_takes_a_password_by_secret_name_only(monkeypatch):
    seen = {}

    def fake_wire(url, **kw):
        seen.update(kw, url=url)
        return FakeJetStreamWire()

    monkeypatch.setattr(nj, "NatsPyWire", fake_wire)
    endpoint = "nats://192.0.2.10:4222"  # no-raw-endpoint: allow a documentation-range bus
    monkeypatch.setenv("HNX_ENDPOINT_EVENTS", endpoint)
    kw = {"scratch": False, "stream": STREAM, "subject_prefix": PREFIX}
    monkeypatch.delenv("HNX_SECRET_EVENTS_BROKER", raising=False)
    with pytest.raises(AdapterConfigError, match="HNX_SECRET_EVENTS_BROKER"):
        nj.make(user="hnx-broker", password_secret="secret:events/broker", **kw)
    with pytest.raises(nj.EventsError, match="secret name"):
        nj.make(user="hnx-broker", password_secret=SECRET, **kw)
    with pytest.raises(nj.EventsError, match="password_secret"):
        nj.make(user="hnx-broker", **kw)
    monkeypatch.setenv("HNX_SECRET_EVENTS_BROKER", SECRET)
    bus = nj.make(user="hnx-broker", password_secret="secret:events/broker", **kw)
    assert seen["user"] == "hnx-broker" and seen["password"]() == SECRET
    assert SECRET not in repr(bus) and SECRET not in repr(seen["url"])
