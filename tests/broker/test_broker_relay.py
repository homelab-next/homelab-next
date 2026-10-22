# SPDX-License-Identifier: Apache-2.0
"""The broker's outbox relay (``hnx broker relay``, :mod:`homelabnext.broker.relay`).

Hermetic: the bus is the JetStream adapter over its in-process wire fake
(:class:`conformance.fakes.jetstream_wire.FakeJetStreamWire`), wrapped where a test needs the bus
to be down, to lose a PubAck, or the relay to crash between the publish and the mark.
"""

from __future__ import annotations

import contextlib
import json
import logging
import textwrap
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from conformance.fakes.jetstream_wire import FakeJetStreamWire
from homelabnext.broker import cli as broker_cli
from homelabnext.broker.relay import (
    BROKER_SOURCE,
    OutboxRelay,
    RelayBusy,
    RelayFirstStart,
    RelayStore,
)
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


def pending(state: StateDir) -> list[dict]:
    """What the relay still has to publish, in order."""
    return [ev for _, ev in RelayStore(state.root).entries()]


def delivered(state: StateDir, event_id: str) -> dict | None:
    return RelayStore(state.root).get("delivered", f"{event_id}.json")


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
    assert pending(state) == [] and delivered(state, ids[0])["seq"] == 1
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
    assert [e["id"] for e in pending(state)] == ids  # nothing marked, order kept
    assert r.pass_once() == 0  # backing off
    clock.t += 1.0
    assert r.pass_once() == 3
    assert [ev["id"] for _, ev, _ in bus.stored()] == ids  # stored once each
    assert delivered(state, ids[0])["seq"] == 1


def test_crash_between_publish_and_mark_republishes_under_the_same_id(tmp_path, monkeypatch):
    state, bus = StateDir(tmp_path / "state"), Bus()
    ids = emit(state, 2)

    class Crash(BaseException):
        pass

    def crash(*_a, **_kw):
        raise Crash

    monkeypatch.setattr(RelayStore, "mark", crash)
    with pytest.raises(Crash):  # the process dies after the PubAck, before the marker
        relay(state, bus).pass_once()
    monkeypatch.undo()
    after = StateDir(tmp_path / "state")  # a restarted relay over the same directory
    assert [e["id"] for e in pending(after)] == ids
    assert relay(after, bus).drain() == 2
    assert [ev["id"] for _, ev, _ in bus.stored()] == ids  # the republish was a duplicate
    assert delivered(after, ids[0])["seq"] == 1 and pending(after) == []


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
    assert [e["id"] for e in pending(state)] == ids[1:]
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
    r = relay(state, bus, since="1970-01-01T00:00:00Z")  # the first start: publish them all
    assert r.drain() == 1 and bus.stored()[0][1] == old


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
    # the bridge consumes with its own lease, as it does in production (sb.ACK_WAIT_S)
    bridge_bus = nj.make(
        wire=bus.wire, scratch=False, stream=STREAM, subject_prefix=PREFIX, ack_wait=sb.ACK_WAIT_S
    )
    bridge = sb.Bridge(bridge_bus, config, poster)
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
def provision(server: FakeJetStreamWire, *, max_bytes: int = 1 << 30) -> None:
    """What the operator does once: the standing stream and its DLQ, each with limits
    (``max_bytes=0``: created by a client that provisions, without any)."""
    if max_bytes:
        made = nj.provision_streams(
            Wire(server), stream=STREAM, subject_prefix=PREFIX, max_bytes=max_bytes
        )
        assert made == [STREAM, f"{STREAM}_DLQ"]
        assert server.streams[f"{STREAM}_DLQ"].config["max_bytes"] == max_bytes // 4
    else:
        nj.make(wire=Wire(server), scratch=False, stream=STREAM, subject_prefix=PREFIX).close()


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
    # the relay never creates the stream: missing (or unbounded) is a failed connect, not a create
    assert broker_cli.main(argv) == 1 and STREAM not in shared.streams
    provision(shared, max_bytes=0)
    assert broker_cli.main(argv) == 1
    capsys.readouterr()
    shared.streams.clear()
    provision(shared)
    assert broker_cli.main(argv) == 0
    assert "published 2, 0 pending" in capsys.readouterr().out
    stored = shared.streams[STREAM]
    assert [json.loads(m.data)["id"] for _, m in sorted(stored.msgs.items())] == ids
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
    endpoint = "tls://192.0.2.10:4222"  # no-raw-endpoint: allow a documentation-range bus
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


def _recording_wire(monkeypatch) -> list[dict]:
    made: list[dict] = []

    def fake_wire(url, **kw):
        made.append({**kw, "url": url})
        return FakeJetStreamWire()

    monkeypatch.setattr(nj, "NatsPyWire", fake_wire)
    monkeypatch.setenv("HNX_SECRET_EVENTS_BROKER", SECRET)
    return made


@pytest.mark.parametrize(
    "endpoint",
    [
        "nats://203.0.113.9:4222",  # no-raw-endpoint: allow a documentation-range host
        "nats://events.lab.example:4222",  # no-raw-endpoint: allow a documentation host
    ],
)
def test_a_password_never_goes_over_plaintext_nats_to_another_host(monkeypatch, endpoint):
    """The reviewer's exp3: make() handed user + password to nats.connect for a plain nats://
    endpoint on another host.  Now it refuses before any connection is made."""
    made = _recording_wire(monkeypatch)
    monkeypatch.setenv("HNX_ENDPOINT_EVENTS", endpoint)
    kw = {"scratch": False, "stream": STREAM, "subject_prefix": PREFIX}
    with pytest.raises(nj.EventsError, match="plaintext nats") as err:
        nj.make(user="hnx-broker", password_secret="secret:events/broker", **kw)
    assert made == [] and SECRET not in str(err.value)
    # explicitly allowed (the lab), and without credentials, it connects
    nj.make(user="hnx-broker", password_secret="secret:events/broker", allow_plaintext=True, **kw)
    nj.make(**kw)
    assert [m["url"] for m in made] == [endpoint, endpoint]


@pytest.mark.parametrize(
    "endpoint",
    # no-raw-endpoint: allow the loopback and TLS cases of the plaintext rule under test
    ["nats://127.0.0.1:4222", "tls://203.0.113.9:4222"],  # no-raw-endpoint: allow the rule's cases
)
def test_tls_or_loopback_carries_the_password(monkeypatch, endpoint, tmp_path):
    made = _recording_wire(monkeypatch)
    monkeypatch.setenv("HNX_ENDPOINT_EVENTS", endpoint)
    ca = str(tmp_path / "ca.pem") if endpoint.startswith("tls") else None
    nj.make(
        user="hnx-broker",
        password_secret="secret:events/broker",
        ca_file=ca,
        scratch=False,
        stream=STREAM,
        subject_prefix=PREFIX,
    )
    assert made[0]["url"] == endpoint and made[0]["ca_file"] == ca
    assert made[0]["password"]() == SECRET


def test_a_ca_file_needs_a_tls_endpoint():
    loopback = "nats://127.0.0.1:4222"  # no-raw-endpoint: allow the refusal under test
    with pytest.raises(nj.EventsError, match="tls://"):
        nj.NatsPyWire(loopback, ca_file="/nonexistent/ca.pem")


def _fake_nats(monkeypatch, *, handshake_first: bool = True) -> dict:
    """A stand-in for nats-py (the CI test job does not install the extra): records what
    NatsPyWire hands ``nats.connect``.  ``handshake_first``: the installed client knows
    ``tls_handshake_first`` (2.7 and later)."""
    import sys
    import types

    seen: dict = {}

    async def connect(url, **kw):
        seen.update(kw, url=url)
        return types.SimpleNamespace(is_closed=True)

    class Client:
        if handshake_first:

            async def connect(self, servers="", tls=None, tls_handshake_first=False): ...
        else:

            async def connect(self, servers="", tls=None): ...

    errors = types.ModuleType("nats.errors")
    for name in ("Error", "NoRespondersError", "MaxPayloadError", "TimeoutError"):
        setattr(errors, name, type(name, (Exception,), {}))
    mods = {
        "nats": types.ModuleType("nats"),
        "nats.errors": errors,
        "nats.aio": types.ModuleType("nats.aio"),
        "nats.aio.client": types.ModuleType("nats.aio.client"),
    }
    mods["nats"].connect, mods["nats"].errors = connect, errors
    mods["nats.aio.client"].Client = Client
    for name, mod in mods.items():
        monkeypatch.setitem(sys.modules, name, mod)
    return seen


def test_a_tls_endpoint_does_the_handshake_before_anything_else(monkeypatch):
    """The reviewer's tls_downgrade: for tls:// nats-py upgraded only when the server's INFO
    said tls_required, so a server (or a man in the middle) that did not ask got the CONNECT,
    password included, in clear.  tls:// now always handshakes first."""
    import ssl

    seen = _fake_nats(monkeypatch)
    endpoint = "tls://192.0.2.10:4222"  # no-raw-endpoint: allow a documentation-range bus
    w = nj.NatsPyWire(endpoint, user="hnx-broker", password=lambda: SECRET)
    w.close()
    assert seen["url"] == endpoint and seen["tls_handshake_first"] is True
    assert isinstance(seen["tls"], ssl.SSLContext) and seen["tls"].verify_mode == ssl.CERT_REQUIRED
    seen.clear()
    loopback = "nats://127.0.0.1:4222"  # no-raw-endpoint: allow a loopback bus, never dialled
    nj.NatsPyWire(loopback, user="hnx-broker", password=lambda: SECRET).close()
    assert "tls_handshake_first" not in seen and "tls" not in seen


def test_a_nats_py_without_handshake_first_refuses_a_tls_endpoint(monkeypatch):
    seen = _fake_nats(monkeypatch, handshake_first=False)
    endpoint = "tls://192.0.2.10:4222"  # no-raw-endpoint: allow a documentation-range bus
    with pytest.raises(nj.EventsError, match="handshake first"):
        nj.NatsPyWire(endpoint, user="hnx-broker", password=lambda: SECRET)
    assert seen == {}  # nothing was dialled


def test_a_server_that_never_asks_for_tls_never_sees_the_connect():
    """End to end with the real nats-py: a fake server answers a tls:// client in plaintext
    and never says tls_required.  The client fails the handshake; no CONNECT, no password."""
    pytest.importorskip("nats")
    import socket
    import threading

    srv = socket.socket()
    srv.bind(("localhost", 0))
    srv.listen(4)
    srv.settimeout(0.05)
    got: list[bytes] = []
    done = threading.Event()

    def serve():
        while not done.is_set():
            try:
                conn, _ = srv.accept()
            except TimeoutError:
                continue
            data = b""
            with conn, contextlib.suppress(OSError):
                conn.sendall(
                    b'INFO {"server_id":"fake","version":"2.10.22","auth_required":true,'
                    b'"max_payload":1048576,"headers":true,"proto":1}\r\n'
                )
                conn.settimeout(2)
                while chunk := conn.recv(4096):
                    data += chunk
            got.append(data)

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    endpoint = f"tls://localhost:{srv.getsockname()[1]}"
    try:
        with pytest.raises(nj.WireError):
            nj.NatsPyWire(endpoint, user="hnx-broker", password=lambda: SECRET, connect_timeout=1)
    finally:
        done.set()
        t.join(10)
        srv.close()
    assert got, "the client never connected"
    sent = b"".join(got)
    assert b"CONNECT" not in sent and SECRET.encode() not in sent
    assert sent[:1] == b"\x16"  # a TLS handshake record (ClientHello), before anything else


# ---------------------------------------------------------------- poison, malformed files, --skip
class Refuse:
    """A bus wrapper refusing, for good, the publishes whose msg id is in ``ids`` (``None``:
    every publish), the way NatsPyWire reports a permission violation or max_payload."""

    def __init__(self, bus: Bus, ids: set[str] | None) -> None:
        self.bus, self.ids, self.tries = bus, ids, 0
        real = bus.wire.request

        def request(subject, payload=b"", *, headers=None, timeout):
            mid = (headers or {}).get("Nats-Msg-Id")
            if mid and (self.ids is None or mid in self.ids):
                self.tries += 1
                raise nj.WireError("permission denied: publish", permanent=True)
            return real(subject, payload, headers=headers, timeout=timeout)

        bus.wire.request = request


def run_until_idle(r: OutboxRelay, clock: Clock, passes: int = 50) -> None:
    for _ in range(passes):
        r.pass_once()
        clock.t = max(clock.t, r.pause_until)


def test_a_poison_event_becomes_undeliverable_and_the_rest_go_on(tmp_path):
    """The reviewer's exp1 A: an event the bus refuses for good stalled the relay forever."""
    state, bus, clock = StateDir(tmp_path / "state"), Bus(), Clock()
    ids = emit(state, 4)
    refuse = Refuse(bus, {ids[1]})
    r = relay(state, bus, clock, max_attempts=3, stats_file=tmp_path / "stats.json")
    assert r.pass_once() == 1 and r.failures == 1  # retried first, with backoff
    run_until_idle(r, clock)
    assert [ev["id"] for _, ev, _ in bus.stored()] == [ids[0], ids[2], ids[3]]
    assert refuse.tries == 3 and pending(state) == []
    mark = RelayStore(state.root).get("undeliverable", f"{ids[1]}.json")
    assert mark["status"] == "undeliverable" and mark["attempts"] == 3
    assert mark["reason"] == "WireError" and mark["event"]["id"] == ids[1]
    doc = json.loads((tmp_path / "stats.json").read_text())
    assert doc["state"] == "fail" and doc["undeliverable"] == 1 and doc["pending"] == 0


def test_an_invalid_subject_is_permanent_too():
    bus = Bus()()
    with pytest.raises(nj.PublishRefused) as err:
        bus.publish("homelabnext.bad subject", b"{}", msg_id="x")
    assert err.value.permanent


def test_an_outage_never_makes_an_event_undeliverable(tmp_path):
    state, bus, clock = StateDir(tmp_path / "state"), Bus(), Clock()
    ids = emit(state, 2)
    bus.wire.lose_acks = 10**6  # no PubAck, ever: transport, not the event
    r = relay(state, bus, clock, max_attempts=1)
    run_until_idle(r, clock, 20)
    assert RelayStore(state.root).count("undeliverable") == 0
    assert [e["id"] for e in pending(state)] == ids


def test_a_bus_refusing_everything_holds_instead_of_draining(tmp_path):
    state, bus, clock = StateDir(tmp_path / "state"), Bus(), Clock()
    emit(state, 6)
    Refuse(bus, None)
    r = relay(state, bus, clock, max_attempts=1, max_undeliverable_run=2)
    run_until_idle(r, clock)
    assert r.undeliverable == 2 and r.holding and len(pending(state)) == 4
    assert r.stats()["state"] == "fail" and r.stats()["holding"] is True


@pytest.mark.parametrize(
    "content,reason",
    [
        ('{"queued": ["x", 1, 2], "event": {"id": "NAME", "type": "t"}}', "bad-queued"),
        ('{"queued": [1], "event": {"id": "NAME", "type": "t"}}', "bad-queued"),
        ('{"queued": 7, "event": {"id": "NAME"}}', "no-type"),
        ('{"queued": 7, "event": {"id": "other", "type": "t"}}', "bad-id"),
        ("{trunc", "not-json"),
        ("[1, 2]", "not-an-object"),
        ('{"type": "homelabnext.decision.requested"}', "bad-id"),  # old format, no id
    ],
)
def test_a_malformed_outbox_file_is_quarantined_not_fatal(tmp_path, content, reason):
    """The reviewer's exp1 B/C/E: such a file raised out of every pass, forever."""
    state, bus, clock = StateDir(tmp_path / "state"), Bus(), Clock()
    ids = emit(state, 2)
    name = "bad-file"
    (state.root / "outbox" / f"{name}.json").write_text(content.replace("NAME", name))
    r = relay(state, bus, clock)
    assert r.drain() == 2 and [ev["id"] for _, ev, _ in bus.stored()] == ids
    record = RelayStore(state.root).get("quarantine", f"{name}.json")
    assert record["reason"] == reason and record["file"] == f"{name}.json"
    assert r.stats()["quarantined"] == 1 and r.stats()["state"] == "fail"
    assert state.prune_outbox(force=True) == 3  # the broker removes all three, bad one included
    assert state.outbox() == [] and r.pending() == 0


def test_skip_is_the_operators_escape(tmp_path, capsys):
    state, bus, clock = StateDir(tmp_path / "state"), Bus(), Clock()
    ids = emit(state, 3)
    assert broker_cli.main(["relay", "--state", str(state.root), "--skip", ids[0]]) == 0
    assert "skipped" in capsys.readouterr().out
    assert broker_cli.main(["relay", "--state", str(state.root), "--skip", "nope"]) == 2
    assert relay(state, bus, clock).drain() == 2
    assert [ev["id"] for _, ev, _ in bus.stored()] == ids[1:]
    mark = RelayStore(state.root).get("undeliverable", f"{ids[0]}.json")
    assert mark["status"] == "skipped"


def test_the_adapter_marks_a_permission_violation_permanent():
    """NatsPyWire: the server drops a denied publish and says so out of band (error_cb); the
    request then times out, and that timeout is reported as permanent for that subject."""
    w = object.__new__(nj.NatsPyWire)
    w._denied = set()

    def run(coro, timeout):
        coro.close()
        w._denied.add("hnx.homelabnext.decision.returned")  # error_cb, meanwhile
        raise nj.WireError("no reply within 6.0s")

    w._run = run
    with pytest.raises(nj.WireError) as err:
        w.request("hnx.homelabnext.decision.returned", b"{}", timeout=5.0)
    assert err.value.permanent
    w._denied = set()
    w._run = lambda coro, t: (coro.close(), (_ for _ in ()).throw(nj.WireError("no reply")))
    with pytest.raises(nj.WireError) as err:
        w.request("hnx.other", b"{}", timeout=5.0)
    assert not err.value.permanent
    m = nj._PERMISSION_DENIED.search('nats: Permissions Violation for Publish to "a.b.c"')
    assert m and m.group(1) == "a.b.c"


# ---------------------------------------------------------------- the first start and growth
def test_the_first_start_supersedes_history_before_since(tmp_path, capsys):
    """Upgrading a broker whose outbox holds files from before the relay: they were never meant
    for a bus, so the first start publishes nothing older than --since (and needs it)."""
    state, bus = StateDir(tmp_path / "state"), Bus()
    olds = []
    for i, when in enumerate(("2026-01-01T00:00:00Z", "2026-03-01T00:00:00Z")):
        old = event(10 + i)
        old["time"] = when
        (state.root / "outbox" / f"{old['id']}.json").write_text(json.dumps(old))
        olds.append(old)
    [new] = emit(state, 1)
    with pytest.raises(RelayFirstStart, match="--since"):
        relay(state, bus).acquire()
    r = relay(state, bus, since="2026-02-01T00:00:00Z")
    r.acquire()
    assert r.drain() == 2
    assert [ev["id"] for _, ev, _ in bus.stored()] == [olds[1]["id"], new]
    assert delivered(state, olds[0]["id"])["status"] == "superseded"
    r.close()
    # initialized: a later start needs no --since
    old = event(20)
    (state.root / "outbox" / f"{old['id']}.json").write_text(json.dumps(old))
    assert relay(state, bus).drain() == 1


def test_an_idle_pass_reads_only_what_is_pending(tmp_path, monkeypatch):
    """Delivered events leave the outbox (the broker prunes them; the relay keeps the copy), so
    a pass costs O(pending), and delivered markers past retention go once pruned."""
    import homelabnext.broker.relay as relay_mod

    state, bus, clock = StateDir(tmp_path / "state"), Bus(), Clock()
    emit(state, 30)
    r = relay(state, bus, clock, retain_s=100.0, wall=lambda: 10**10)
    assert r.drain() == 30
    assert len(list((state.root / "outbox").glob("*.json"))) == 30  # until the broker prunes
    assert state.prune_outbox(force=True) == 30 and state.outbox() == []
    reads = []
    real = relay_mod.read_outbox_file
    monkeypatch.setattr(relay_mod, "read_outbox_file", lambda p: reads.append(p) or real(p))
    fresh = event(99)["id"]
    state.put_outbox(event(99))
    assert r.pass_once() == 1 and len(reads) == 1
    assert r.pass_once() == 0 and len(reads) == 1  # idle: nothing parsed
    store = RelayStore(state.root)
    assert store.count("delivered") == 31
    # retention: old markers go once their outbox file is gone, the fresh one's file is still there
    assert store.sweep(retain_s=100.0, now=10**10) == 30
    assert store.get("delivered", f"{fresh}.json") is not None


# ---------------------------------------------------------------- the relay's own user
def _forge(state: StateDir, ev: dict, queued: int) -> None:
    """A file someone other than the broker put into outbox/ (bypassing put_outbox)."""
    doc = {"queued": queued, "event": ev}
    (state.root / "outbox" / f"{ev['id']}.json").write_text(json.dumps(doc))


def test_the_relay_publishes_only_the_brokers_valid_events(tmp_path):
    """Whoever can drop a file into outbox/ must not get it published under the broker's bus
    user: the envelope and type schema must hold, the source must be the broker's and the type
    one the broker emits; anything else is quarantined and later events go on."""
    state, bus = StateDir(tmp_path / "state"), Bus()
    [first] = emit(state, 1)
    foreign = build_event("homelabnext.decision.returned", "svc:someone-else",
                          {"decision_id": "req-0009", "verdict": "accept", "confidence": 1.0,
                           "tier_used": "human"}, dedupe_key="f", subject="req-0009")  # fmt: skip
    broken = event(8, "homelabnext.decision.returned")
    broken["data"] = {"verdict": "maybe"}  # fails the type's schema
    example = ROOT / "schemas" / "events" / "examples" / "agent.job.failed.valid.json"
    other_type = {**json.loads(example.read_text()), "source": BROKER_SOURCE}
    other_type["id"] = "evt-other-type"
    for n, ev in enumerate((foreign, broken, other_type), start=100):
        _forge(state, ev, n)
    last = event(7, "homelabnext.decision.returned")
    state.put_outbox(last)
    assert relay(state, bus).drain() == 2
    assert [ev["id"] for _, ev, _ in bus.stored()] == [first, last["id"]]
    store = RelayStore(state.root)
    reasons = {e["id"]: store.get("quarantine", f"{e['id']}.json")["reason"]
               for e in (foreign, broken, other_type)}  # fmt: skip
    assert reasons == {foreign["id"]: "not-the-broker", broken["id"]: "invalid-event",
                       other_type["id"]: "not-a-broker-type"}  # fmt: skip


def test_the_relay_only_reads_the_outbox_and_needs_nothing_else(tmp_path, monkeypatch):
    """The relay runs as its own user that may read outbox/ and write relay/ only: a full pass
    changes nothing outside relay/ and opens nothing of the broker's other state."""
    state, bus = StateDir(tmp_path / "state"), Bus()
    emit(state, 3)
    root = state.root

    def snapshot():
        return {
            str(p.relative_to(root)): (p.stat().st_mtime_ns, p.stat().st_mode)
            for p in root.rglob("*")
            if not str(p.relative_to(root)).startswith("relay")
        }

    before = snapshot()
    opened = []
    real_open = Path.open

    def spy(self, *a, **kw):
        opened.append(self)
        return real_open(self, *a, **kw)

    monkeypatch.setattr(Path, "open", spy)
    r = OutboxRelay(root, bus)  # a path: no StateDir (which would read audit/ and more)
    assert r.drain() == 3
    r.close()
    assert snapshot() == before
    outside = [p for p in opened if p.parent.name != "outbox" and "relay" not in p.parts]
    assert outside == []


def test_a_user_gets_its_own_inbox_prefix(monkeypatch):
    """Replies arrive on _INBOX.<user>, so the server can grant each user its own inbox instead of
    _INBOX.> (where any client reads every other client's replies)."""
    made = _recording_wire(monkeypatch)
    loopback = "nats://127.0.0.1:4222"  # no-raw-endpoint: allow a loopback bus, never dialled
    monkeypatch.setenv("HNX_ENDPOINT_EVENTS", loopback)
    kw = {"scratch": False, "stream": STREAM, "subject_prefix": PREFIX}
    nj.make(user="hnx-broker", password_secret="secret:events/broker", **kw)
    nj.make(user="hnx-broker", password_secret="secret:events/broker", inbox_prefix="_I.b", **kw)
    assert [m["inbox_prefix"] for m in made] == ["_INBOX.hnx-broker", "_I.b"]
    with pytest.raises(nj.EventsError, match="user name"):
        nj.make(user="a.b", password_secret="secret:events/broker", **kw)
