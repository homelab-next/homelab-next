# SPDX-License-Identifier: Apache-2.0
"""The lab-in-a-box product adapters (NATS JetStream, OpenBao, ntfy), offline.

Each adapter runs its capability's whole conformance suite against an in-process stand-in of the
product's API (``conformance/fakes/{jetstream_wire,openbao_api,ntfy_api}.py``), and a defective
stand-in proves the suite, through the adapter, catches the defect.  The real products are
exercised by the nightly lab smoke (``compose/lab-in-a-box/targets/``).
"""

import base64
import json

import pytest

from conformance.fakes.jetstream_wire import FakeJetStreamWire
from conformance.fakes.ntfy_api import FakeNtfy
from conformance.fakes.openbao_api import FakeOpenBao
from conformance.protocols.events import EventBus, EventsError
from conformance.protocols.notify import NotifyTarget
from conformance.protocols.secrets import LeaseError, SecretNotFound, SecretStore
from conformance.suites import events as events_suite
from conformance.suites import notify as notify_suite
from conformance.suites import secrets as secrets_suite
from conformance.suites._util import exc_text
from homelabnext.conform.adapters import nats_jetstream as nj
from homelabnext.conform.adapters import ntfy as ntfy_adapter
from homelabnext.conform.adapters import openbao as bao
from homelabnext.conform.adapters._env import AdapterConfigError
from homelabnext.conform.core import run_checks
from homelabnext.conform.target import load_target
from homelabnext.notify import Message, SendError

TOKEN = "fake-root-token-0000"  # scrub-allow: fake placeholder
WRONG_SCHEME = "http://127.0.0.1:4222"  # no-raw-endpoint: allow never connected; wrong scheme


def _failing(results):
    return sorted(r.check for r in results if r.status != "pass")


# ============================================================================ events / JetStream
def _bus(wire=None, **kw):
    kw.setdefault("ack_wait", 0.2)
    kw.setdefault("dlq_wait", 0.2)
    return nj.make(wire=wire or FakeJetStreamWire(), **kw)


def test_events_suite_passes_over_the_jetstream_wire():
    results = run_checks(events_suite.SUITE, _bus)
    assert _failing(results) == []
    assert len(results) == len(events_suite.SUITE.specs)


def test_events_suite_catches_a_server_that_drops_dlq_advisories():
    results = run_checks(events_suite.SUITE, lambda: _bus(FakeJetStreamWire(drop_advisories=True)))
    assert _failing(results) == ["dlq-after-max-deliver", "term-dead-letters-immediately"]


def test_bus_maps_onto_streams_consumers_and_acked_settlements():
    wire = FakeJetStreamWire()
    bus = _bus(wire)
    assert isinstance(bus, EventBus)
    main, dlq = wire.streams[bus.stream].config, wire.streams[bus.dlq_stream].config
    assert main["subjects"] == [f"{bus.prefix}.>"] and main["retention"] == "limits"
    assert main["duplicate_window"] == 3600 * 10**9
    assert dlq["subjects"] == [
        f"$JS.EVENT.ADVISORY.CONSUMER.MAX_DELIVERIES.{bus.stream}.*",
        f"$JS.EVENT.ADVISORY.CONSUMER.MSG_TERMINATED.{bus.stream}.*",
    ]
    c = bus.consumer("worker", "jobs.*", max_deliver=4)
    cfg = wire.streams[bus.stream].consumers["worker"].config
    assert cfg == {
        "durable_name": "worker",
        "deliver_policy": "new",
        "ack_policy": "explicit",
        "ack_wait": int(0.2 * 10**9),
        "max_deliver": 4,
        "filter_subject": f"{bus.prefix}.jobs.*",
        "replay_policy": "instant",
    }
    seq = bus.publish("jobs.a", b"x", msg_id="m1")
    assert wire.log[-1] == (f"{bus.prefix}.jobs.a", b"x", {"Nats-Msg-Id": "m1"})
    (d,) = c.fetch(3)
    assert (d.seq, d.subject, d.data, d.msg_id, d.attempt) == (seq, "jobs.a", b"x", "m1", 1)
    pull = wire.log[-1]
    assert pull[0] == f"$JS.API.CONSUMER.MSG.NEXT.{bus.stream}.worker"
    assert json.loads(pull[1]) == {"batch": 3, "no_wait": True}
    d.nack()
    sent = wire.log[-1]
    assert sent[0].startswith(f"$JS.ACK.{bus.stream}.worker.1.{seq}.") and sent[1] == b"-NAK"
    (d2,) = c.fetch(1)
    d2.term()
    assert wire.log[-1][1] == b"+TERM"
    (dead,) = c.dead_letters()
    assert (dead.seq, dead.data, dead.msg_id, dead.attempt) == (seq, b"x", "m1", 2)
    dead.ack()  # a dead letter is settled already: a no-op, never an error
    bus.close()
    assert wire.streams == {} and wire.closed


def test_reopen_waits_for_leases_only_when_deliveries_are_unsettled():
    slept = []
    wire = FakeJetStreamWire()
    bus = nj.JetStreamBus(wire, stream="S1", subject_prefix="p", ack_wait=0.2, sleep=slept.append)
    c = bus.consumer("c", "a")
    bus.publish("a", b"1")
    (d,) = c.fetch(1)
    d.ack()
    bus.consumer("c", "a")
    assert slept == [], "a reopen with nothing unsettled must not wait"
    bus.publish("a", b"2")
    c = bus.consumer("c", "a")
    (old,) = c.fetch(1)
    bus.consumer("c", "a")
    assert len(slept) == 1 and slept[0] > 0.2
    before = len(wire.log)
    old.ack()  # handed out before the reopen: detached
    assert len(wire.log) == before, "a detached delivery was still settled"


def test_reopen_on_another_subject_is_refused():
    bus = _bus()
    bus.consumer("c", "a")
    with pytest.raises(EventsError, match="another subject"):
        bus.consumer("c", "b")


def test_api_errors_and_missing_streams_are_events_errors():
    bus = _bus()
    with pytest.raises(nj.JetStreamApiError) as e:
        bus.api("CONSUMER.INFO.NOPE.c")
    assert e.value.err_code == 10059 and isinstance(e.value, EventsError)
    with pytest.raises(nj.WireError, match="no responders"):
        bus._wire.request("elsewhere.x", b"", timeout=1)
    with pytest.raises(EventsError):
        bus.publish("a.*", b"x")
    for bad in ("", "a..b", "a b", "a.>.b"):
        with pytest.raises(EventsError):
            bus.consumer("c", bad)


def test_fake_wire_enforces_the_servers_stream_subject_rules():
    wire = FakeJetStreamWire()
    with pytest.raises(nj.JetStreamApiError, match="no-ack"):
        nj.JetStreamBus(wire, stream="ALL", subject_prefix="x").api(
            "STREAM.CREATE.BAD", {"name": "BAD", "subjects": [">"]}
        )
    with pytest.raises(nj.JetStreamApiError, match="overlap"):
        nj.JetStreamBus(wire, stream="TWO", subject_prefix="x")


def test_ack_reply_parsing_and_durable_names():
    assert nj.parse_ack_reply("$JS.ACK.S.c.3.17.9.1700000000.0") == ("S", "c", 3, 17)
    assert nj.parse_ack_reply("$JS.ACK.dom.acchash.S.c.2.5.4.1700000000.0.tok") == ("S", "c", 2, 5)
    for bad in ("_INBOX.x", "$JS.ACK.S.c.x.1.1.1.0"):
        with pytest.raises(EventsError):
            nj.parse_ack_reply(bad)
    assert nj.durable_name("c-r0-1") == "c-r0-1"
    hashed = nj.durable_name("odd.name with spaces")
    assert hashed.startswith("h") and "." not in hashed and " " not in hashed
    raw = base64.b64decode(base64.b64encode(b"NATS/1.0\r\nNats-Msg-Id: m9\r\n\r\n"))
    assert nj.parse_headers(raw) == {"Nats-Msg-Id": "m9"}


def test_events_make_needs_the_endpoint(monkeypatch):
    monkeypatch.delenv("HNX_ENDPOINT_EVENTS", raising=False)
    with pytest.raises(AdapterConfigError, match="HNX_ENDPOINT_EVENTS"):
        nj.make()
    monkeypatch.setenv("HNX_ENDPOINT_EVENTS", WRONG_SCHEME)
    with pytest.raises(AdapterConfigError, match="nats"):
        nj.make()


def test_nats_py_wire_refuses_a_non_nats_url():
    pytest.importorskip("nats")
    with pytest.raises(EventsError, match="nats://"):
        nj.NatsPyWire(WRONG_SCHEME)


# ============================================================================ secrets / OpenBao
@pytest.fixture
def openbao(monkeypatch):
    with FakeOpenBao(TOKEN) as srv:
        monkeypatch.setenv("HNX_ENDPOINT_SECRETS", srv.url)
        monkeypatch.setenv("LAB_SECRETS_DEV_TOKEN", TOKEN)
        yield srv


def test_secrets_suite_passes_over_the_openbao_api(openbao):
    results = run_checks(secrets_suite.SUITE, bao.make)
    assert _failing(results) == []
    assert openbao.kv == {} and openbao.policies == {}, "scratch namespaces were not cleaned up"


def test_secrets_suite_catches_tokens_that_never_expire(monkeypatch):
    with FakeOpenBao(TOKEN, ignore_ttl=True) as srv:
        monkeypatch.setenv("HNX_ENDPOINT_SECRETS", srv.url)
        monkeypatch.setenv("LAB_SECRETS_DEV_TOKEN", TOKEN)
        results = run_checks(
            secrets_suite.SUITE, bao.make, only=["lease-expires", "revoke-ends-lease"]
        )
    assert _failing(results) == ["lease-expires"]


def test_leases_are_child_token_accessors_scoped_to_the_store(openbao):
    s = bao.make()
    assert isinstance(s, SecretStore)
    s.put("db/main", {"password": "fake-pw-0000"})  # scrub-allow: fake placeholder
    lease = s.lease("db/main", 0.2)
    assert lease.id.startswith("fake-accessor-") and dict(lease.data) == {
        "password": "fake-pw-0000"
    }
    child = next(t for t, e in openbao.tokens.items() if e["accessor"] == lease.id)
    assert openbao.tokens[child]["policies"] == [s.policy]
    assert "fake-child-token" not in repr(lease) and "fake-child-token" not in repr(vars(s))
    other = bao.make()
    assert s.lease_valid(lease.id) and not other.lease_valid(lease.id), "a foreign lease was valid"
    s.revoke(lease.id)
    s.revoke(lease.id)
    assert not s.lease_valid(lease.id)
    with pytest.raises(SecretNotFound):
        s.lease("db/none", 5)
    s.close()
    other.close()


def test_versions_reads_and_listing_map_onto_kv_v2(openbao):
    s = bao.make()
    assert s.put("a/x", {"k": "1"}) == 1 and s.put("a/x", {"k": "2"}) == 2
    s.put("a/b/y", {"k": "v"})
    s.put("ab", {"k": "v"})
    assert s.get("a/x").version == 2 and dict(s.get("a/x", 1).data) == {"k": "1"}
    assert list(s.list("a/")) == ["a/b/y", "a/x"] and list(s.list("a")) == ["a/b/y", "a/x", "ab"]
    paths = [p for m, p in openbao.requests if m == "POST" and "/data/" in p]
    assert all(p.startswith(f"secret/data/{s.namespace}/") for p in paths)
    s.delete("a/x")
    with pytest.raises(SecretNotFound):
        s.delete("a/x")
    s.close()


def test_version_zero_and_negative_versions_are_absent_not_latest(openbao):
    """KV v2 answers ``?version=0`` with the latest version; the Protocol numbers versions from
    1, so the adapter refuses 0 and negative versions itself, before any request."""
    s = bao.make()
    s.put("a/x", {"k": "1"})
    s.put("a/x", {"k": "2"})
    sent = len(openbao.requests)
    for v in (0, -1, -2):
        with pytest.raises(SecretNotFound):
            s.get("a/x", version=v)
    assert len(openbao.requests) == sent, "a non-positive version reached the server"
    assert dict(s.get("a/x", version=1).data) == {"k": "1"}
    s.close()


def test_a_lease_ttl_that_never_ends_is_refused_before_any_policy_is_written(openbao):
    """``lease(path, inf)`` raised a raw OverflowError from ``math.ceil`` after the lease ACL
    policy was already written; ``nan`` was refused only by accident of comparison."""
    s = bao.make()
    s.put("a/x", {"k": "1"})
    sent = len(openbao.requests)
    for ttl in (float("inf"), float("nan"), float("-inf")):
        with pytest.raises(LeaseError):
            s.lease("a/x", ttl)
    assert openbao.policies == {} and len(openbao.requests) == sent, "a refused lease wrote"
    s.close()


def test_server_error_bodies_never_reach_the_exception(monkeypatch):
    value = "fake-value-DO-NOT-LEAK"  # scrub-allow: fake placeholder
    with FakeOpenBao(TOKEN, mounted=False, echo_errors=True) as srv:
        monkeypatch.setenv("HNX_ENDPOINT_SECRETS", srv.url)
        monkeypatch.setenv("LAB_SECRETS_DEV_TOKEN", TOKEN)
        s = bao.make(ensure_mount=False)
        with pytest.raises(bao.OpenBaoError) as e:
            s.put("p", {"password": value})
        assert e.value.status == 404 and value not in exc_text(e.value)
        # with ensure_mount the store enables KV v2 itself
        assert bao.make().put("p", {"k": "v"}) == 1
        assert srv.mounts["secret"] == {"type": "kv", "options": {"version": "2"}}


def test_ensure_mount_refuses_kv_version_1(openbao):
    openbao.mounts["secret"] = {"type": "kv", "options": {"version": "1"}}
    with pytest.raises(bao.OpenBaoError, match="not KV version 2"):
        bao.make()


def test_secrets_credentials_and_plaintext(monkeypatch, openbao):
    monkeypatch.delenv("LAB_SECRETS_DEV_TOKEN")
    with pytest.raises(AdapterConfigError, match="LAB_SECRETS_DEV_TOKEN"):
        bao.make()
    url = "http://192.0.2.1:8200"  # no-raw-endpoint: allow RFC 5737 documentation address
    with pytest.raises(ValueError, match="plaintext"):
        bao.OpenBaoStore(url, lambda: TOKEN)
    stopped = FakeOpenBao(TOKEN)
    dead = bao.OpenBaoStore(stopped.url, lambda: TOKEN, timeout=1)
    stopped._httpd.server_close()
    with pytest.raises(bao.OpenBaoError, match="transport"):
        dead.get("x")


# ============================================================================ notify / ntfy
@pytest.fixture
def ntfy(monkeypatch):
    with FakeNtfy() as srv:
        monkeypatch.setenv("HNX_ENDPOINT_NOTIFY", srv.url)
        yield srv


def test_notify_suite_passes_over_the_ntfy_api(ntfy):
    results = run_checks(notify_suite.SUITE, ntfy_adapter.make)
    assert _failing(results) == []
    assert ntfy.polls >= 8, "received() must read the far side back from ntfy"


def test_notify_suite_catches_a_channel_that_duplicates(monkeypatch):
    with FakeNtfy(duplicate=True) as srv:
        monkeypatch.setenv("HNX_ENDPOINT_NOTIFY", srv.url)
        results = run_checks(
            notify_suite.SUITE, ntfy_adapter.make, only=["first-report-delivers-once"]
        )
    assert _failing(results) == ["first-report-delivers-once"]


def test_notify_suite_catches_a_channel_that_rewrites(monkeypatch):
    with FakeNtfy(rewrite=lambda s: s.replace("café", "cafe")) as srv:
        monkeypatch.setenv("HNX_ENDPOINT_NOTIFY", srv.url)
        results = run_checks(notify_suite.SUITE, ntfy_adapter.make, only=["message-fidelity"])
    assert _failing(results) == ["message-fidelity"]


def test_received_rebuilds_messages_from_what_ntfy_stored(ntfy):
    t = ntfy_adapter.make()
    assert isinstance(t, NotifyTarget)
    t.sender.send(
        Message(key="disk,a b", title="Disk full", body="  padded  ", level="warn", tags=("x",))
    )
    # a message posted to the topic by someone else carries no key tag and is not ours
    ntfy.publish(t.topic, {"Title": "stranger"}, b"hello")
    (m,) = t.received()
    assert (m.key, m.title, m.body, m.level, m.tags) == (
        "disk,a b",
        "Disk full",
        "padded",
        "warn",
        ("x",),
    )
    stored = ntfy.messages[0]
    assert stored["priority"] == 4 and stored["topic"] == t.topic
    t.fail_next(1)
    with pytest.raises(SendError):
        t.sender.send(Message(key="k", title="T", body="b"))
    assert len(ntfy.messages) == 2, "a failed send reached ntfy"
    t.close()


def test_received_surfaces_a_failed_poll():
    with FakeNtfy() as srv:
        url = srv.url
    t = ntfy_adapter.NtfyTarget(url, timeout=1)
    with pytest.raises(SendError, match="reading topic"):
        t.received()


# ============================================================================ target files
@pytest.mark.parametrize("cap", ["events", "secrets", "notify"])
def test_lab_target_files_bind_the_adapters(cap):
    target = load_target(f"compose/lab-in-a-box/targets/{cap}.yml")
    b = target.binding(cap)
    assert b.adapter and b.adapter.startswith("homelabnext.conform.adapters.")
    mod, _, fn = b.adapter.partition(":")
    assert callable(getattr(__import__(mod, fromlist=[fn]), fn))


# ============================================================================ shared settings
NEVER = "http://127.0.0.1:1"  # no-raw-endpoint: allow never contacted
NOT_HTTP = "ftp://127.0.0.1:1"  # no-raw-endpoint: allow never contacted; wrong scheme
LAB_VARS = (
    "HNX_ENDPOINT_EVENTS",
    "HNX_ENDPOINT_NOTIFY",
    "HNX_ENDPOINT_SECRETS",
    "HNX_ENDPOINT_OBJECT_STORE",
    "HNX_ENDPOINT_LAKE_QUERY",
    "HNX_ENDPOINT_LAKE_CATALOG",
    "LAB_SECRETS_DEV_TOKEN",
    "LAB_S3_ACCESS_KEY",
    "LAB_S3_SECRET_KEY",
    "LAB_S3_REGION",
)


def _factories():
    from homelabnext.conform.adapters import lake, s3

    return {
        "events": lambda: nj.make(),
        "notify": lambda: ntfy_adapter.make(),
        "secrets": lambda: bao.make(),
        "object-store": lambda: s3.make_object_store(domain="example.internal"),
        "lake": lambda: lake.make_lake(domain="example.internal", warehouse="lab"),
    }


@pytest.mark.parametrize("name", ["events", "notify", "secrets", "object-store", "lake"])
def test_every_adapter_reports_a_missing_setting_as_one_error_type(monkeypatch, name):
    """One helper module: a missing endpoint override (or, for the adapters that resolve a
    domain, a missing credential) is an AdapterConfigError naming the variable."""
    for var in LAB_VARS:
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("HNX_ENDPOINT_OBJECT_STORE", NEVER)
    monkeypatch.setenv("LAB_S3_REGION", "garage")
    monkeypatch.setenv("HNX_ENDPOINT_LAKE_QUERY", NOT_HTTP)
    want = {
        "events": "HNX_ENDPOINT_EVENTS",
        "notify": "HNX_ENDPOINT_NOTIFY",
        "secrets": "HNX_ENDPOINT_SECRETS",
        "object-store": "LAB_S3_ACCESS_KEY",
        "lake": "HNX_ENDPOINT_LAKE_QUERY",
    }[name]
    with pytest.raises(AdapterConfigError, match=want):
        _factories()[name]()


def test_the_lake_factory_refuses_plaintext_by_the_shared_rule(monkeypatch):
    """lake uses homelabnext._http.check_plaintext, the rule every other HTTP client applies."""
    from homelabnext._http import check_plaintext
    from homelabnext.conform.adapters.lake import make_lake
    from homelabnext.lake.errors import LakeError

    url = "http://192.0.2.9:8080"  # no-raw-endpoint: allow RFC 5737 documentation address
    monkeypatch.setenv("HNX_ENDPOINT_LAKE_QUERY", url)
    with pytest.raises(ValueError) as rule:
        check_plaintext(url, credentials=True, allow_plaintext=False)
    with pytest.raises(LakeError) as got:
        make_lake(domain="example.internal", warehouse="lab")
    assert str(rule.value) in str(got.value)


def _dead_lettered(bodies):
    wire = FakeJetStreamWire()
    bus = nj.make(wire=wire, ack_wait=0.2, dlq_wait=0.2)
    c = bus.consumer("c1", "a.b", max_deliver=5)
    for body in bodies:
        bus.publish("a.b", body)
        (d,) = c.fetch(1)
        d.term()
    return wire, bus, c


def test_dead_letters_skip_an_original_that_aged_out_of_the_stream():
    # the advisory outlives its original (the main stream evicts first): the listing still works
    wire, bus, c = _dead_lettered([b"old", b"new"])
    st = wire.streams[bus.stream]
    first = min(st.msgs)
    del st.msgs[first]  # aged out (max_age, or max_bytes with discard old)
    assert [d.data for d in c.dead_letters()] == [b"new"]
    assert c.dead_evicted == [first]
    bus.close()


def test_dead_letters_read_on_from_where_the_last_call_stopped():
    wire, bus, c = _dead_lettered([b"one", b"two"])
    assert [d.data for d in c.dead_letters()] == [b"one", b"two"]
    get = f"$JS.API.STREAM.MSG.GET.{bus.dlq_stream}"
    before = [json.loads(p[1]) for p in wire.log if p[0] == get]
    bus.publish("a.b", b"three")
    (d,) = c.fetch(1)
    d.term()
    assert [d.data for d in c.dead_letters()] == [b"one", b"two", b"three"]
    after = [json.loads(p[1]) for p in wire.log if p[0] == get][len(before) :]
    assert after and all(q["seq"] > 2 for q in after), after  # never again from seq 1
    bus.close()
