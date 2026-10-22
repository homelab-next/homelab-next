# SPDX-License-Identifier: Apache-2.0
"""The lab's broker end-to-end scenario (``compose/lab-in-a-box/broker_e2e.py``) without docker.

The nightly runs it in the lab-in-a-box, where the broker, the hub and every peer are separate
processes with their own uids.  Here they are separate processes too -- the hub
(``broker_e2e.py serve-hub`` -> ``hnx status serve``), the agent's ``hnx broker mcp`` behind a real
MCP stdio client, and ``hnx broker`` CLI calls -- talking to a real socket, but they all run as this
test's uid.  So the broker runs in this process and maps each peer to a distinct uid by the role
its process was started with (``HNX_LAB_ROLE`` in ``/proc/<pid>/environ``, read for the pid the
kernel reports with ``SO_PEERCRED``): the stand-in for distinct users that only the docker path
has.  Skipped off Linux and without the ``mcp`` extra."""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest
import yaml

from homelabnext.broker.server import BrokerServer, peer_credentials, supported
from homelabnext.broker.service import BrokerService

ROOT = Path(__file__).resolve().parents[2]
LAB = ROOT / "compose" / "lab-in-a-box"
UIDS = {"agent": 4_100_011, "relay": 4_100_012, "stranger": 4_100_013}
SECRET = "fake-front-door-secret-e2e"  # scrub-allow: fake placeholder
LOOPBACK = "127.0.0.1"  # no-raw-endpoint: allow the hub binds loopback only
EDGE = "198.51.100.250"  # no-raw-endpoint: allow a documentation-range edge address

pytestmark = [
    pytest.mark.skipif(not supported(), reason="SO_PEERCRED: Linux only"),
    pytest.mark.skipif(not sys.platform.startswith("linux"), reason="/proc: Linux only"),
]


@pytest.fixture(scope="module")
def e2e():
    from test_lab_in_a_box import load_module

    return load_module("broker_e2e", LAB / "broker_e2e.py")


def _role(pid: int, role_env: str) -> str | None:
    try:
        raw = Path(f"/proc/{pid}/environ").read_bytes()
    except OSError:
        return None
    for item in raw.split(b"\0"):
        if item.startswith(role_env.encode() + b"="):
            return item.split(b"=", 1)[1].decode()
    return None


def _free_port() -> int:
    with socket.socket() as s:
        s.bind((LOOPBACK, 0))
        return s.getsockname()[1]


@pytest.fixture
def lab(tmp_path, e2e, monkeypatch):
    """A broker (in process, peers mapped by role) and a hub (a subprocess) on a real socket."""
    pytest.importorskip("mcp")
    src = ROOT / "examples" / "broker"
    dst = tmp_path / "broker"
    shutil.copytree(src, dst)
    doc = yaml.safe_load((src / "manifest.production.yml").read_text())
    doc["callers"] = [{"uid": UIDS["agent"], "profile": "profile:triage"}]
    doc["approval_relays"] = [{"uid": UIDS["relay"], "issuer": "sso"}]
    (dst / "manifest.yml").write_text(yaml.safe_dump(doc))
    monkeypatch.setenv("HNX_BROKER_SECRET_DEMO_API_TOKEN", "fake-demo-token-e2e")
    svc = BrokerService.from_manifest(dst / "manifest.yml", tmp_path / "state",
                                      data_root=tmp_path / "data")  # fmt: skip
    sock = tmp_path / "run" / "broker.sock"
    srv = BrokerServer(svc, sock)

    def by_role(conn):
        pid, uid, gid = peer_credentials(conn)
        role = _role(pid, e2e.ROLE_ENV)
        return pid, UIDS.get(role, uid) if role else uid, gid

    srv.credentials = by_role
    srv.start()
    env = {**os.environ, "PYTHONPATH": str(ROOT), e2e.SECRET_ENV: SECRET, e2e.ROLE_ENV: "relay"}
    port = _free_port()
    hub = subprocess.Popen(
        [sys.executable, str(LAB / "broker_e2e.py"), "serve-hub", "--dir", str(tmp_path / "hub"),
         "--edge-address", LOOPBACK, "--socket", str(sock), "--bind", LOOPBACK,
         "--port", str(port)],
        cwd=ROOT, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
    )  # fmt: skip
    base = f"http://{LOOPBACK}:{port}"
    try:
        for _ in range(150):
            if e2e.main(["ready", "--socket", str(sock), "--hub", base]) == 0:
                break
            assert hub.poll() is None, hub.stderr.read().decode()
            time.sleep(0.1)
        else:
            pytest.fail("the hub did not come up")

        def setup(secret: str = SECRET):
            return e2e.Setup(
                socket=sock,
                hub=base,
                data_root=tmp_path / "data",
                uids=UIDS,
                secret=secret,
                env={**os.environ, "PYTHONPATH": str(ROOT)},
            )

        yield setup, svc
    finally:
        hub.terminate()
        hub.wait(timeout=10)
        srv.close()


class _SharedWire:
    """The JetStream wire fake, kept open across the relay's and the check's adapters."""

    def __init__(self):
        from conformance.fakes.jetstream_wire import FakeJetStreamWire

        self.server = FakeJetStreamWire()

    def request(self, *a, **kw):
        return self.server.request(*a, **kw)

    def pull(self, *a, **kw):
        return self.server.pull(*a, **kw)

    def close(self):
        pass


def _relay(e2e, state_root: Path, wire: _SharedWire, *, drop_marks: bool = False):
    """The scenario's relay, in this process: ``OutboxRelay`` on the broker's state over the wire
    fake (the CLI is tested in tests/broker/test_broker_relay.py)."""
    from homelabnext.broker.relay import OutboxRelay
    from homelabnext.broker.state import StateDir
    from homelabnext.conform.adapters import nats_jetstream as nj

    def bus():
        return nj.make(wire=wire, scratch=False, stream="HNXT", subject_prefix="hnxt")

    def once():
        state = StateDir(state_root)
        if drop_marks:  # a defect: publishes and never marks, so every pass republishes
            state.mark_delivered = lambda *_a: True
        r = OutboxRelay(state, bus)
        try:
            n = r.drain()
            left = len(state.outbox_pending()) if not drop_marks else 0
        finally:
            r.close()
        return (1 if left else 0), f"hnx broker relay: published {n}, {left} pending"

    return e2e.Relay(str(state_root), "unused", "HNXT", "hnxt", open_bus=bus, run_once=once)


def test_the_scenario_passes_every_step(lab, e2e):
    setup, svc = lab
    s = setup()
    s.relay = _relay(e2e, svc.state.root, _SharedWire())
    rows = e2e.run_scenario(s)
    assert [r["step"] for r in rows] == list(e2e.steps(s)), rows
    assert "bus-relay" in e2e.steps(s) and "bus-relay" not in e2e.STEPS
    assert all(r["ok"] for r in rows), [r for r in rows if not r["ok"]]
    # what the steps claim, checked here against the broker's own state
    vias = {r["via"] for r in svc.audit_documents()}
    assert vias == {f"uid:{u}" for u in UIDS.values()}
    [rid] = svc.state.request_ids()
    [approval] = svc.state.approvals(rid)
    assert approval["approver"] == {"issuer": "sso", "subject": e2e.APPROVER}


def test_the_scenario_fails_when_the_edge_lacks_the_front_door_secret(lab, e2e):
    setup, svc = lab
    rows = e2e.run_scenario(setup(secret="fake-wrong-secret"))
    assert [r["step"] for r in rows][-1] == "hub-approve" and not rows[-1]["ok"], rows
    assert "HTTP 403" in rows[-1]["detail"]
    assert all(r["ok"] for r in rows[:-1])
    [pending] = svc.pending()  # never approved, never run
    assert not svc.state.approvals(pending["request_id"])


def test_the_relay_check_refuses_an_empty_bus_and_a_republish(e2e, tmp_path):
    from homelabnext.broker.relay import BROKER_SOURCE
    from homelabnext.broker.state import StateDir
    from homelabnext.events.envelope import build_event

    assert e2e.BROKER_SOURCE == BROKER_SOURCE
    state = StateDir(tmp_path / "state")
    setup = e2e.Setup(socket=tmp_path / "s", hub="", data_root=tmp_path, uids={}, secret="")
    setup.relay = _relay(e2e, state.root, _SharedWire())
    with pytest.raises(e2e.StepFailed, match=r"no homelabnext\.decision\.requested"):
        e2e.check_relay(setup, "req-1")
    data = {"decision_id": "req-1", "verdict": "accept", "confidence": 1.0, "tier_used": "human"}
    req = {"decision_id": "req-1", "spec": "broker-approval", "subject": "requests/req-1.json",
           "action": "service.restart", "actor": "profile:triage",
           "request_digest": "sha256:" + "0" * 64}  # fmt: skip
    state.put_outbox(build_event("homelabnext.decision.requested", BROKER_SOURCE, req,
                                 dedupe_key="q", subject="req-1"))  # fmt: skip
    state.put_outbox(build_event("homelabnext.decision.returned", BROKER_SOURCE, data,
                                 dedupe_key="r", subject="req-1"))  # fmt: skip
    assert "requested seq 1 < returned seq 2" in e2e.check_relay(setup, "req-1")
    with pytest.raises(e2e.StepFailed, match="is not the broker's for req-2"):
        e2e.check_relay(setup, "req-2")
    other = StateDir(tmp_path / "other")
    for ev in state.outbox():
        other.put_outbox(ev)
    setup.relay = _relay(e2e, other.root, _SharedWire(), drop_marks=True)
    with pytest.raises(e2e.StepFailed, match="republished"):
        e2e.check_relay(setup, "req-1")


def test_form_fields_and_the_audit_check_refuse_what_is_missing(e2e, tmp_path):
    page = '<div class="pane" id="req-1"><h3>x</h3></div>'
    with pytest.raises(e2e.StepFailed, match="no decide form"):
        e2e.form_fields(page, "req-1")
    form = (
        '<div class="pane" id="req-1"><form method="post">'
        '<input type="hidden" name="request_id" value="req-1">'
        '<input type="hidden" name="digest" value="sha256:ab">'
        '<input type="hidden" name="token" value="1.fake"></form></div>'
    )
    assert e2e.form_fields(form, "req-1")["digest"] == "sha256:ab"
    with pytest.raises(e2e.StepFailed, match="no decide form"):
        e2e.form_fields(form, "req-2")


def test_hub_files_trust_only_the_edge_address(e2e, tmp_path):
    from homelabnext.registry.model import load
    from homelabnext.status.agents import load_config

    files = e2e.hub_files(tmp_path, edge_address=EDGE, socket_path="/run/x.sock")
    reg = load(files["services"])
    cfg = load_config(files["agents"], reg, lambda ref: SECRET, base=tmp_path)
    assert cfg.front_door.trusted == frozenset({EDGE})
    assert cfg.approvals.socket == Path("/run/x.sock") and cfg.approvals.issuer == "sso"
    with pytest.raises(ValueError):
        e2e.hub_files(tmp_path, edge_address="not-an-address", socket_path="/run/x.sock")
