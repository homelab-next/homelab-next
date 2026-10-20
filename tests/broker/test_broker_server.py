# SPDX-License-Identifier: Apache-2.0
"""The broker's Unix-socket transport (stage 2a): the caller is the peer, never the body.

Real sockets and real ``SO_PEERCRED`` throughout: this process's uid is mapped to
``profile:triage``.  The relay role needs a second identity, which one process cannot have, so
those tests swap the server's credential reader for one that reports a fixed uid (the mapping,
the protocol and the service are the real ones)."""

from __future__ import annotations

import contextlib
import json
import os
import shutil
import socket
import stat
import sys
import threading
import time
from pathlib import Path

import pytest
import yaml

from conformance.protocols.broker import BrokerError, Denied, InvalidArguments
from homelabnext.agent.readers import default_classes, reader_problems
from homelabnext.agent.schemas import schema_errors
from homelabnext.broker.cli import main
from homelabnext.broker.client import BrokerClient
from homelabnext.broker.server import (
    BrokerServer,
    PeerMap,
    handle_request,
    peer_credentials,
    supported,
)
from homelabnext.broker.service import BrokerService, ManifestError, validate_manifest

ROOT = Path(__file__).resolve().parents[2]
EXAMPLES = ROOT / "examples" / "broker"
ME = os.getuid()
READER_UID = 4_000_001  # mapped to profile:reader; no process here has it
RELAY_UID = 4_000_002  # the approval relay for issuer sso
STRANGER_UID = 4_000_003  # in neither list

pytestmark = pytest.mark.skipif(
    not supported(), reason="SO_PEERCRED: the broker socket authenticates peers on Linux only"
)


def _manifest_dir(tmp_path: Path, **changes) -> Path:
    """The example broker with transport peers: this uid is triage, plus a reader and a relay."""
    dst = tmp_path / "broker"
    shutil.copytree(EXAMPLES, dst)
    doc = yaml.safe_load((EXAMPLES / "manifest.yml").read_text(encoding="utf-8"))
    doc.update(
        dev_identity=False,
        callers=[
            {"uid": ME, "profile": "profile:triage"},
            {"uid": READER_UID, "profile": "profile:reader"},
        ],
        approval_relays=[{"uid": RELAY_UID, "issuer": "sso"}],
    )
    doc.update(changes)
    (dst / "manifest.yml").write_text(yaml.safe_dump(doc), encoding="utf-8")
    return dst / "manifest.yml"


def _service(tmp_path: Path, **changes) -> BrokerService:
    return BrokerService.from_manifest(
        _manifest_dir(tmp_path, **changes), tmp_path / "state", data_root=tmp_path / "data"
    )


@pytest.fixture
def broker(tmp_path, monkeypatch):
    """A running server on ``<tmp>/run/broker.sock`` and a way to speak as another uid."""
    monkeypatch.setenv("HNX_BROKER_SECRET_DEMO_API_TOKEN", "fake-socket-token")
    svc = _service(tmp_path)
    run = tmp_path / "run"
    srv = BrokerServer(svc, run / "broker.sock").start()

    def as_uid(uid: int | None) -> None:
        srv.credentials = peer_credentials if uid is None else (lambda conn: (0, uid, 0))

    srv.as_uid = as_uid  # type: ignore[attr-defined]
    yield srv
    srv.close()


def _raw(path: Path, data: bytes, *, shut: bool = True) -> dict:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(10)
        s.connect(str(path))
        try:  # a busy broker answers and closes without reading
            s.sendall(data)
            if shut:
                s.shutdown(socket.SHUT_WR)
        except BrokenPipeError:
            pass
        out = b""
        while chunk := s.recv(65536):
            out += chunk
    return json.loads(out)


def _audit(svc: BrokerService, **match) -> list[dict]:
    return svc.audit_documents(**match)


# -- every operation over the socket ------------------------------------------------------------


def test_every_operation_round_trips(broker, tmp_path):
    c = BrokerClient(broker.path)
    acts = c.actions()
    assert acts["caller"] == "profile:triage"
    rows = {r["action"]: r for r in acts["actions"]}
    assert set(rows) == {
        "memory.write",
        "finding.write",
        "proposal.file",
        "service.status",
        "service.restart",
    }
    assert rows["service.restart"]["needs_approval"] is True
    assert rows["memory.write"]["kind"] == "lane" and "name" in rows["memory.write"]["params"]
    assert rows["service.status"]["params_schema"]["type"] == "object"

    # call: a lane write now
    out = c.call("memory.write", {"name": "notes.md", "content": "drains slowly\n"})
    assert out["path"] == "memory/triage/notes.md"
    assert (tmp_path / "data/memory/triage/notes.md").read_text() == "drains slowly\n"

    # submit, status, pending-for-me, cancel
    sub = c.submit("finding.write", {"name": "2026-01-15-queue.md", "content": "x"})
    assert sub["awaiting_approval"] is False
    assert c.status(sub["request_id"])["state"] == "pending"
    assert [r["request_id"] for r in c.pending_for_me()] == [sub["request_id"]]
    assert c.cancel(sub["request_id"])["state"] == "cancelled"
    assert c.pending_for_me() == []

    # an approval-gated action: submit, relay pending, relay approve, run
    rid = c.submit("service.restart", {"grace_s": 5}, target="svc:queue")["request_id"]
    with pytest.raises(Denied) as exc:
        c.run(rid)
    assert exc.value.reason == "approval-required"
    broker.as_uid(RELAY_UID)
    assert [r["request_id"] for r in c.pending()] == [rid]
    doc = c.approve(rid, "sso", "operator-one", note="ok")
    assert doc["decision"] == "approved" and doc["approver"]["subject"] == "operator-one"
    records = c.audit(request_id=rid, tail=10)
    assert [r["operation"] for r in records][-1] == "approve"
    broker.as_uid(None)
    result = c.run(rid)
    assert result["output"]["would_restart"] == "svc:queue"
    assert c.status(rid)["state"] == "done"

    # deny
    rid2 = c.submit("service.restart", {"grace_s": 1})["request_id"]
    broker.as_uid(RELAY_UID)
    assert c.deny(rid2, "sso", "operator-one")["decision"] == "denied"
    broker.as_uid(None)
    assert c.status(rid2)["state"] == "denied"

    # every record the socket produced names its peer
    svc = broker.service
    vias = {r.get("via") for r in _audit(svc)}
    assert vias == {f"uid:{ME}", f"uid:{RELAY_UID}"}
    for r in _audit(svc):
        assert schema_errors("broker", "audit", r) == []


def test_the_reader_sees_only_its_grant_and_not_others_requests(broker):
    c = BrokerClient(broker.path)
    rid = c.submit("memory.write", {"name": "a.md", "content": "x"})["request_id"]
    broker.as_uid(READER_UID)
    assert [r["action"] for r in c.actions()["actions"]] == ["service.status"]
    with pytest.raises(Denied) as exc:
        c.status(rid)
    assert exc.value.reason == "not-request-owner"
    with pytest.raises(Denied) as exc:
        c.call("memory.write", {"name": "b.md", "content": "x"})
    assert exc.value.reason == "not-granted"


# -- identity --------------------------------------------------------------------------------


def test_an_unmapped_peer_is_refused_and_audited(tmp_path):
    """Real SO_PEERCRED: this process's uid is in neither list."""
    svc = _service(tmp_path, callers=[{"uid": READER_UID, "profile": "profile:reader"}])
    with BrokerServer(svc, tmp_path / "run" / "b.sock") as srv, pytest.raises(Denied) as exc:
        BrokerClient(srv.path).call("memory.write", {"name": "a.md", "content": "x"})
    assert exc.value.reason == "unknown-caller"
    (rec,) = _audit(svc, reason="unknown-caller")
    assert (rec["caller"], rec["operation"], rec["outcome"]) == (f"uid:{ME}", "connect", "denied")
    assert rec["via"] == f"uid:{ME}" and rec["action"] == ""  # the body was never read
    assert not (tmp_path / "data").exists()


def test_the_body_may_not_name_the_actor(broker):
    for field in ("actor", "caller", "as", "profile", "uid"):
        body = {"op": "call", "action": "memory.write", "params": {}, field: "profile:other"}
        resp = _raw(broker.path, json.dumps(body).encode())
        assert (resp["ok"], resp["error"]) == (False, "actor-in-body"), field
    recs = _audit(broker.service, reason="actor-in-body")
    assert len(recs) == 5 and {r["operation"] for r in recs} == {"call"}
    assert {r["caller"] for r in recs} == {"profile:triage"}


def test_an_agent_cannot_approve_and_a_relay_cannot_act(broker):
    c = BrokerClient(broker.path)
    rid = c.submit("service.restart", {"grace_s": 1})["request_id"]
    with pytest.raises(Denied) as exc:  # the agent itself, claiming a human
        c.approve(rid, "sso", "operator-one")
    assert exc.value.reason == "not-an-approval-relay"
    assert _audit(broker.service, reason="not-an-approval-relay")[0]["operation"] == "approve"
    broker.as_uid(RELAY_UID)
    with pytest.raises(Denied) as exc:
        c.call("memory.write", {"name": "a.md", "content": "x"})
    assert exc.value.reason == "not-a-caller"
    assert broker.service.state.state_of(rid) == "pending"


def test_relay_approvals_obey_the_approver_rules(broker):
    c = BrokerClient(broker.path)
    rid = c.submit("service.restart", {"grace_s": 1})["request_id"]
    broker.as_uid(RELAY_UID)
    cases = [
        (("sso", "someone-else"), "approval-approver-not-allowed"),
        (("sso", "triage"), "approval-self-approved"),
        (("other-idp", "operator-one"), "relay-issuer-mismatch"),
    ]
    for (issuer, subject), reason in cases:
        with pytest.raises(Denied) as exc:
            c.approve(rid, issuer, subject)
        assert exc.value.reason == reason
        with pytest.raises(Denied) as exc:
            c.deny(rid, issuer, subject)
        assert exc.value.reason == reason
    assert broker.service.state.approvals(rid) == []
    with pytest.raises(InvalidArguments) as exc:
        c.request("approve", request_id=rid, approver={"issuer": "sso"})
    assert exc.value.reason == "request-invalid"


# -- the protocol's bounds ---------------------------------------------------------------------


def test_oversized_and_slow_requests_are_refused(tmp_path):
    svc = _service(tmp_path)
    srv = BrokerServer(svc, tmp_path / "run" / "b.sock", max_request_bytes=512, timeout_s=0.3)
    with srv:
        big = json.dumps({"op": "call", "action": "memory.write", "params": {"x": "y" * 600}})
        resp = _raw(srv.path, big.encode())
        assert resp["error"] == "request-too-large"
        ok = json.dumps({"op": "actions"}).encode()
        assert _raw(srv.path, ok)["ok"] is True
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:  # never finishes its line
            s.settimeout(5)
            s.connect(str(srv.path))
            s.sendall(b'{"op": "act')
            assert json.loads(s.recv(65536))["error"] == "request-timeout"
    reasons = [r["reason"] for r in _audit(svc, operation="connect")]
    assert reasons == ["request-too-large", "request-timeout"]


@pytest.mark.parametrize(
    ("body", "reason"),
    [
        (b"not json", "request-malformed"),
        (b"[1, 2]", "request-malformed"),
        (b'{"action": "memory.write"}', "request-malformed"),
        (b'{"op": "shell", "cmd": "id"}', "unknown-operation"),
        (b'{"op": "actions", "v": 2}', "unsupported-version"),
        (b'{"op": "status", "request_id": "req-1", "extra": 1}', "request-invalid"),
        (b'{"op": "run"}', "request-invalid"),
        (b'{"op": "call", "params": {}}', "request-invalid"),
        (b"[" * 100_000 + b"]" * 100_000, "request-malformed"),
    ],
)
def test_malformed_requests(broker, body, reason):
    resp = _raw(broker.path, body)
    assert (resp["ok"], resp["error"]) == (False, reason)
    assert _audit(broker.service, reason=reason)


def test_one_line_per_connection_and_a_newline_terminates(broker):
    resp = _raw(broker.path, b'{"op": "actions"}\n{"op": "garbage"', shut=False)
    assert resp["ok"] is True


def test_a_full_server_answers_busy(tmp_path):
    svc = _service(tmp_path)
    srv = BrokerServer(svc, tmp_path / "run" / "b.sock", max_connections=1, timeout_s=3)
    with srv, socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as hold:
        hold.connect(str(srv.path))  # occupies the only slot until it times out
        time.sleep(0.2)
        assert _raw(srv.path, b'{"op": "actions"}')["error"] == "busy"


def test_concurrent_runs_of_one_approved_request_run_it_once(broker):
    c = BrokerClient(broker.path)
    rid = c.submit("service.restart", {"grace_s": 2})["request_id"]
    broker.as_uid(RELAY_UID)
    c.approve(rid, "sso", "operator-one")
    broker.as_uid(None)
    outcomes: list[str] = []

    def go():
        try:
            c.run(rid)
            outcomes.append("ok")
        except BrokerError as exc:
            outcomes.append(getattr(exc, "reason", "?"))

    threads = [threading.Thread(target=go) for _ in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert outcomes.count("ok") == 1, outcomes
    assert set(outcomes) - {"ok"} <= {"not-pending", "approval-replayed"}


# -- review regressions: the deadline, strangers, relay slots, the directory's owner ----------


def _server(tmp_path, **kw) -> BrokerServer:
    return BrokerServer(_service(tmp_path), tmp_path / "run" / "b.sock", **kw)


def test_the_socket_directory_must_be_owned_by_the_broker(tmp_path, monkeypatch):
    srv = _server(tmp_path)
    run = tmp_path / "run"
    run.mkdir(mode=0o700)
    if os.geteuid() == 0:
        os.chown(run, 65534, -1)  # another account's directory
    else:
        monkeypatch.setattr(os, "geteuid", lambda: ME + 1)
    with pytest.raises(BrokerError, match="owned by"):
        srv.start()


def test_a_slow_sender_cannot_hold_a_connection_past_the_deadline(tmp_path):
    with _server(tmp_path, timeout_s=0.5) as srv, socket.socket(socket.AF_UNIX) as s:
        s.settimeout(10)
        s.connect(str(srv.path))
        started = time.monotonic()
        answer = b""
        for _ in range(40):  # one byte every 0.1 s: each recv is quick, the whole is not
            try:
                s.sendall(b" ")
            except OSError:
                break
            s.setblocking(False)
            with contextlib.suppress(BlockingIOError):
                answer = s.recv(65536)
            s.setblocking(True)
            if answer:
                break
            time.sleep(0.1)
        elapsed = time.monotonic() - started
    assert answer and json.loads(answer)["error"] == "request-timeout"
    assert elapsed < 2.0


def test_an_unknown_peer_is_answered_without_holding_its_slot(tmp_path):
    srv = _server(tmp_path, max_connections=1, timeout_s=3)
    with srv, socket.socket(socket.AF_UNIX) as stranger:
        srv.credentials = lambda conn: (0, STRANGER_UID, 0)
        stranger.settimeout(5)
        stranger.connect(str(srv.path))
        assert json.loads(stranger.recv(65536))["error"] == "unknown-caller"
        srv.credentials = peer_credentials  # the stranger keeps its connection open
        time.sleep(0.2)
        assert _raw(srv.path, b'{"op": "actions"}\n')["ok"] is True


def test_agents_cannot_starve_the_approval_relay(tmp_path):
    srv = _server(tmp_path, max_connections=1, timeout_s=3)
    with srv, socket.socket(socket.AF_UNIX) as hold:
        hold.connect(str(srv.path))  # an agent's connection holds every agent slot
        time.sleep(0.2)
        assert _raw(srv.path, b'{"op": "actions"}\n')["error"] == "busy"
        srv.credentials = lambda conn: (0, RELAY_UID, 0)
        assert _raw(srv.path, b'{"op": "pending"}\n')["ok"] is True


# -- the socket file ---------------------------------------------------------------------------


def test_socket_file_and_directory_modes(tmp_path):
    svc = _service(tmp_path)
    with BrokerServer(svc, tmp_path / "run" / "b.sock") as srv:
        assert stat.S_IMODE(srv.path.stat().st_mode) == 0o600
        assert stat.S_ISSOCK(srv.path.stat().st_mode)
        assert stat.S_IMODE(srv.path.parent.stat().st_mode) == 0o700
    assert not srv.path.exists()
    with BrokerServer(svc, tmp_path / "run" / "b.sock", mode=0o660, group=os.getgid()) as srv:
        assert stat.S_IMODE(srv.path.stat().st_mode) == 0o660
    for bad in (0o666, 0o640 | 0o004, 0o060):
        with pytest.raises(ValueError):
            BrokerServer(svc, tmp_path / "run" / "b.sock", mode=bad)
    loose = tmp_path / "loose"
    loose.mkdir(mode=0o777)
    loose.chmod(0o777)
    with pytest.raises(BrokerError, match="0700 or 0750"):
        BrokerServer(svc, loose / "b.sock").start()
    (tmp_path / "run" / "file").write_text("not a socket")
    with pytest.raises(BrokerError, match="not a socket"):
        BrokerServer(svc, tmp_path / "run" / "file").start()


def test_a_stale_socket_is_replaced(tmp_path):
    svc = _service(tmp_path)
    path = tmp_path / "run" / "b.sock"
    path.parent.mkdir(mode=0o700)
    stale = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    stale.bind(str(path))
    stale.close()
    with BrokerServer(svc, path) as srv:
        assert BrokerClient(srv.path).actions()["caller"] == "profile:triage"


# -- the manifest ------------------------------------------------------------------------------


def test_peers_are_listed_once(tmp_path):
    path = _manifest_dir(tmp_path)
    doc = yaml.safe_load(path.read_text())
    assert validate_manifest(doc, path.parent)[1] == []
    doc["approval_relays"].append({"uid": ME, "issuer": "sso"})
    assert any("already listed in callers" in p for p in validate_manifest(doc, path.parent)[1])
    doc = yaml.safe_load(path.read_text())
    doc["callers"].append({"uid": ME, "profile": "profile:reader"})
    assert any("uid" in p and "already" in p for p in validate_manifest(doc, path.parent)[1])
    doc = yaml.safe_load(path.read_text())
    doc["callers"][0]["user"] = "someone"  # uid and user at once: the schema refuses it
    assert any(p.startswith("manifest:") for p in validate_manifest(doc, path.parent)[1])


def test_user_names_resolve_once_and_unknown_users_fail(tmp_path):
    m = {"callers": [{"user": "agent-one", "profile": "profile:triage"}]}
    m["approval_relays"] = [{"user": "hub", "issuer": "sso"}]
    peers = PeerMap(m, user_uid={"agent-one": 2001, "hub": 2002}.__getitem__)
    assert peers.lookup(2001).profile == "profile:triage"
    assert peers.lookup(2002).issuer == "sso" and peers.lookup(2002).role == "relay"
    assert peers.lookup(2003) is None
    with pytest.raises(ManifestError, match="no such user"):
        PeerMap(m, user_uid={"hub": 2002}.__getitem__)


def test_handle_request_is_the_whole_protocol(tmp_path):
    svc = _service(tmp_path)
    peers = PeerMap(svc.manifest)
    resp = handle_request(svc, peers, STRANGER_UID, b'{"op": "actions"}')
    assert resp["error"] == "unknown-caller"
    resp = handle_request(svc, peers, READER_UID, b'{"op": "actions"}')
    assert resp["ok"] and resp["result"]["caller"] == "profile:reader"


# -- the CLI -----------------------------------------------------------------------------------


@pytest.fixture
def cli(capsys):
    def run(*argv, code=0):
        rc = main([argv[0], "--json", *argv[1:]])
        out = capsys.readouterr()
        assert rc == code, (rc, out.out, out.err)
        return json.loads(out.out) if out.out.strip() else out

    return run


def test_cli_over_the_socket(broker, cli, tmp_path):
    s = str(broker.path)
    note = '{"name":"cli.md","content":"x"}'
    assert cli("call", "memory.write", "--socket", s, "--params", note)["result"]["bytes"] == 1
    rid = cli("submit", "service.restart", "--socket", s, "--params", '{"grace_s": 1}')
    rid = rid["request_id"]
    assert cli("pending", "--mine", "--socket", s)[0]["request_id"] == rid
    assert cli("actions", "--socket", s)["caller"] == "profile:triage"
    refused = cli("approve", rid, "--as", "sso:operator-one", "--socket", s, code=1)
    assert refused["error"] == "not-an-approval-relay"
    broker.as_uid(RELAY_UID)
    assert cli("approve", rid, "--as", "sso:operator-one", "--socket", s)["decision"] == "approved"
    assert (
        cli("audit", "--socket", s, "--operation", "approve", "--tail", "1")[0]["outcome"] == "ok"
    )
    broker.as_uid(None)
    assert cli("run", rid, "--socket", s)["result"]["exit_code"] == 0
    assert cli("status", rid, "--socket", s)["state"] == "done"
    # with a socket, an asserted identity is a usage error
    out = cli("status", rid, "--socket", s, "--as", "profile:reader", code=2)
    assert "authenticates you" in out.err


def test_cli_dev_identity_is_refused_unless_the_manifest_allows_it(tmp_path, cli, monkeypatch):
    path = _manifest_dir(tmp_path)  # dev_identity: false
    monkeypatch.setenv("HNX_BROKER_MANIFEST", str(path))
    monkeypatch.setenv("HNX_BROKER_STATE", str(tmp_path / "state"))
    monkeypatch.delenv("HNX_BROKER_SOCKET", raising=False)
    note = '{"name":"a.md","content":"x"}'
    for argv in (
        ("submit", "memory.write", "--as", "profile:triage", "--params", note),
        ("approve", "req-0001", "--as", "sso:operator-one"),
        ("actions", "--as", "profile:triage"),
    ):
        assert cli(*argv, code=1)["error"] == "dev-identity-disabled"
    doc = yaml.safe_load(path.read_text())
    del doc["dev_identity"]  # absent means false
    path.write_text(yaml.safe_dump(doc))
    assert cli("call", "memory.write", "--as", "profile:triage", "--params", note, code=1)[
        "error"
    ] == ("dev-identity-disabled")
    doc["dev_identity"] = True
    path.write_text(yaml.safe_dump(doc))
    assert cli("call", "memory.write", "--as", "profile:triage", "--params", note)["result"]
    assert cli("pending") == []  # the operator's read of the state needs no identity


def test_the_production_example_validates_and_refuses_dev_identity():
    doc = yaml.safe_load((EXAMPLES / "manifest.production.yml").read_text())
    assert validate_manifest(doc, EXAMPLES)[1] == []
    assert doc["dev_identity"] is False and doc["callers"] and doc["approval_relays"]
    walk = yaml.safe_load((EXAMPLES / "manifest.yml").read_text())
    assert walk["dev_identity"] is True


def test_serve_command_runs_until_terminated(tmp_path):
    import subprocess

    path = _manifest_dir(tmp_path)
    sock = tmp_path / "run" / "b.sock"
    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "homelabnext.cli",
            "broker",
            "serve",
            "--manifest",
            str(path),
            "--state",
            str(tmp_path / "state"),
            "--socket",
            str(sock),
        ],
        cwd=ROOT,
        env={**os.environ, "PYTHONPATH": str(ROOT)},
        stderr=subprocess.PIPE,
    )
    try:
        for _ in range(100):
            if sock.exists():
                break
            time.sleep(0.1)
        assert BrokerClient(sock).actions()["caller"] == "profile:triage"
    finally:
        proc.terminate()
        assert proc.wait(timeout=10) == 0
    assert not sock.exists()


# -- the MCP server's registration -------------------------------------------------------------


def test_hnx_broker_is_classified_and_kept_from_readers():
    assert default_classes().classify("mcp", "hnx-broker") == ("exec", "record-write")
    problems = reader_problems({"mcp": ["hnx-broker"], "capabilities": []})
    assert problems and "readers cannot act" in problems[0]
