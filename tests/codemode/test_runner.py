# SPDX-License-Identifier: Apache-2.0
"""The Code Mode runner (CM-5b): ``codemode.execute``'s handler against the reference broker and
the fake one, the forking test executor, the step journal, pause and resume, exec envelopes, and
the runner and sandbox roles over the broker's socket protocol."""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from conformance.fakes.command_broker import FakeBroker
from conformance.protocols.broker import CODEMODE_EXECUTE, ArgSpec, BrokerError, code_digest
from homelabnext.broker.client import BrokerClient
from homelabnext.broker.server import PeerMap, handle_request
from homelabnext.broker.service import BrokerService
from homelabnext.broker.validation import named_errors
from homelabnext.codemode.journal import Journal, JournalError
from homelabnext.codemode.runner import (
    Runner,
    RunnerError,
    SocketRunnerBroker,
    SocketSandboxBroker,
    load_index,
    unwrap,
)
from homelabnext.conform.runner import mutation_runs, run_capability

ROOT = Path(__file__).resolve().parents[2]
EXAMPLE = ROOT / "examples" / "broker" / "manifest.yml"
INDEX = ROOT / "examples" / "codemode"
AGENT = "profile:triage"
RUNNER = "svc:codemode-runner"
T0 = datetime(2026, 1, 15, 10, 0, tzinfo=UTC)


class Clock:
    def __init__(self) -> None:
        self.t = T0

    def __call__(self) -> datetime:
        return self.t

    def advance(self, **kw: float) -> None:
        self.t += timedelta(**kw)


def _example(tmp_path, executor, **kw):
    """The reference broker over the example manifest, with its runner registered."""
    clock = kw.pop("clock", None) or Clock()
    svc = BrokerService.from_manifest(
        EXAMPLE,
        tmp_path / "state",
        data_root=tmp_path / "data",
        clock=clock,
        resolve_secret={"DEMO_API_TOKEN": "fake-demo-token-4b1d"}.__getitem__,
        page_timers=False,
    )
    svc.allow(AGENT, [CODEMODE_EXECUTE])
    runner = Runner(svc, executor, tmp_path / "runner", index=load_index(INDEX), clock=clock, **kw)
    svc.register_runner(RUNNER, runner.handle)
    return svc, runner, clock


def _run(svc, code, *, eid="exec-0001", resume=False, actor=AGENT, **budget):
    params = {"execution_id": eid, "language": "python", "code": code}
    if budget:
        params["budget"] = budget
    if resume:
        params["resume"] = True
    res = svc.call(actor, CODEMODE_EXECUTE, params)
    assert named_errors("codemode/execution_result", res) == [], res
    return res


def _fake(tmp_path, executor, commands, **kw):
    """The fake broker with ``commands`` ({name: handler}) granted to the agent."""
    b = FakeBroker()
    for name, fn in commands.items():
        b.register(name, fn, {"name": ArgSpec("str")})
    b.allow(AGENT, [CODEMODE_EXECUTE, *commands])
    kw.setdefault("actions_for", lambda actor: sorted(commands))
    runner = Runner(b, executor, tmp_path / "runner", clock=Clock(), **kw)
    b.register_runner(RUNNER, runner.handle)
    return b, runner


# -- the conformance suite -------------------------------------------------------------------------


def test_the_suite_passes_on_both_brokers():
    for target in ("fake", "broker-reference"):
        run = run_capability("codemode-runner", target, ROOT)
        assert run.error is None and run.too_few is None, run.error
        assert [r.status for r in run.results] == ["pass"] * 8, [r.evidence for r in run.results]


def test_every_mutant_is_caught_by_its_own_check_only():
    runs = mutation_runs("codemode-runner", ROOT)
    assert len(runs) == 8
    for m in runs:
        assert m.detected and m.failed == [m.expected], (m.mutant, m.failed, m.reason)


# -- exec actions, approval and resume against the reference broker ------------------------------


def test_an_exec_result_is_unwrapped_to_its_output(tmp_path, executor):
    svc, _runner, _ = _example(tmp_path, executor)
    res = _run(
        svc,
        "result = broker.call('service.status', {'verbose': True}, target='svc:queue')\n",
    )
    assert res["status"] == "ok", res
    assert res["value"] == {"service": "svc:queue", "state": "running", "params": {"verbose": True}}
    (call,) = res["calls"]
    assert (call["action"], call["target"], call["outcome"]) == (
        "service.status",
        "svc:queue",
        "ok",
    )


def test_a_call_needing_approval_pauses_and_waits_without_a_token(tmp_path, executor):
    svc, runner, _clock = _example(tmp_path, executor)
    code = (
        "s = broker.call('service.status', {}, target='svc:queue')\n"
        "r = broker.call('service.restart', {'grace_s': 5}, target='svc:queue')\n"
        "result = [s['state'], r['would_restart']]\n"
    )
    first = _run(svc, code)
    assert first["status"] == "paused", first
    (pending,) = first["pending"]
    rid = pending["request_id"]
    assert pending["action"] == "service.restart" and pending["step"] == 1
    assert svc.detail(AGENT, rid)["state"] == "pending"
    issued = len(list((svc.tokens.root / "tokens").glob("*.json")))
    # not approved: the resume reads token_status and pauses again, issued nothing, sent nothing
    waiting = _run(svc, code, resume=True)
    assert waiting["status"] == "paused" and waiting["pending"] == first["pending"]
    assert [c.get("replayed", False) for c in waiting["calls"]] == [True, False]
    assert len(list((svc.tokens.root / "tokens").glob("*.json"))) == issued, "a token was issued"
    svc.approve(rid, "sso:operator-one")
    done = _run(svc, code, resume=True)
    assert done["status"] == "ok" and done["value"] == ["running", "svc:queue"], done
    assert [(c["step"], c["outcome"], c.get("replayed", False)) for c in done["calls"]] == [
        (0, "ok", True),
        (1, "ok", False),
    ]
    assert done["calls"][1]["request_id"] == rid
    assert svc.detail(AGENT, rid)["state"] == "done"
    steps = [(r["step"], r["outcome"]) for r in runner.journal(AGENT, "exec-0001")]
    assert steps == [(0, "ok"), (1, "pending"), (1, "ok")], "the journal is not append-only"
    again = _run(svc, code, resume=True)
    assert (again["status"], again["error"]["message"]) == ("error", "execution-not-resumable")
    ran = [
        r for r in svc.state.audit_records() if r.get("action") == "service.status"
    ]  # the status call ran once, in the first run
    assert [r["outcome"] for r in ran if r["operation"] == "call"].count("ok") == 1


def test_a_denied_paused_request_reaches_the_program_as_a_denial(tmp_path, executor):
    svc, _runner, _ = _example(tmp_path, executor)
    code = (
        "try:\n"
        "    broker.call('service.restart', {'grace_s': 5}, target='svc:queue')\n"
        "    result = 'restarted'\n"
        "except broker.Denied as exc:\n"
        "    result = exc.reason\n"
    )
    first = _run(svc, code)
    rid = first["pending"][0]["request_id"]
    svc.deny(rid, "sso:operator-one")
    res = _run(svc, code, resume=True)
    assert res["status"] == "ok" and res["value"] == "request-denied", res
    (call,) = res["calls"]
    assert (call["outcome"], call["reason"], call["request_id"]) == (
        "denied",
        "request-denied",
        rid,
    )


def test_a_submit_through_the_wire_pauses_and_runs_on_resume(tmp_path, executor):
    svc, _runner, _ = _example(tmp_path, executor)
    code = (
        "broker.submit('service.status', {}, target='svc:queue')\n"
        "result = broker.call('service.status', {'verbose': False}, target='svc:queue')['state']\n"
    )
    first = _run(svc, code)
    assert first["status"] == "paused" and first["pending"][0]["step"] == 0
    res = _run(svc, code, resume=True)  # a submit of an allowed action needs no approval
    assert res["status"] == "ok" and res["value"] == "running", res
    assert [c["outcome"] for c in res["calls"]] == ["ok", "ok"]


def test_a_result_schema_mismatch_and_envelopes_are_data(tmp_path, executor):
    envelope = {"exit_code": 0, "truncated": False, "stderr_bytes": 0}
    commands = {
        "cm.text": lambda **kw: {**envelope, "output": "plain text\n"},
        "cm.cut": lambda **kw: {**envelope, "output": "partial", "truncated": True},
        "cm.typed": lambda **kw: {"count": "not a number"},
    }
    index = {
        AGENT: {
            "cm.text": {"kind": "exec"},
            "cm.cut": {"kind": "exec"},
            "cm.typed": {"result": {"schema": {"type": "object", "required": ["n"]}}},
        }
    }
    b, _runner = _fake(tmp_path, executor, commands, index=index)
    code = (
        "out = [broker.call('cm.text', {'name': 'a'})]\n"
        "for action in ('cm.cut', 'cm.typed'):\n"
        "    try:\n"
        "        out.append(broker.call(action, {'name': 'a'}))\n"
        "    except broker.Error as exc:\n"
        "        out.append(exc.reason)\n"
        "result = out\n"
    )
    res = _run(b, code)
    assert res["value"] == ["plain text\n", "output-truncated", "result-schema-mismatch"], res
    assert [c["outcome"] for c in res["calls"]] == ["ok", "ok", "ok"], "the broker's outcome stands"
    assert [c.get("delivered_as") for c in res["calls"]] == [
        None,
        "output-truncated",
        "result-schema-mismatch",
    ], "an ok record must say what the program got instead"


def test_unwrap():
    env = {"exit_code": 0, "truncated": False, "stderr_bytes": 3, "output": {"a": 1}}
    assert unwrap(env, "exec") == ("ok", {"a": 1})
    assert unwrap({**env, "truncated": True}, "exec") == ("error", "output-truncated")
    assert unwrap(env, "lane") == ("ok", env), "only an exec action's envelope is unwrapped"
    assert unwrap(env, None) == ("ok", env), "an action the index does not know is not unwrapped"
    assert unwrap({**env, "extra": 1}, "exec")[1]["extra"] == 1, "only the exact envelope"
    assert unwrap("text", "exec") == ("ok", "text")


def test_a_program_that_changes_its_calls_is_not_replayed(tmp_path, executor):
    calls = []
    b, _runner = _fake(
        tmp_path,
        executor,
        {"cm.a": lambda **kw: calls.append(kw["name"]) or kw["name"], "cm.b": lambda **kw: 1},
    )
    code = (
        "import time\n"
        "broker.call('cm.a', {'name': str(time.time_ns())})\n"
        "broker.submit('cm.b', {'name': 'x'})\n"
    )
    assert _run(b, code)["status"] == "paused"
    res = _run(b, code, resume=True)
    assert res["status"] == "error" and res["error"]["kind"] == "runtime", res
    assert "differs from the journal" in res["error"]["message"]
    assert len(calls) == 1, "a call that differs from its journalled step was sent"


def test_a_resume_with_another_program_or_of_nothing_is_refused(tmp_path, executor):
    b, _runner = _fake(tmp_path, executor, {"cm.a": lambda **kw: 1})
    assert _run(b, "broker.submit('cm.a', {'name': 'x'})\n")["status"] == "paused"
    other = _run(b, "broker.submit('cm.a', {'name': 'y'})\n", resume=True)
    assert other["error"] == {"kind": "token", "message": "resume-code-mismatch"}
    unknown = _run(b, "result = 1\n", eid="exec-0002", resume=True)
    assert unknown["error"] == {"kind": "token", "message": "execution-not-resumable"}
    again = _run(b, "result = 1\n")  # a fresh run of an id that exists
    assert again["status"] == "error" and again["error"]["kind"] == "token", again


def test_a_program_error_and_an_unknown_language_are_results(tmp_path, executor):
    b, _runner = _fake(tmp_path, executor, {"cm.a": lambda **kw: 1})
    res = _run(b, "raise ValueError('boom')\n")
    assert res["status"] == "error" and res["error"]["kind"] == "runtime"
    params = {"execution_id": "exec-0003", "language": "typescript", "code": "1"}
    res = b.call(AGENT, CODEMODE_EXECUTE, params)
    assert res["status"] == "error" and res["error"]["kind"] == "sandbox", res


def test_a_wrong_token_on_the_wire_is_refused_and_not_forwarded(tmp_path, executor):
    ran = []
    b, _runner = _fake(tmp_path, executor, {"cm.a": lambda **kw: ran.append(1)})
    code = (
        "import json, socket\n"
        "s = socket.socket()\n"
        "s.connect(broker._addr)\n"
        "bad = 'hnxcmt_' + 'x' * 43\n"
        "s.sendall(json.dumps(dict(token=bad, action='cm.a', args={'name': 'a'})).encode() + b'\\n')\n"
        "result = json.loads(s.makefile().readline())\n"
    )
    res = _run(b, code)
    assert res["value"] == {"ok": False, "denied": True, "reason": "token-invalid"}, res
    assert res["calls"] == [], "a request the relay refused took a step"
    assert ran == []


# -- the journal ----------------------------------------------------------------------------------


def _record(step, outcome, **kw):
    rec = {
        "execution_id": "exec-0001",
        "actor": AGENT,
        "code_digest": code_digest("python", "x = 1"),
        "step": step,
        "action": "cm.a",
        "outcome": outcome,
        "request_id": f"req-{step}",
        "request_digest": "sha256:" + "0" * 64,
        "recorded_at": "2026-01-15T10:00:00Z",
    }
    rec.update(kw)
    return rec


def test_the_journal_is_append_only_bounded_and_private(tmp_path):
    j = Journal(tmp_path / "runner", max_result_bytes=64)
    assert j.begin(AGENT, "exec-0001", code_digest("python", "x = 1"), "tok-1", T0)
    assert not j.begin(AGENT, "exec-0001", code_digest("python", "x = 1"), "tok-2", T0)
    fp = j.fingerprint("call:cm.a", None, {"secret": "hunter2"})
    assert "hunter2" not in fp and fp.startswith("hmac-sha256:")
    j.answer(AGENT, "exec-0001", 1, call=fp, record=_record(1, "pending"))
    with pytest.raises(JournalError, match="without its intent"):  # an answer needs its intent
        j.steps(AGENT, "exec-0001")
    (j._dir(AGENT, "exec-0001") / "000001-0.json").unlink()
    j.intend(AGENT, "exec-0001", 0, op="call", action="cm.a", target=None, call=fp)
    with pytest.raises(JournalError):
        j.intend(AGENT, "exec-0001", 0, op="call", action="cm.a", target=None, call=fp)
    j.answer(AGENT, "exec-0001", 0, call=fp, record=_record(0, "pending"))
    with pytest.raises(JournalError):  # one answer: nothing replaces it
        j.answer(AGENT, "exec-0001", 0, call=fp, refusal={"outcome": "denied", "reason": "x"})
    j.intend_run(AGENT, "exec-0001", 0, call=fp)
    ok = _record(0, "ok", result={"a": 1}, result_digest="sha256:" + "1" * 64)
    j.settle(AGENT, "exec-0001", 0, call=fp, record=ok)
    with pytest.raises(JournalError):  # settled: nothing after it
        j.settle(AGENT, "exec-0001", 0, call=fp, record=ok)
    with pytest.raises(JournalError):
        j.intend(AGENT, "exec-0001", 200, op="call", action="cm.a", target=None, call=fp)
    kept, digest, whole = j.kept_result({"big": "x" * 100})
    assert kept is None and not whole and digest.startswith("sha256:")
    kept, _, whole = j.kept_result({"a": 1}, used=j.max_execution_bytes)
    assert kept is None and not whole, "the execution's total bound is not held"
    assert (j.root.stat().st_mode & 0o777) == 0o700
    key = j.root / "journal.key"
    assert (key.stat().st_mode & 0o777) == 0o600 and len(key.read_bytes()) == 32
    assert j.execution("profile:other", "exec-0001") is None, "an id is the actor's own"


def test_journal_records_are_checked_when_read(tmp_path):
    j = Journal(tmp_path / "runner")
    digest = code_digest("python", "x = 1")
    assert j.begin(AGENT, "exec-0001", digest, "tok-1", T0)
    fp = j.fingerprint("call:cm.a", None, {})
    j.intend(AGENT, "exec-0001", 0, op="call", action="cm.a", target=None, call=fp)
    other = _record(0, "pending", execution_id="exec-0002")
    j.answer(AGENT, "exec-0001", 0, call=fp, record=other)
    with pytest.raises(JournalError, match="another execution"):
        j.steps(AGENT, "exec-0001")
    path = next(j._dir(AGENT, "exec-0001").glob("000000-0.json"))
    path.write_text('{"record": {"step": "zero"}}')
    with pytest.raises(JournalError, match="malformed"):
        j.records(AGENT, "exec-0001")


def test_the_journal_tightens_and_takes_over_what_a_crash_left(tmp_path):
    # a directory someone made under the common umask 022 (0755), looser than the journal allows
    old = os.umask(0o022)
    try:
        (tmp_path / "runner" / "journal").mkdir(parents=True)
    finally:
        os.umask(old)
    assert (tmp_path / "runner" / "journal").stat().st_mode & 0o077, "the setup is not looser"
    j = Journal(tmp_path / "runner")
    assert (j.root.stat().st_mode & 0o777) == 0o700, "an existing directory was not tightened"
    j._dir(AGENT, "exec-0001").mkdir(mode=0o700)  # a crash between mkdir and meta.json
    assert j.begin(AGENT, "exec-0001", code_digest("python", "x = 1"), "tok-1", T0)
    assert j.execution(AGENT, "exec-0001")["state"] == "running"


def test_the_state_change_is_a_check_and_set(tmp_path):
    j = Journal(tmp_path / "runner")
    j.begin(AGENT, "exec-0001", code_digest("python", "x = 1"), "tok-1", T0)
    assert j.update(AGENT, "exec-0001", T0, state="paused")
    assert j.update(AGENT, "exec-0001", T0, expect="paused", state="running")
    assert not j.update(AGENT, "exec-0001", T0, expect="paused", state="running")


def test_the_journal_refuses_symlinks(tmp_path):
    (tmp_path / "elsewhere").mkdir()
    (tmp_path / "runner").mkdir()
    os.symlink(tmp_path / "elsewhere", tmp_path / "runner" / "journal")
    with pytest.raises(JournalError):
        Journal(tmp_path / "runner")


def test_the_sweep_keeps_paused_executions_longer(tmp_path):
    j = Journal(tmp_path / "runner", retention_days=7, paused_retention_days=30)
    digest = code_digest("python", "x = 1")
    for eid, state in (("exec-done", "finished"), ("exec-held", "paused")):
        j.begin(AGENT, eid, digest, "tok-1", T0)
        j.update(AGENT, eid, T0, state=state)
    assert j.sweep(T0 + timedelta(days=8))["removed"] == 1
    assert j.execution(AGENT, "exec-done") is None and j.execution(AGENT, "exec-held")
    assert j.sweep(T0 + timedelta(days=31))["removed"] == 1
    assert j.execution(AGENT, "exec-held") is None


def test_a_large_result_is_journalled_by_digest_only(tmp_path, executor):
    b, runner = _fake(
        tmp_path,
        executor,
        {"cm.big": lambda **kw: "x" * 500, "cm.hold": lambda **kw: 1},
        max_result_bytes=100,
    )
    code = (
        "out = []\n"
        "try:\n"
        "    out.append(broker.call('cm.big', {'name': 'a'}))\n"
        "except broker.Error as exc:\n"
        "    out.append(exc.reason)\n"
        "result = out\n"
    )
    res = _run(b, code)
    assert res["value"] == ["result-too-large"], res
    (rec,) = runner.journal(AGENT, "exec-0001")
    assert rec["result"] is None and rec["result_digest"].startswith("sha256:")


def test_an_invalid_execution_request_is_a_runner_error(tmp_path, executor):
    _b, runner = _fake(tmp_path, executor, {"cm.a": lambda **kw: 1})
    with pytest.raises(RunnerError):
        runner.handle({"request_id": "req-1", "actor": AGENT, "params": {"code": "x"}})


# -- the socket roles -----------------------------------------------------------------------------

AGENT_UID, RUNNER_UID, POOL_UID = 2001, 3001, 3102


class _Wire(BrokerClient):
    """A broker client whose exchange is one request to the service as the peer ``uid``, through
    the server's own request handling (bearer line included), with no socket."""

    def __init__(self, svc, peers, uid):
        super().__init__("/nonexistent")
        self.svc, self.peers, self.uid = svc, peers, uid

    def _exchange(self, op, bearer, fields):
        body = {"v": 1, "op": op, **{k: v for k, v in fields.items() if v is not None}}
        response = handle_request(
            self.svc, self.peers, self.uid, json.dumps(body).encode(), bearer=bearer
        )
        if not response["ok"]:
            from homelabnext.broker.client import _raise

            _raise(response)
        return response


def test_the_runner_and_its_relay_speak_as_their_own_peers(tmp_path, executor):
    manifest = {
        "manifest_id": "cm",
        "default": "deny",
        "mode": "enforce",
        "actions": [],
        "grants": [],
        "callers": [{"uid": AGENT_UID, "profile": AGENT}],
        "codemode": {
            "runners": [{"uid": RUNNER_UID, "service": RUNNER}],
            "sandboxes": [{"uid": POOL_UID}],
        },
    }
    svc = BrokerService(tmp_path / "state", manifest, data_root=tmp_path / "data", clock=Clock())
    ran = []
    svc.register("cm.echo", lambda **kw: ran.append(kw["name"]) or kw, {"name": ArgSpec("str")})
    svc.allow(AGENT, [CODEMODE_EXECUTE, "cm.echo"])
    peers = PeerMap(svc.manifest)
    runner = Runner(
        SocketRunnerBroker(_Wire(svc, peers, RUNNER_UID)),
        executor,
        tmp_path / "runner",
        sandbox_broker=SocketSandboxBroker(_Wire(svc, peers, POOL_UID)),
        actions_for=lambda actor: ["cm.echo"],
        clock=Clock(),
    )
    svc.register_runner(RUNNER, runner.handle)
    code = (
        "a = broker.call('cm.echo', {'name': 'one'})\n"
        "broker.submit('cm.echo', {'name': 'two'})\n"
        "result = a\n"
    )
    agent = _Wire(svc, peers, AGENT_UID)
    params = {"execution_id": "exec-0001", "language": "python", "code": code}
    first = agent.call(CODEMODE_EXECUTE, params)
    assert first["status"] == "paused", first
    done = agent.call(CODEMODE_EXECUTE, {**params, "resume": True})
    assert done["status"] == "ok" and done["value"] == {"name": "one"}, done
    assert ran == ["one", "two"]
    vias = {r.get("via") for r in svc.state.audit_records() if r.get("token_id")}
    assert {f"uid:{RUNNER_UID}", f"uid:{POOL_UID}"} <= vias, vias


def test_a_broker_that_cannot_be_reached_is_an_error_call(tmp_path, executor):
    class Down:
        def token_call(self, *a, **kw):
            err = BrokerError("socket gone")
            err.reason = "transport-error"
            raise err

        token_submit = token_call

    b, _runner = _fake(tmp_path, executor, {"cm.a": lambda **kw: 1}, sandbox_broker=Down())
    code = (
        "try:\n"
        "    broker.call('cm.a', {'name': 'x'})\n"
        "except broker.Error as exc:\n"
        "    result = exc.reason\n"
    )
    res = _run(b, code)
    assert res["value"] == "broker-unreachable"
    assert res["calls"] == [
        {"step": 0, "action": "cm.a", "outcome": "error", "reason": "broker-unreachable"}
    ]
