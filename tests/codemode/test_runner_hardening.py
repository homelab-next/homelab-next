# SPDX-License-Identifier: Apache-2.0
"""The runner's review fixes (CM-5b): steps only for calls the relay accepted, bounded steps and
refusals, an intent before every call and no silent journal failure, unknown steps never re-sent,
interrupted runs, atomic resumes, validated targets, a relay one idle connection cannot block, a
peer check, and the expired state.  The first three tests are the review's probes."""

from __future__ import annotations

import json
import os
import threading

import pytest
from test_runner import AGENT, _example, _fake, _run

from conformance.protocols.broker import CODEMODE_EXECUTE
from homelabnext.codemode.journal import JournalError
from homelabnext.codemode.runner import MAX_LOCAL_REFUSALS, Runner


def _counted(*names):
    ran = {n: [] for n in names}

    def make(n):
        return lambda **kw: ran[n].append(kw["name"]) or kw["name"]

    return ran, {n: make(n) for n in names}


# -- the probes ------------------------------------------------------------------------------------


def test_a_bad_token_line_takes_no_step_and_a_resume_sends_nothing_twice(tmp_path, executor):
    """Probe H1: a co-tenant's (or the program's) bad-token line used to take a step, so the
    resume re-sent step 0 and then failed replay-mismatch."""
    ran, cmds = _counted("cm.a", "cm.b")
    b, runner = _fake(tmp_path, executor, cmds)
    orig = runner.serve_call
    state = {"inject": True}

    def serve(run, msg):
        if state["inject"]:
            state["inject"] = False
            got = orig(run, {"token": "nope", "action": "cm.a", "args": {}})
            assert got == {"ok": False, "denied": True, "reason": "token-invalid"}
        return orig(run, msg)

    runner.serve_call = serve
    code = "broker.call('cm.a', {'name': 'side-effect'})\nbroker.submit('cm.b', {'name': 'x'})\n"
    first = _run(b, code)
    assert first["status"] == "paused" and [c["step"] for c in first["calls"]] == [0, 1]
    res = _run(b, code, resume=True)
    assert res["status"] == "ok", res
    assert [c.get("replayed", False) for c in res["calls"]] == [True, False]
    assert ran["cm.a"] == ["side-effect"], f"step 0 was sent again: {ran['cm.a']}"


def test_a_flood_of_bad_lines_ends_the_run_and_sends_nothing(tmp_path, executor):
    """Probe H1 (flood): free refusals at the relay are bounded."""
    ran, cmds = _counted("cm.a")
    b, runner = _fake(tmp_path, executor, cmds)
    code = (
        "import json, socket\n"
        f"for i in range({MAX_LOCAL_REFUSALS + 5}):\n"
        "    s = socket.socket(); s.connect(broker._addr)\n"
        "    s.sendall(json.dumps(dict(token='bad', action='cm.a', args={})).encode()+b'\\n')\n"
        "    s.makefile().readline(); s.close()\n"
        "try:\n"
        "    broker.call('cm.a', {'name': 'side-effect'})\n"
        "except broker.Error as exc:\n"
        "    result = exc.reason\n"
    )
    res = _run(b, code)
    assert res["status"] == "error" and res["error"]["kind"] == "token", res
    assert res["calls"] == [] and ran["cm.a"] == [], "a call was sent after the flood"
    assert runner.journal(AGENT, "exec-0001") == []


@pytest.mark.parametrize(
    "target", ["SVC:Queue", "x" * 300, "svc:queue\nfoo", "svc:queue\n", 7, "svc:"]
)
def test_an_invalid_target_is_refused_before_the_broker(tmp_path, executor, target):
    """Probe M3: an invalid target crashed the relay and dropped the record."""
    svc, _runner, _ = _example(tmp_path, executor)
    code = (
        "try:\n"
        f"    result = broker.call('service.status', {{}}, target={target!r})\n"
        "except broker.Error as exc:\n"
        "    result = exc.reason\n"
    )
    res = _run(svc, code)
    assert (res["status"], res["value"], res["calls"]) == ("ok", "request-malformed", [])
    sent = [a for a in svc.state.audit_records() if a.get("action") == "service.status"]
    assert sent == [], "an invalid target reached the broker"


# -- bounds and journal failures -------------------------------------------------------------------


def test_steps_are_bounded_and_refused_before_sending(tmp_path, executor):
    """H2: past MAX_STEPS calls nothing more is sent, the run ends limit (calls), and calls stays
    within the schema's bound, even when every call is a free (uncounted) broker refusal."""
    _ran, cmds = _counted("cm.a")
    b, _runner = _fake(tmp_path, executor, cmds, actions_for=lambda actor: ["cm.a"])
    b.register("cm.other", lambda **kw: 1, {})
    b.allow("profile:admin", ["cm.other"])
    code = (
        "for i in range(205):\n"
        "    try:\n"
        "        broker.call('cm.other', {})\n"
        "    except (broker.Denied, broker.Error):\n"
        "        pass\n"
        "result = 'done'\n"
    )
    res = _run(b, code, max_calls=50)
    assert (res["status"], res.get("limit")) == ("limit", "calls"), res["status"]
    assert len(res["calls"]) == 200
    audited = [r for r in b.audit() if r.command == "cm.other"]
    assert len(audited) == 200, f"{len(audited)} calls reached the broker"


def test_an_answer_the_journal_cannot_write_stops_the_run(tmp_path, executor, monkeypatch):
    """H2: the call happened, so it is reported; the run stops, ends error, and its execution
    never resumes (the token is spent finished)."""
    ran, cmds = _counted("cm.a", "cm.b")
    b, runner = _fake(tmp_path, executor, cmds)

    def full(*a, **kw):
        raise JournalError("No space left on device")

    monkeypatch.setattr(runner.store, "answer", full)
    code = (
        "out = []\n"
        "for name in ('one', 'two'):\n"
        "    try:\n"
        "        out.append(broker.call('cm.a', {'name': name}))\n"
        "    except broker.Error as exc:\n"
        "        out.append(exc.reason)\n"
        "broker.submit('cm.b', {'name': 'held'})\n"
        "result = out\n"
    )
    res = _run(b, code)
    assert res["status"] == "error" and res["error"]["kind"] == "broker", res
    assert ran["cm.a"] == ["one"] and ran["cm.b"] == [], "a call was sent after the failure"
    assert [(c["step"], c["outcome"]) for c in res["calls"]] == [(0, "ok")]
    again = _run(b, code, resume=True)
    assert again["status"] == "error" and ran["cm.a"] == ["one"], "the execution resumed"


def test_an_intent_the_journal_cannot_write_is_never_sent(tmp_path, executor, monkeypatch):
    ran, cmds = _counted("cm.a")
    b, runner = _fake(tmp_path, executor, cmds)
    monkeypatch.setattr(
        runner.store, "intend", lambda *a, **kw: (_ for _ in ()).throw(JournalError("ro"))
    )
    res = _run(b, "broker.call('cm.a', {'name': 'x'})\n")
    assert res["status"] == "error" and ran["cm.a"] == [] and res["calls"] == []


def test_a_journal_that_fails_inside_handle_is_an_error_result(tmp_path, executor, monkeypatch):
    """Design item 5: a JournalError outside a call (the execution's directory gone) is a result
    with the token spent, never a handler crash."""
    _ran, cmds = _counted("cm.a")
    b, runner = _fake(tmp_path, executor, cmds)
    spent = []
    monkeypatch.setattr(b, "spend_token", lambda r, t, o="finished": spent.append(o))

    def gone(*a, **kw):
        raise JournalError("no journal for execution")

    monkeypatch.setattr(runner.store, "begin", gone)
    res = _run(b, "result = 1\n")
    assert res["status"] == "error" and res["error"]["kind"] == "broker"
    assert spent == ["finished"], "the token was not spent"


def test_a_step_with_no_recorded_answer_is_never_sent_again(tmp_path, executor):
    """The crash window: the broker ran the call and the answer was never written."""
    ran, cmds = _counted("cm.a", "cm.b")
    b, runner = _fake(tmp_path, executor, cmds)
    code = "broker.call('cm.a', {'name': 'once'})\nbroker.submit('cm.b', {'name': 'x'})\n"
    assert _run(b, code)["status"] == "paused"
    d = runner.store._dir(AGENT, "exec-0001")
    (d / "000000-0.json").unlink()  # as if the runner died between the broker and the journal
    res = _run(b, code, resume=True)
    assert res["status"] == "error" and "step-outcome-unknown" in res["error"]["message"], res
    assert ran == {"cm.a": ["once"], "cm.b": []}


def test_a_crashed_run_is_interrupted_and_never_resumes(tmp_path, executor):
    ran, cmds = _counted("cm.a", "cm.b")
    b, runner = _fake(tmp_path, executor, cmds)
    code = "broker.call('cm.a', {'name': 'once'})\nbroker.submit('cm.b', {'name': 'x'})\n"
    assert _run(b, code)["status"] == "paused"
    gone = {**runner._identity, "pid": 2**22 + 7, "pid_start": "1", "request_id": "req-gone"}
    runner.store.update(AGENT, "exec-0001", runner.clock(), state="running", owner=gone)
    res = _run(b, code, resume=True)
    assert res["error"] == {"kind": "token", "message": "execution-interrupted"}, res
    assert runner.store.execution(AGENT, "exec-0001")["state"] == "interrupted"
    assert ran["cm.b"] == []
    runner.store.update(AGENT, "exec-0001", runner.clock(), state="running", owner=gone)
    assert runner.sweep(force=True)["interrupted"] == 1


def test_two_resumes_at_once_run_the_paused_request_once(tmp_path, executor):
    svc, _runner, _ = _example(tmp_path, executor)
    code = "result = broker.call('service.restart', {'grace_s': 1}, target='svc:queue')\n"
    first = _run(svc, code)
    svc.approve(first["pending"][0]["request_id"], "sso:operator-one")
    params = {"execution_id": "exec-0001", "language": "python", "code": code, "resume": True}
    got, gate = [], threading.Barrier(2)

    def resume():
        gate.wait()
        got.append(svc.call(AGENT, CODEMODE_EXECUTE, params))

    threads = [threading.Thread(target=resume) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sorted(r["status"] for r in got) == ["error", "ok"], got
    ran = [
        r
        for r in svc.state.audit_records()
        if r.get("action") == "service.restart" and r.get("operation") == "run"
    ]
    assert [r["outcome"] for r in ran if r["outcome"] != "started"] == ["ok"]


def test_an_expired_approval_pauses_again_without_a_token(tmp_path, executor):
    svc, _runner, clock = _example(tmp_path, executor)
    code = "result = broker.call('service.restart', {'grace_s': 1}, target='svc:queue')\n"
    first = _run(svc, code)
    svc.approve(first["pending"][0]["request_id"], "sso:operator-one")
    clock.advance(seconds=901)  # past approval_ttl_s
    tokens = len(list((svc.tokens.root / "tokens").glob("*.json")))
    res = _run(svc, code, resume=True)
    assert res["status"] == "paused" and res["pending"] == first["pending"], res
    assert len(list((svc.tokens.root / "tokens").glob("*.json"))) == tokens


def test_a_fresh_run_never_touches_an_existing_journal(tmp_path, executor):
    """Nit: when the broker knows no execution of that id but the runner's journal does, the
    run is refused and the existing journal's state stays as it was."""
    _ran, cmds = _counted("cm.a", "cm.b")
    b, _runner = _fake(tmp_path, executor, cmds)
    code = "broker.submit('cm.b', {'name': 'x'})\n"
    assert _run(b, code)["status"] == "paused"
    b2, runner2 = _fake(tmp_path, executor, cmds)  # a new broker over the same runner state
    res = _run(b2, code)
    assert res["error"] == {"kind": "token", "message": "execution-exists"}, res
    assert runner2.store.execution(AGENT, "exec-0001")["state"] == "paused"


# -- the relay -------------------------------------------------------------------------------------


def test_an_idle_connection_does_not_block_the_calls(tmp_path, executor):
    """M4: connections are served concurrently with a short read timeout."""
    _ran, cmds = _counted("cm.a")
    b, _runner = _fake(tmp_path, executor, cmds)
    code = (
        "import socket\n"
        "idle = socket.socket(); idle.connect(broker._addr)\n"
        "result = [broker.call('cm.a', {'name': str(i)}) for i in range(3)]\n"
        "idle.close()\n"
    )
    res = _run(b, code, wall_s=4)
    assert res["status"] == "ok" and res["value"] == ["0", "1", "2"], res


def test_the_relay_serves_only_the_users_it_names(tmp_path, executor):
    ran, cmds = _counted("cm.a")
    b, _runner = _fake(tmp_path, executor, cmds, relay_uids=[os.getuid()])
    assert _run(b, "result = broker.call('cm.a', {'name': 'me'})\n")["value"] == "me"
    b2, _runner2 = _fake(tmp_path / "other", executor, cmds, relay_uids=[os.getuid() + 1])
    code = (
        "try:\n"
        "    broker.call('cm.a', {'name': 'stranger'})\n"
        "except broker.Error as exc:\n"
        "    result = exc.reason\n"
    )
    res = _run(b2, code)
    assert res["value"] == "broker-unreachable" and res["calls"] == []
    assert ran["cm.a"] == ["me"]


def test_the_relay_stops_before_the_result(tmp_path, executor):
    """Nothing changes a run once its result is built: a request after the end is refused."""
    ran, cmds = _counted("cm.a")
    b, runner = _fake(tmp_path, executor, cmds)
    seen = {}
    orig = Runner._finish

    def finish(self, run, res, **kw):
        out = orig(self, run, res, **kw)
        seen["late"] = self.serve_call(run, {"token": run.secret, "action": "cm.a", "args": {}})
        return out

    runner._finish = finish.__get__(runner)
    res = _run(b, "result = broker.call('cm.a', {'name': 'x'})\n")
    assert res["status"] == "ok" and seen["late"]["reason"] == "run-ended"
    assert ran["cm.a"] == ["x"]


def test_relay_replies_are_json_lines(tmp_path, executor):
    _ran, cmds = _counted("cm.a")
    b, _runner = _fake(tmp_path, executor, cmds)
    code = (
        "import json, socket\n"
        "s = socket.socket(); s.connect(broker._addr)\n"
        "s.sendall(b'not json\\n')\n"
        "result = json.loads(s.makefile().readline())\n"
    )
    res = _run(b, code)
    assert res["value"] == {"ok": False, "error": True, "reason": "request-malformed"}
    assert json.dumps(res["calls"]) == "[]"


def test_a_pause_the_journal_cannot_record_is_reported_stopped(tmp_path, executor, monkeypatch):
    """A pending answer the journal cannot write: the run is not paused (it could never resume
    safely), and the call is reported as an error call, run-stopped, naming its request."""
    _ran, cmds = _counted("cm.b")
    b, runner = _fake(tmp_path, executor, cmds)
    orig = runner.store.answer

    def answer(*a, **kw):
        if (kw.get("record") or {}).get("outcome") == "pending":
            raise JournalError("No space left on device")
        return orig(*a, **kw)

    monkeypatch.setattr(runner.store, "answer", answer)
    res = _run(b, "broker.submit('cm.b', {'name': 'held'})\n")
    assert res["status"] == "error" and "pending" not in res, res
    (call,) = res["calls"]
    assert (call["outcome"], call["reason"]) == ("error", "run-stopped") and call["request_id"]
