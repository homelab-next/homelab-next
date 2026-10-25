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
from test_runner import AGENT, T0, _example, _fake, _run

from conformance.protocols.broker import CODEMODE_EXECUTE
from homelabnext.codemode.journal import JournalError
from homelabnext.codemode.runner import MAX_LOCAL_REFUSALS, MAX_RELAY_REFUSALS, Runner


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


def test_lines_without_the_token_never_count_against_the_run(tmp_path, executor):
    """Probe H1 (flood), round 3: lines without the run's token are answered token-invalid,
    then dropped unanswered, and never count: the program's own call still runs."""
    ran, cmds = _counted("cm.a")
    b, _runner = _fake(tmp_path, executor, cmds)
    code = (
        "import json, socket\n"
        "replies = []\n"
        f"for i in range({MAX_LOCAL_REFUSALS + 70}):\n"
        "    s = socket.socket(); s.connect(broker._addr)\n"
        "    s.sendall(json.dumps(dict(token='bad', action='cm.a', args={})).encode()+b'\\n')\n"
        "    replies.append(s.makefile().readline()); s.close()\n"
        "result = [broker.call('cm.a', {'name': 'mine'}), sum(1 for r in replies if r)]\n"
    )
    res = _run(b, code)
    assert res["status"] == "ok" and res["value"] == ["mine", 64], res
    assert ran["cm.a"] == ["mine"] and len(res["calls"]) == 1
    assert "relay_refusals" not in res, "a line without the token was listed as the program's"


def test_a_flood_of_the_programs_own_malformed_calls_ends_the_run(tmp_path, executor):
    """The program's own refusals (with its token) are bounded: past them nothing is sent."""
    ran, cmds = _counted("cm.a")
    b, runner = _fake(tmp_path, executor, cmds)
    code = (
        "import json, socket\n"
        f"for i in range({MAX_LOCAL_REFUSALS + 5}):\n"
        "    s = socket.socket(); s.connect(broker._addr)\n"
        "    line = dict(token=broker._token, action='NOT AN ACTION', args={})\n"
        "    s.sendall(json.dumps(line).encode()+b'\\n')\n"
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
    # every one of them is in the result, never sent: the malformed ones, then the bound's
    refused = [(r["action"], r["outcome"], r["reason"]) for r in res["relay_refusals"]]
    assert refused == [("NOT AN ACTION", "error", "request-malformed")] * MAX_LOCAL_REFUSALS + [
        ("NOT AN ACTION", "error", "too-many-refusals")
    ] * 5 + [("cm.a", "error", "too-many-refusals")]
    assert {r["at_step"] for r in res["relay_refusals"]} == {0}


def test_refusals_after_a_pause_never_change_its_outcome(tmp_path, executor):
    """Probe pause-flood: 33 bad lines after a legitimate submit used to turn the paused run
    into an error and orphan its request."""
    ran, cmds = _counted("cm.a", "cm.b")
    b, runner = _fake(tmp_path, executor, cmds)
    orig = runner.serve_call

    def serve(run, msg):
        got = orig(run, msg)
        if got and got.get("pending"):
            for _ in range(MAX_LOCAL_REFUSALS + 1):
                orig(run, {"token": "bad", "action": "cm.a"})
                orig(run, {"token": run.secret, "action": "NOT AN ACTION"})
        return got

    runner.serve_call = serve
    code = "broker.call('cm.a', {'name': 'a'})\nbroker.submit('cm.b', {'name': 'b'})\n"
    first = _run(b, code)
    assert first["status"] == "paused", first
    assert runner.store.execution(AGENT, "exec-0001")["state"] == "paused"
    after = [
        (r["at_step"], r["action"], r["outcome"], r["reason"]) for r in first["relay_refusals"]
    ]
    assert after == [(2, "NOT AN ACTION", "denied", "token-paused")] * (MAX_LOCAL_REFUSALS + 1)
    runner.serve_call = orig
    res = _run(b, code, resume=True)
    assert res["status"] == "ok" and ran == {"cm.a": ["a"], "cm.b": ["b"]}, res


def test_relay_refusals_are_bounded_and_the_rest_counted(tmp_path, executor):
    """A result lists the first MAX_RELAY_REFUSALS of the program's requests the relay refused,
    each action cut to one line, and counts the rest."""
    _ran, cmds = _counted("cm.a", "cm.b")
    b, runner = _fake(tmp_path, executor, cmds)
    orig = runner.serve_call

    def serve(run, msg):
        got = orig(run, msg)
        if got and got.get("pending"):
            for i in range(MAX_RELAY_REFUSALS + 6):
                orig(run, {"token": run.secret, "op": "submit", "action": f"cm.a\n{i}" + "x" * 200})
        return got

    runner.serve_call = serve
    res = _run(b, "broker.submit('cm.b', {'name': 'b'})\n")
    assert res["status"] == "paused", res
    assert len(res["relay_refusals"]) == MAX_RELAY_REFUSALS
    assert res["relay_refusals_omitted"] == 6
    first = res["relay_refusals"][0]
    assert first["op"] == "submit" and first["action"] == "cm.a 0" + "x" * 122, first


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
    assert res["relay_refusals"] == [
        {
            "at_step": 0,
            "op": "call",
            "action": "service.status",
            "outcome": "error",
            "reason": "request-malformed",
        }
    ]
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
    past = [(r["at_step"], r["action"], r["reason"]) for r in res["relay_refusals"]]
    # the one the executor's client sends past the bound (its own cap is one more), listed
    assert past == [(200, "cm.other", "call-cap-reached")]
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
    assert res["value"] == {"ok": False, "denied": True, "reason": "token-invalid"}
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
    assert (call["outcome"], call.get("delivered_as")) == ("pending", "journal-unavailable")
    assert call["request_id"] and b.status(AGENT, call["request_id"]).state == "pending"


# -- round 3: the verifier's probes ------------------------------------------------------------


@pytest.mark.parametrize("odd", [float("nan"), float("inf"), {1, 2}])
def test_a_result_that_is_not_json_is_a_defined_answer(tmp_path, executor, odd):
    """Probe nan: a NaN result made canonical() raise after the broker ran the call; the call
    vanished from calls, the run paused, and its resume was unrecoverable."""
    ran, cmds = _counted("cm.a", "cm.b")
    cmds["cm.a"] = lambda **kw: ran["cm.a"].append(kw["name"]) or odd
    b, _runner = _fake(tmp_path, executor, cmds)
    code = (
        "try:\n"
        "    broker.call('cm.a', {'name': 'a'})\n"
        "    seen = 'value'\n"
        "except broker.Error as exc:\n"
        "    seen = exc.reason\n"
        "broker.submit('cm.b', {'name': 'b'})\n"
        "result = seen\n"
    )
    first = _run(b, code)
    assert first["status"] == "paused", first
    call = first["calls"][0]
    assert (call["outcome"], call.get("delivered_as")) == ("ok", "result-not-json"), call
    res = _run(b, code, resume=True)
    assert (res["status"], res["value"]) == ("ok", "result-not-json"), res
    assert res["calls"][0].get("replayed") and ran == {"cm.a": ["a"], "cm.b": ["b"]}


def test_any_failure_after_the_send_stops_the_run(tmp_path, executor, monkeypatch):
    """Must-fix 1: whatever raises once the broker has answered, the call is reported, the run
    ends error and its token is spent finished; nothing is swallowed by the relay."""
    ran, cmds = _counted("cm.a", "cm.b")
    b, runner = _fake(tmp_path, executor, cmds)

    def boom(*a, **kw):
        raise RuntimeError("an unexpected bug after the broker answered")

    monkeypatch.setattr(runner, "_answered", boom)
    code = (
        "try:\n"
        "    broker.call('cm.a', {'name': 'a'})\n"
        "except broker.Error:\n"
        "    pass\n"
        "broker.submit('cm.b', {'name': 'b'})\n"
    )
    res = _run(b, code)
    assert res["status"] == "error" and res["error"]["kind"] == "broker", res
    assert [c["step"] for c in res["calls"]] == [0] and ran == {"cm.a": ["a"], "cm.b": []}
    again = _run(b, code, resume=True)
    assert again["status"] == "error" and ran["cm.a"] == ["a"], "the execution resumed"


def test_a_resume_that_read_before_another_ran_backs_off(tmp_path, executor):
    """Probe stale: resume B ran (and paused again) inside resume A's window; A claimed with
    its stale journal and ended the execution, orphaning B's request."""
    ran, cmds = _counted("cm.b", "cm.c")
    b, runner = _fake(tmp_path, executor, cmds)
    code = "broker.submit('cm.b', {'name': 'b'})\nbroker.submit('cm.c', {'name': 'c'})\n"
    assert _run(b, code)["status"] == "paused"
    orig, inner = b.token_status, {}

    def token_status(runner_id, token_id):
        got = orig(runner_id, token_id)
        if not inner:
            inner["started"] = True
            inner["b"] = _run(b, code, resume=True)  # B, entirely inside A's window
        return got

    b.token_status = token_status
    res = _run(b, code, resume=True)
    assert inner["b"]["status"] == "paused", inner["b"]
    assert res["error"] == {"kind": "token", "message": "execution-not-resumable"}, res
    meta = runner.store.execution(AGENT, "exec-0001")
    assert meta["state"] == "paused", "the stale resume changed the execution"
    b.token_status = orig
    last = _run(b, code, resume=True)
    assert last["status"] == "ok" and ran == {"cm.b": ["b"], "cm.c": ["c"]}, last


def test_dripping_connections_do_not_lock_the_program_out(tmp_path, executor):
    """Probe drip: eight connections dripping a byte at a time held every slot; the program got
    busy and the run's end waited for them."""
    import socket as _socket
    import time

    _ran, cmds = _counted("cm.a")
    b, _runner = _fake(tmp_path, executor, cmds)
    orig, socks = executor.run, []

    def run(code, *, broker, **kw):
        for _ in range(8):
            s = _socket.create_connection((broker.host, broker.port))
            s.sendall(b" ")
            socks.append(s)
        return orig(code, broker=broker, **kw)

    executor.run = run
    try:
        code = "result = broker.call('cm.a', {'name': 'mine'})\n"
        start = time.monotonic()  # hermetic: allow measuring the run's end, not a date
        res = _run(b, code, wall_s=30)
        took = time.monotonic() - start  # hermetic: allow measuring the run's end, not a date
    finally:
        executor.run = orig
        for s in socks:
            s.close()
    assert res["status"] == "ok" and res["value"] == "mine", res
    assert took < 3.0, f"the run's end waited {took:.1f}s for connections that never sent"


def test_the_peer_uid_is_read_from_the_connection_and_only_established(tmp_path):
    """Probe uid: the lookup used the listener's address (which broke a wildcard bind), and
    closing rows read as uid 0.  The listener here is bound to loopback only; the connection's own
    address (conn.getsockname()) is what the lookup must use, and the wildcard address, which a
    listener bound to all interfaces would report, must not match."""
    import socket as _socket

    from homelabnext.codemode.runner import _tcp_peer_uid

    loopback = "127.0.0.1"  # no-raw-endpoint: allow loopback, the test's own listener
    lst = _socket.socket()
    lst.bind((loopback, 0))
    lst.listen(2)
    port = lst.getsockname()[1]
    cli = _socket.create_connection((loopback, port))
    conn, addr = lst.accept()
    try:
        assert _tcp_peer_uid(addr, conn.getsockname()[:2]) == os.getuid()
        assert _tcp_peer_uid(addr, ("0.0.0.0", port)) is None, "the listener address matched"
        cli.close()
        assert _tcp_peer_uid(addr, conn.getsockname()[:2]) is None, "a closing row was trusted"
        assert _tcp_peer_uid(("::1", 1), ("::1", 2)) is None, "IPv6 is not read"
    finally:
        conn.close()
        lst.close()


def test_malformed_journal_entries_are_errors_never_crashes(tmp_path, executor):
    """LOW: a refusal, an intent or a meta.json that is `{}` used to pass and raise KeyError
    later; now each is a JournalError, a result for the run, and the sweep goes on."""
    _ran, cmds = _counted("cm.a", "cm.b")
    b, runner = _fake(tmp_path, executor, cmds)
    code = "broker.submit('cm.b', {'name': 'x'})\n"
    assert _run(b, code)["status"] == "paused"
    d = runner.store._dir(AGENT, "exec-0001")
    (d / "000000-i.json").write_text('{"call": "hmac-sha256:00"}')  # an intent with no intent
    res = _run(b, code, resume=True)
    assert res["status"] == "error" and res["error"]["kind"] == "broker", res
    (d / "meta.json").write_text("{}")
    res = _run(b, code, resume=True)
    assert res["status"] == "error", res
    assert _run(b, "result = 1\n", eid="exec-0002")["status"] == "ok", "one bad journal broke runs"
    runner.sweep(force=True)


def test_an_existing_execution_directory_is_tightened(tmp_path, executor):
    _ran, cmds = _counted("cm.b")
    b, runner = _fake(tmp_path, executor, cmds)
    d = runner.store._dir(AGENT, "exec-0001")
    old = os.umask(0o022)
    try:
        d.mkdir()  # left loose by someone else's umask, the way it would arrive in practice
    finally:
        os.umask(old)
    assert d.stat().st_mode & 0o077, "the setup is not looser"
    assert _run(b, "broker.submit('cm.b', {'name': 'x'})\n")["status"] == "paused"
    assert (d.stat().st_mode & 0o777) == 0o700


def test_an_interrupted_run_is_found_by_its_instance_in_any_namespace(tmp_path, executor):
    """LOW: the owner check keys on the runner instance's lock in the state directory, so a
    runner restarted in another pid namespace still marks a crashed run interrupted."""
    _ran, cmds = _counted("cm.b")
    b, runner = _fake(tmp_path, executor, cmds)
    assert _run(b, "broker.submit('cm.b', {'name': 'x'})\n")["status"] == "paused"
    other = {"instance": "run-0123456789abcdef", "pid": 1, "pid_ns": "elsewhere", "host": "x"}
    runner.store.update(AGENT, "exec-0001", runner.clock(), state="running", owner=other)
    assert runner.sweep(force=True)["interrupted"] == 1


# -- round 4 ---------------------------------------------------------------------------------------


def test_a_settled_refusal_of_the_pending_step_is_what_resumes_replay(tmp_path, executor):
    """Probe settled-refusal: a token_run refused without ids was journalled as the step's
    settled entry, but replay fell back to the answer's pending record: the next resume replayed
    a pending call, failed its schema and orphaned the request it had paused on."""
    from conformance.protocols.broker import BrokerError

    ran, cmds = _counted("cm.a", "cm.b")
    b, _runner = _fake(tmp_path, executor, cmds)
    code = (
        "try:\n"
        "    broker.submit('cm.a', {'name': 'a'})\n"
        "except broker.Error as exc:\n"
        "    print('refused', exc.reason)\n"
        "broker.submit('cm.b', {'name': 'b'})\n"
    )
    assert _run(b, code)["status"] == "paused"
    orig, once = b.token_run, []

    def token_run(*a, **kw):
        if not once:
            once.append(1)
            err = BrokerError("rate limited")
            err.reason = "rate-limited"
            raise err
        return orig(*a, **kw)

    b.token_run = token_run
    second = _run(b, code, resume=True)
    assert second["status"] == "paused", second
    assert [(c["step"], c["outcome"], c.get("reason")) for c in second["calls"]] == [
        (0, "error", "rate-limited"),
        (1, "pending", None),
    ]
    third = _run(b, code, resume=True)
    assert third["status"] == "ok", third
    assert [(c["step"], c["outcome"], c.get("replayed", False)) for c in third["calls"]] == [
        (0, "error", True),
        (1, "ok", False),
    ]
    assert ran == {"cm.a": [], "cm.b": ["b"]}


def _flooded(executor, flooders):
    """Wrap ``executor.run`` so ``flooders`` threads keep opening (and holding) connections to
    the run's relay while the program runs."""
    import socket as _socket
    import threading
    import time

    orig, stop = executor.run, threading.Event()

    def flood(host, port):
        held = []
        while not stop.is_set():
            try:
                held.append(_socket.create_connection((host, port)))
                if len(held) > 8:
                    held.pop(0).close()
            except OSError:
                time.sleep(0.001)
        for s in held:
            s.close()

    def run(code, *, broker, **kw):
        threads = [
            threading.Thread(target=flood, args=(broker.host, broker.port), daemon=True)
            for _ in range(flooders)
        ]
        for t in threads:
            t.start()
        time.sleep(0.3)
        try:
            return orig(code, broker=broker, **kw)
        finally:
            stop.set()

    executor.run = run
    return orig


@pytest.mark.parametrize("slow", [False, True])
def test_an_evicted_connection_is_never_served(tmp_path, executor, monkeypatch, slow):
    """Probe evict: eviction cut off a connection whose line was already in, the worker still
    ran serve_call, and the program got broker-unreachable for a call that ran (a retry would
    have been a second side effect).  Now "evict" and "start serving" are one check-and-set: a
    call the program was told failed never ran, and every call that ran is one it got back."""
    import time

    import homelabnext.codemode.runner as R

    if slow:  # widen the window between reading the line and serving it
        serve = R._Relay._serve

        def slowly(self, conn, state):
            time.sleep(0.2)
            return serve(self, conn, state)

        monkeypatch.setattr(R._Relay, "_serve", slowly)
    ran, cmds = _counted("cm.a")
    b, _runner = _fake(tmp_path, executor, cmds)
    orig = _flooded(executor, 12)
    n = 8 if slow else 40
    code = (
        "out = []\n"
        f"for i in range({n}):\n"
        "    try:\n"
        "        out.append(broker.call('cm.a', {'name': str(i)}))\n"
        "    except broker.Error as exc:\n"
        "        out.append('ERR:' + exc.reason)\n"
        "result = out\n"
    )
    try:
        res = _run(b, code, wall_s=60)
    finally:
        executor.run = orig
    value = res.get("value") or []
    told_failed = [str(i) for i, v in enumerate(value) if str(v).startswith("ERR")]
    assert not set(told_failed) & set(ran["cm.a"]), (
        f"calls {sorted(set(told_failed) & set(ran['cm.a']))} ran while the program was told "
        "they failed"
    )
    got = [v for v in value if not str(v).startswith("ERR")]
    assert got == ran["cm.a"], "a call ran that the program never got back"
    assert len([c for c in res["calls"] if c["outcome"] == "ok"]) == len(ran["cm.a"])


def test_the_sweep_prunes_the_locks_of_instances_gone(tmp_path):
    from homelabnext.codemode.journal import Journal

    j = Journal(tmp_path / "runner")
    mine = j.instance_id()
    gone = j.root / "live" / "run-00000000deadbeef"
    gone.write_bytes(b"")  # an instance file nobody holds: its process is gone
    assert j.sweep(T0)["instances"] == 1
    assert not gone.exists() and (j.root / "live" / mine).exists() and j.instance_alive(mine)


def test_a_refusal_with_a_malformed_reason_is_a_journal_error(tmp_path, executor):
    _ran, cmds = _counted("cm.b")
    b, runner = _fake(tmp_path, executor, cmds)
    b.register("cm.other", lambda **kw: 1, {})
    b.allow("profile:admin", ["cm.other"])
    code = (
        "try:\n"
        "    broker.call('cm.other', {})\n"
        "except broker.Denied:\n"
        "    pass\n"
        "broker.submit('cm.b', {'name': 'x'})\n"
    )
    assert _run(b, code)["status"] == "paused"
    entry = runner.store._dir(AGENT, "exec-0001") / "000000-0.json"
    doc = json.loads(entry.read_text())
    assert doc["refusal"]["reason"] == "token-action-not-allowed"
    doc["refusal"]["reason"] = "Not A Reason!"
    entry.write_text(json.dumps(doc))
    with pytest.raises(JournalError, match="neither record nor refusal"):
        runner.store.steps(AGENT, "exec-0001")
    res = _run(b, code, resume=True)
    assert res["status"] == "error" and res["error"]["kind"] == "broker", res


def test_a_fault_of_the_runner_is_named_as_one(tmp_path, executor, monkeypatch):
    _ran, cmds = _counted("cm.a")
    b, runner = _fake(tmp_path, executor, cmds)
    monkeypatch.setattr(runner, "_answered", lambda *a, **kw: {}["boom"])
    res = _run(
        b, "try:\n    broker.call('cm.a', {'name': 'a'})\nexcept broker.Error as e:\n    pass\n"
    )
    assert res["calls"] == [
        {"step": 0, "action": "cm.a", "outcome": "error", "reason": "runner-fault"}
    ]
    assert "runner-fault" in res["error"]["message"]
