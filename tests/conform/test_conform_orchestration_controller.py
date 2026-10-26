# SPDX-License-Identifier: Apache-2.0
"""The ``orchestration`` adapter for the LLM orchestrator (the Go controller), offline.

The adapter runs the whole ``orchestration`` suite against the loopback stand-in of the
controller's job API (``conformance/fakes/llm_orchestrator_api.py``, shapes cited from the Go code
at ``a52a1c4``).  As recorded, the stand-in fails the same three MUST checks the live controller
failed on 2026-10-22; with the proposed controller fixes turned on, it passes all of them.  The
five capacity checks need ``admission``, which a52a1c4 lacks (they skip); with the in-flight route
that landed upstream they run, the kill and restart hooks driving the stand-in's model of the
controller's process kill and restart reconciliation.  The live run is described in
docs/orchestration-controller.md.
"""

import base64
import json

import pytest

from conformance.fakes import llm_orchestrator_api as api
from conformance.fakes import llm_orchestrator_hermes as hermes
from conformance.fakes.llm_orchestrator_api import FakeController
from conformance.protocols.orchestration import (
    OrchestrationError,
    Orchestrator,
)
from conformance.suites import orchestration as suite
from homelabnext.conform import run_capability
from homelabnext.conform.adapters import llm_orchestrator as lo
from homelabnext.conform.adapters._env import AdapterConfigError
from homelabnext.conform.core import run_checks

#: what a52a1c4 fails: no unknown-agent rejection, no per-job retries
CONTROLLER_GAPS = ["retries-are-bounded", "retries-until-success", "unknown-job-raises"]
FIXES = ("reject-unknown-agent-key", "max-attempts")
#: the checks that hold capacity to account (clauses a-e); all need ``admission``
HOLDS = sorted(
    s.id
    for s in suite.SUITE.specs
    if "admission" in s.requires and s.id != "deadline-expiry-frees-capacity"
)
CALLBACK = "http://127.0.0.1:8123"  # no-raw-endpoint: allow the stand-in's loopback handler host


def _failing(results):
    return sorted(r.check for r in results if r.status not in ("pass", "skip"))


def _skipped(results):
    return sorted(r.check for r in results if r.status == "skip")


def test_recorded_target_fails_exactly_the_controller_gaps():
    run = run_capability("orchestration", "orchestration-llm-orchestrator-recorded")
    assert run.error is None, run.error
    assert _failing(run.results) == CONTROLLER_GAPS
    # a52a1c4 serves no in-flight route: every capacity check skips, the hook ones included
    assert _skipped(run.results) == sorted([*HOLDS, "deadline-expiry-frees-capacity"])
    assert len(run.results) == len(suite.SUITE.specs)
    evidence = {r.check: r.evidence for r in run.results}
    assert "attempts=1" in evidence["retries-until-success"]
    assert "expected an error" in evidence["unknown-job-raises"]


def test_proposed_controller_fixes_clear_the_gaps_and_the_capacity_checks_pass():
    """With the fixes and the upstream in-flight route the three gaps pass, and so do the
    capacity checks against the stand-in's model of the controller (cancel kills the process, a
    defer releases the slot, a restart runs ReconcileOrphans).  The other checks do not depend on
    the fixes and run in the recorded test above; the deadline one skips (no per-run deadline)."""
    fixes = (*FIXES, *api.UPSTREAM)
    wanted = [*CONTROLLER_GAPS, *HOLDS, "deadline-expiry-frees-capacity"]
    results = run_checks(suite.SUITE, lambda: lo.make(recorded_fake=True, fixes=fixes), only=wanted)
    assert _failing(results) == []
    assert _skipped(results) == ["deadline-expiry-frees-capacity"]


def test_a_skipped_check_never_starts_the_stand_in(monkeypatch):
    started = []
    real = lo._start_recorded
    monkeypatch.setattr(lo, "_start_recorded", lambda *a: started.append(a) or real(*a))
    (res,) = run_checks(
        suite.SUITE, lambda: lo.make(recorded_fake=True), only=["cancel-running-run-frees-capacity"]
    )
    assert res.status == "skip" and started == []
    (res,) = run_checks(
        suite.SUITE, lambda: lo.make(recorded_fake=True), only=["runs-job-and-returns-result"]
    )
    assert res.status == "pass" and len(started) == 1
    with pytest.raises(ValueError, match="unknown fixes"):
        lo.make(recorded_fake=True, fixes=["teleport"])


class _FlakyRoute(FakeController):
    def inflight(self):
        return 503, "backend status unavailable"


def test_the_feature_probe_skips_only_on_a_missing_route(tmp_path):
    """404 is "no route" (the capacity checks skip); a 503 is a fault, which must make the run
    unmeasured rather than turn five MUST checks into skips."""
    flaky = _FlakyRoute(tmp_path, fixes=api.UPSTREAM).start()
    o = lo.LLMOrchestrator(flaky.url, profiles_dir=tmp_path, on_close=flaky.stop)
    try:
        with pytest.raises(OrchestrationError, match="HTTP 503"):
            o.features  # noqa: B018 - the probe is the property
    finally:
        o.close()
    absent = FakeController(tmp_path).start()
    o = lo.LLMOrchestrator(absent.url, profiles_dir=tmp_path, on_close=absent.stop)
    try:
        assert "admission" not in o.features
    finally:
        o.close()


class _LeakOnCancel(FakeController):
    """A controller whose cancel flips the row but never kills the process: the slot stays
    reserved until the job body returns by itself (a52a1c4's parent, before cancelRun)."""

    def cancel(self, run_id):
        with self._lock:
            kills, self._kills = self._kills, {}
        try:
            return super().cancel(run_id)
        finally:
            with self._lock:
                self._kills = kills


def test_a_controller_that_does_not_kill_on_cancel_fails_the_cancel_check(monkeypatch):
    monkeypatch.setattr(api, "FakeController", _LeakOnCancel)
    (res,) = run_checks(
        suite.SUITE,
        lambda: lo.make(recorded_fake=True, fixes=api.UPSTREAM),
        only=["cancel-running-run-frees-capacity"],
    )
    assert res.status == "fail" and "capacity still held" in res.evidence, res


def test_stand_in_reports_holds_kills_and_reconciles_like_the_controller(tmp_path):
    fake = FakeController(tmp_path, fixes=api.UPSTREAM).start()
    o = lo.LLMOrchestrator(fake.url, profiles_dir=tmp_path, poll=0.01, wait_floor=5)
    import threading

    release = threading.Event()
    try:
        assert fake.inflight() == (200, {"backends": {}})  # no counter before first use
        o.define("block", lambda p: release.wait(30) and "late")
        a = o.submit("block", {}, idempotency_key="a")
        o._get(a)  # a client is waiting: admittable
        assert _until(
            lambda: (
                a
                in fake.inflight()[1]["backends"].get("primary-local", {}).get("reserved_runs", [])
            )
        )
        assert o.capacity() == (None, 1, frozenset({a}))
        assert fake.kill(a) is True
        assert _until(lambda: o._get(a)["state"] == "failed")
        assert o._get(a)["local_failed_reason"] == "hermes -z failed: signal: killed"
        assert o.capacity() == (None, 0, frozenset())
        b = o.submit("block", {}, idempotency_key="b")
        o._get(b)
        assert _until(lambda: o._get(b)["state"] == "running")
        q = o.submit("block", {}, idempotency_key="q")  # concurrency 1: stays queued
        fake.restart()
        assert o._get(b)["state"] == "failed"
        assert o._get(b)["local_failed_reason"] == api.RECONCILE_REASON
        assert o.capacity() == (None, 0, frozenset())
        assert fake._jobs[q]["state"] == "queued"  # read without making it admittable
        assert o.submit("block", {}, idempotency_key="q") == q  # the key survived
        release.set()
        assert o.wait(q).state == "succeeded"
        assert o._get(b)["state"] == "failed", "a pre-restart process's result was recorded"
        assert fake.kill(b) is False
    finally:
        release.set()
        o.close()
        fake.stop()


def _until(pred, seconds=10.0):
    import time

    end = time.monotonic() + seconds
    while not pred():
        if time.monotonic() > end:
            return False
        time.sleep(0.01)
    return True


def test_a_live_controller_declares_admission_by_its_route_and_never_the_fault_hook(tmp_path):
    """On a live controller the adapter cannot kill a worker or restart the service, so
    ``fault-injection`` is never declared: with ``admission`` the hook checks are ``untested``
    (a MUST is not skipped by leaving a hook out); without it they skip."""
    for fixes, feats, hook_status in (
        ((), frozenset({"priority"}), "skip"),
        (api.UPSTREAM, frozenset({"priority", "admission"}), "untested"),
    ):
        fake = FakeController(tmp_path, fixes=fixes).start()
        o = lo.LLMOrchestrator(fake.url, profiles_dir=tmp_path, poll=0.01, wait_floor=5)
        try:
            assert o.features == feats  # the methods always exist; the features say what works
            with pytest.raises(OrchestrationError, match="recorded stand-in"):
                o.kill("any")
            with pytest.raises(OrchestrationError, match="recorded stand-in"):
                o.restart()
        finally:
            o.close()
            fake.stop()
        hooked = [s.id for s in suite.SUITE.specs if "fault-injection" in s.requires]
        assert hooked
        for cid in hooked:
            stand = FakeController(tmp_path, fixes=fixes).start()
            subject = lo.LLMOrchestrator(stand.url, profiles_dir=tmp_path, on_close=stand.stop)
            (res,) = run_checks(suite.SUITE, lambda s=subject: s, only=[cid])
            assert res.status == hook_status, (fixes, cid, res)


def test_subject_maps_onto_profiles_jobs_and_states(tmp_path):
    fake = FakeController(tmp_path, fixes=FIXES).start()
    o = lo.LLMOrchestrator(fake.url, profiles_dir=tmp_path, poll=0.01, wait_floor=5)
    try:
        assert isinstance(o, Orchestrator)
        o.define("echo", lambda p: {"got": p}, retries=2)
        (written,) = tmp_path.glob("*.yaml")
        profile = json.loads(written.read_text().split("\n", 1)[1])
        assert profile["agent_key"].endswith("-echo") and profile["agent_key"] in fake.profiles
        assert profile["local_only"] is True and profile["max_attempts"] == 3
        rid = o.submit("echo", {"x": "café"}, idempotency_key="k1")
        job = fake._jobs[rid]
        assert job["idempotency_key"].startswith("hnxconf-") and job["idempotency_key"].endswith(
            "-k1"
        )
        assert hermes.decode(job["task_description"])["params"] == {"x": "café"}
        st = o.wait(rid)
        assert (st.state, st.attempts, st.result) == ("succeeded", 1, {"got": {"x": "café"}})
        assert o.cancel(rid).state == "succeeded"  # 409 from the controller: read back unchanged
    finally:
        o.close()
        fake.stop()
    assert list(tmp_path.glob("*.yaml")) == [], "profiles the adapter wrote are removed on close"


def test_attempts_fall_back_to_executions_the_handler_host_saw(tmp_path):
    fake = FakeController(tmp_path).start()  # as a52a1c4: no attempts field
    o = lo.LLMOrchestrator(fake.url, profiles_dir=tmp_path, poll=0.01, wait_floor=5)
    try:
        o.define("once", lambda p: "ok")
        rid = o.submit("once", {}, idempotency_key="k")
        assert "attempts" not in fake.status(rid)[1]
        assert o.wait(rid).attempts == 1
        queued = o.submit("once", {}, idempotency_key="k2")
        assert o.cancel(queued).attempts == 0
    finally:
        o.close()
        fake.stop()


def test_handler_host_runs_only_the_jobs_it_issued(tmp_path):
    """Each submit gets its own token and an HMAC of it under a key that never leaves the
    adapter: the job line (readable by any client of the controller's API) carries no host-wide
    secret, a token the host did not issue or a wrong MAC is refused, and an issued token runs
    only its own job with its own parameters."""
    fake = FakeController(tmp_path).start()
    o = lo.LLMOrchestrator(fake.url, profiles_dir=tmp_path)
    try:
        o.define("j", lambda p: p.get("n"))
        o.define("other", lambda p: "other ran")
        rid = o.submit("j", {"n": 1}, idempotency_key="k")
        job = hermes.decode(fake._jobs[rid]["task_description"])
        assert set(job) == {"v", "callback", "token", "mac", "job", "params"}
        assert "secret" not in job and not hasattr(o._host, "secret")
        assert o._host._key.hex() not in fake._jobs[rid]["task_description"]
        good = {k: job[k] for k in ("token", "mac", "job", "params")}
        assert o._host.run(good) == (200, {"ok": True, "result": 1})
        refused = [
            {**good, "mac": "00" * 32},  # a wrong MAC
            {**good, "token": "fake-not-issued"},  # a token the host never issued
            {**good, "job": next(k for k in o._host.handlers if k.endswith("-other"))},
            {**good, "params": {"n": 2}},  # its own job, someone else's parameters
            {"secret": "fake-old-style", "token": job["token"], "job": job["job"]},
            [good],
        ]
        for body in refused:
            status, doc = o._host.run(body)
            assert status in (400, 403) and doc["ok"] is False, body
    finally:
        o.close()
        fake.stop()


@pytest.mark.parametrize(
    "length,expect",
    [("abc", 400), ("-5", 400), (str(10**9), 413), ("", 400)],
)
def test_handler_host_bounds_the_request_body(tmp_path, length, expect):
    import http.client
    from urllib.parse import urlsplit

    fake = FakeController(tmp_path).start()
    o = lo.LLMOrchestrator(fake.url, profiles_dir=tmp_path)
    try:
        u = urlsplit(o._host.url)
        conn = http.client.HTTPConnection(u.hostname, u.port, timeout=5)
        conn.putrequest("POST", "/run")
        if length:
            conn.putheader("Content-Length", length)
        conn.endheaders()
        resp = conn.getresponse()
        assert resp.status == expect and json.loads(resp.read())["ok"] is False
        conn.close()
    finally:
        o.close()
        fake.stop()


def test_hermes_stand_in_answers_like_hermes(tmp_path):
    job = {"callback": CALLBACK, "token": "t", "mac": "fake-mac", "job": "j"}
    prompt = "task\n" + lo.encode_job({**job, "params": {"a": [1, None]}}) + "\n\ncontracts"
    assert hermes.decode(prompt)["params"] == {"a": [1, None]}
    usage = tmp_path / "usage.json"
    seen = []

    def ok(url, body):
        seen.append((url, body))
        return {"ok": True, "result": {"n": 2}}

    code, out, err = hermes.run(["-z", prompt, "--usage-file", str(usage)], post=ok)
    assert (code, json.loads(out), err) == (0, {"hnx_result": {"n": 2}}, "")
    assert seen[0][0] == CALLBACK + "/run" and seen[0][1]["params"] == {"a": [1, None]}
    assert json.loads(usage.read_text())["completed"] is True
    code, out, err = hermes.run(
        ["-z", prompt], post=lambda u, b: {"ok": False, "error": "RuntimeError: boom"}
    )
    assert (code, out, err) == (1, "", "RuntimeError: boom")
    assert hermes.run(["-z", "a prompt with no job line"])[0] == 1
    assert hermes.run(["--toolsets", "x"])[0] == 2
    bad = hermes.JOB_MARKER + base64.urlsafe_b64encode(b"[1]").decode()
    assert hermes.decode(bad) is None


@pytest.mark.parametrize(
    "callback",
    [
        "file:///etc/passwd",
        "https://203.0.113.7:8443",  # no-raw-endpoint: allow a callback under test
        "http://203.0.113.7:8123",  # no-raw-endpoint: allow a callback under test
        "http://handler.invalid:8123",  # no-raw-endpoint: allow a callback under test
        "http://localhost:8123",  # no-raw-endpoint: allow a callback under test
        "http://fake-user@127.0.0.1:8123",  # no-raw-endpoint: allow a callback under test
        "http://127.0.0.1@203.0.113.7:8123",  # no-raw-endpoint: allow a callback under test
        "http://127.0.0.1",  # no-raw-endpoint: allow a callback under test
        "http://127.0.0.1:8123/elsewhere",  # no-raw-endpoint: allow a callback under test
        "http://127.0.0.1:8123?x=1",  # no-raw-endpoint: allow a callback under test
        "https://127.0.0.1:8123",  # no-raw-endpoint: allow a callback under test
        "gopher://127.0.0.1:8123",  # no-raw-endpoint: allow a callback under test
    ],
)
def test_hermes_stand_in_follows_only_a_loopback_callback(callback):
    """The job line is controller data anyone can read and write: the stand-in only ever posts to
    the handler host on IPv4 loopback, never a file, another host or a URL with userinfo."""
    job = {"callback": callback, "token": "t", "job": "j", "params": {}}
    seen = []
    code, out, err = hermes.run(
        ["-z", lo.encode_job(job)], post=lambda u, b: seen.append(u) or {"ok": True}
    )
    assert (code, out, seen) == (1, "", []) and "callback" in err


def test_unknown_controller_state_is_an_orchestration_error(tmp_path):
    fake = FakeController(tmp_path).start()
    o = lo.LLMOrchestrator(fake.url, profiles_dir=tmp_path)
    try:
        o.define("j", lambda p: 1)
        rid = o.submit("j", {}, idempotency_key="k")
        fake._jobs[rid]["state"] = "exploded"
        with pytest.raises(Exception, match="unknown state"):
            o.wait(rid)
    finally:
        o.close()
        fake.stop()


def test_make_needs_an_endpoint_and_a_profiles_dir(monkeypatch, tmp_path):
    monkeypatch.delenv("HNX_ENDPOINT_ORCHESTRATION", raising=False)
    monkeypatch.delenv(lo.PROFILES_ENV, raising=False)
    with pytest.raises(AdapterConfigError, match="profiles_dir"):
        lo.make()
    with pytest.raises(AdapterConfigError, match="HNX_ENDPOINT_ORCHESTRATION"):
        lo.make(profiles_dir=str(tmp_path))
    with pytest.raises(AdapterConfigError, match="recorded fake"):
        lo.make(profiles_dir=str(tmp_path), fixes=["max-attempts"])
    with pytest.raises(ValueError, match="unknown fixes"):
        FakeController(tmp_path, fixes=["teleport"])
    with pytest.raises(ValueError, match="concurrency"):
        FakeController(tmp_path, concurrency=0)


def test_one_subject_builds_one_opener(monkeypatch, tmp_path):
    """Building an opener loads the CA bundle (tens of ms of CPU); the capacity checks poll the
    controller many times a second, so a subject builds one and reuses it."""
    built = []
    real = lo.safe_opener
    monkeypatch.setattr(lo, "safe_opener", lambda: built.append(1) or real())
    fake = FakeController(tmp_path, fixes=api.UPSTREAM).start()
    o = lo.LLMOrchestrator(fake.url, profiles_dir=tmp_path, on_close=fake.stop)
    try:
        for _ in range(5):
            o.capacity()
        assert built == [1]
    finally:
        o.close()
    assert hermes._opener() is hermes._opener()
