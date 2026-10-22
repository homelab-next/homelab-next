# SPDX-License-Identifier: Apache-2.0
"""The ``orchestration`` adapter for the LLM orchestrator (the Go controller), offline.

The adapter runs the whole ``orchestration`` suite against the loopback stand-in of the
controller's job API (``conformance/fakes/llm_orchestrator_api.py``, shapes cited from the Go code
at ``a52a1c4``).  As recorded, the stand-in fails the same three MUST checks the live controller
failed on 2026-10-22; with the proposed controller fixes turned on, it passes all of them.  The
live run is described in docs/orchestration-controller.md.
"""

import base64
import json

import pytest

from conformance.fakes import llm_orchestrator_hermes as hermes
from conformance.fakes.llm_orchestrator_api import FakeController
from conformance.protocols.orchestration import Orchestrator
from conformance.suites import orchestration as suite
from homelabnext.conform import run_capability
from homelabnext.conform.adapters import llm_orchestrator as lo
from homelabnext.conform.adapters._env import AdapterConfigError
from homelabnext.conform.core import run_checks

#: what a52a1c4 fails: no unknown-agent rejection, no per-job retries
CONTROLLER_GAPS = ["retries-are-bounded", "retries-until-success", "unknown-job-raises"]
FIXES = ("reject-unknown-agent-key", "max-attempts")


def _failing(results):
    return sorted(r.check for r in results if r.status != "pass")


def test_recorded_target_fails_exactly_the_controller_gaps():
    run = run_capability("orchestration", "orchestration-llm-orchestrator-recorded")
    assert run.error is None, run.error
    assert _failing(run.results) == CONTROLLER_GAPS
    assert len(run.results) == len(suite.SUITE.specs)
    evidence = {r.check: r.evidence for r in run.results}
    assert "attempts=1" in evidence["retries-until-success"]
    assert "expected an error" in evidence["unknown-job-raises"]


def test_proposed_controller_fixes_pass_the_whole_suite():
    results = run_checks(suite.SUITE, lambda: lo.make(recorded_fake=True, fixes=FIXES))
    assert _failing(results) == []
    assert len(results) == len(suite.SUITE.specs)


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


def test_handler_host_rejects_a_wrong_secret(tmp_path):
    fake = FakeController(tmp_path).start()
    o = lo.LLMOrchestrator(fake.url, profiles_dir=tmp_path)
    try:
        o.define("j", lambda p: 1)
        key = next(iter(fake.profiles))
        status, doc = o._host.run({"secret": "fake-wrong", "token": "t", "job": key})
        assert status == 403 and not doc["ok"]
        status, doc = o._host.run({"secret": o._host.secret, "token": "t", "job": key})
        assert (status, doc) == (200, {"ok": True, "result": 1})
    finally:
        o.close()
        fake.stop()


def test_hermes_stand_in_answers_like_hermes(tmp_path):
    job = {"callback": "http://handler.invalid", "secret": "fake-s", "token": "t", "job": "j"}
    prompt = "task\n" + lo.encode_job({**job, "params": {"a": [1, None]}}) + "\n\ncontracts"
    assert hermes.decode(prompt)["params"] == {"a": [1, None]}
    usage = tmp_path / "usage.json"
    seen = []

    def ok(url, body):
        seen.append((url, body))
        return {"ok": True, "result": {"n": 2}}

    code, out, err = hermes.run(["-z", prompt, "--usage-file", str(usage)], post=ok)
    assert (code, json.loads(out), err) == (0, {"hnx_result": {"n": 2}}, "")
    assert seen[0][0] == "http://handler.invalid/run" and seen[0][1]["params"] == {"a": [1, None]}
    assert json.loads(usage.read_text())["completed"] is True
    code, out, err = hermes.run(
        ["-z", prompt], post=lambda u, b: {"ok": False, "error": "RuntimeError: boom"}
    )
    assert (code, out, err) == (1, "", "RuntimeError: boom")
    assert hermes.run(["-z", "a prompt with no job line"])[0] == 1
    assert hermes.run(["--toolsets", "x"])[0] == 2
    bad = hermes.JOB_MARKER + base64.urlsafe_b64encode(b"[1]").decode()
    assert hermes.decode(bad) is None


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
