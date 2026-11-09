# SPDX-License-Identifier: Apache-2.0
"""The ``orchestration`` adapter for the controller (``homelabnext.conform.adapters.orchestrator``).

The whole suite runs strict against this repository's controller binary in CI's
``orchestration-conformance`` job (tools/orchestration_conformance.py); the recorded stand-in it
replaced is retired (ADR-0026 decision 15). Here: the adapter's mapping onto the job API and the
handler host, on the binary where a controller's real answers are what is checked, and on
:class:`~tests.conform.controller_rig.FakeJobAPI` where a test breaks an answer on purpose.
"""

import base64
import http.client
import json
import threading
from pathlib import Path
from urllib.parse import urlsplit

import pytest

from conformance.fakes import llm_orchestrator_hermes as hermes
from conformance.protocols.orchestration import OrchestrationError, Orchestrator
from conformance.suites import orchestration as suite
from homelabnext.conform.adapters import orchestrator as lo
from homelabnext.conform.adapters._env import AdapterConfigError
from homelabnext.conform.core import run_checks
from tests.conform.controller_rig import FakeJobAPI, controller_binary, live_controller

__all__ = ["controller_binary"]  # the session fixture, imported for its tests

ROOT = Path(__file__).resolve().parents[2]
CALLBACK = f"http://{hermes.LOOPBACK}:8123"


@pytest.fixture
def fake():
    api = FakeJobAPI()
    yield api
    api.close()


def _subject(api: FakeJobAPI, tmp_path: Path) -> lo.Controller:
    return lo.Controller(api.url, profiles_dir=tmp_path, poll=0.01, wait_floor=5)


# --- on the binary ------------------------------------------------------------------------------


def test_subject_maps_onto_profiles_jobs_and_states(controller_binary, tmp_path):
    """Was the stand-in's; now the real controller: the profile the adapter writes, the job it
    submits (the namespaced key, the job line), the states it reads and the cancel of a finished
    run (409, read back unchanged)."""
    work = tmp_path / "work"
    with live_controller(controller_binary, work) as o:
        assert isinstance(o, Orchestrator)
        o.define("echo", lambda p: {"got": p}, retries=2)
        (written,) = (work / "profiles").glob("*.yaml")
        profile = json.loads(written.read_text().split("\n", 1)[1])
        assert profile["agent_key"].endswith("-echo")
        assert profile["local_only"] is True and profile["max_attempts"] == 3
        rid = o.submit("echo", {"x": "café"}, idempotency_key="k1")
        job = o._get(rid)
        assert job["agent_key"] == profile["agent_key"]
        assert hermes.decode(job["task_description"])["params"] == {"x": "café"}
        st = o.wait(rid, timeout=30)
        assert (st.state, st.attempts, st.result) == ("succeeded", 1, {"got": {"x": "café"}})
        assert o.cancel(rid).state == "succeeded"
        assert o.submit("echo", {"x": "café"}, idempotency_key="k1") == rid  # the key replays
    assert list((work / "profiles").glob("*.yaml")) == [], "the adapter's profiles are removed"


def test_a_live_controller_declares_admission_and_never_the_fault_hook(controller_binary, tmp_path):
    """Without fault injection the binary's subject declares ``admission`` (its in-flight route)
    and not the hook, so the hook's MUST checks are ``untested``, never skipped."""
    with live_controller(controller_binary, tmp_path / "work") as o:
        assert o.features == frozenset({"priority", "admission"})
        with pytest.raises(OrchestrationError, match="fault injection"):
            o.kill("0" * 32)
        with pytest.raises(OrchestrationError, match="fault injection"):
            o.restart()
        hooked = [s.id for s in suite.SUITE.specs if "fault-injection" in s.requires]
        assert hooked
        results = run_checks(suite.SUITE, lambda: o, only=hooked)
        assert {r.status for r in results} == {"untested"}, results


# --- on the scripted fake -----------------------------------------------------------------------


def test_the_feature_probe_skips_only_on_a_missing_route(tmp_path):
    """404 is "no route" (the capacity checks skip); a 503 is a fault, which must make the run
    unmeasured rather than turn five MUST checks into skips."""
    for inflight, expect in (((404, {}), None), ((503, "unavailable"), "HTTP 503")):
        api = FakeJobAPI(inflight=inflight)
        o = _subject(api, tmp_path)
        try:
            if expect:
                with pytest.raises(OrchestrationError, match=expect):
                    o.features  # noqa: B018 - the probe is the property
            else:
                assert "admission" not in o.features
                hooked = [s.id for s in suite.SUITE.specs if "fault-injection" in s.requires]
                assert {r.status for r in run_checks(suite.SUITE, lambda o=o: o, only=hooked)} == {
                    "skip"
                }
        finally:
            o.close()
            api.close()


def test_attempts_fall_back_to_executions_the_handler_host_saw(fake, tmp_path):
    o = _subject(fake, tmp_path)
    try:
        o.define("once", lambda p: "ok")
        rid = o.submit("once", {}, idempotency_key="k")
        assert "attempts" not in o._get(rid)
        assert o.wait(rid).attempts == 1
        queued = o.submit("once", {}, idempotency_key="k2")
        assert o.cancel(queued).attempts == 0
    finally:
        o.close()


def test_handler_host_runs_only_the_jobs_it_issued(fake, tmp_path):
    """Each submit gets its own token and an HMAC of it under a key that never leaves the
    adapter: the job line (readable by any client of the job API) carries no host-wide secret, a
    token the host did not issue or a wrong MAC is refused, and an issued token runs only its own
    job with its own parameters."""
    o = _subject(fake, tmp_path)
    try:
        o.define("j", lambda p: p.get("n"))
        o.define("other", lambda p: "other ran")
        rid = o.submit("j", {"n": 1}, idempotency_key="k")
        line = fake.jobs[rid]["task_description"]
        job = hermes.decode(line)
        assert set(job) == {"v", "callback", "token", "mac", "job", "params"}
        assert "secret" not in job and not hasattr(o._host, "secret")
        assert o._host._key.hex() not in line
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


@pytest.mark.parametrize(
    "length,expect",
    [("abc", 400), ("-5", 400), (str(10**9), 413), ("", 400)],
)
def test_handler_host_bounds_the_request_body(fake, tmp_path, length, expect):
    o = _subject(fake, tmp_path)
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


def test_unknown_controller_state_is_an_orchestration_error(tmp_path):
    api = FakeJobAPI(job=lambda doc: {**doc, "state": "exploded"})
    o = _subject(api, tmp_path)
    try:
        o.define("j", lambda p: 1)
        rid = o.submit("j", {}, idempotency_key="k")
        with pytest.raises(OrchestrationError, match="unknown state"):
            o.wait(rid)
    finally:
        o.close()
        api.close()


def test_one_subject_builds_one_opener(monkeypatch, tmp_path):
    """Building an opener loads the CA bundle (tens of ms of CPU); the capacity checks poll the
    controller many times a second, so a subject builds one and reuses it."""
    built = []
    real = lo.safe_opener
    monkeypatch.setattr(lo, "safe_opener", lambda: built.append(1) or real())
    api = FakeJobAPI(inflight=(200, {"backends": {}}))
    o = _subject(api, tmp_path)
    try:
        for _ in range(5):
            o.capacity()
        assert built == [1]
    finally:
        o.close()
        api.close()
    assert hermes._opener() is hermes._opener()


# --- the runner body and the factory ------------------------------------------------------------


def test_the_runner_body_answers_like_a_session(tmp_path):
    job = {"callback": CALLBACK, "token": "t", "mac": "fake-mac", "job": "j"}
    prompt = "task\n" + lo.encode_job({**job, "params": {"a": [1, None]}}) + "\n\ncontracts"
    assert hermes.decode(prompt)["params"] == {"a": [1, None]}
    usage = tmp_path / "usage.json"
    seen = []

    def ok(url, body):
        seen.append((url, body))
        return {"ok": True, "result": {"n": 2}}

    code, out, err = hermes.run(
        ["--stdin", "--usage-file", str(usage)], post=ok, stdin=lambda: prompt
    )
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
def test_the_runner_body_follows_only_a_loopback_callback(callback):
    """The job line is controller data anyone can read and write: the runner body only ever posts
    to the handler host on IPv4 loopback, never a file, another host or a URL with userinfo."""
    job = {"callback": callback, "token": "t", "job": "j", "params": {}}
    seen = []
    code, out, err = hermes.run(
        ["-z", lo.encode_job(job)], post=lambda u, b: seen.append(u) or {"ok": True}
    )
    assert (code, out, seen) == (1, "", []) and "callback" in err


def test_make_needs_an_endpoint_and_a_profiles_dir(monkeypatch, tmp_path):
    monkeypatch.delenv("HNX_ENDPOINT_ORCHESTRATION", raising=False)
    monkeypatch.delenv(lo.PROFILES_ENV, raising=False)
    with pytest.raises(AdapterConfigError, match="profiles_dir"):
        lo.make()
    with pytest.raises(AdapterConfigError, match="HNX_ENDPOINT_ORCHESTRATION"):
        lo.make(profiles_dir=str(tmp_path))
    with pytest.raises(TypeError):
        lo.make(profiles_dir=str(tmp_path), recorded_fake=True)  # the stand-in is retired


def test_the_recorded_stand_in_stays_retired():
    """ADR-0026 decision 15: no orchestration target is a recording, and nothing under
    conformance/ cites the private controller's internal/hermesagent package."""
    targets = sorted(p.name for p in (ROOT / "conformance" / "targets").glob("orchestration-*.yml"))
    assert targets and not [t for t in targets if t.removesuffix(".yml").endswith("-recorded")], (
        targets
    )
    cites = [
        p.relative_to(ROOT).as_posix()
        for p in (ROOT / "conformance").rglob("*")
        if p.is_file()
        and p.suffix in (".py", ".yml", ".yaml", ".md", ".json")
        and "internal/hermesagent" in p.read_text(errors="replace")
    ]
    assert cites == []
    assert not (ROOT / "conformance" / "fakes" / "llm_orchestrator_api.py").exists()


def test_a_threadsafe_fake_counts_nothing_it_did_not_run(fake, tmp_path):
    """The scripted fake itself: a cancelled queued job never runs its handler."""
    o = _subject(fake, tmp_path)
    ran = threading.Event()
    try:
        o.define("never", lambda p: ran.set())
        rid = o.submit("never", {}, idempotency_key="k")
        assert o.cancel(rid).state == "cancelled" and not ran.is_set()
    finally:
        o.close()
