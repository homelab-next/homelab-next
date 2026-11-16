# SPDX-License-Identifier: Apache-2.0
"""The load/unload policy and the HTTP service over a real socket, with a fake engine (the voice
model itself needs torch and 2 GB of weights; ``modules/tts/README.md`` records the real run)."""

from __future__ import annotations

import io
import json
import threading
import time
import urllib.error
import urllib.request
import wave
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

from homelabnext.tts_service import gates, server
from homelabnext.tts_service.contract import MAX_BODY_BYTES, SAMPLE_RATE
from homelabnext.tts_service.engine import EngineHost, Unavailable


class FakeEngine:
    def __init__(self, log):
        self.log = log
        self.unloaded = False

    def synthesize(self, text, temperature, top_p):
        self.log.append(("synth", text, temperature, top_p))
        return [0.0, 0.5, -0.5, 1.0, -1.0, 2.0] * 4000  # 1 s at 24 kHz, one sample out of range

    def unload(self):
        self.unloaded = True
        self.log.append(("unload",))


class Clock:
    def __init__(self):
        self.t = 100.0

    def __call__(self):
        return self.t


def host(log, idle=0.0, before=None, clock=None):
    engines: list[FakeEngine] = []

    def load():
        log.append(("load",))
        e = FakeEngine(log)
        engines.append(e)
        return e

    h = EngineHost(load, before, idle, clock or Clock())
    h.engines = engines  # type: ignore[attr-defined]
    return h


# --- the policy -------------------------------------------------------------------------------


def test_the_engine_loads_on_the_first_job_and_stays_when_idle_unload_is_off():
    log: list = []
    clock = Clock()
    h = host(log, 0.0, clock=clock)
    assert not h.loaded
    with h.lease() as e:
        e.synthesize("a", 0.6, 0.85)
    clock.t += 10**6
    assert h.reap() is False and h.loaded and h.loads == 1
    with h.lease():
        pass
    assert h.loads == 1  # never reloaded


def test_the_engine_unloads_after_the_idle_timeout_and_reloads_for_the_next_job():
    log: list = []
    clock = Clock()
    h = host(log, 60.0, clock=clock)
    with h.lease():
        pass
    clock.t += 59
    assert h.reap() is False and h.loaded
    clock.t += 2
    assert h.reap() is True and not h.loaded and h.engines[0].unloaded
    with h.lease():
        pass
    assert h.loads == 2 and h.unloads == 1
    assert [x[0] for x in log if x[0] in ("load", "unload")] == ["load", "unload", "load"]


def test_the_idle_clock_starts_when_a_job_ends_not_when_it_starts():
    log: list = []
    clock = Clock()
    h = host(log, 60.0, clock=clock)
    with h.lease():
        clock.t += 500  # a long job
    assert h.reap() is False
    clock.t += 61
    assert h.reap() is True


def test_a_running_job_is_never_unloaded_under_it():
    log: list = []
    clock = Clock()
    h = host(log, 1.0, clock=clock)
    with h.lease() as e:
        clock.t += 10**6
        assert h.reap() is False
        assert not e.unloaded
    assert h.loaded


def test_jobs_are_serialised():
    h = host([])
    state = {"inside": 0, "max": 0}
    guard = threading.Lock()

    def job():
        with h.lease():
            with guard:
                state["inside"] += 1
                state["max"] = max(state["max"], state["inside"])
            time.sleep(0.02)
            with guard:
                state["inside"] -= 1

    ts = [threading.Thread(target=job) for _ in range(4)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert state["max"] == 1 and h.loads == 1


def test_a_refused_load_is_unavailable_and_nothing_is_loaded():
    log: list = []

    def before():
        raise gates.Refusal("GPU 0's power limit is 300 W, above the 200 W limit")

    h = host(log, before=before)
    with pytest.raises(Unavailable, match="above the 200 W limit"), h.lease():
        raise AssertionError("the body must not run")
    assert not h.loaded and ("load",) not in log


def test_the_gate_runs_before_every_load_not_only_the_first():
    log: list = []
    clock = Clock()
    allowed = {"ok": True}

    def before():
        log.append(("gate",))
        if not allowed["ok"]:
            raise gates.Refusal("cap raised")

    h = host(log, 10.0, before=before, clock=clock)
    with h.lease():
        pass
    clock.t += 11
    h.reap()
    allowed["ok"] = False  # the cap is raised while the engine is out of VRAM
    with pytest.raises(Unavailable, match="cap raised"), h.lease():
        pass
    assert not h.loaded
    assert [x[0] for x in log if x[0] in ("gate", "load")] == ["gate", "load", "gate"]


def test_a_failed_load_is_unavailable_and_the_next_job_tries_again():
    state = {"n": 0}

    def load():
        state["n"] += 1
        if state["n"] == 1:
            raise RuntimeError("out of memory")
        return FakeEngine([])

    h = EngineHost(load, None, 0.0)
    with pytest.raises(Unavailable, match="out of memory"), h.lease():
        pass
    with h.lease():
        pass
    assert h.loaded


def test_the_reaper_thread_unloads_by_itself():
    log: list = []
    h = host(log, 0.05, clock=time.monotonic)
    stop = h.start_reaper(every_s=0.02)
    try:
        with h.lease():
            pass
        deadline = time.monotonic() + 3
        while h.loaded and time.monotonic() < deadline:
            time.sleep(0.02)
        assert not h.loaded and h.unloads == 1
    finally:
        stop.set()


# --- the service over a socket --------------------------------------------------------------------


def make_env(tmp: Path) -> dict[str, str]:
    from tests.tts.test_tts_gates import make_store

    model, listing, digest = make_store(tmp)
    voice = tmp / "voice"
    voice.mkdir()
    for n in server.DEFAULT_REFS:
        (voice / n).write_bytes(b"RIFF")
    return {
        "TTS_BACKEND": "cpu", "TTS_PORT": "0", "TTS_MODEL_DIR": str(model),
        "TTS_MODEL_LISTING": str(listing), "TTS_MODEL_DIGEST": digest,
        "TTS_REFS_DIR": str(voice), "TTS_CACHE_DIR": str(tmp / "cache"),
    }  # fmt: skip


class Running:
    def __init__(self, tmp: Path, log: list, *, env_over=None, engine_host=None, run=None):
        env = make_env(tmp)
        env.update(env_over or {})
        self.config = server.Config.from_env(env)
        self.host = engine_host or host(log)
        gate = gates.WeightsGate(
            self.config.model_dir, self.config.listing, self.config.model_digest
        )
        self.service = server.Service(self.config, self.host, gate, run)
        self.httpd = ThreadingHTTPServer(("localhost", 0), server.make_handler(self.service))
        self.httpd.daemon_threads = True
        self.url = f"http://localhost:{self.httpd.server_address[1]}"

    def __enter__(self):
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        return self

    def __exit__(self, *exc):
        self.httpd.shutdown()
        self.httpd.server_close()

    def call(self, method, path, body=None, headers=None):
        req = urllib.request.Request(
            self.url + path, data=body, method=method, headers=headers or {}
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status, dict(r.headers), r.read()
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers), e.read()

    def post(self, doc):
        return self.call(
            "POST", "/synthesize", json.dumps(doc).encode(), {"Content-Type": "application/json"}
        )


def test_synthesize_answers_a_24k_mono_16bit_wav_with_the_wav_type(tmp_path):
    log: list = []
    with Running(tmp_path, log) as s:
        status, headers, data = s.post(
            {"text": "The US is here.", "temperature": 0.7, "top_p": 0.9}
        )
    assert status == 200 and headers["Content-Type"] == "audio/wav"
    with wave.open(io.BytesIO(data)) as w:
        assert (w.getframerate(), w.getnchannels(), w.getsampwidth(), w.getnframes()) == (
            SAMPLE_RATE, 1, 2, 24000,
        )  # fmt: skip
    # the engine saw the normalised text and the caller's sampling values
    assert ("synth", "The U.S. is here.", 0.7, 0.9) in log


def test_a_sample_out_of_range_is_clipped_not_wrapped(tmp_path):
    with Running(tmp_path, []) as s:
        _, _, data = s.post({"text": "x"})
    with wave.open(io.BytesIO(data)) as w:
        frames = w.readframes(6)
    import struct

    vals = struct.unpack("<6h", frames)
    assert vals[3] == 32767 and vals[4] == -32767 and vals[5] == 32767  # 1.0, -1.0, 2.0 -> clipped


def test_defaults_reach_the_engine_when_the_caller_sends_only_text(tmp_path):
    log: list = []
    with Running(tmp_path, log) as s:
        assert s.post({"text": "Hello."})[0] == 200
    assert ("synth", "Hello.", 0.6, 0.85) in log


def test_empty_text_is_400_before_the_engine_is_touched(tmp_path):
    log: list = []
    with Running(tmp_path, log) as s:
        status, _, data = s.post({"text": "  "})
    assert status == 400 and json.loads(data) == {"detail": "text must not be empty"}
    assert ("load",) not in log


def test_a_bad_body_is_422_with_a_detail_list(tmp_path):
    with Running(tmp_path, []) as s:
        status, _, data = s.post({"text": "x", "temperature": 9})
        bad = s.call("POST", "/synthesize", b"not json", {"Content-Type": "application/json"})
    assert status == 422 and json.loads(data)["detail"][0]["loc"] == ["body", "temperature"]
    assert bad[0] == 422


def test_a_refused_load_is_503_with_the_reason_and_nothing_loads(tmp_path):
    log: list = []

    def hot(cmd, **kw):
        from types import SimpleNamespace

        return SimpleNamespace(returncode=0, stdout="300\n", stderr="")

    env = {"TTS_BACKEND": "cuda"}
    with Running(tmp_path, log, env_over=env, run=hot) as s:
        # the real build() wires the gate; here the host's before_load is the same call
        s.host._before_load = lambda: gates.check_power_cap("cuda", 200, 0, hot)
        status, _, data = s.post({"text": "x"})
    assert status == 503 and "above the 200 W limit" in json.loads(data)["detail"]
    assert ("load",) not in log


def test_health_is_the_old_shape_and_reports_whether_the_model_is_loaded(tmp_path):
    with Running(tmp_path, []) as s:
        status, _, data = s.call("GET", "/health")
        before = json.loads(data)
        s.post({"text": "x"})
        after = json.loads(s.call("GET", "/health")[2])
    assert status == 200 and set(before) == {"status", "model_loaded", "refs"}
    assert (
        before["status"] == "ok"
        and before["model_loaded"] is False
        and after["model_loaded"] is True
    )
    assert [Path(r).name for r in before["refs"]] == [
        "ref1.wav",
        "ref2.wav",
        "ref3.wav",
        "ref4.wav",
    ]


def test_ready_is_503_with_the_failing_check_until_the_voice_is_there(tmp_path):
    with Running(tmp_path, []) as s:
        assert s.call("GET", "/ready")[0] == 200
        (s.config.refs_dir / "ref3.wav").unlink()
        status, _, data = s.call("GET", "/ready")
    doc = json.loads(data)
    assert (
        status == 503
        and doc["ready"] is False
        and "ref3.wav" in doc["checks"]["voice_refs"]["detail"]
    )


def test_ready_does_not_load_the_model(tmp_path):
    log: list = []
    with Running(tmp_path, log) as s:
        s.call("GET", "/ready")
    assert ("load",) not in log


def test_unknown_paths_and_wrong_methods_answer_as_before(tmp_path):
    with Running(tmp_path, []) as s:
        assert json.loads(s.call("GET", "/nope")[2]) == {"detail": "Not Found"}
        assert s.call("GET", "/synthesize")[0] == 405
        assert s.call("POST", "/health", b"{}")[0] == 405
        assert s.call("POST", "/elsewhere", b"{}")[0] == 404


def test_an_oversized_body_is_refused_without_reading_it(tmp_path):
    import http.client

    with Running(tmp_path, []) as s:
        conn = http.client.HTTPConnection("localhost", s.httpd.server_address[1], timeout=10)
        conn.putrequest("POST", "/synthesize")
        conn.putheader("Content-Length", str(MAX_BODY_BYTES + 1))
        conn.endheaders()  # the body is never sent
        resp = conn.getresponse()
        assert resp.status == 413
        conn.close()


def test_the_self_check_passes_on_a_good_answer_and_fails_on_a_wrong_one(tmp_path, capsys):
    with Running(tmp_path, []) as s:
        env = {"TTS_CHECK_URL": s.url}
        assert server.check(env, ["--min-seconds", "0.5", "--max-seconds", "2"]) == 0
        doc = json.loads(capsys.readouterr().out)
        assert doc["ok"] and doc["sample_rate"] == 24000 and doc["seconds"] == 1.0
        # a duration outside the bounds fails
        assert server.check(env, ["--min-seconds", "2", "--max-seconds", "9"]) == 1
        assert json.loads(capsys.readouterr().out)["ok"] is False
    # nothing listening: a failure with a reason, not a traceback
    import socket

    with socket.socket() as sock:  # a port nothing listens on: bound, then released
        sock.bind(("localhost", 0))
        closed = sock.getsockname()[1]
    assert server.check({"TTS_CHECK_URL": f"http://localhost:{closed}"}, ["--timeout", "2"]) == 1
    assert "error" in json.loads(capsys.readouterr().out)


def test_the_config_refuses_what_would_loosen_the_rules(tmp_path):
    base = make_env(tmp_path)
    for over in (
        {"TTS_POWER_CAP_MAX_WATTS": "201"}, {"TTS_POWER_CAP_MAX_WATTS": "0"},
        {"TTS_BACKEND": "vulkan"}, {"TTS_IDLE_UNLOAD_S": "-1"}, {"TTS_REF_FILES": "../x.wav"},
    ):  # fmt: skip
        with pytest.raises(ValueError):
            server.Config.from_env({**base, **over})
    for name in ("TTS_MODEL_DIR", "TTS_MODEL_LISTING", "TTS_MODEL_DIGEST", "TTS_REFS_DIR"):
        with pytest.raises(ValueError, match=name):
            server.Config.from_env({k: v for k, v in base.items() if k != name})


def test_build_wires_every_gate_before_the_engine_loads(tmp_path):
    """The assembled service refuses (503) for each missing precondition, loading nothing."""
    env = make_env(tmp_path)
    cfg = server.Config.from_env(env)
    svc = server.build(cfg)
    (cfg.refs_dir / "ref2.wav").unlink()
    with pytest.raises(Unavailable, match="voice reference"), svc.host.lease():
        pass
    (cfg.refs_dir / "ref2.wav").write_bytes(b"RIFF")
    (cfg.model_dir / "model.pth").write_bytes(b"corrupt")
    with pytest.raises(Unavailable, match=r"model\.pth is sha256"), svc.host.lease():
        pass
    assert not svc.host.loaded
