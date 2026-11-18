# SPDX-License-Identifier: Apache-2.0
"""The inference provider role that serves decision models, as well as chat ones, run on localhost against fakes (CI is unprivileged):

* mode ``generate`` (the default) starts the server without batch flags and its health asks for one
  chat token; a server that refuses chat (501) is unhealthy, never vacuously healthy;
* mode ``decision`` (a decision model: chat is refused by design, ``POST /v1/systemone`` answers)
  starts the server with ``-b`` and ``-ub`` equal to the per-slot context (LL-492), and its health
  asks ``/v1/systemone`` for a probability in [0, 1] for a tiny state and, when a slot holds it, for a
  state past 512 tokens; an empty, partial, boolean, out-of-range or non-200 answer is a failure,
  and so is a server that still caps the batch at 512.
"""

from __future__ import annotations

import http.server
import json
import os
import socket
import threading
import time
from pathlib import Path

import pytest
import yaml
from rolerun import fake, first_run, run_role

ROOT = Path(__file__).resolve().parents[2]
pytestmark = pytest.mark.requires_tool("ansible-playbook")
# the role under test is the one that ships the decision-model probe (named by what it does, not by product)
ROLE_DIR = next((ROOT / "modules").glob("*/roles/*/tasks/decision_probe.yml")).parents[1]
ROLE = str(ROLE_DIR)
P = ROLE_DIR.name + "_"  # the role's variable prefix
PRECHECK = str(next((ROLE_DIR / "files").glob("hnx-*-precheck")))
LOOP = socket.gethostbyname("localhost")
USER = __import__("pwd").getpwuid(os.getuid()).pw_name
GID = str(os.getgid())
# the server's own limit in this mode when -b/-ub are not raised
FORCED_BATCH_TOKENS = 512


def vs(tmp: Path, **over) -> dict:
    v = {
        "logical_id": "inference-small",
        "backend": "cpu",
        "image": "registry.example.internal/inference/server:server-b12033@sha256:" + "a" * 64,
        "bind": LOOP,
        "dir": str(tmp / "app"),
        "data_root": str(tmp / "data"),
        "owner": USER,
        "uid": os.getuid(),  # chown to another id needs root; the role wants 1000 or more
        "gid": os.getgid(),
        "store_root": str(tmp / "models"),
        "models_gid": GID,
        "precheck_bin": PRECHECK,
        "unit_dir": str(tmp / "units"),
        "systemctl_cli": str(tmp / "bin" / "systemctl"),
        "start": False,
        "validate_with_docker": False,
        "context_size": 4096,
        "parallel": 2,
    }
    v.update(over)
    return {P + k: val for k, val in v.items()}


def _flag(cmd: list, name: str):
    return cmd[cmd.index(name) + 1] if name in cmd else None


def _compose_command(tmp: Path, **over) -> list:
    v = vs(tmp, **over)
    store = Path(v[P + "store_root"]) / "gguf" / "ggml-org" / "Clef-GGUF"
    (tmp / "units").mkdir()
    store.mkdir(parents=True)
    (store / "Clef-Q4_K_M.gguf").write_bytes(b"x")
    (Path(v[P + "store_root"]) / "manifests" / "listings").mkdir(parents=True)
    r = run_role(tmp, ROLE, "main", v)
    assert r.returncode == 0, r.stdout[-2500:] + r.stderr
    svc = yaml.safe_load((tmp / "app" / "docker-compose.yml").read_text())["services"][
        ROLE_DIR.name
    ]
    return svc["command"]


def test_generate_mode_starts_without_batch_flags(tmp_path):
    cmd = _compose_command(tmp_path)
    assert _flag(cmd, "-c") == "8192"  # 4096 per slot, two slots
    assert "-b" not in cmd and "-ub" not in cmd


@pytest.mark.parametrize("ctx", [4096, 8192])
def test_decision_mode_raises_both_batch_sizes_to_the_slot_context(tmp_path, ctx):
    cmd = _compose_command(tmp_path, mode="decision", context_size=ctx)
    assert _flag(cmd, "-b") == str(ctx) and _flag(cmd, "-ub") == str(ctx)
    assert _flag(cmd, "-c") == str(ctx * 2)


def _first_an_unknown_mode_is_refused(tmp_path):
    return {"role": ROLE, "tasks_from": "health", "extra_vars": vs(tmp_path, mode="chatty")}


@first_run(_first_an_unknown_mode_is_refused)
def test_an_unknown_mode_is_refused(first):
    r, _ = first
    assert r.returncode != 0 and "a mode (generate or decision)" in r.stdout


# ---------------------------------------------------------------------------------- health
ANSWERS = {"answers": {"hnx-health": {"type": "noul", "noul": 0.93}}, "usage": {}}
CHAT_OK = {"choices": [{"message": {"content": "p"}}], "usage": {"completion_tokens": 1}}
REFUSED = {
    "error": {"code": 501, "message": "This model is a decision model without text generation"}
}


class _Server:
    """A server stand-in: /health, /v1/models, /metrics, chat, and systemone."""

    def __init__(self, ctx=4096, chat=(200, CHAT_OK), systemone=None, batch=None):
        outer = self
        outer.ctx, outer.chat, outer.batch = ctx, chat, batch
        outer.systemone = systemone or (lambda state, body: (200, ANSWERS))
        outer.seen = []

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, status, body, raw=False):
                data = body.encode() if raw else json.dumps(body).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                if self.path == "/health":
                    return self._send(200, {"status": "ok"})
                if self.path == "/v1/models":
                    return self._send(200, {"data": [{"id": "clef", "meta": {"n_ctx": outer.ctx}}]})
                if self.path == "/metrics":
                    return self._send(200, f"{ROLE_DIR.name}:requests_processing 0\n", raw=True)
                self.send_error(404)

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
                outer.seen.append((self.path, body))
                if self.path == "/v1/chat/completions":
                    return self._send(*outer.chat)
                if self.path == "/v1/systemone":
                    state = body.get("state", "")
                    if outer.batch and len(state.split()) > outer.batch:
                        return self._send(
                            500, {"error": {"message": "input is too large to process"}}
                        )
                    return self._send(*outer.systemone(state, body))
                self.send_error(404)

        self._httpd = http.server.ThreadingHTTPServer((LOOP, 0), H)

    def __enter__(self):
        threading.Thread(
            target=self._httpd.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True
        ).start()
        return self

    def __exit__(self, *a):
        self._httpd.shutdown()
        self._httpd.server_close()

    @property
    def port(self):
        return self._httpd.server_address[1]


def _health(tmp: Path, server: _Server, **over):
    bindir = tmp / "bin"
    bindir.mkdir(exist_ok=True)
    fake(bindir / "systemctl", "print('active')\n")
    state = json.dumps({"Service": ROLE_DIR.name, "State": "running", "Health": "healthy"})
    fake(bindir / "docker", f"import sys\nsys.stdout.write({state + chr(10)!r})\n")
    (tmp / "models" / "gguf" / "ggml-org" / "Clef-GGUF").mkdir(parents=True, exist_ok=True)
    env = {"PATH": f"{bindir}:{os.environ['PATH']}"}
    return run_role(tmp, ROLE, "health", vs(tmp, port=server.port, **over), env=env)


def test_generate_health_passes_on_a_chat_token(tmp_path):
    with _Server() as s:
        r = _health(tmp_path, s)
    assert r.returncode == 0, r.stdout[-2500:]
    # the warm-up, then the timed probe
    assert [p for p, _ in s.seen] == ["/v1/chat/completions"] * 2


@pytest.mark.parametrize("chat", [(501, REFUSED), (200, {}), (200, {"choices": []})])
def test_generate_health_is_never_vacuous_on_a_server_that_gives_no_token(tmp_path, chat):
    with _Server(chat=chat) as s:
        r = _health(tmp_path, s)
    assert r.returncode != 0, r.stdout[-1500:]


def test_decision_health_passes_on_a_probability_and_never_calls_chat(tmp_path):
    with _Server(chat=(501, REFUSED)) as s:
        r = _health(tmp_path, s, mode="decision")
    assert r.returncode == 0, r.stdout[-2500:]
    paths = [p for p, _ in s.seen]
    # the warm-up, the tiny state, then the long one
    assert paths == ["/v1/systemone"] * 3
    _warm, tiny, long_ = (b for _, b in s.seen)
    assert tiny["model"] == "clef" and list(tiny["questions"]) == ["hnx-health"]
    assert tiny["questions"]["hnx-health"]["type"] == "noul"
    assert len(long_["state"].split()) > FORCED_BATCH_TOKENS  # past the forced batch


def _slow_systemone(first=0.0, every=0.0):
    """A /v1/systemone answer that takes ``first`` s on the first call and ``every`` s on each."""
    calls = []

    def answer(state, body):
        calls.append(1)
        time.sleep(every + (first if len(calls) == 1 else 0.0))
        return 200, ANSWERS

    return answer


def test_decision_health_survives_a_cold_first_call_slower_than_the_steady_state_timeout(tmp_path):
    """The decision-mode warm-up takes the first-request timeout; the timed probes after it
    run warm under the steady-state one."""
    with _Server(systemone=_slow_systemone(first=3.0)) as s:
        r = _health(tmp_path, s, mode="decision", health_timeout=1, first_request_timeout=30)
    assert r.returncode == 0, r.stdout[-2500:]


def test_decision_health_still_fails_a_server_that_is_slow_on_every_call(tmp_path):
    with _Server(systemone=_slow_systemone(every=3.0)) as s:
        r = _health(tmp_path, s, mode="decision", health_timeout=1, first_request_timeout=30)
    assert r.returncode != 0


def test_decision_health_skips_the_long_probe_when_a_slot_cannot_hold_it(tmp_path):
    with _Server(ctx=1024) as s:
        r = _health(tmp_path, s, mode="decision", context_size=1024)
    assert r.returncode == 0, r.stdout[-2500:]
    assert len(s.seen) == 2  # the warm-up and the tiny state


def test_decision_health_fails_when_the_server_still_caps_the_batch(tmp_path):
    with _Server(batch=FORCED_BATCH_TOKENS) as s:
        r = _health(tmp_path, s, mode="decision")
    assert r.returncode != 0 and "LL-492" in r.stdout, r.stdout[-1500:]


@pytest.mark.parametrize(
    "answer",
    [
        (501, REFUSED),  # a chat-only server (a generation model run in decision mode)
        (200, {}),
        (200, {"answers": {}}),
        (200, {"answers": {"hnx-health": {"type": "noul"}}}),
        (200, {"answers": {"hnx-health": {"type": "noul", "noul": True}}}),
        (200, {"answers": {"hnx-health": {"type": "noul", "noul": "0.5"}}}),
        (200, {"answers": {"hnx-health": {"type": "noul", "noul": 1.5}}}),
        (200, {"answers": {"hnx-health": {"type": "noul", "noul": -0.1}}}),
        (200, {"answers": {"other": {"type": "noul", "noul": 0.5}}}),
        (200, {"answers": {"hnx-health": {"type": "text", "noul": 0.5}}}),
        (500, {"error": {"message": "boom"}}),
    ],
)
def test_decision_health_fails_on_anything_but_a_probability(tmp_path, answer):
    with _Server(systemone=lambda st, b: answer) as s:
        r = _health(tmp_path, s, mode="decision")
    assert r.returncode != 0, r.stdout[-1500:]


@pytest.mark.parametrize("p", [0, 0.0, 1, 0.5])
def test_decision_health_accepts_the_edges_of_the_range(tmp_path, p):
    with _Server(
        systemone=lambda st, b: (200, {"answers": {"hnx-health": {"type": "noul", "noul": p}}})
    ) as s:
        r = _health(tmp_path, s, mode="decision")
    assert r.returncode == 0, r.stdout[-1500:]
