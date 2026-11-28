# SPDX-License-Identifier: Apache-2.0
"""The concierge shim (the chat module's sidecar, files/concierge_shim.py): run in-process against a fake
gateway and a fake context service.

* a tier is listed only while the gateway lists its role (the main tier always), and a request for
  a tier that is not live is a 404 naming the live models, never a fallback to another tier;
* the bearer token is required (a wrong one is a 401), the gateway key is the shim's own and the
  caller's TLP label and usage tag pass through (defaults when absent, a label above the ceiling
  refused);
* the persona is added, history is trimmed to the budget (system messages and the last turn stay),
  and retrieved passages above the ceiling are never sent to the model;
* a gateway refusal is passed on as it is, and streaming is passed through.
"""

from __future__ import annotations

import http.server
import importlib.util
import json
import socket
import threading
import urllib.error
import urllib.request
from pathlib import Path
from typing import ClassVar

import pytest

ROOT = Path(__file__).resolve().parents[2]
(SRC,) = ROOT.glob("modules/*/roles/*/files/concierge_shim.py")
spec = importlib.util.spec_from_file_location("concierge_shim", SRC)
cs = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cs)  # type: ignore[union-attr]

TOKEN, GWKEY, CTXTOKEN = "shim-token-" + "t" * 30, "gw-key-" + "g" * 30, "ctx-" + "c" * 20


class _Fake(http.server.BaseHTTPRequestHandler):
    seen: ClassVar[list[dict]] = []
    roles: ClassVar[list[str]] = ["main-reasoner"]
    refuse = False
    hits: ClassVar[list[dict]] = []
    status: ClassVar[int] = 200
    raw: ClassVar[bytes | None] = None
    gate: ClassVar[threading.Event | None] = None
    first_sent: ClassVar[threading.Event] = threading.Event()

    def log_message(self, *a):  # quiet
        pass

    def _send(self, code, doc, ctype="application/json"):
        data = doc if isinstance(doc, bytes) else json.dumps(doc).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        assert self.headers["Authorization"] == "Bearer " + GWKEY
        self._send(200, {"object": "list", "data": [{"id": r} for r in self.roles]})

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        if self.path == "/v1/query":
            assert self.headers["Authorization"] == "Bearer " + CTXTOKEN
            _Fake.seen.append({"path": "query", "body": body})
            return self._send(200, {"hits": self.hits})
        _Fake.seen.append(
            {
                "path": "chat",
                "body": body,
                "tlp": self.headers.get("X-HNX-TLP"),
                "tag": self.headers.get("X-HNX-Tag"),
                "auth": self.headers["Authorization"],
            }
        )
        if self.status != 200:
            return self._send(self.status, {"error": {"message": "refused"}})
        if self.raw is not None:
            return self._send(200, self.raw)
        if body.get("stream") and self.gate is not None:
            # two chunks, the second only after the test saw the first: proves nothing is buffered
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(b'data: {"model":"main-reasoner","n":1}\n\n')
            self.wfile.flush()
            _Fake.first_sent.set()
            self.gate.wait(10)
            self.wfile.write(b'data: {"model":"main-reasoner","n":2}\n\ndata: [DONE]\n\n')
            self.wfile.flush()
            self.close_connection = True
            return
        if self.refuse:
            return self._send(429, {"error": {"message": "rate limited"}})
        if body.get("stream"):
            return self._send(200, b'data: {"x":1}\n\ndata: [DONE]\n\n', "text/event-stream")
        self._send(
            200,
            {
                "model": body["model"],
                "choices": [{"message": {"role": "assistant", "content": "pong"}}],
            },
        )


@pytest.fixture
def stack(monkeypatch):
    _Fake.seen, _Fake.roles, _Fake.refuse, _Fake.hits = [], ["main-reasoner"], False, []
    _Fake.status, _Fake.raw, _Fake.gate = 200, None, None
    _Fake.first_sent = threading.Event()
    fake = http.server.ThreadingHTTPServer(("localhost", 0), _Fake)
    threading.Thread(target=fake.serve_forever, daemon=True).start()
    base = f"http://localhost:{fake.server_port}"
    cfg = {
        "port": 0,
        "gateway_url": base,
        "default_tlp": "amber",
        "max_tlp": "amber",
        "default_tag": "chat-app",
        "history_chars": 100,
        "max_body_bytes": 4000,
        "timeout_s": 10,
        "always_on_tier": "main",
        "tiers": {"fast": "fast", "main": "main-reasoner", "deep": "deep"},
        "models": [
            {"id": "concierge-fast", "tier": "fast"},
            {"id": "concierge", "tier": "main", "context": True},
            {"id": "concierge-deep", "tier": "deep"},
        ],
        "persona": "You are the concierge.",
        "context": {"url": base, "allowed": ["lab"], "ceiling": "amber", "top_k": 3},
    }
    shim = cs.Shim(cfg, GWKEY, TOKEN, CTXTOKEN)
    front = http.server.ThreadingHTTPServer(("localhost", 0), cs.make_handler(shim))
    front.daemon_threads = True
    threading.Thread(target=front.serve_forever, daemon=True).start()
    yield shim, f"http://localhost:{front.server_port}"
    fake.shutdown()
    front.shutdown()


def call(url, path, body=None, token=TOKEN, headers=None):
    req = urllib.request.Request(
        url + path,
        data=None if body is None else json.dumps(body).encode(),
        headers={
            "Authorization": "Bearer " + token,
            "Content-Type": "application/json",
            **(headers or {}),
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def chat(url, model="concierge", content="hello", **kw):
    return call(
        url,
        "/v1/chat/completions",
        {"model": model, "messages": [{"role": "user", "content": content}]},
        **kw,
    )


def test_a_tier_is_listed_only_while_its_role_is_live(stack):
    shim, url = stack
    listed = lambda: [m["id"] for m in json.loads(call(url, "/v1/models")[1])["data"]]  # noqa: E731
    assert listed() == ["concierge"]
    _Fake.roles = ["main-reasoner", "fast"]
    shim._live = (0.0, set())  # the cache expires
    assert listed() == ["concierge-fast", "concierge"]


def test_a_tier_that_is_not_live_is_a_404_never_a_fallback(stack):
    _, url = stack
    code, body = chat(url, model="concierge-deep")
    assert code == 404 and b"concierge-deep" in body and b"live models: concierge" in body
    assert not [s for s in _Fake.seen if s["path"] == "chat"]  # nothing reached the gateway


def test_the_token_is_required_and_the_gateway_key_stays_the_shims(stack):
    _, url = stack
    assert chat(url, token="wrong")[0] == 401
    assert call(url, "/v1/models", token="")[0] == 401
    code, body = chat(url)
    assert code == 200 and json.loads(body)["model"] == "concierge"
    seen = next(s for s in _Fake.seen if s["path"] == "chat")
    assert seen["auth"] == "Bearer " + GWKEY and seen["body"]["model"] == "main-reasoner"


def test_headers_pass_through_with_defaults_and_a_ceiling(stack):
    _, url = stack
    chat(url, headers={"X-HNX-Tag": "chat-app:u1", "X-HNX-TLP": "green"})
    chat(url)
    first, second = [s for s in _Fake.seen if s["path"] == "chat"]
    assert (first["tlp"], first["tag"]) == ("green", "chat-app:u1")
    assert (second["tlp"], second["tag"]) == ("amber", "chat-app")
    assert chat(url, headers={"X-HNX-TLP": "red"})[0] == 400


def test_persona_added_history_trimmed_and_the_last_turn_kept(stack):
    _, url = stack
    msgs = [{"role": "system", "content": "s"}]
    for i in range(6):
        msgs += [
            {"role": "user", "content": f"q{i}" + "x" * 30},
            {"role": "assistant", "content": f"a{i}" + "y" * 30},
        ]
    msgs.append({"role": "user", "content": "the question"})
    assert call(url, "/v1/chat/completions", {"model": "concierge", "messages": msgs})[0] == 200
    sent = next(s for s in _Fake.seen if s["path"] == "chat")["body"]["messages"]
    assert sent[0] == {"role": "system", "content": "You are the concierge."}
    assert sent[-1]["content"] == "the question" and {"role": "system", "content": "s"} in sent
    assert (
        sum(len(cs.message_text(m["content"])) for m in sent if m["role"] != "system") <= 100 + 80
    )
    assert len(sent) < len(msgs) + 1


def test_retrieved_passages_above_the_ceiling_are_never_sent(stack):
    _, url = stack
    _Fake.hits = [
        {"id": "lesson:LL-1", "tlp": "amber", "content": "AMBERTEXT"},
        {"id": "lesson:LL-2", "tlp": "red", "content": "REDTEXT"},
    ]
    assert chat(url, content="what is LL-1")[0] == 200
    sent = json.dumps(next(s for s in _Fake.seen if s["path"] == "chat")["body"]["messages"])
    assert "AMBERTEXT" in sent and "lesson:LL-1" in sent and "REDTEXT" not in sent
    q = next(s for s in _Fake.seen if s["path"] == "query")["body"]
    assert q["allowed"] == ["lab"] and q["ceiling"] == "amber"


def test_a_gateway_refusal_is_passed_on_and_streaming_passes_through(stack):
    _, url = stack
    _Fake.refuse = True
    code, body = chat(url)
    assert code == 429 and b"rate limited" in body
    _Fake.refuse = False
    req = urllib.request.Request(
        url + "/v1/chat/completions",
        headers={"Authorization": "Bearer " + TOKEN, "Content-Type": "application/json"},
        data=json.dumps(
            {"model": "concierge", "stream": True, "messages": [{"role": "user", "content": "hi"}]}
        ).encode(),
    )
    with urllib.request.urlopen(req, timeout=10) as r:
        assert r.headers["Content-Type"] == "text/event-stream" and b"[DONE]" in r.read()


def test_trim_history_keeps_system_and_the_last_message_even_over_budget():
    msgs = [{"role": "system", "content": "s"}, {"role": "user", "content": "x" * 500}]
    out, dropped = cs.trim_history(msgs, 10)
    assert out == msgs and dropped == 0


# ----------------------------------------------------------------------------- hardening
def raw_exchange(url, request: bytes) -> bytes:
    host, port = url.removeprefix("http://").split(":")
    with socket.create_connection((host, int(port)), timeout=10) as c:
        c.sendall(request)
        c.shutdown(socket.SHUT_WR)
        out = b""
        while chunk := c.recv(65536):
            out += chunk
    return out


def post_raw(url, headers: dict, body: bytes = b"", path="/v1/chat/completions"):
    h = {"Authorization": "Bearer " + TOKEN, **headers}
    head = f"POST {path} HTTP/1.1\r\nHost: x\r\n" + "".join(f"{k}: {v}\r\n" for k, v in h.items())
    return raw_exchange(url, head.encode() + b"\r\n" + body)


def test_413_missing_body_and_malformed_length_are_fixed_400s_or_413(stack):
    _, url = stack
    assert post_raw(url, {"Content-Length": "10000000"}).startswith(b"HTTP/1.1 413")
    assert post_raw(url, {"Content-Length": "0"}).startswith(b"HTTP/1.1 400")
    assert post_raw(url, {}).startswith(b"HTTP/1.1 400")
    out = post_raw(url, {"Content-Length": "abc"}, b"{}")
    assert out.startswith(b"HTTP/1.1 400") and b"Traceback" not in out


@pytest.mark.parametrize("body", [b"[1,2]", b'"x"', b"not json", b'{"model":"concierge","messages":[1]}',
                                  b'{"model":"concierge","messages":"x"}'])  # fmt: skip
def test_malformed_bodies_are_400_never_a_traceback(stack, body):
    _, url = stack
    out = post_raw(
        url, {"Content-Length": str(len(body)), "Content-Type": "application/json"}, body
    )
    assert out.startswith(b"HTTP/1.1 400") and b"Traceback" not in out


def test_a_refusal_before_the_body_is_read_closes_the_connection(stack):
    _, url = stack
    # a bad token on a wrong path, with a body that looks like a second request: it must not be run
    smuggled = b"GET /v1/models HTTP/1.1\r\nHost: x\r\n\r\n"
    out = post_raw(
        url,
        {"Content-Length": str(len(smuggled)), "Authorization": "Bearer wrong"},
        smuggled,
        path="/nope",
    )
    assert (
        out.count(b"HTTP/1.1 ") == 1
        and out.startswith(b"HTTP/1.1 401")
        and b"Connection: close" in out
    )
    out = post_raw(url, {"Content-Length": str(len(smuggled))}, smuggled, path="/nope")
    assert out.count(b"HTTP/1.1 ") == 1 and out.startswith(b"HTTP/1.1 404")


def test_the_usage_tag_can_extend_the_prefix_but_not_forge_another(stack):
    _, url = stack
    for sent in ("chat-app:u1", "other:u1", "chat-app bad tag", "x" * 200, ""):
        chat(url, headers={"X-HNX-Tag": sent} if sent else None)
    tags = [s["tag"] for s in _Fake.seen if s["path"] == "chat"]
    assert tags == ["chat-app:u1", "chat-app", "chat-app", "chat-app", "chat-app"]


def test_system_messages_count_toward_the_history_budget(stack):
    _, url = stack
    msgs = [{"role": "system", "content": "S" * 90}]
    msgs += [{"role": "user", "content": "a" * 40}, {"role": "assistant", "content": "b" * 40},
             {"role": "user", "content": "last"}]  # fmt: skip
    assert call(url, "/v1/chat/completions", {"model": "concierge", "messages": msgs})[0] == 200
    sent = next(s for s in _Fake.seen if s["path"] == "chat")["body"]["messages"]
    assert [m["content"] for m in sent if m["role"] != "system"] == ["last"]  # 90 + history > 100


def test_a_gateway_auth_failure_is_a_502_not_a_wrong_token(stack):
    _, url = stack
    _Fake.status = 401
    code, body = chat(url)
    assert code == 502 and b"upstream_auth_failed" in body
    _Fake.status = 403
    assert chat(url)[0] == 502


def test_a_non_json_upstream_200_is_a_502(stack):
    _, url = stack
    _Fake.raw = b"<html>oops</html>"
    code, body = chat(url)
    assert code == 502 and b"Traceback" not in body


def test_streaming_is_incremental_and_names_the_tier(stack):
    _, url = stack
    _Fake.gate = threading.Event()
    req = urllib.request.Request(
        url + "/v1/chat/completions",
        headers={"Authorization": "Bearer " + TOKEN, "Content-Type": "application/json"},
        data=json.dumps({"model": "concierge", "stream": True, "messages": [{"role": "user", "content": "hi"}]}).encode(),
    )  # fmt: skip
    with urllib.request.urlopen(req, timeout=10) as r:
        first = r.readline()  # arrives while the gateway is still holding the second chunk back
        assert not _Fake.gate.is_set() and b'"n": 1' in first
        assert json.loads(first[5:])["model"] == "concierge"  # not the gateway's role name
        _Fake.gate.set()
        rest = r.read()
    assert b'"n": 2' in rest and b'"model": "concierge"' in rest and b"[DONE]" in rest
    assert b"main-reasoner" not in first + rest


def test_too_many_requests_in_flight_is_a_503(stack):
    shim, _ = stack
    shim.cfg = {**shim.cfg, "max_concurrent": 1}
    front = cs.ThreadingHTTPServer(("localhost", 0), cs.make_handler(shim))
    front.daemon_threads = True
    threading.Thread(target=front.serve_forever, daemon=True).start()
    url = f"http://localhost:{front.server_port}"
    _Fake.gate = threading.Event()
    held = threading.Thread(target=lambda: call(url, "/v1/chat/completions",
                                                {"model": "concierge", "stream": True,
                                                 "messages": [{"role": "user", "content": "hi"}]}))  # fmt: skip
    held.start()
    assert _Fake.first_sent.wait(10)
    assert chat(url)[0] == 503
    _Fake.gate.set()
    held.join(10)
    front.shutdown()


def test_scope_allowed_narrows_the_service_scope_and_never_widens_it():
    svc = ["lab", "tax:", "yardi:kb/"]
    assert cs.scope_allowed(svc, None) == svc and cs.scope_allowed(svc, []) == svc
    assert cs.scope_allowed(svc, ["tax:library/"]) == ["tax:library/"]  # inside a namespace
    assert cs.scope_allowed(svc, ["lab"]) == ["lab"]  # an exact id
    # not covered: dropped (a "lab:" namespace is not the exact id "lab"; "yardi:" is wider than "yardi:kb/")
    assert cs.scope_allowed(svc, ["secrets:", "yardi:", "lab:x"]) == []


def _persona_model(shim, **over):
    m = {
        "id": "concierge-tax",
        "tier": "main",
        "persona": "You are the tax research assistant.",
        "context": True,
        "context_allowed": ["tax:library/"],
        "context_top_k": 6,
        "grounded": True,
    }
    m.update(over)
    shim.models[m["id"]] = m
    shim.cfg["models"].append(m)
    shim.cfg["context"]["allowed"] = ["lab", "tax:"]


def test_a_persona_model_has_its_own_prompt_and_its_own_retrieval_scope(stack):
    shim, url = stack
    _persona_model(shim)
    _Fake.hits = [{"id": "tax:library/irc-469", "tlp": "amber", "content": "PASSIVEACTIVITY"}]
    assert chat(url, model="concierge-tax", content="rental losses")[0] == 200
    q = next(s for s in _Fake.seen if s["path"] == "query")["body"]
    assert q["allowed"] == ["tax:library/"] and q["budget"] == 6
    sent = next(s for s in _Fake.seen if s["path"] == "chat")["body"]
    assert sent["model"] == "main-reasoner"  # the local tier's role: no other binding exists
    text = json.dumps(sent["messages"])
    assert "tax research assistant" in text and "You are the concierge." not in text
    assert "PASSIVEACTIVITY" in text and "tax:library/irc-469" in text


def test_a_grounded_persona_is_told_when_nothing_was_retrieved(stack):
    shim, url = stack
    _persona_model(shim)
    _Fake.hits = []
    assert chat(url, model="concierge-tax", content="rental losses")[0] == 200
    text = json.dumps(next(s for s in _Fake.seen if s["path"] == "chat")["body"]["messages"])
    assert "No passages were retrieved" in text
    # an ungrounded model is not given the note
    _Fake.seen.clear()
    assert chat(url, content="hello")[0] == 200
    assert "No passages were retrieved" not in json.dumps(
        next(s for s in _Fake.seen if s["path"] == "chat")["body"]["messages"]
    )


def test_a_persona_scope_the_service_does_not_cover_reads_nothing(stack):
    shim, url = stack
    _persona_model(shim, context_allowed=["secrets:"])
    _Fake.hits = [{"id": "x", "tlp": "amber", "content": "LEAK"}]
    assert chat(url, model="concierge-tax")[0] == 200
    assert not [s for s in _Fake.seen if s["path"] == "query"]  # never asked
    assert "LEAK" not in json.dumps(next(s for s in _Fake.seen if s["path"] == "chat")["body"])
