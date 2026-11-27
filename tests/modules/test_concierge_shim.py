# SPDX-License-Identifier: Apache-2.0
"""The concierge shim (modules/openwebui, files/concierge_shim.py): run in-process against a fake
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
import threading
import urllib.error
import urllib.request
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "modules" / "openwebui" / "roles" / "openwebui" / "files" / "concierge_shim.py"
spec = importlib.util.spec_from_file_location("concierge_shim", SRC)
cs = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cs)  # type: ignore[union-attr]

TOKEN, GWKEY, CTXTOKEN = "shim-token-" + "t" * 30, "gw-key-" + "g" * 30, "ctx-" + "c" * 20


class _Fake(http.server.BaseHTTPRequestHandler):
    seen: list[dict] = []
    roles: list[str] = ["main-reasoner"]
    refuse = False
    hits: list[dict] = []

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
        _Fake.seen.append({"path": "chat", "body": body, "tlp": self.headers.get("X-HNX-TLP"),
                           "tag": self.headers.get("X-HNX-Tag"), "auth": self.headers["Authorization"]})
        if self.refuse:
            return self._send(429, {"error": {"message": "rate limited"}})
        if body.get("stream"):
            return self._send(200, b'data: {"x":1}\n\ndata: [DONE]\n\n', "text/event-stream")
        self._send(200, {"model": body["model"], "choices": [{"message": {"role": "assistant", "content": "pong"}}]})


@pytest.fixture()
def stack(monkeypatch):
    _Fake.seen, _Fake.roles, _Fake.refuse, _Fake.hits = [], ["main-reasoner"], False, []
    fake = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Fake)
    threading.Thread(target=fake.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{fake.server_port}"
    cfg = {"port": 0, "gateway_url": base, "default_tlp": "amber", "max_tlp": "amber", "default_tag": "openwebui",
           "history_chars": 100, "max_body_bytes": 100000, "timeout_s": 10, "always_on_tier": "main",
           "tiers": {"fast": "fast", "main": "main-reasoner", "deep": "deep"},
           "models": [{"id": "concierge-fast", "tier": "fast"}, {"id": "concierge", "tier": "main", "context": True},
                      {"id": "concierge-deep", "tier": "deep"}],
           "persona": "You are the concierge.",
           "context": {"url": base, "allowed": ["lab"], "ceiling": "amber", "top_k": 3}}
    shim = cs.Shim(cfg, GWKEY, TOKEN, CTXTOKEN)
    front = http.server.ThreadingHTTPServer(("127.0.0.1", 0), cs.make_handler(shim))
    front.daemon_threads = True
    threading.Thread(target=front.serve_forever, daemon=True).start()
    yield shim, f"http://127.0.0.1:{front.server_port}"
    fake.shutdown()
    front.shutdown()


def call(url, path, body=None, token=TOKEN, headers=None):
    req = urllib.request.Request(url + path, data=None if body is None else json.dumps(body).encode(),
                                 headers={"Authorization": "Bearer " + token, "Content-Type": "application/json", **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def chat(url, model="concierge", content="hello", **kw):
    return call(url, "/v1/chat/completions", {"model": model, "messages": [{"role": "user", "content": content}]}, **kw)


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
    seen = [s for s in _Fake.seen if s["path"] == "chat"][0]
    assert seen["auth"] == "Bearer " + GWKEY and seen["body"]["model"] == "main-reasoner"


def test_headers_pass_through_with_defaults_and_a_ceiling(stack):
    _, url = stack
    chat(url, headers={"X-HNX-Tag": "openwebui:u1", "X-HNX-TLP": "green"})
    chat(url)
    first, second = [s for s in _Fake.seen if s["path"] == "chat"]
    assert (first["tlp"], first["tag"]) == ("green", "openwebui:u1")
    assert (second["tlp"], second["tag"]) == ("amber", "openwebui")
    assert chat(url, headers={"X-HNX-TLP": "red"})[0] == 400


def test_persona_added_history_trimmed_and_the_last_turn_kept(stack):
    _, url = stack
    msgs = [{"role": "system", "content": "s"}]
    for i in range(6):
        msgs += [{"role": "user", "content": f"q{i}" + "x" * 30}, {"role": "assistant", "content": f"a{i}" + "y" * 30}]
    msgs.append({"role": "user", "content": "the question"})
    assert call(url, "/v1/chat/completions", {"model": "concierge", "messages": msgs})[0] == 200
    sent = [s for s in _Fake.seen if s["path"] == "chat"][0]["body"]["messages"]
    assert sent[0] == {"role": "system", "content": "You are the concierge."}
    assert sent[-1]["content"] == "the question" and {"role": "system", "content": "s"} in sent
    assert sum(len(cs.message_text(m["content"])) for m in sent if m["role"] != "system") <= 100 + 80
    assert len(sent) < len(msgs) + 1


def test_retrieved_passages_above_the_ceiling_are_never_sent(stack):
    _, url = stack
    _Fake.hits = [{"id": "lesson:LL-1", "tlp": "amber", "content": "AMBERTEXT"},
                  {"id": "lesson:LL-2", "tlp": "red", "content": "REDTEXT"}]
    assert chat(url, content="what is LL-1")[0] == 200
    sent = json.dumps([s for s in _Fake.seen if s["path"] == "chat"][0]["body"]["messages"])
    assert "AMBERTEXT" in sent and "lesson:LL-1" in sent and "REDTEXT" not in sent
    q = [s for s in _Fake.seen if s["path"] == "query"][0]["body"]
    assert q["allowed"] == ["lab"] and q["ceiling"] == "amber"


def test_a_gateway_refusal_is_passed_on_and_streaming_passes_through(stack):
    _, url = stack
    _Fake.refuse = True
    code, body = chat(url)
    assert code == 429 and b"rate limited" in body
    _Fake.refuse = False
    req = urllib.request.Request(url + "/v1/chat/completions", headers={"Authorization": "Bearer " + TOKEN, "Content-Type": "application/json"},
                                 data=json.dumps({"model": "concierge", "stream": True, "messages": [{"role": "user", "content": "hi"}]}).encode())
    with urllib.request.urlopen(req, timeout=10) as r:
        assert r.headers["Content-Type"] == "text/event-stream" and b"[DONE]" in r.read()


def test_trim_history_keeps_system_and_the_last_message_even_over_budget():
    msgs = [{"role": "system", "content": "s"}, {"role": "user", "content": "x" * 500}]
    out, dropped = cs.trim_history(msgs, 10)
    assert out == msgs and dropped == 0
