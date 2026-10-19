# SPDX-License-Identifier: Apache-2.0
"""homelabnext._http: plaintext refusal, same-origin redirects, bounded reads, and the clients
that use them (notify, events forwarder, the OpenAI-compatible adapter)."""

from __future__ import annotations

import io
import json
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from homelabnext._http import (
    ResponseTooLarge,
    check_plaintext,
    read_bounded,
    safe_urlopen,
)
from homelabnext.conform.adapters.openai_compat import InferenceError, OpenAICompat
from homelabnext.notify import Message
from homelabnext.notify.core import SendError
from homelabnext.notify.senders import NtfySender


class _Server:
    """A loopback server; ``routes`` maps path -> (status, headers, body); records auth seen."""

    def __init__(self, routes):
        seen = self.seen = []

        class H(BaseHTTPRequestHandler):
            def _go(self):
                seen.append((self.path, self.headers.get("Authorization")))
                status, headers, body = routes.get(self.path, (404, {}, b""))
                self.send_response(status)
                for k, v in headers.items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            do_GET = do_POST = _go

            def log_message(self, *a):
                pass

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    @property
    def url(self):
        return f"http://127.0.0.1:{self.httpd.server_address[1]}"

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture
def servers():
    made = []

    def make(routes):
        s = _Server(routes)
        made.append(s)
        return s

    yield make
    for s in made:
        s.close()


def test_check_plaintext():
    with pytest.raises(ValueError, match="plaintext"):
        check_plaintext("http://n.example.internal/x", credentials=True, allow_plaintext=False)
    check_plaintext("http://n.example.internal/x", credentials=False, allow_plaintext=False)
    check_plaintext("http://n.example.internal/x", credentials=True, allow_plaintext=True)
    check_plaintext("https://n.example.internal/x", credentials=True, allow_plaintext=False)
    for host in ("127.0.0.1", "localhost", "[::1]"):
        check_plaintext(f"http://{host}:8080/x", credentials=True, allow_plaintext=False)


def test_read_bounded():
    assert read_bounded(io.BytesIO(b"abc"), 3) == b"abc"
    with pytest.raises(ResponseTooLarge):
        read_bounded(io.BytesIO(b"abcd"), 3)


def test_cross_origin_redirect_is_refused_and_auth_not_replayed(servers):
    evil = servers({"/steal": (200, {}, b"{}")})
    home = servers(
        {
            "/go": (302, {"Location": evil.url + "/steal"}, b""),
            "/local": (302, {"Location": "/ok"}, b""),
            "/ok": (200, {}, b"fine"),
        }
    )
    req = urllib.request.Request(home.url + "/go", headers={"Authorization": "Bearer s3cret"})
    with pytest.raises(urllib.error.HTTPError, match="cross-origin"):
        safe_urlopen(req, timeout=5)
    assert evil.seen == []
    with safe_urlopen(urllib.request.Request(home.url + "/local"), timeout=5) as resp:
        assert resp.read() == b"fine"


def test_ntfy_refuses_token_over_plaintext_unless_allowed():
    calls = []

    def op(req, timeout):
        calls.append(req)

        class R:
            status = 200

        return R()

    s = NtfySender(
        lambda: "http://n.example.internal", default_topic="ops", auth=lambda: "t", opener=op
    )
    with pytest.raises(SendError, match="plaintext"):
        s.send(Message("k", "t", "b"))
    assert calls == []
    NtfySender(lambda: "http://n.example.internal", default_topic="ops", opener=op).send(
        Message("k", "t", "b")
    )  # no credentials: plain http is allowed
    NtfySender(
        lambda: "http://n.example.internal",
        default_topic="ops",
        auth=lambda: "t",
        opener=op,
        allow_plaintext=True,
    ).send(Message("k", "t", "b"))
    assert len(calls) == 2


def test_ntfy_default_opener_refuses_cross_origin_redirect(servers):
    evil = servers({"/ops": (200, {}, b"")})
    home = servers({"/ops": (307, {"Location": evil.url + "/ops"}, b"")})
    s = NtfySender(lambda: home.url, default_topic="ops", auth=lambda: "Bearer s3cret")
    with pytest.raises(SendError):
        s.send(Message("k", "t", "b"))
    assert evil.seen == []


def test_openai_compat_plaintext_redirect_and_size(servers):
    with pytest.raises(ValueError, match="plaintext"):
        OpenAICompat("http://llm.example.internal", auth=lambda: "Bearer k")
    OpenAICompat("http://llm.example.internal", auth=lambda: "k", allow_plaintext=True)
    evil = servers({"/v1/models": (200, {}, b'{"data": []}')})
    big = json.dumps({"data": [{"id": "m" * 100}]}).encode()
    home = servers(
        {
            "/v1/models": (302, {"Location": evil.url + "/v1/models"}, b""),
            "/big/v1/models": (200, {}, big),
        }
    )
    with pytest.raises(InferenceError):
        OpenAICompat(home.url, auth=lambda: "Bearer k").models()
    assert evil.seen == []
    with pytest.raises(InferenceError, match="larger than"):
        OpenAICompat(home.url + "/big", max_bytes=50).models()
    assert OpenAICompat(home.url + "/big").models() == ["m" * 100]
