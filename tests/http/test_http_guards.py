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

LOOPBACK = "127.0.0.1"  # no-raw-endpoint: allow test servers bind loopback only


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

            do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = _go

            def log_message(self, *a):
                pass

        self.httpd = ThreadingHTTPServer((LOOPBACK, 0), H)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    @property
    def url(self):
        return f"http://{LOOPBACK}:{self.httpd.server_address[1]}"

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
    for host in (LOOPBACK, "localhost", "[::1]"):  # no-raw-endpoint: allow loopback literals
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


@pytest.mark.parametrize("code", [301, 302, 303, 307, 308])
@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
def test_a_write_is_never_redirected_but_a_read_still_follows_same_origin(servers, code, method):
    """Regression: a POST answered with a same-origin 301/302/303 was resent by urllib as a GET
    with no body, and the 2xx to that GET read as the write's result (the target answered, the
    write never arrived)."""
    home = servers({"/w": (code, {"Location": "/target"}, b""), "/target": (200, {}, b"fine")})
    req = urllib.request.Request(home.url + "/w", data=b"{}", method=method)
    refused = None
    try:
        safe_urlopen(req, timeout=5).close()
    except urllib.error.HTTPError as exc:
        refused = exc
    assert refused is not None and refused.code == code
    assert [path for path, _ in home.seen] == ["/w"]
    with safe_urlopen(urllib.request.Request(home.url + "/w"), timeout=5) as resp:
        assert resp.read() == b"fine"
    assert [path for path, _ in home.seen] == ["/w", "/w", "/target"]


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
    home = servers(
        {
            "/ops": (307, {"Location": evil.url + "/ops"}, b""),
            "/local": (302, {"Location": "/ok"}, b""),
            "/ok": (200, {}, b"page"),
        }
    )
    s = NtfySender(lambda: home.url, default_topic="ops", auth=lambda: "Bearer s3cret")
    with pytest.raises(SendError):
        s.send(Message("k", "t", "b"))
    assert evil.seen == []
    # Regression: a same-origin 302 to the POST was followed as a GET with no body, and the 200
    # to that GET reported the message delivered although the server never received it.
    raised = None
    try:
        s.send(Message("k", "t", "b", topic="local"))
    except SendError as exc:
        raised = exc
    assert raised is not None
    assert [path for path, _ in home.seen] == ["/ops", "/local"]


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


def test_model_transport_follows_no_redirect_and_never_replays_the_key(servers):
    """Regression: ``registry.models.urllib_transport`` used urllib's stock redirect handler
    while :func:`authorized` added ``Authorization: Bearer <key>``, so a cross-origin redirect
    handed the key to the second server, and a POST answered 302 was resent there as a GET."""
    from homelabnext.registry.models import authorized

    evil = servers({"/v1/models": (200, {}, b'{"data": []}'), "/c": (200, {}, b"{}")})
    home = servers(
        {
            "/v1/models": (302, {"Location": evil.url + "/v1/models"}, b""),
            "/w": (302, {"Location": "/c"}, b""),
            "/c": (200, {}, b'{"choices": []}'),
        }
    )
    send = authorized("s3cret")
    status, _ = send("GET", home.url + "/v1/models", None, 5)
    assert status == 302
    assert evil.seen == []
    status, _ = send("POST", home.url + "/w", {"x": 1}, 5)
    assert status == 302
    assert [path for path, _ in home.seen] == ["/v1/models", "/w"]


def test_the_no_redirect_opener_never_hands_a_credential_to_an_environment_proxy(
    servers, monkeypatch
):
    """Regression: ``no_redirect_urlopen`` (the default opener of the events forwarder and the
    notify sender) used ``build_opener``'s default ``ProxyHandler``, so ``HTTP_PROXY`` in the
    environment received the request and its ``Authorization`` header (in clear for http)."""
    from homelabnext._http import no_redirect_urlopen
    from homelabnext.events.forwarder import HttpForwarder

    proxy = servers({})
    home = servers({"/e": (202, {}, b"{}"), "/ops": (200, {}, b"{}")})
    for name in ("no_proxy", "NO_PROXY", "REQUEST_METHOD"):
        monkeypatch.delenv(name, raising=False)
    for name in ("http_proxy", "HTTP_PROXY"):
        monkeypatch.setenv(name, proxy.url)
    auth = {"Authorization": "Bearer s3cret"}
    sends = (
        lambda: HttpForwarder(home.url + "/e", auth=lambda: auth["Authorization"]).forward(
            {"id": "e1"}
        ),
        lambda: no_redirect_urlopen(
            urllib.request.Request(home.url + "/ops", data=b"b", headers=auth), timeout=5
        ).close(),
    )
    failures = []
    for send in sends:
        try:
            send()
        except Exception as exc:  # the proxy's 404: asserted on below, after what it saw
            failures.append(exc)
    assert proxy.seen == []
    assert failures == []
    assert home.seen == [("/e", "Bearer s3cret"), ("/ops", "Bearer s3cret")]


def test_safe_urlopen_never_hands_a_credential_to_an_environment_proxy(servers, monkeypatch):
    """Regression: ``safe_opener`` used ``build_opener``'s default ``ProxyHandler``, so
    ``HTTP_PROXY`` in the environment received every request of its callers (the gateway key
    writes, the OpenAI-compatible, OpenBao and notify conformance adapters, the status hub's
    collectors, the OpenProject client) with its ``Authorization`` or ``X-Vault-Token``
    header, in clear for http.  Lab endpoints are reached directly."""
    from homelabnext._http import safe_opener

    proxy = servers({})
    home = servers({"/r": (200, {}, b"read"), "/w": (200, {}, b"wrote")})
    for name in ("no_proxy", "NO_PROXY", "REQUEST_METHOD"):
        monkeypatch.delenv(name, raising=False)
    for name in ("http_proxy", "HTTP_PROXY"):
        monkeypatch.setenv(name, proxy.url)
    vault = dict.fromkeys(["X-Vault-Token"], "fake")  # the header the OpenBao adapter sends
    sends = (
        lambda: safe_urlopen(
            urllib.request.Request(home.url + "/r", headers={"Authorization": "Bearer s3cret"}),
            timeout=5,
        ).read(),
        lambda: (
            safe_opener()
            .open(
                urllib.request.Request(home.url + "/w", data=b"{}", method="POST", headers=vault),
                timeout=5,
            )
            .read()
        ),
    )
    got, failures = [], []
    for send in sends:
        try:
            got.append(send())
        except Exception as exc:  # the proxy's 404: asserted on below, after what it saw
            failures.append(exc)
    assert proxy.seen == []
    assert failures == []
    assert got == [b"read", b"wrote"]
    assert [path for path, _ in home.seen] == ["/r", "/w"]


def test_model_key_with_a_control_character_is_refused_without_quoting_it(servers):
    """Regression: a key holding a control character reached ``http.client``, whose
    ``ValueError`` quoted the whole header value, key included (and escaped ``ModelError``, so a
    probe crashed instead of reporting ``error``)."""
    from homelabnext.registry.models import ModelError, authorized

    home = servers({"/v1/models": (200, {}, b'{"data": []}')})
    raised = None
    try:
        authorized("s3cret\nX-Injected: 1")("GET", home.url + "/v1/models", None, 5)
    except Exception as exc:
        raised = exc
    assert isinstance(raised, ModelError) and raised.kind == "misconfigured"
    assert "s3cret" not in str(raised) and "Injected" not in str(raised)
    assert home.seen == []


def test_a_redirect_to_an_ambiguous_or_invalid_authority_is_refused():
    """Regression: a same-host ``Location`` with userinfo or a backslash passed the origin check
    (urlsplit drops the userinfo) and was followed into a URL ``http.client`` reads as another
    host, and a bad port made urlsplit raise ``ValueError`` out of the redirect handler instead
    of the ``HTTPError`` every caller handles."""
    from homelabnext._http import SameOriginRedirectHandler

    here = f"http://{LOOPBACK}:8080"
    targets = [
        f"http://user@{LOOPBACK}:8080/ok",
        f"http://{LOOPBACK}:8080\\@{LOOPBACK}:8080/ok",
        f"http://{LOOPBACK}%2e:8080/ok",
        f"http://{LOOPBACK}:99999/ok",
        f"http://{LOOPBACK}:8080x/ok",
        f"http://[{LOOPBACK}/ok",
    ]
    outcomes = []
    for target in targets:
        req = urllib.request.Request(here + "/r")
        try:
            SameOriginRedirectHandler().redirect_request(
                req, io.BytesIO(), 302, "Found", {"Location": target}, target
            )
            outcomes.append(f"followed {target}")
        except urllib.error.HTTPError as exc:
            outcomes.append("refused" if exc.code == 302 and "refusing" in str(exc) else repr(exc))
        except Exception as exc:
            outcomes.append(repr(exc))
    assert outcomes == ["refused"] * len(targets)
