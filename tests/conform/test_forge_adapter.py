# SPDX-License-Identifier: Apache-2.0
"""The shared, product-free client of the ``forge`` slot (homelabnext.conform.adapters.forge): it
reads health without a credential, everything else with an access token it is given by secret name
(never a value), sends the token only as an Authorization header, reports a refused anonymous read
and the registry's bearer challenge, bounds and parses what comes back, and refuses settings it does
not know."""

from __future__ import annotations

import http.server
import json
import socket
import socketserver
import threading

import pytest

from homelabnext.conform.adapters import forge as adapter
from homelabnext.conform.adapters._env import AdapterConfigError

LOOPBACK = socket.gethostbyname("localhost")
TOKEN = "t" * 24


class _Quick(http.server.HTTPServer):
    def server_bind(self):
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = self.server_address[:2]


def _service(seen: list, *, open_read=False, challenge=True):
    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            seen.append((self.path, self.headers.get("Authorization")))
            path = self.path.split("?")[0]
            authed = self.headers.get("Authorization") == f"token {TOKEN}"
            body, code, extra = b"{}", 200, []
            if path == "/api/healthz":
                body = json.dumps({"status": "pass"}).encode()
            elif path == "/v2/":
                code = 401
                extra = [("WWW-Authenticate", 'Basic realm="r"')] + (
                    [("WWW-Authenticate", 'Bearer realm="r"')] if challenge else []
                )
            elif not (authed or open_read):
                code = 401
            elif path == "/api/v1/version":
                body = json.dumps({"version": "28.4.0"}).encode()
            elif path == "/api/v1/repos/search":
                body = json.dumps(
                    {"data": [{"full_name": "labs/alpha"}, {"full_name": "labs/beta"}]}
                ).encode()
            self.send_response(code)
            for k, v in extra:
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    srv = _Quick((LOOPBACK, 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


@pytest.fixture
def env(monkeypatch):
    monkeypatch.setenv("HNX_SECRET_FORGE_PULL", TOKEN)

    def point(srv):
        monkeypatch.setenv("HNX_ENDPOINT_FORGE", f"http://{LOOPBACK}:{srv.server_port}")

    return point


def test_it_reads_health_without_a_credential_and_the_rest_with_the_token_in_the_header(env):
    seen: list = []
    srv = _service(seen)
    env(srv)
    t = adapter.make(credential="secret:forge/pull")
    assert t.healthy() is True
    assert t.version() == "28.4.0"
    assert t.repositories() == ["labs/alpha", "labs/beta"]
    assert seen[0] == ("/api/healthz", None)  # health carries no credential
    assert all(auth == f"token {TOKEN}" for path, auth in seen[1:])
    assert TOKEN not in repr(t)
    srv.shutdown()


def test_an_anonymous_read_that_is_refused_is_reported_and_one_that_is_open_is_too(env):
    for open_read, want in ((False, True), (True, False)):
        srv = _service([], open_read=open_read)
        env(srv)
        assert adapter.make().anonymous_read_refused() is want
        srv.shutdown()


def test_the_registry_challenge_is_found_among_repeated_headers_and_its_absence_is_reported(env):
    for challenge, want in ((True, True), (False, False)):
        srv = _service([], challenge=challenge)
        env(srv)
        assert adapter.make().registry_challenges() is want
        srv.shutdown()


def test_a_read_that_needs_a_credential_is_refused_without_one_and_a_bad_limit_is_refused(env):
    srv = _service([])
    env(srv)
    t = adapter.make()
    with pytest.raises(adapter.ForgeError, match="no credential"):
        t.version()
    with pytest.raises(ValueError):
        adapter.make(credential="secret:forge/pull").repositories(limit=51)
    srv.shutdown()


def test_a_failure_names_the_path_and_never_the_credential(env, monkeypatch):
    srv = _service([])
    env(srv)
    monkeypatch.setenv("HNX_SECRET_FORGE_PULL", "w" * 24)
    with pytest.raises(adapter.ForgeError) as e:
        adapter.make(credential="secret:forge/pull").version()
    assert "401" in str(e.value) and "w" * 24 not in str(e.value)
    srv.shutdown()


@pytest.mark.parametrize("config, error", [
    ({"nope": 1}, ValueError),
    ({"credential": "a value, not a name"}, AdapterConfigError),
])  # fmt: skip
def test_settings_it_does_not_know_and_a_credential_that_is_a_value_are_refused(env, config, error):
    env(_service([]))
    with pytest.raises(error):
        adapter.make(**config)
