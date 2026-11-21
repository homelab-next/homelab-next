# SPDX-License-Identifier: Apache-2.0
"""The shared, product-free client of the ``case-management`` slot
(homelabnext.conform.adapters.case_management): it reports a refused anonymous call, sends the API
key only as a bearer header read by secret name (never a value), reads the version, bounds and
parses what comes back, and refuses settings it does not know."""

from __future__ import annotations

import http.server
import json
import socket
import socketserver
import threading

import pytest

from homelabnext.conform.adapters import case_management as adapter
from homelabnext.conform.adapters._env import AdapterConfigError

LOOPBACK = socket.gethostbyname("localhost")
KEY = "k" * 24


class _Quick(http.server.HTTPServer):
    def server_bind(self):
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = self.server_address[:2]


def _service(seen: list, *, open_api=False):
    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            seen.append((self.path, self.headers.get("Authorization")))
            authed = self.headers.get("Authorization") == f"Bearer {KEY}"
            code, body = 200, {"status": "success", "message": "", "data": {}}
            if not (authed or open_api):
                code, body = 401, {"status": "error"}
            elif self.path == "/api/ping":
                body["message"] = "pong"
            elif self.path == "/api/versions":
                body["data"] = {"iris_current": "v9.9.9"}
            raw = json.dumps(body).encode()
            self.send_response(code)
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def log_message(self, *a):
            pass

    srv = _Quick((LOOPBACK, 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


@pytest.fixture
def env(monkeypatch):
    monkeypatch.setenv("HNX_SECRET_CASE_MGMT_KEY", KEY)

    def point(srv):
        monkeypatch.setenv("HNX_ENDPOINT_CASE_MANAGEMENT", f"http://{LOOPBACK}:{srv.server_port}")

    return point


def test_it_sends_the_key_only_as_a_bearer_header_and_reads_the_version(env):
    seen: list = []
    srv = _service(seen)
    env(srv)
    t = adapter.make(credential="secret:case-mgmt/key")
    assert t.api_is_private() is True
    assert t.api_answers() is True
    assert t.version() == "v9.9.9"
    assert seen[0] == ("/api/ping", None)  # the privacy probe carries no credential
    assert all(auth == f"Bearer {KEY}" for _, auth in seen[1:])
    assert KEY not in repr(t)
    srv.shutdown()


def test_an_open_api_is_reported_as_not_private(env):
    srv = _service([], open_api=True)
    env(srv)
    assert adapter.make().api_is_private() is False
    srv.shutdown()


def test_a_call_that_needs_a_credential_is_refused_without_one(env):
    srv = _service([])
    env(srv)
    with pytest.raises(adapter.CaseManagementError, match="no credential"):
        adapter.make().api_answers()
    srv.shutdown()


def test_a_failure_names_the_path_and_never_the_credential(env, monkeypatch):
    srv = _service([])
    env(srv)
    monkeypatch.setenv("HNX_SECRET_CASE_MGMT_KEY", "w" * 24)
    with pytest.raises(adapter.CaseManagementError) as e:
        adapter.make(credential="secret:case-mgmt/key").api_answers()
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
