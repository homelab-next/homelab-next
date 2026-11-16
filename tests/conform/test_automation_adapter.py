# SPDX-License-Identifier: Apache-2.0
"""The shared, product-free client of the ``automation`` slot (homelabnext.conform.adapters.automation):
it reads a service's executions and rules with the API key it is given in the header it is told,
bounds and parses what comes back, and refuses what is not a list, a plaintext key off loopback and
settings it does not know."""

from __future__ import annotations

import http.server
import json
import secrets
import socket
import socketserver
import threading

import pytest

from homelabnext.conform.adapters import automation as adapter
from homelabnext.conform.adapters._env import AdapterConfigError

LOOPBACK = socket.gethostbyname("localhost")
KEY = secrets.token_urlsafe(
    12
)  # a fresh stand-in per run: nothing a scanner could take for a credential


class _Quick(http.server.HTTPServer):
    def server_bind(self):
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = self.server_address[:2]


def _service(answers: dict, status=200, seen: list | None = None):
    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            if seen is not None:
                seen.append((self.path, dict(self.headers)))
            path = self.path.split("?")[0]
            body = json.dumps(answers.get(path, {"faultstring": "no"})).encode()
            self.send_response(status)
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
    monkeypatch.setenv("AUTOMATION_KEY", KEY)

    def point(srv):
        monkeypatch.setenv("HNX_ENDPOINT_AUTOMATION", f"http://{LOOPBACK}:{srv.server_port}")

    return point


def test_it_reads_executions_and_rule_states_with_the_key_in_the_named_header(env):
    seen: list = []
    srv = _service(
        {
            "/api/v1/executions": [{"id": "1", "status": "succeeded"}],
            "/api/v1/rules": [{"name": "a", "enabled": False}, {"name": "b", "enabled": True}],
        },
        seen=seen,
    )
    try:
        env(srv)
        target = adapter.make(api_key_env="AUTOMATION_KEY", api_key_header="X-Api-Key")
        assert target.executions(limit=5)[0]["status"] == "succeeded"
        assert target.rule_states("p") == {"a": False, "b": True}
        assert seen[0][0] == ("/api/v1/executions?limit=5") and seen[1][0] == "/api/v1/rules?pack=p"
        assert all(h.get("X-Api-Key") == KEY for _, h in seen)
        assert KEY not in repr(target)
    finally:
        srv.shutdown()


def test_it_refuses_what_is_not_a_list_and_a_non_success_status(env):
    srv = _service({"/api/v1/executions": {"not": "a list"}})
    try:
        env(srv)
        t = adapter.make(api_key_env="AUTOMATION_KEY", api_key_header="X-Api-Key")
        with pytest.raises(adapter.AutomationError, match="not a list"):
            t.executions()
        with pytest.raises(ValueError):
            t.executions(limit=0)
    finally:
        srv.shutdown()
    srv = _service({}, status=401)
    try:
        env(srv)
        with pytest.raises(adapter.AutomationError, match="HTTP 401"):
            adapter.make(api_key_env="AUTOMATION_KEY", api_key_header="X-Api-Key").rules("p")
    finally:
        srv.shutdown()


def test_it_has_no_default_endpoint_no_unknown_setting_and_needs_its_key_and_header(monkeypatch):
    monkeypatch.delenv("HNX_ENDPOINT_AUTOMATION", raising=False)
    monkeypatch.setenv("AUTOMATION_KEY", KEY)
    with pytest.raises(AdapterConfigError, match="HNX_ENDPOINT_AUTOMATION"):
        adapter.make(api_key_env="AUTOMATION_KEY", api_key_header="X-Api-Key")
    monkeypatch.setenv("HNX_ENDPOINT_AUTOMATION", f"http://{LOOPBACK}:9")
    with pytest.raises(ValueError, match="unknown setting"):
        adapter.make(api_key_env="AUTOMATION_KEY", api_key_header="X-Api-Key", token="x")
    with pytest.raises(ValueError, match="api_key_header is required"):
        adapter.make(api_key_env="AUTOMATION_KEY")
    with pytest.raises(ValueError, match="api_key_env is required"):
        adapter.make(api_key_header="X-Api-Key")
    with pytest.raises(AdapterConfigError):
        adapter.make(api_key_env="NOT_SET_ANYWHERE", api_key_header="X-Api-Key")
    with pytest.raises(ValueError, match="plain header name"):
        adapter.make(api_key_env="AUTOMATION_KEY", api_key_header="X: injected")


def test_a_key_does_not_go_over_plaintext_off_loopback_unless_the_site_says_so():
    with pytest.raises(ValueError, match="plaintext"):
        adapter.AutomationTarget(
            "http://automation.example.internal", api_key=lambda: KEY, api_key_header="X-Api-Key"
        )
    adapter.AutomationTarget(
        "http://automation.example.internal",
        api_key=lambda: KEY,
        api_key_header="X-Api-Key",
        allow_plaintext=True,
    )
    with pytest.raises(ValueError):
        adapter.AutomationTarget("ftp://x", api_key=lambda: KEY, api_key_header="X-Api-Key")
