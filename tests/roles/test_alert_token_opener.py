# SPDX-License-Identifier: Apache-2.0
"""The host scripts that post an alert with an access token (needrestart's `needrestart-check`,
lynis's `dpkg-verify`) follow no redirect and use no proxy from the environment.  They run on lab
hosts and cannot import homelabnext, so each carries its own opener; this renders each template
with test values, loads it as a module and calls its `send` against loopback servers.  Rendering
is plain Jinja2 with Ansible's `to_json` and `bool` filters added (`int` is Jinja2's own), with no
playbook run, so it is fast."""

from __future__ import annotations

import http.server
import importlib.util
import json
import socketserver
import threading
import urllib.error
import urllib.request
from pathlib import Path

import pytest

jinja2 = pytest.importorskip("jinja2")

ROOT = Path(__file__).resolve().parents[2]
LOOPBACK = "127.0.0.1"  # no-raw-endpoint: allow test servers bind loopback
TOKEN = "tk-test-not-a-secret"


def _vars(prefix, url, token_file):
    common = {
        "state_dir": "/nonexistent",
        "notify_url": url,
        "notify_topic": "topic",
        "notify_priority": 3,
        "notify_auth_file": str(token_file),
        "notify_auth_ref": "secret:notify-token",
        "sendmail_cli": "/bin/false",
        "mail_to": "root",
    }
    extra = {
        "needrestart": {"cli": "/bin/false", "mode": "notify", "alert_kernel": False},
        "lynis": {
            "dpkg_cli": "/bin/false",
            "debsums_cli": "/bin/false",
            "notify_mode": "notify",
            "dpkg_verify_include_conffiles": False,
            "dpkg_verify_allow": [],
            "dpkg_cfg_files": [],
        },
    }[prefix]
    return {f"{prefix}_{k}": v for k, v in {**common, **extra}.items()}


TEMPLATES = {
    "needrestart": "ansible/roles/needrestart/templates/needrestart-check.py.j2",
    "lynis": "ansible/roles/lynis/templates/dpkg-verify.py.j2",
}


def load(tmp_path, role, url):
    """The role's alert script rendered for `url` with a token file, loaded as a module."""
    env = jinja2.Environment(undefined=jinja2.StrictUndefined, keep_trailing_newline=True)
    env.filters["to_json"] = json.dumps
    env.filters["bool"] = lambda v: v is True or str(v).lower() in ("yes", "true", "1", "on")
    token = tmp_path / "token"
    token.write_text(TOKEN + "\n")
    text = env.from_string((ROOT / TEMPLATES[role]).read_text()).render(_vars(role, url, token))
    script = tmp_path / f"{role}_alert.py"
    script.write_text(text)
    spec = importlib.util.spec_from_file_location(f"{role}_alert", script)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class _Quick(http.server.HTTPServer):
    """HTTPServer without its bind-time reverse lookup (socket.getfqdn), which costs seconds
    where DNS is slow."""

    def server_bind(self):
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = self.server_address[:2]


class Server:
    """A loopback server recording each request's (method, path, headers); answers `reply`."""

    def __init__(self, reply):
        seen = self.seen = []

        class H(http.server.BaseHTTPRequestHandler):
            def _any(self):
                n = int(self.headers.get("Content-Length") or 0)
                self.rfile.read(n)
                seen.append((self.command, self.path, dict(self.headers)))
                code, headers = reply()
                self.send_response(code)
                for k, v in headers.items():
                    self.send_header(k, v)
                self.send_header("Content-Length", "0")
                self.end_headers()

            do_GET = do_POST = _any

            def log_message(self, *a):
                pass

        self.srv = _Quick((LOOPBACK, 0), H)
        self.url = f"http://{LOOPBACK}:{self.srv.server_port}"
        threading.Thread(target=self.srv.serve_forever, args=(0.02,), daemon=True).start()

    def close(self):
        self.srv.shutdown()
        self.srv.server_close()


@pytest.fixture
def servers():
    made = []

    def make(reply=lambda: (200, {})):
        made.append(Server(reply))
        return made[-1]

    yield make
    for s in made:
        s.close()


@pytest.fixture(autouse=True)
def no_env_proxy(monkeypatch):
    for name in (
        "http_proxy",
        "HTTP_PROXY",
        "https_proxy",
        "HTTPS_PROXY",
        "all_proxy",
        "ALL_PROXY",
        "no_proxy",
        "NO_PROXY",
        "REQUEST_METHOD",
    ):
        monkeypatch.delenv(name, raising=False)
    # urlopen caches its opener (and the proxies it read) on first use: start each test without one
    monkeypatch.setattr(urllib.request, "_opener", None)


@pytest.mark.parametrize("role", sorted(TEMPLATES))
def test_the_alert_token_never_follows_a_redirect_to_another_origin(tmp_path, servers, role):
    other = servers()
    first = servers(lambda: (302, {"Location": other.url + "/elsewhere"}))
    mod = load(tmp_path, role, first.url)
    try:
        mod.send("t", "b")
        code = None
    except urllib.error.HTTPError as exc:
        code = exc.code
    assert other.seen == [], "the redirect target received the request (and the token)"
    assert code == 302  # the 3xx is the answer: send raises, so the alert stays owed
    assert [(m, h.get("Authorization")) for m, _, h in first.seen] == [("POST", "Bearer " + TOKEN)]


@pytest.mark.parametrize("role", sorted(TEMPLATES))
def test_the_alert_token_never_reaches_an_environment_proxy(tmp_path, servers, monkeypatch, role):
    target, proxy = servers(), servers()
    for name in (
        "http_proxy",
        "HTTP_PROXY",
        "https_proxy",
        "HTTPS_PROXY",
        "all_proxy",
        "ALL_PROXY",
    ):
        monkeypatch.setenv(name, proxy.url)
    mod = load(tmp_path, role, target.url)
    mod.send("t", "b")
    assert proxy.seen == [], "the environment's proxy received the request (and the token)"
    assert [(m, h.get("Authorization")) for m, _, h in target.seen] == [("POST", "Bearer " + TOKEN)]
