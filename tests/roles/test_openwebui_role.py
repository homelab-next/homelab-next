# SPDX-License-Identifier: Apache-2.0
"""The role of the chat provider module (the one the module that fills the ``chat`` slot
contributes), run on localhost against fakes (CI is unprivileged):

* main renders the compose project through the core open_webui role: models only through the
  gateway (its registry URL plus /v1, the app's own key only in the 0600 env_file), the gateway's
  two headers on the one connection, the sign-in and the break-glass administrator, and no setting
  that calls out; a second run is ``changed=0``;
* it refuses what the module forbids: a gateway id that is an engine, a row that is not the chat
  row or is public under another name, a label of ``red``, a missing sign-in or administrator;
* health reads the container and the anonymous public configuration, and fails on a fresh instance
  (no administrator: the first visitor would become one), open sign-up and a second provider;
* upgrade refuses another repository.
"""

from __future__ import annotations

import http.server
import json
import os
import socket
import threading
from pathlib import Path

import pytest
import yaml
from rolerun import fake, first_run, run_role

ROOT = Path(__file__).resolve().parents[2]
pytestmark = pytest.mark.requires_tool("ansible-playbook")
MID = "openwebui"
ROLE = str(ROOT / "modules" / MID / "roles" / MID)
LOOP = socket.gethostbyname("localhost")  # the published address: compose wants an IP
USER = __import__("pwd").getpwuid(os.getuid()).pw_name

REGISTRY = """\
lab: {name: demo, domain: example.internal, svc_label: svc, owner: platform-team}
hosts:
  chat-01: {zone: mgmt}
  gate-01: {zone: mgmt}
services:
  chat: {capability: chat, impl: chat-app, host: chat-01, protocol: http, port: 8080, tls: none,
         auth: idp, public_hostname: chat.example.internal}
  gate: {capability: inference, impl: gate-impl, host: gate-01, protocol: http, port: 4100,
         tls: none}
  engine: {capability: inference, impl: engine-impl, host: gate-01, protocol: http, port: 8001,
           tls: none}
  other: {capability: notify, impl: x, host: gate-01, protocol: http, port: 80, tls: none,
          public_hostname: other.example.internal}
"""
# secrets are short obviously-fake words, long enough only where the role checks a length
GW = "g" * 40
SES = "s" * 40
CLI = "c" * 40
ADM = "adm-pass-12345"
ENV = {
    "HNX_SECRET_GATEWAY_KEY_OPENWEBUI": GW,
    "HNX_SECRET_OPENWEBUI_SESSION_KEY": SES,
    "HNX_SECRET_IDP_CLIENTS_CHAT": CLI,
    "HNX_SECRET_OPENWEBUI_ADMIN_PASSWORD": ADM,
}


def vs(tmp: Path, **over) -> dict:
    (tmp / "registry.yml").write_text(REGISTRY)
    v = {
        "hnx_registry_file": str(tmp / "registry.yml"),
        "openwebui_logical_id": "chat",
        "openwebui_gateway_id": "gate",
        "openwebui_gateway_impls": ["gate-impl"],
        "openwebui_oidc_client_secret_ref": "secret:idp/clients/chat",
        "openwebui_public_url": "https://chat.example.internal",
        "openwebui_oidc_issuer_url": "https://sso.example.internal/realms/lab",
        "openwebui_admin_email": "admin@example.internal",
        "openwebui_bind": LOOP,
        "openwebui_dir": str(tmp / "app"),
        "openwebui_export_dir": str(tmp / "export"),
        "openwebui_owner": USER,
        "openwebui_group": __import__("grp").getgrgid(os.getgid()).gr_name,
        "openwebui_start": False,
        "openwebui_validate_with_docker": False,
    }
    v.update(over)
    return v


def _main(tmp):
    return {"role": ROLE, "tasks_from": "main", "extra_vars": vs(tmp), "env": ENV}


@first_run(_main)
def test_main_renders_the_gateway_only_app_with_its_headers_and_sign_in(first):
    r, tmp = first
    assert r.returncode == 0, r.stdout + r.stderr
    svc = yaml.safe_load((tmp / "app" / "docker-compose.yml").read_text())["services"]["open-webui"]
    env = svc["environment"]
    gateway = (
        "inference.svc.example.internal",
        4100,
    )  # the row's alias and port, from the registry
    assert env["OPENAI_API_BASE_URLS"] == f"http://{gateway[0]}:{gateway[1]}/v1"
    assert env["ENABLE_DIRECT_CONNECTIONS"] == "false"
    assert env["ENABLE_WEB_SEARCH"] == "false" and env["OFFLINE_MODE"] == "true"
    assert env["ENABLE_SIGNUP"] == "false" and env["ENABLE_PERSISTENT_CONFIG"] == "false"
    # the one connection's headers: a label the gateway reads, and a per-user usage tag
    headers = json.loads(env["OPENAI_API_CONFIGS"])["0"]["headers"]
    assert headers == {"X-HNX-TLP": "amber", "X-HNX-Tag": "openwebui:{{USER_ID}}"}
    assert env["OPENID_PROVIDER_URL"].startswith("https://sso.example.internal/realms/lab/")
    assert env["OAUTH_CLIENT_ID"] == "chat"
    assert env["WEBUI_URL"] == env["CORS_ALLOW_ORIGIN"] == "https://chat.example.internal"
    assert [p.rsplit(":", 2)[1:] for p in svc["ports"]] == [["8080", "8080"]]  # the row's port
    # no key, secret or password anywhere in the compose file; all four only in the env_file
    assert not any(w in k for k in env for w in ("KEY", "SECRET", "PASSWORD"))
    stored = (tmp / "app" / "secrets" / "open-webui.env").read_text()
    for name, value in (("OPENAI_API_KEYS", GW), ("WEBUI_SECRET_KEY", SES),
                        ("OAUTH_CLIENT_SECRET", CLI), ("WEBUI_ADMIN_PASSWORD", ADM)):  # fmt: skip
        assert f"{name}='{value}'" in stored
    for value in (GW, SES, CLI, ADM):
        assert value not in r.stdout
    assert (tmp / "app" / "docker-compose.yml").read_text().count(GW) == 0


def test_a_second_run_changes_nothing(tmp_path):
    v = vs(tmp_path)
    first = run_role(tmp_path, ROLE, "main", v, env=ENV)
    assert first.returncode == 0, first.stdout + first.stderr
    again = run_role(tmp_path, ROLE, "main", v, env=ENV)
    assert again.returncode == 0 and "changed=0" in again.stdout, again.stdout


@pytest.mark.parametrize(
    ("over", "needle"),
    [
        (
            {"openwebui_gateway_id": "engine"},
            "talks to the LLM gateway only",
        ),  # an engine behind it
        ({"openwebui_gateway_id": "other"}, "talks to the LLM gateway only"),  # not inference
        ({"openwebui_logical_id": "other"}, "must be a registry row of capability chat"),
        ({"openwebui_logical_id": "gate"}, "the instance's registry id"),  # the gateway itself
        ({"openwebui_public_url": "https://elsewhere.example.internal"}, "public_hostname"),
        ({"openwebui_gateway_tlp": "red"}, "nothing red goes to a model"),
        ({"openwebui_gateway_tlp": ""}, "nothing red goes to a model"),
        ({"openwebui_gateway_impls": []}, "must be named"),
        ({"openwebui_oidc_issuer_url": "http://sso.example.internal/realms/lab"}, "issuer"),
        ({"openwebui_oidc_issuer_url": "https://sso.example.internal"}, "issuer"),
        ({"openwebui_admin_email": "nobody"}, "break-glass administrator"),
        ({"openwebui_gateway_tag_prefix": "has space"}, "usage tag"),
        (
            {"openwebui_extra_env": {"ENABLE_WEB_SEARCH": "true"}},
            "refused names: ENABLE_WEB_SEARCH",
        ),
        ({"openwebui_extra_env": {"OAUTH_CLIENT_ID": "x"}}, "refused names: OAUTH_CLIENT_ID"),
    ],
)
@first_run(lambda tmp, over, needle: {"role": ROLE, "tasks_from": "main",
                                      "extra_vars": vs(tmp, **over), "env": ENV})  # fmt: skip
def test_main_refuses_what_the_module_forbids(first, over, needle):
    r, tmp = first
    assert r.returncode != 0 and needle in r.stdout, (over, r.stdout[-1500:])
    assert not (tmp / "app" / "docker-compose.yml").exists()


# ---------------------------------------------------------------------------------- health
CONFIG = {
    "status": True,
    "features": {"auth": True, "enable_signup": False, "enable_login_form": True},
    "oauth": {"providers": {"oidc": "SSO"}},
}


GATEWAY_URL = "http://{}:{}/v1".format("inference.svc.example.internal", 4100)
RUNNING = {
    "ENABLE_OPENAI_API": True,
    "OPENAI_API_BASE_URLS": [GATEWAY_URL],
    "OPENAI_API_KEYS": ["k" * 8],
    "OPENAI_API_CONFIGS": {
        "0": {"headers": {"X-HNX-TLP": "amber", "X-HNX-Tag": "openwebui:{{USER_ID}}"}}
    },
}


class _App:
    """The anonymous endpoints health reads, and the administrator's two (sign-in, connections)."""

    def __init__(self, config, running):
        outer = self
        outer.config, outer.running = config, running
        outer.signins = []

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, body, status=200):
                data = json.dumps(body).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                if self.path == "/openai/config":
                    if self.headers.get("Authorization") != "Bearer admin-token":
                        return self._send({"detail": "no"}, 401)
                    return self._send(outer.running)
                body = {"/health": {"status": True}, "/api/config": outer.config}.get(self.path)
                if body is None:
                    self.send_error(404)
                    return
                self._send(body)

            def do_POST(self):
                n = int(self.headers.get("Content-Length", 0))
                outer.signins.append(json.loads(self.rfile.read(n)))
                if self.path != "/api/v1/auths/signin":
                    return self._send({}, 404)
                self._send({"token": "admin-token"})

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


def _health(tmp, config, running=None):
    bindir = tmp / "bin"
    bindir.mkdir(exist_ok=True)
    state = json.dumps({"Service": "open-webui", "State": "running", "Health": "healthy"})
    fake(bindir / "docker", f"import sys\nsys.stdout.write({state + chr(10)!r})\n")
    with _App(config, running or RUNNING) as app:
        v = vs(tmp, openwebui_port=app.port)
        env = {**ENV, "PATH": f"{bindir}:{os.environ['PATH']}"}
        r = run_role(tmp, ROLE, "health", v, env=env)
        r.signins = app.signins
        return r


def test_health_passes_on_a_deployed_instance(tmp_path):
    r = _health(tmp_path, CONFIG)
    assert r.returncode == 0, r.stdout + r.stderr


@pytest.mark.parametrize(
    "mutate",
    [
        lambda c: c.update(onboarding=True),  # no administrator: the first visitor becomes one
        lambda c: c["features"].update(enable_signup=True),
        lambda c: c["features"].update(enable_login_form=False),
        lambda c: c["oauth"].update(providers={}),
        lambda c: c["oauth"].update(providers={"oidc": "SSO", "github": "GitHub"}),
    ],
)
def test_health_fails_on_a_config_that_breaks_the_policy(tmp_path, mutate):
    cfg = json.loads(json.dumps(CONFIG))
    mutate(cfg)
    r = _health(tmp_path, cfg)
    assert r.returncode != 0 and "does not show the policy" in r.stdout, r.stdout[-1500:]


# --------------------------------------------------------------------------------- upgrade
def _first_upgrade_records_a_bump_of_the_same_repository_and_refuses_another(tmp_path):
    v = vs(tmp_path)
    return {"role": ROLE, "tasks_from": "main", "extra_vars": v, "env": ENV, "setup": {"v": v}}


@first_run(_first_upgrade_records_a_bump_of_the_same_repository_and_refuses_another)
def test_upgrade_records_a_bump_of_the_same_repository_and_refuses_another(first):
    first_result, tmp_path = first
    v = first.setup["v"]
    assert first_result.returncode == 0
    same = "ghcr.io/open-webui/open-webui:v0.12.6@sha256:" + "a" * 64
    ok = run_role(tmp_path, ROLE, "upgrade", {**v, "openwebui_target_image": same})
    assert ok.returncode == 0, ok.stdout + ok.stderr
    for bad in (
        "registry.example.internal/other/open-webui:v0.12.6@sha256:" + "a" * 64,
        "ghcr.io/open-webui/open-webui:latest",
    ):
        r = run_role(tmp_path, ROLE, "upgrade", {**v, "openwebui_target_image": bad})
        assert r.returncode != 0, bad


def test_health_signs_in_as_the_break_glass_administrator_without_logging_the_password(tmp_path):
    r = _health(tmp_path, CONFIG)
    assert r.returncode == 0, r.stdout + r.stderr
    assert r.signins == [{"email": "admin@example.internal", "password": ADM}]
    assert ADM not in r.stdout and ADM not in r.stderr


def _edit(mutate):
    running = json.loads(json.dumps(RUNNING))
    mutate(running)
    return running


@pytest.mark.parametrize(
    "mutate",
    [
        lambda r: r.update(OPENAI_API_BASE_URLS=["https://elsewhere.example.internal/v1"]),
        lambda r: r["OPENAI_API_BASE_URLS"].append("https://second.example.internal/v1"),
        lambda r: r["OPENAI_API_CONFIGS"]["0"]["headers"].update({"X-HNX-TLP": "green"}),
        lambda r: r["OPENAI_API_CONFIGS"]["0"]["headers"].pop("X-HNX-Tag"),
        lambda r: r["OPENAI_API_CONFIGS"].pop("0"),
        lambda r: r.update(ENABLE_OPENAI_API=False),
    ],
)
def test_health_fails_when_an_admin_ui_edit_changed_the_running_connection(tmp_path, mutate):
    r = _health(tmp_path, CONFIG, _edit(mutate))
    assert r.returncode != 0 and "differs from the rendered one" in r.stdout, r.stdout[-1500:]
    assert "k" * 8 not in r.stdout  # the keys the answer carries are never printed
