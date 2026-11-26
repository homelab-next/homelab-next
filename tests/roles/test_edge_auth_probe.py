# SPDX-License-Identifier: Apache-2.0
"""the edge's forward-auth proxy role's health signs in THROUGH THE EDGE, as a user does.

oauth2-proxy trusts ``X-Forwarded-*`` only from the gateway of its own network
(``--trusted-proxy-ip``), so a probe sent straight to its published port, from the host's own
address, has its ``X-Forwarded-Host`` ignored and the ``redirect_uri`` names the bind address: health
failed while the real sign-in was right. The probe now asks ``https://<site>/oauth2/start`` on the
edge's address with the site as the verified TLS name. These tests pin that path, that no
direct-to-proxy sign-in probe is used, and the probe's own behaviour against a local TLS server."""

from __future__ import annotations

import json
import ssl
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import quote

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
ROLE = next((ROOT / "modules").glob("*/roles/*auth_proxy"))  # the edge module's auth-proxy role
HEALTH = (ROLE / "tasks" / "health.yml").read_text()
VARS = yaml.safe_load((ROLE / "vars" / "main.yml").read_text())
SCRIPT = next(v for k, v in VARS.items() if k.endswith("_probe_script"))
SITE = "hub.example.internal"
ISSUER = "sso.example.internal"
GONE = "gone.example.internal"  # served by the edge, but with a 404
PROTECTED_SITES = (
    f"{SITE} {{\n\timport hnx_forward_auth admins\n\treverse_proxy x\n}}\n"
    f"{ISSUER} {{\n\treverse_proxy y\n}}\n"
)


@pytest.mark.static
def test_health_signs_in_through_the_front_door_not_straight_to_the_proxy():
    tasks = yaml.safe_load(HEALTH)[0]["block"]
    text = json.dumps(tasks)
    assert "/oauth2/sign_in" not in text  # the direct probe's path
    assert "X-Forwarded-Host" not in text and "X-Forwarded-Proto" not in text
    probe = next(t for t in tasks if "_probe_script" in json.dumps(t))
    spec = json.dumps(probe)
    for needle in ("_edge_address", "_edge_port", "_edge_trust_bundle", "_sites"):
        assert needle in spec
    # the only requests that use the proxy's own bind address are /ping and /oauth2/auth
    for t in tasks:
        uri = t.get("ansible.builtin.uri")
        if uri and "_bind" in uri["url"]:
            assert uri["url"].rsplit("/", 1)[1] in ("ping", "auth")
    assert "/oauth2/start" in SCRIPT


def test_the_assertions_are_kept():
    for needle in (
        "openid-connect/auth",
        "client_id=",
        "code_challenge_method=S256",
        "redirect_uri=https%3A%2F%2F",
        "%2Foauth2%2Fcallback",
    ):
        assert needle in HEALTH


@pytest.fixture
def edge(tmp_path):
    key, crt = tmp_path / "k.pem", tmp_path / "c.pem"
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(key),
            "-out",
            str(crt),
            "-days",
            "2",
            "-subj",
            f"/CN={SITE}",
            "-addext",
            f"subjectAltName=DNS:{SITE},DNS:{GONE}",
        ],
        check=True,
        capture_output=True,
    )
    seen = []

    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            seen.append((self.path, self.headers.get("Host")))
            # only the one known site name is echoed (never the raw header)
            host = next((n for n in (SITE,) if n == self.headers.get("Host")), "unknown")
            loc = (
                "https://idp.example.internal/realms/lab/protocol/openid-connect/auth?"
                "client_id=auth-proxy&code_challenge_method=S256&redirect_uri="
                + quote(f"https://{host}/oauth2/callback", safe="")
            )
            if self.headers.get("Host") == GONE:
                self.send_response(404)
                self.end_headers()
                return
            self.send_response(302)
            self.send_header("Location", loc)
            self.end_headers()

        def log_message(self, *a):
            pass

    srv = HTTPServer(("localhost", 0), H)
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(str(crt), str(key))
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True).start()
    yield srv.server_address[1], str(crt), seen
    srv.shutdown()


def probe(port, bundle, names, sites=None):
    spec = {
        "sites": sites if sites is not None else PROTECTED_SITES,
        "address": "localhost",
        "port": port,
        "bundle": bundle,
        "names": names,
        "timeout": 5,
    }
    r = subprocess.run(
        [sys.executable, "-I", "-c", SCRIPT, json.dumps(spec)],
        capture_output=True,
        text=True,
        check=True,
    )
    return json.loads(r.stdout)


@pytest.mark.requires_tool("openssl")
def test_the_probe_asks_the_site_by_name_on_the_edge_address_and_reads_the_redirect(edge):
    port, bundle, seen = edge
    out = probe(port, bundle, [SITE])
    assert seen == [("/oauth2/start?rd=%2F", SITE)]
    assert out[SITE]["status"] == 302
    assert quote(f"https://{SITE}/oauth2/callback", safe="") in out[SITE]["location"]


@pytest.mark.requires_tool("openssl")
def test_the_probe_refuses_a_certificate_that_does_not_verify_by_the_site_name(edge):
    port, bundle, _ = edge
    other = "other.example.internal"
    sites = f"{other} {{\n\timport hnx_forward_auth admins\n}}\n"
    out = probe(port, bundle, [other], sites=sites)
    assert out["other.example.internal"]["status"] == 0
    assert "SSLCertVerificationError" in out["other.example.internal"]["error"]


def test_only_the_forward_auth_sites_are_probed_never_the_issuers_own(edge):
    port, bundle, seen = edge
    out = probe(port, bundle, [ISSUER, SITE])
    assert list(out) == [SITE]
    assert [h for _, h in seen] == [SITE]  # the issuer was never asked


def test_a_protected_site_that_answers_404_still_fails_the_assertion(edge):
    port, bundle, _ = edge
    sites = PROTECTED_SITES + f"{GONE} {{\n\timport hnx_forward_auth admins\n}}\n"
    out = probe(port, bundle, [SITE, GONE], sites=sites)
    assert out[SITE]["status"] == 302
    assert out[GONE]["status"] == 404  # health asserts every status is 302, so this fails it


def test_health_asserts_a_non_empty_set_of_302s_and_reads_the_deployed_sites():
    assert "_sites_file" in HEALTH and "_sites_deployed" in HEALTH
    assert "length > 0" in HEALTH
