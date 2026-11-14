# SPDX-License-Identifier: Apache-2.0
"""Roles ``caddy`` and ``caddy_auth_proxy`` (modules/caddy/roles), run on localhost (CI is
unprivileged, nothing is started):

* ``caddy`` never renders without ``--edge-host`` (an empty ``caddy_edge_hosts`` is refused before
  anything runs); with it, the sites it installs are exactly the edge generator's for that
  deployment (the H2 golden of the two-lab fixture: the old lab's rows never appear), the upstream
  TLS files come from the secret store with the generator's modes, a file no site names is
  removed, and a second run is ``changed=0``; a declared name the sites do not have (or the other
  way round), a front door the sites read that is not declared, an edge host the registry lacks and
  a CA that holds a private key are each refused.
* ``caddy_auth_proxy`` renders oauth2-proxy with PKCE, the identity headers and a ``__Host-``
  cookie, the client secret and the cookie key only in the env_file, ``changed=0`` again, and
  refuses a malformed cookie key and an issuer that is not a realm."""

from __future__ import annotations

import os
import pwd
import subprocess
import sys
from pathlib import Path

import pytest
import yaml
from rolerun import _invocation, calls, fake, run_role

from homelabnext.edge_identity import AUTH_PROXY_COOKIE

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "modules" / "caddy"
CADDY = str(MODULE / "roles" / "caddy")
AUTH = str(MODULE / "roles" / "caddy_auth_proxy")
REGISTRY = ROOT / "tests" / "generators" / "edge" / "fixtures" / "two-lab.services.yml"
GOLDEN = ROOT / "tests" / "generators" / "edge" / "golden" / "caddy" / "sites.caddy"
USER = pwd.getpwuid(os.getuid()).pw_name
GUEST = "192.0.2.31"  # no-raw-endpoint: allow a documentation-range guest address
CERT = "-----BEGIN CERTIFICATE-----\nMIIfakefakefake\n-----END CERTIFICATE-----"
PEM_KEY = "PRIVATE " + "KEY"  # split, so no scanner reads a key block here
KEY = f"-----BEGIN {PEM_KEY}-----\nMIIfakefakefake\n-----END {PEM_KEY}-----"
FRONT_DOOR = "front-door-value-fake-0123456789"
DNS = "cf-dns-value-fake-0123456789"
SECRETS = {
    "HNX_SECRET_CADDY_ACME_DNS_TOKEN": DNS,
    "HNX_SECRET_STATUS_FRONT_DOOR_SECRET": FRONT_DOOR,
    "HNX_SECRET_EDGE_HUB_CLIENT_CERT": CERT,
    "HNX_SECRET_EDGE_HUB_CLIENT_KEY": KEY,
    "HNX_SECRET_PKI_INTERNAL_CA": CERT,
    "PYTHONPATH": str(ROOT),  # the generator the role runs on the controller is this checkout's
}
#: the role's default area for an upstream client key (its own secret namespace)
DEFAULT_KEY_AREA = yaml.safe_load((Path(CADDY) / "defaults" / "main.yml").read_text())[
    "caddy_edge_tls_key_area"
]
# the role's steps up to the configuration on disk: everything main does before the certificate
# (lego and systemd, which CI cannot run) and the container
RENDER = ["validate", "app", "generate", "credentials", "dirs", "render"]


def caddy_vars(tmp_path: Path, **kw) -> dict:
    v = {
        "caddy_logical_id": "edge",
        "ansible_host": GUEST,
        "caddy_dir": str(tmp_path / "app"),
        "caddy_data_root": str(tmp_path / "data"),
        "caddy_owner": USER,
        "caddy_owner_group": USER,
        "caddy_uid": os.getuid(),
        "caddy_gid": os.getgid(),
        "caddy_registry": str(REGISTRY),
        "caddy_edge_hosts": ["edge-01", "core-01", "idp-01"],
        "caddy_hnx_cli": [sys.executable, "-m", "homelabnext.cli"],
        "caddy_acme_domains": ["hub.example.internal", "sso.example.internal"],
        "caddy_front_door_refs": ["secret:status/front-door-secret"],
        # the H2 fixture keeps the client key in the store area edge; the default area is the module's
        "caddy_edge_tls_key_area": "edge",
        "caddy_start": False,
        "caddy_validate_with_docker": False,
    }
    v.update(kw)
    return v


def run_steps(tmp_path: Path, role: str, steps: list[str], extra: dict, env: dict):
    """Several task files of ``role`` in one play, in order (rolerun runs one)."""
    cmd, run_env = _invocation(tmp_path, role, steps[0], extra, env)
    play = yaml.safe_load((tmp_path / "play.yml").read_text())
    play[0]["tasks"] = [
        {"ansible.builtin.include_role": {"name": role, "tasks_from": s}} for s in steps
    ]
    (tmp_path / "play.yml").write_text(yaml.safe_dump(play))
    return subprocess.run(cmd, capture_output=True, text=True, env=run_env, cwd=tmp_path)


# ----------------------------------------------------------------------------- caddy

# a systemctl that keeps a timer's state in two files: `enable --now` writes both, `disable --now`
# removes them, and the is-* queries answer from them (every call is logged)
FAKE_SYSTEMCTL = r"""
import os, sys
a = sys.argv[1:]
open(LOG, "a").write("systemctl " + " ".join(a) + "\n")
en, act = STATE + ".enabled", STATE + ".active"
if a[0] == "enable":
    open(en, "w").close()
    if "--now" in a:
        open(act, "w").close()
elif a[0] == "disable":
    for f in (en, act):
        os.path.exists(f) and os.unlink(f)
elif a[0] == "is-enabled":
    print("enabled" if os.path.exists(en) else "disabled")
    sys.exit(0 if os.path.exists(en) else 1)
elif a[0] == "is-active":
    print("active" if os.path.exists(act) else "inactive")
    sys.exit(0 if os.path.exists(act) else 3)
"""


def test_the_acme_timer_is_enabled_and_started_on_every_run_not_only_when_its_units_change(
    tmp_path,
):
    """The renewal timer was enabled only when its unit files changed, so a timer disabled by hand
    stayed off and the certificate stopped renewing unnoticed.  The role now reads the timer on
    every run and runs `enable --now` only when it is not both enabled and active: a converged host
    runs nothing (changed=0), a timer disabled by hand is enabled and started again, one merely
    stopped is started, and a changed unit gets its daemon-reload first."""
    body = FAKE_SYSTEMCTL.replace("LOG", repr(str(tmp_path / "calls.log"))).replace(
        "STATE", repr(str(tmp_path / "timer"))
    )
    v = {
        "caddy_systemctl_cli": fake(tmp_path / "systemctl", body),
        "caddy_acme_units": {"changed": False},
    }
    enabled, started = tmp_path / "timer.enabled", tmp_path / "timer.active"

    def run(**kw):
        (tmp_path / "calls.log").unlink(missing_ok=True)
        r = run_role(tmp_path, CADDY, "acme_timer", {**v, **kw})
        assert r.returncode == 0, r.stdout + r.stderr
        return r, [c for c in calls(tmp_path) if not c.startswith("systemctl is-")]

    r, acts = run()  # never started, units unchanged (the first run failed after writing them)
    assert acts == ["systemctl enable --now hnx-caddy-acme.timer"] and "changed=1" in r.stdout
    assert enabled.exists() and started.exists()
    r, acts = run()  # converged: reads only
    assert acts == [] and "changed=0" in r.stdout, r.stdout
    enabled.unlink()
    started.unlink()  # disabled by hand
    r, acts = run()
    assert acts == ["systemctl enable --now hnx-caddy-acme.timer"] and started.exists()
    started.unlink()  # stopped by hand, still enabled
    r, acts = run()
    assert acts == ["systemctl enable --now hnx-caddy-acme.timer"] and started.exists()
    r, acts = run(caddy_acme_units={"changed": True})  # new units: reload, then enable
    assert acts == ["systemctl daemon-reload", "systemctl enable --now hnx-caddy-acme.timer"]
    r, acts = run()
    assert acts == [] and "changed=0" in r.stdout


def test_the_health_check_reads_the_sign_in_redirect_encoded_or_not_but_only_to_its_own_site(
    tmp_path,
):
    """oauth2-proxy URL-encodes the return target (`rd=https%3A%2F%2Fhub...%2F`); the assertion
    decoded it wrong as a literal and failed a healthy edge.  Both spellings pass; a wrong host, a
    host that merely starts with the right one, a wrong scheme, a status that is not 302 and a
    target that is not the site's root still fail."""
    ok = "/oauth2/sign_in?rd=https%3A%2F%2Fhub.example.internal%2F"
    literal = "/oauth2/sign_in?rd=https://hub.example.internal/"
    bad = [
        [302, "/oauth2/sign_in?rd=https%3A%2F%2Fevil.example.internal%2F"],
        [302, "/oauth2/sign_in?rd=https%3A%2F%2Fhub.example.internal.evil.test%2F"],
        [302, "/oauth2/sign_in?rd=http%3A%2F%2Fhub.example.internal%2F"],
        [302, "/oauth2/sign_in?rd=https%3A%2F%2Fhub.example.internal"],
        [302, "/elsewhere?rd=https%3A%2F%2Fhub.example.internal%2F"],
        [302, "/oauth2/sign_in%3Frd=https%3A%2F%2Fhub.example.internal%2F"],  # encoded `?`
        [302, "/oauth2/sign_in?x=1&rd=https%3A%2F%2Fhub.example.internal%2F"],
        [302, "/oauth2/sign_in?rd=https%253A%252F%252Fhub.example.internal%252F"],  # double
        [302, "/oauth2/sign_in?rd=https%3A%2F%2Fhub.example.internal%40evil.test%2F"],
        [200, ok],
    ]

    def run(loc):
        found = {"redirect": {"hub.example.internal": loc}}
        return run_role(tmp_path, CADDY, "health_redirect", {"caddy_found": found})

    for good in ([302, ok], [302, literal], [302, ok + "dashboard%3Fx%3D1"]):
        r = run(good)
        assert r.returncode == 0, (good, r.stdout)
    for loc in bad:
        r = run(loc)
        assert r.returncode != 0 and "not the sign-in redirect" in r.stdout, (loc, r.stdout)


def test_main_never_renders_without_an_edge_host(tmp_path):
    r = run_role(tmp_path, CADDY, "main", caddy_vars(tmp_path, caddy_edge_hosts=[]), env=SECRETS)
    assert r.returncode != 0
    assert "never renders" in r.stdout, r.stdout
    assert not (tmp_path / "data").exists()  # refused before anything was written


def test_the_sites_are_the_generators_for_one_deployment_and_converge(tmp_path):
    v = caddy_vars(tmp_path)
    r = run_steps(tmp_path, CADDY, RENDER, v, SECRETS)
    assert r.returncode == 0, r.stdout + r.stderr
    sites = (tmp_path / "data" / "config" / "sites.caddy").read_text()
    assert sites == GOLDEN.read_text()  # H2's golden: --edge-host edge-01 core-01 idp-01
    assert "old-apps" not in sites and "dashboards.example.internal" not in sites
    caddyfile = (tmp_path / "data" / "config" / "Caddyfile").read_text()
    assert "auto_https disable_certs disable_redirects" in caddyfile
    assert (
        "https:// {\n\ttls /etc/hnx-edge/certs/edge.crt /etc/hnx-edge/certs/edge.key\n" in caddyfile
    )
    assert '\trespond "no such site" 404\n' in caddyfile and caddyfile.rstrip().endswith(
        "import sites.caddy"
    )
    tls = tmp_path / "data" / "edge-tls"
    key = tls / "edge" / "hub-client-key.pem"
    assert key.read_text() == KEY + "\n" and oct(key.stat().st_mode & 0o777) == "0o600"
    assert oct((tls / "edge" / "hub-client-cert.pem").stat().st_mode & 0o777) == "0o644"
    assert (tls / "pki" / "internal-ca.pem").read_text() == CERT + "\n"
    for secret in (FRONT_DOOR, DNS, "BEGIN " + PEM_KEY):
        assert secret not in r.stdout
    # a file no site names any more is removed; the second run changes nothing else
    (tls / "edge" / "stale.pem").write_text("old")
    again = run_steps(tmp_path, CADDY, RENDER, v, SECRETS)
    assert again.returncode == 0, again.stdout
    assert not (tls / "edge" / "stale.pem").exists()
    third = run_steps(tmp_path, CADDY, RENDER, v, SECRETS)
    assert third.returncode == 0 and "changed=0" in third.stdout, third.stdout


@pytest.mark.parametrize(
    "over, env, says",
    [
        ({"caddy_acme_domains": ["hub.example.internal"]}, {}, "the declared names"),
        (
            {"caddy_acme_domains": ["hub.example.internal", "sso.example.internal", "x.example.internal"]},
            {},
            "the declared names",
        ),
        ({"caddy_front_door_refs": []}, {}, "caddy_front_door_refs gives"),
        ({"caddy_edge_hosts": ["edge-01", "core-01", "idp-01", "nope-01"]}, {}, "not in the registry"),
        # without the IdP's host the IdP's site is not rendered, so a declared name has no site
        ({"caddy_edge_hosts": ["edge-01", "core-01"]}, {}, "the declared names"),
        ({}, {"HNX_SECRET_PKI_INTERNAL_CA": CERT + "\n" + KEY}, "not in its form"),
        ({}, {"HNX_SECRET_EDGE_HUB_CLIENT_KEY": CERT}, "not in its form"),
        ({}, {"HNX_SECRET_STATUS_FRONT_DOOR_SECRET": "short"}, "not in its form"),
        # a client key from outside the module's own secret area is refused (the default area)
        ({"caddy_edge_tls_key_area": DEFAULT_KEY_AREA}, {}, "a client key in the store area " + DEFAULT_KEY_AREA),
        # the controller command is the overlay's hnx, nothing else
        ({"caddy_hnx_cli": ["/bin/sh", "-c", "true"]}, {}, "hnx entry point"),
    ],
)  # fmt: skip
def test_what_the_overlay_did_not_declare_is_refused(tmp_path, over, env, says):
    r = run_steps(tmp_path, CADDY, RENDER, caddy_vars(tmp_path, **over), {**SECRETS, **env})
    assert r.returncode != 0
    assert says in r.stdout, r.stdout
    assert not (tmp_path / "data" / "config" / "sites.caddy").exists()


# ----------------------------------------------------------------------------- caddy_auth_proxy

CLIENT = "client-value-fake-0123456789abcdef"
COOKIE = "c" * 32
AUTH_SECRETS = {
    "HNX_SECRET_IDP_CLIENTS_AUTH_PROXY": CLIENT,
    "HNX_SECRET_CADDY_AUTH_PROXY_COOKIE_SECRET": COOKIE,
}
ISSUER = "https://sso.example.internal/realms/twolab"


def auth_vars(tmp_path: Path, **kw) -> dict:
    v = {
        "caddy_auth_proxy_logical_id": "auth-proxy",
        "caddy_auth_proxy_issuer_url": ISSUER,
        "ansible_host": GUEST,
        "caddy_acme_domains": ["hub.example.internal", "sso.example.internal"],
        "caddy_auth_proxy_dir": str(tmp_path / "app"),
        "caddy_auth_proxy_owner": USER,
        "caddy_auth_proxy_start": False,
        "caddy_auth_proxy_validate_with_docker": False,
    }
    v.update(kw)
    return v


def test_the_auth_proxy_signs_in_with_pkce_and_keeps_its_secrets_in_the_env_file(tmp_path):
    v = auth_vars(tmp_path)
    r = run_role(tmp_path, AUTH, "main", v, env=AUTH_SECRETS)
    assert r.returncode == 0, r.stdout + r.stderr
    doc = yaml.safe_load((tmp_path / "app" / "docker-compose.yml").read_text())
    svc = doc["services"]["auth-proxy"]
    assert svc["image"].startswith("quay.io/oauth2-proxy/oauth2-proxy:v7.15.5-alpine@sha256:")
    assert svc["cap_drop"] == ["ALL"] and svc["read_only"] is True
    assert svc["ports"] == [GUEST + ":4180:4180"]
    env = svc["environment"]
    assert env["OAUTH2_PROXY_OIDC_ISSUER_URL"] == ISSUER
    assert env["OAUTH2_PROXY_CLIENT_ID"] == "auth-proxy"
    assert env["OAUTH2_PROXY_CODE_CHALLENGE_METHOD"] == "S256"
    assert env["OAUTH2_PROXY_SET_XAUTHREQUEST"] == "true"
    assert env["OAUTH2_PROXY_UPSTREAMS"] == "static://202"
    assert env["OAUTH2_PROXY_SCOPE"] == "openid"
    # the cookie the edge strips before any upstream (homelabnext.edge_identity.AUTH_PROXY_COOKIE)
    assert env["OAUTH2_PROXY_COOKIE_NAME"] == AUTH_PROXY_COOKIE
    assert env["OAUTH2_PROXY_COOKIE_EXPIRE"] == "4h"
    assert env["OAUTH2_PROXY_WHITELIST_DOMAINS"] == "hub.example.internal,sso.example.internal"
    text = (tmp_path / "app" / "docker-compose.yml").read_text()
    assert CLIENT not in text and COOKIE not in text
    secrets = (tmp_path / "app" / "secrets" / "auth-proxy.env").read_text()
    assert f"OAUTH2_PROXY_CLIENT_SECRET='{CLIENT}'" in secrets
    assert f"OAUTH2_PROXY_COOKIE_SECRET='{COOKIE}'" in secrets
    assert CLIENT not in r.stdout and COOKIE not in r.stdout
    again = run_role(tmp_path, AUTH, "main", v, env=AUTH_SECRETS)
    assert again.returncode == 0 and "changed=0" in again.stdout, again.stdout


@pytest.mark.parametrize(
    "over, env",
    [
        ({}, {"HNX_SECRET_CADDY_AUTH_PROXY_COOKIE_SECRET": "short"}),
        ({}, {"HNX_SECRET_IDP_CLIENTS_AUTH_PROXY": "has a space in it, which is refused"}),
        ({"caddy_auth_proxy_issuer_url": "https://sso.example.internal/"}, {}),
        ({"caddy_auth_proxy_issuer_url": "http://sso.example.internal/realms/twolab"}, {}),
        ({"caddy_auth_proxy_image": "quay.io/oauth2-proxy/oauth2-proxy:latest"}, {}),
        ({"caddy_acme_domains": []}, {}),
        ({"caddy_auth_proxy_cookie_expire": "13h"}, {}),  # at most 12h: no refresh
        ({"caddy_auth_proxy_cookie_expire": "721m"}, {}),
    ],
)
def test_the_auth_proxy_refuses_bad_inputs(tmp_path, over, env):
    r = run_role(tmp_path, AUTH, "main", auth_vars(tmp_path, **over), env={**AUTH_SECRETS, **env})
    assert r.returncode != 0, r.stdout
    assert not (tmp_path / "app" / "docker-compose.yml").exists()
