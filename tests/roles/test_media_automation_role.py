# SPDX-License-Identifier: Apache-2.0
"""Role ``media_automation`` (modules/media-automation/roles/media_automation), run on localhost
against fakes (CI is unprivileged): main renders one compose project through compose_app (every
image pinned, the library writable at the same path in the apps that need it, the download clients
inside the VPN client's network namespace and publishing nothing, the VPN credentials only in the
VPN client's 0600 env file), a second run is ``changed=0``; an unset secret reference or a malformed
input is refused by name before anything is written; health passes against stand-ins and fails on
every broken invariant (a client not behind the VPN client, a library that is not mounted, a
hardlink that cannot be made); export, restore, backup and upgrade; the helper units."""

from __future__ import annotations

import hashlib
import json
import os
import pwd
import tarfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import ClassVar

import pytest
import yaml
from rolerun import fake, first_run, last_run_vars, run_role

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "modules" / "media-automation"
ROLE = str(MODULE / "roles" / "media_automation")
DEFAULTS = yaml.safe_load(
    (MODULE / "roles" / "media_automation" / "defaults" / "main.yml").read_text()
)
MANIFEST = yaml.safe_load((MODULE / "module.yml").read_text())
# the manifest's product (the request app): the one name the product lint holds tests to
S = MANIFEST["product"]["name"]
P = "sonarr"  # a library manager: not a product of the manifest
USER = pwd.getpwuid(os.getuid()).pw_name
GUEST = yaml.safe_load((ROOT / "examples" / "services.yml").read_text())["hosts"]["dns-core"][
    "address"
]
CLIENTS = ["qbittorrent", "nzbget"]
SUBNET = ".".join(str(o) for o in (10, 20, 0, 0)) + "/16"  # a lab range, built here
# runtime-built values: nothing here looks like a key or a token to a secret scanner
PRIVATE = "P" * 43 + "="
PRESHARED = "S" * 43 + "="
ADDRESSES = f"{GUEST}/32"
PASSWORD = "pw-" + "q" * 14
SECRETS = {
    "HNX_SECRET_MEDIA_AUTOMATION_VPN_WIREGUARD_PRIVATE_KEY": PRIVATE,
    "HNX_SECRET_MEDIA_AUTOMATION_VPN_WIREGUARD_PRESHARED_KEY": PRESHARED,
    "HNX_SECRET_MEDIA_AUTOMATION_VPN_WIREGUARD_ADDRESSES": ADDRESSES,
    "HNX_SECRET_MEDIA_AUTOMATION_QBITTORRENT_PASSWORD": PASSWORD,
}
REFS = dict(
    zip(
        SECRETS,
        [
            "secret:media-automation/vpn-wireguard-private-key",
            "secret:media-automation/vpn-wireguard-preshared-key",
            "secret:media-automation/vpn-wireguard-addresses",
            "secret:media-automation/qbittorrent-password",
        ],
        strict=True,
    )
)


def mv(tmp_path: Path, **kw) -> dict:
    lib = tmp_path / "library"
    lib.mkdir(exist_ok=True)
    (lib / ".hnx-media-library").write_text("")  # the operator's marker on a mounted library
    v = {
        "media_automation_logical_id": "media-automation",
        "ansible_host": GUEST,
        "media_automation_dir": str(tmp_path / "app"),
        "media_automation_data_root": str(tmp_path / "data"),
        "media_automation_cache_dir": str(tmp_path / "cache"),
        "media_automation_library_path": str(lib),
        "media_automation_owner": USER,
        "media_automation_group": str(os.getgid()),
        "media_automation_uid": os.getuid(),
        "media_automation_gid": os.getgid(),
        f"media_automation_{S}_uid": os.getuid(),
        f"media_automation_{S}_gid": os.getgid(),
        "media_automation_vpn_outbound_subnets": [SUBNET],
        "media_automation_vpn_input_ports": [51000],
        "media_automation_helpers_enabled": False,
        "media_automation_start": False,
        "media_automation_validate_with_docker": False,
        **last_run_vars(tmp_path, "media_automation"),
    }
    v.update(kw)
    return v


def compose(tmp_path: Path) -> dict:
    return yaml.safe_load((tmp_path / "app" / "docker-compose.yml").read_text())["services"]


def main_ok(tmp_path, **kw):
    r = run_role(tmp_path, ROLE, "main", mv(tmp_path, **kw), env=SECRETS)
    assert r.returncode == 0, r.stdout + r.stderr
    return r


# ----------------------------------------------------------------------------- render


def test_main_renders_the_stack_pinned_and_hardened_exactly(tmp_path):
    main_ok(tmp_path)
    svc = compose(tmp_path)
    assert sorted(svc) == sorted(
        [
            "gluetun",
            "qbittorrent",
            "nzbget",
            "prowlarr",
            "flaresolverr",
            P,
            "radarr",
            "lidarr",
            S,
            "tdarr",
        ]
    )
    for name, s in svc.items():
        assert "@sha256:" in s["image"], name
        assert s["security_opt"] == ["no-new-privileges:true"]
        assert s["cap_drop"] == ["ALL"]
        assert not s.get("privileged")
    again = run_role(tmp_path, ROLE, "main", mv(tmp_path), env=SECRETS)
    assert again.returncode == 0 and "changed=0" in again.stdout, again.stdout


def test_the_download_clients_are_inside_the_vpn_namespace_and_publish_nothing_exactly(tmp_path):
    """The kill-switch: no network of their own, so no route but the tunnel."""
    main_ok(tmp_path)
    svc = compose(tmp_path)
    for name in CLIENTS:
        assert svc[name]["network_mode"] == "service:gluetun", name
        assert "ports" not in svc[name], name
        assert "gluetun" in svc[name]["depends_on"]  # waits for the tunnel to be healthy
    # their two web interfaces are published on the VPN client, on the guest's own address only
    assert sorted(svc["gluetun"]["ports"]) == sorted([f"{GUEST}:8080:8080", f"{GUEST}:6789:6789"])
    # nothing else shares a namespace or reaches the host's network
    others = [n for n in svc if n not in CLIENTS]
    assert not [n for n in others if "network_mode" in svc[n]]
    for s in svc.values():
        for p in s.get("ports", []):
            assert p.startswith(GUEST + ":"), p  # never all interfaces


def test_only_the_vpn_client_has_net_admin_and_the_tunnel_device(tmp_path):
    main_ok(tmp_path)
    svc = compose(tmp_path)
    assert svc["gluetun"]["cap_add"] == ["NET_ADMIN"] and svc["gluetun"]["devices"] == [
        "/dev/net/tun"
    ]
    assert not [n for n in svc if n != "gluetun" and "NET_ADMIN" in svc[n].get("cap_add", [])]
    assert not [n for n in svc if n != "gluetun" and svc[n].get("devices")]
    env = svc["gluetun"]["environment"]
    assert env["VPN_SERVICE_PROVIDER"] == "airvpn" and env["VPN_TYPE"] == "wireguard"
    assert env["FIREWALL_OUTBOUND_SUBNETS"] == SUBNET
    assert env["FIREWALL_VPN_INPUT_PORTS"] == "51000"
    assert "SERVER_HOSTNAMES" not in env  # optional: empty lets the client pick


def test_server_hostnames_and_no_forwarded_port_are_plain_optional_settings_as_documented(tmp_path):
    main_ok(
        tmp_path,
        media_automation_vpn_server_hostnames="a.example.internal,b.example.internal",
        media_automation_vpn_input_ports=[],
    )
    env = compose(tmp_path)["gluetun"]["environment"]
    assert env["SERVER_HOSTNAMES"] == "a.example.internal,b.example.internal"
    assert "FIREWALL_VPN_INPUT_PORTS" not in env


def test_the_vpn_credentials_are_only_in_the_vpn_clients_env_file(tmp_path):
    main_ok(tmp_path)
    text = (tmp_path / "app" / "docker-compose.yml").read_text()
    for secret in (PRIVATE, PRESHARED, ADDRESSES, PASSWORD):
        assert secret not in text
    envfile = tmp_path / "app" / "secrets" / "gluetun.env"
    body = envfile.read_text()
    assert PRIVATE in body and PRESHARED in body and ADDRESSES in body and PASSWORD not in body
    assert oct(envfile.stat().st_mode & 0o777) == "0o600"
    assert [p.name for p in (tmp_path / "app" / "secrets").iterdir()] == ["gluetun.env"]


def test_the_library_is_writable_at_the_same_path_with_downloads_inside_it(tmp_path):
    main_ok(tmp_path, media_automation_start=False)
    svc = compose(tmp_path)
    lib = str(tmp_path / "library")
    for name in (P, "radarr", "lidarr", "qbittorrent", "nzbget", "tdarr"):
        assert f"{lib}:{lib}" in svc[name]["volumes"], name  # no :ro
    assert not [
        n
        for n in ("prowlarr", "flaresolverr", S, "gluetun")
        if any(lib in v for v in svc[n].get("volumes", []))
    ]
    # the config of each app is the module's own state, outside the library
    assert f"{tmp_path}/data/config/{P}:/config" in svc[P]["volumes"]
    assert f"{tmp_path}/cache:/temp" in svc["tdarr"]["volumes"]


def test_the_apps_run_as_the_configured_ids_and_the_request_app_as_its_own_as_documented(tmp_path):
    main_ok(tmp_path)  # the ids are the unprivileged test's own: it can chown to no other
    ids = f"{os.getuid()}:{os.getgid()}"
    svc = compose(tmp_path)
    for name in (P, "radarr", "lidarr", "prowlarr", "qbittorrent", "nzbget"):
        assert svc[name]["user"] == ids, name
    assert svc[S]["user"] == f"{os.getuid()}:{os.getgid()}" and svc[S]["init"] is True
    env = svc["tdarr"][
        "environment"
    ]  # the one image with no user setting: it drops to these itself
    assert (env["PUID"], env["PGID"]) == (str(os.getuid()), str(os.getgid()))
    assert sorted(svc["tdarr"]["cap_add"]) == [
        "CHOWN",
        "DAC_OVERRIDE",
        "FOWNER",
        "SETGID",
        "SETUID",
    ]


def test_the_container_joins_the_role_slice_the_module_play_names(tmp_path):
    main_ok(tmp_path, hnx_module_slice="hnx-media_automation-server.slice")
    for name, s in compose(tmp_path).items():
        assert s["cgroup_parent"] == "hnx-media_automation-server.slice", name


def test_the_data_directories_and_only_the_missing_downloads_directories_are_created(tmp_path):
    lib = tmp_path / "library"
    lib.mkdir()
    (lib / ".hnx-media-library").write_text("")
    (lib / "downloads" / "qbittorrent").mkdir(parents=True)
    os.chmod(lib / "downloads" / "qbittorrent", 0o700)
    _docker_log(tmp_path)
    r = run_role(
        tmp_path,
        ROLE,
        "main",
        mv(tmp_path, media_automation_start=True),
        env={**SECRETS, "PATH": f"{tmp_path / 'bin'}:{os.environ['PATH']}"},
    )
    assert r.returncode == 0, r.stdout + r.stderr
    assert oct((lib / "downloads" / "qbittorrent").stat().st_mode & 0o777) == "0o700"  # not touched
    for sub in (
        "qbittorrent/completed",
        "qbittorrent/incomplete",
        "nzbget/completed",
        "nzbget/intermediate",
    ):
        assert (lib / "downloads" / sub).is_dir(), sub
    assert oct((tmp_path / "data" / "config" / "gluetun").stat().st_mode & 0o777) == "0o700"
    assert (tmp_path / "data" / "state").is_dir() and (tmp_path / "cache").is_dir()


# ----------------------------------------------------------------------------- refusals


def _first_main_refuses_an_unset_secret_naming_the_reference_and_writes_nothing(tmp_path, unset):
    env = {**SECRETS, unset: ""}
    return {"role": ROLE, "tasks_from": "main", "extra_vars": mv(tmp_path), "env": env}


@pytest.mark.parametrize("unset", list(SECRETS))
@first_run(_first_main_refuses_an_unset_secret_naming_the_reference_and_writes_nothing)
def test_main_refuses_an_unset_secret_naming_the_reference_and_writes_nothing(first, unset):
    """Review Focus 3: a module deployed before its secret exists is refused, by name."""
    r, tmp_path = first
    assert r.returncode != 0, r.stdout
    out = r.stdout + r.stderr
    assert REFS[unset] in out
    assert not (tmp_path / "app").exists() and not (tmp_path / "data").exists()
    for value in (PRIVATE, PRESHARED, PASSWORD):
        assert value not in out


def _first_main_refuses_a_credential_in_the_wrong_form(tmp_path, var, bad):
    return {
        "role": ROLE,
        "tasks_from": "main",
        "extra_vars": mv(tmp_path),
        "env": {**SECRETS, var: bad},
    }


@pytest.mark.parametrize(
    "var, bad",
    [
        ("HNX_SECRET_MEDIA_AUTOMATION_VPN_WIREGUARD_PRIVATE_KEY", "short"),
        ("HNX_SECRET_MEDIA_AUTOMATION_VPN_WIREGUARD_PRESHARED_KEY", PRIVATE),  # the same key twice
        ("HNX_SECRET_MEDIA_AUTOMATION_VPN_WIREGUARD_ADDRESSES", "not an address"),
        ("HNX_SECRET_MEDIA_AUTOMATION_QBITTORRENT_PASSWORD", "has a space in it 123"),
    ],
)
@first_run(_first_main_refuses_a_credential_in_the_wrong_form)
def test_main_refuses_a_credential_in_the_wrong_form(first, var, bad):
    r, tmp_path = first
    assert r.returncode != 0
    assert "must resolve in their form" in r.stdout + r.stderr
    assert not (tmp_path / "app").exists()


def _first_main_refuses_bad_inputs(tmp_path, over):
    return {"role": ROLE, "tasks_from": "main", "extra_vars": mv(tmp_path, **over), "env": SECRETS}


@pytest.mark.parametrize(
    "over",
    [
        {f"media_automation_{P}_image": f"ghcr.io/linuxserver/{P}:latest"},
        {"media_automation_gluetun_image": "docker.io/qmcgaw/gluetun:v3.41.3"},  # no digest
        {"ansible_host": "0.0.0.0"},
        {"ansible_host": "guest.example.internal"},
        {"media_automation_uid": 0},
        {f"media_automation_{S}_gid": 5},
        {f"media_automation_{P}_port": 70000},
        {"media_automation_library_path": "/srv"},  # a host-wide directory
        {"media_automation_library_path": "relative/media"},
        {"media_automation_library_path": "/var/lib/../etc"},
        {"media_automation_downloads_subdir": ".."},
        {"media_automation_vpn_outbound_subnets": []},  # the kill-switch would admit nothing
        {"media_automation_vpn_outbound_subnets": ["not-a-cidr"]},
        {"media_automation_vpn_outbound_subnets": ["0.0.0.0/0"]},
        {"media_automation_vpn_outbound_subnets": [SUBNET] * 9},
        {"media_automation_vpn_input_ports": [0]},
        {"media_automation_vpn_server_hostnames": "bad host"},
        {
            "media_automation_qbittorrent_login_ref": "secret:media-automation/vpn-wireguard-addresses"
        },
        {"media_automation_vpn_key_ref": "not-a-ref"},
        {"media_automation_helpers_enabled": "yes please"},
    ],
)
@first_run(_first_main_refuses_bad_inputs)
def test_main_refuses_bad_inputs(first, over):
    r, tmp_path = first
    assert r.returncode != 0, r.stdout
    assert not (tmp_path / "app" / "docker-compose.yml").exists()


def _cidr(*parts: int) -> str:
    return "{}.{}.{}.{}/{}".format(*parts)


def _first_the_kill_switch_admits_lab_ranges_only(tmp_path, bad):
    over = {"media_automation_vpn_outbound_subnets": [SUBNET, _cidr(*bad)]}
    return {"role": ROLE, "tasks_from": "main", "extra_vars": mv(tmp_path, **over), "env": SECRETS}


@pytest.mark.parametrize(
    "bad",
    [
        (8, 0, 0, 0, 8),
        (1, 1, 1, 1, 32),
        (100, 0, 0, 0, 8),
        (128, 0, 0, 0, 8),
        (192, 168, 0, 0, 8),  # a public /8 spelt like a private range
        (172, 16, 0, 0, 8),
        (172, 32, 0, 0, 16),
    ],
)
@first_run(_first_the_kill_switch_admits_lab_ranges_only)
def test_the_kill_switch_admits_lab_ranges_only(first, bad):
    """A public range in FIREWALL_OUTBOUND_SUBNETS is a hole around the tunnel."""
    r, tmp_path = first
    assert r.returncode != 0 and not (tmp_path / "app" / "docker-compose.yml").exists()


def test_the_required_variables_have_no_default(tmp_path):
    v = mv(tmp_path)
    del v["media_automation_vpn_outbound_subnets"]
    r = run_role(tmp_path, ROLE, "main", v, env=SECRETS)
    assert r.returncode != 0 and not (tmp_path / "app").exists()


def test_main_refuses_a_library_inside_the_data_root_or_the_compose_project(tmp_path):
    for name in ("data", "app"):
        inside = tmp_path / name / "lib"
        inside.mkdir(parents=True, exist_ok=True)
        r = run_role(
            tmp_path,
            ROLE,
            "main",
            mv(tmp_path, media_automation_library_path=str(inside)),
            env=SECRETS,
        )
        assert r.returncode != 0 and not (tmp_path / "app" / "docker-compose.yml").exists()


def test_main_refuses_to_start_on_a_library_that_is_not_there_or_empty_and_unmounted(tmp_path):
    for lib in (tmp_path / "not-mounted", tmp_path / "empty"):
        lib.mkdir(exist_ok=True) if lib.name == "empty" else None
        r = run_role(
            tmp_path,
            ROLE,
            "main",
            mv(tmp_path, media_automation_start=True, media_automation_library_path=str(lib)),
            env=SECRETS,
        )
        assert r.returncode != 0 and "is not a mounted library" in r.stdout
        assert not (tmp_path / "app" / "docker-compose.yml").exists()
        assert not (lib / "downloads").exists()  # nothing was written into the unmounted directory


# ----------------------------------------------------------------------------- health


class _Stand(BaseHTTPRequestHandler):
    codes: ClassVar[dict[str, int]] = {}

    def log_message(self, *a):
        pass

    def do_GET(self):
        code = self.codes.get(self.path, 200)
        body = json.dumps({"version": "1"}).encode()
        self.send_response(code)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class Stack:
    """Every web interface of the stack on one local port."""

    def __init__(self, codes=None):
        handler = type("H", (_Stand,), {"codes": codes or {}})
        self.httpd = ThreadingHTTPServer(("localhost", 0), handler)
        self.host, self.port = self.httpd.server_address[:2]

    def __enter__(self):
        threading.Thread(
            target=self.httpd.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True
        ).start()
        return self

    def __exit__(self, *a):
        self.httpd.shutdown()
        self.httpd.server_close()


DOCKER = """
import os, sys, json
a = sys.argv[1:]
log = open(LOG, 'a'); log.write(' '.join(a) + '\\n'); log.close()
services = %s
if 'ps' in a and '-q' in a:
    print('id-' + a[-1])
elif 'ps' in a:
    for s in services:
        print(json.dumps({'Service': s, 'State': 'running', 'Health': 'healthy'}))
elif a[0] == 'inspect':
    cid = a[-1]
    net = NET.get(cid, 'container:abc')
    print(net + ' ' + PORTS.get(cid, '{}'))
elif 'exec' in a and 'readlink' in a:
    print(NSMAP.get(a[a.index('-T') + 1], 'net:[4026531992]'))
elif 'exec' in a:
    sys.exit(1 if os.path.exists(HARDLINK_FAIL) else 0)
"""
SERVICES = [
    "gluetun",
    "qbittorrent",
    "nzbget",
    "prowlarr",
    "flaresolverr",
    P,
    "radarr",
    "lidarr",
    S,
    "tdarr",
]


def _env(tmp_path: Path, net=None, ports=None, unit_fail=False, ns=None) -> dict:
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    body = (
        (DOCKER % repr(SERVICES))
        .replace("LOG", repr(str(tmp_path / "docker.log")))
        .replace("NSMAP", repr(ns or {}))
        .replace("NET", repr(net or {}))
        .replace("PORTS", repr(ports or {}))
        .replace("HARDLINK_FAIL", repr(str(tmp_path / "hardlink.fails")))
    )
    fake(bindir / "docker", body)
    fake(bindir / "systemctl", f"import sys\nsys.exit({1 if unit_fail else 0})\n")
    return {"PATH": f"{bindir}:{os.environ['PATH']}"}


def _ports(port: int) -> dict:
    return {
        f"media_automation_{a}_port": port
        for a in (
            P,
            "radarr",
            "lidarr",
            "prowlarr",
            "qbittorrent",
            "nzbget",
            S,
            "tdarr",
        )
    }


def _health(tmp_path, stack, env=None, **kw):
    v = mv(tmp_path, ansible_host=stack.host, **_ports(stack.port), **kw)
    return run_role(tmp_path, ROLE, "health", v, env=env or _env(tmp_path))


def test_health_passes_and_checks_the_kill_switch_and_the_hardlink(tmp_path):
    with Stack() as s:
        r = _health(tmp_path, s)
    assert r.returncode == 0, r.stdout + r.stderr
    log = (tmp_path / "docker.log").read_text()
    assert "inspect" in log and f"exec -T {P}" in log


@pytest.mark.parametrize("client", CLIENTS)
def test_health_fails_when_a_download_client_is_not_behind_the_vpn_client_as_documented(
    tmp_path, client
):
    with Stack() as s:
        r = _health(tmp_path, s, env=_env(tmp_path, net={f"id-{client}": "bridge"}))
    assert r.returncode != 0 and "not fail-closed behind the VPN client" in r.stdout


@pytest.mark.parametrize("client", CLIENTS)
def test_health_catches_a_client_orphaned_by_a_vpn_client_restart(tmp_path, client):
    """A restart keeps the container id and builds a new namespace: the mode still reads container:<id>."""
    with Stack() as s:
        r = _health(tmp_path, s, env=_env(tmp_path, ns={client: "net:[1]"}))
    assert r.returncode != 0 and "stale network namespace" in r.stdout


def _recover(tmp_path, ns):
    env = _env(tmp_path, ns=ns)
    r = run_role(tmp_path, ROLE, "recover", mv(tmp_path), env=env)
    assert r.returncode == 0, r.stdout + r.stderr
    return [
        line
        for line in (tmp_path / "docker.log").read_text().splitlines()
        if "force-recreate" in line
    ]


def test_recover_recreates_only_the_orphaned_clients_and_never_the_vpn_client_exactly(tmp_path):
    calls = _recover(tmp_path, {"nzbget": "net:[1]"})
    assert len(calls) == 1 and calls[0].endswith("--no-deps nzbget")
    assert "gluetun" not in calls[0] and "qbittorrent" not in calls[0]


def test_recover_does_nothing_when_every_client_is_in_the_current_namespace(tmp_path):
    assert _recover(tmp_path, {}) == []


def test_health_fails_when_a_download_client_publishes_a_port(tmp_path):
    with Stack() as s:
        r = _health(
            tmp_path, s, env=_env(tmp_path, ports={"id-nzbget": '{"6789/tcp":[{"HostPort":"1"}]}'})
        )
    assert r.returncode != 0 and "not fail-closed" in r.stdout


def test_health_fails_when_an_interface_does_not_answer(tmp_path):
    with Stack({"/ping": 500}) as s:
        r = _health(tmp_path, s)
    assert r.returncode != 0


def test_health_fails_when_the_hardlink_cannot_be_made(tmp_path):
    (tmp_path / "hardlink.fails").write_text("")
    with Stack() as s:
        r = _health(tmp_path, s)
    assert r.returncode != 0 and "A hardlink can be made" in r.stdout


def test_health_fails_when_the_library_is_no_longer_mounted(tmp_path):
    with Stack() as s:
        v = mv(tmp_path, ansible_host=s.host, **_ports(s.port))
        (
            tmp_path / "library" / ".hnx-media-library"
        ).unlink()  # the mount (and its marker) went away
        r = run_role(tmp_path, ROLE, "health", v, env=_env(tmp_path))
    assert r.returncode != 0 and "is not a mounted library" in r.stdout


def test_health_fails_when_a_helper_timer_is_not_active_as_documented(tmp_path):
    with Stack() as s:
        r = _health(
            tmp_path,
            s,
            env={**_env(tmp_path, unit_fail=True)},
            media_automation_helpers_enabled=True,
            media_automation_systemctl_cli=str(tmp_path / "bin" / "systemctl"),
        )
    assert r.returncode != 0 and "helper timers are active" in r.stdout


# ----------------------------------------------------------------------------- export, restore, backup


def _config(root: Path) -> None:
    for app in (P, "radarr", "lidarr", "prowlarr"):
        (root / "config" / app / "logs").mkdir(parents=True)
        (root / "config" / app / "MediaCover").mkdir()
        (root / "config" / app / "config.xml").write_text(f"<Config>{app}</Config>")
        (root / "config" / app / f"{app}.db").write_bytes(b"db")
        (root / "config" / app / "logs" / "x.log").write_text("noise")
        (root / "config" / app / "MediaCover" / "c.jpg").write_text("cover")
    (root / "config" / S).mkdir()
    (root / "config" / S / "settings.json").write_text("{}")


def _docker_log(tmp_path: Path) -> Path:
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    log = tmp_path / "docker.log"
    fake(
        bindir / "docker",
        f"import sys\nopen({str(log)!r}, 'a').write(' '.join(sys.argv[1:]) + '\\n')\n",
    )
    return log


def test_export_archives_the_configs_with_the_stack_stopped_and_restore_checks_it_as_documented(
    tmp_path,
):
    v = mv(tmp_path)
    _config(tmp_path / "data")
    log = _docker_log(tmp_path)
    env = {"PATH": f"{tmp_path / 'bin'}:{os.environ['PATH']}"}
    r = run_role(tmp_path, ROLE, "export", {**v, "media_automation_start": True}, env=env)
    assert r.returncode == 0, r.stdout + r.stderr
    calls = log.read_text().splitlines()
    assert calls[0].endswith(" stop") and calls[-1].endswith(
        " up -d"
    )  # restarted whatever happened
    export = tmp_path / "data" / "export"
    with tarfile.open(export / "media-automation-config.tar.gz") as t:
        names = sorted(t.getnames())
    assert f"./{P}/config.xml" in names and f"./{S}/settings.json" in names
    assert not any("logs" in n or "MediaCover" in n for n in names)  # logs and cover art left out
    listing = json.loads((export / "listing.jsonl").read_text())
    assert (
        listing["sha256"]
        == hashlib.sha256((export / "media-automation-config.tar.gz").read_bytes()).hexdigest()
    )
    # restore from a copy of the export into a config that differs
    src = tmp_path / "src"
    src.mkdir()
    for p in export.iterdir():
        (src / p.name).write_bytes(p.read_bytes())
    (tmp_path / "data" / "config" / P / "config.xml").write_text("<Config>other</Config>")
    log.unlink()
    ok = run_role(
        tmp_path, ROLE, "restore", {**v, "media_automation_restore_source": str(src)}, env=env
    )
    assert ok.returncode == 0, ok.stdout + ok.stderr
    assert (tmp_path / "data" / "config" / P / "config.xml").read_text() == f"<Config>{P}</Config>"
    assert (
        tmp_path / "data" / "config.before-restore" / P / "config.xml"
    ).read_text() == "<Config>other</Config>"
    # a tampered archive is refused before anything is stopped or moved
    log.unlink(missing_ok=True)
    with open(src / "media-automation-config.tar.gz", "ab") as f:
        f.write(b"x")
    bad = run_role(
        tmp_path, ROLE, "restore", {**v, "media_automation_restore_source": str(src)}, env=env
    )
    assert bad.returncode != 0 and "not intact" in bad.stdout
    assert not log.exists()


def _archive(tmp_path: Path, members: dict[str, str]) -> Path:
    src = tmp_path / "src2"
    src.mkdir()
    payload = tmp_path / "payload"
    for name, text in members.items():
        (payload / name).parent.mkdir(parents=True, exist_ok=True)
        (payload / name).write_text(text)
    archive = src / "media-automation-config.tar.gz"
    with tarfile.open(archive, "w:gz") as t:
        for name in members:
            t.add(payload / name, arcname=name)
    (src / "listing.jsonl").write_text(
        json.dumps(
            {"key": archive.name, "sha256": hashlib.sha256(archive.read_bytes()).hexdigest()}
        )
        + "\n"
    )
    return src


def test_restore_refuses_an_archive_without_each_library_managers_config(tmp_path):
    src = _archive(tmp_path, {f"{P}/config.xml": "x"})
    _docker_log(tmp_path)
    env = {"PATH": f"{tmp_path / 'bin'}:{os.environ['PATH']}"}
    r = run_role(
        tmp_path,
        ROLE,
        "restore",
        {**mv(tmp_path), "media_automation_restore_source": str(src)},
        env=env,
    )
    assert r.returncode != 0 and "lacks one of" in r.stdout
    assert not (tmp_path / "data" / "config.restoring").exists()


def test_restore_refuses_an_archive_with_a_link(tmp_path):
    src = tmp_path / "src3"
    src.mkdir()
    payload = tmp_path / "p3"
    for app in (P, "radarr", "lidarr", "prowlarr"):
        (payload / app).mkdir(parents=True)
        (payload / app / "config.xml").write_text("x")
    os.symlink("/etc", payload / P / "etc")
    archive = src / "media-automation-config.tar.gz"
    with tarfile.open(archive, "w:gz") as t:
        t.add(payload, arcname=".")
    (src / "listing.jsonl").write_text(
        json.dumps(
            {"key": archive.name, "sha256": hashlib.sha256(archive.read_bytes()).hexdigest()}
        )
        + "\n"
    )
    _docker_log(tmp_path)
    env = {"PATH": f"{tmp_path / 'bin'}:{os.environ['PATH']}"}
    r = run_role(
        tmp_path,
        ROLE,
        "restore",
        {**mv(tmp_path), "media_automation_restore_source": str(src)},
        env=env,
    )
    assert r.returncode != 0 and "link" in r.stdout


def _first_backup_names_the_data_root_not_the_library(tmp_path):
    return {"role": ROLE, "tasks_from": "backup", "extra_vars": mv(tmp_path)}


@first_run(_first_backup_names_the_data_root_not_the_library)
def test_backup_names_the_data_root_not_the_library(first):
    first_result, tmp_path = first
    assert first_result.returncode == 0
    manifest = json.loads((tmp_path / "app" / "backup-manifest.json").read_text())
    assert manifest == {"app": "media-automation", "paths": [str(tmp_path / "data")]}


# ----------------------------------------------------------------------------- upgrade


def _first_upgrade_records_one_apps_bump_and_refuses_an_unpinned_or_foreign_target(tmp_path):
    cur = DEFAULTS[f"media_automation_{P}_image"]
    repo = cur.split("@")[0].rsplit(":", 1)[0]
    new = f"{repo}:99.0.1-ls1@sha256:" + "b" * 64
    (tmp_path / "app").mkdir()  # an installed stack: upgrade records beside its compose file
    return {
        "role": ROLE,
        "tasks_from": "upgrade",
        "extra_vars": mv(
            tmp_path, media_automation_upgrade_app=P, media_automation_target_image=new
        ),
        "setup": {"new": new, "repo": repo},
    }


@first_run(_first_upgrade_records_one_apps_bump_and_refuses_an_unpinned_or_foreign_target)
def test_upgrade_records_one_apps_bump_and_refuses_an_unpinned_or_foreign_target(first):
    ok, tmp_path = first
    new = first.setup["new"]
    repo = first.setup["repo"]
    assert ok.returncode == 0, ok.stdout + ok.stderr
    pending = json.loads((tmp_path / "app" / "pending-upgrade.json").read_text())
    assert pending["service"] == P and pending["tag"] == "99.0.1-ls1"
    (tmp_path / "app" / "pending-upgrade.json").unlink()
    for app, target in (
        (P, f"{repo}:99.0.1"),  # no digest
        (
            P,
            "ghcr.io/linuxserver/radarr:1-ls1@sha256:" + "b" * 64,
        ),  # another app's repository
        ("nothing", new),
    ):
        r = run_role(
            tmp_path,
            ROLE,
            "upgrade",
            mv(tmp_path, media_automation_upgrade_app=app, media_automation_target_image=target),
        )
        assert r.returncode != 0, (app, target)
        assert not (tmp_path / "app" / "pending-upgrade.json").exists()


# ----------------------------------------------------------------------------- helpers


def _helpers(tmp_path, **kw):
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    calls = tmp_path / "systemctl.log"
    fake(
        bindir / "systemctl",
        f"import sys\nopen({str(calls)!r}, 'a').write(' '.join(sys.argv[1:]) + '\\n')\nsys.exit(1 if 'is-enabled' in sys.argv else 0)\n",
    )
    units = tmp_path / "units"
    units.mkdir(exist_ok=True)
    return calls, units


def test_the_helper_scripts_are_carried_and_run_by_hardened_timers():
    files = MODULE / "roles" / "media_automation" / "files"
    assert sorted(p.name for p in files.iterdir()) == [
        "cleanup-downloads.py",
        "qbittorrent-excluded-file-names.txt",
        "rename_cleanup.py",
        "stalled-torrent-repair.py",
    ]
    for p in files.glob("*.py"):
        text = p.read_text()
        compile(text, str(p), "exec")
        assert "media-core" not in text and "/mnt/media" not in text and "gluck" not in text
    tmpl = (
        MODULE / "roles" / "media_automation" / "templates" / "cleanup-downloads.service.j2"
    ).read_text()
    for hardening in (
        "NoNewPrivileges=yes",
        "ProtectSystem=strict",
        "ProtectHome=yes",
        "PrivateTmp=yes",
    ):
        assert hardening in tmpl
    assert "User={{ media_automation_uid | int }}" in tmpl  # never root
    timer = (
        MODULE / "roles" / "media_automation" / "templates" / "cleanup-downloads.timer.j2"
    ).read_text()
    assert "Persistent=true" in timer and "OnCalendar=" in timer


def _first_the_helper_env_file_holds_the_client_password_0600_and_nothing_else_secret(tmp_path):
    calls, units = _helpers(tmp_path)
    v = mv(
        tmp_path,
        media_automation_helpers_enabled=True,
        media_automation_unit_dir=str(units),
        media_automation_libexec_dir=str(tmp_path / "libexec"),
        media_automation_systemctl_cli=str(tmp_path / "bin" / "systemctl"),
    )
    return {
        "role": ROLE,
        "tasks_from": "main",
        "extra_vars": v,
        "env": SECRETS,
        "setup": {"calls": calls, "units": units},
    }


@first_run(_first_the_helper_env_file_holds_the_client_password_0600_and_nothing_else_secret)
def test_the_helper_env_file_holds_the_client_password_0600_and_nothing_else_secret(first):
    """The password comes from the secret store into a 0600 file the units read; the units carry
    none of it."""
    r, tmp_path = first
    calls = first.setup["calls"]
    units = first.setup["units"]
    assert r.returncode == 0, r.stdout + r.stderr
    env_file = tmp_path / "app" / "helpers" / "helper.env"
    body = env_file.read_text()
    assert f"QBIT_PASS={PASSWORD}" in body and PRIVATE not in body
    assert oct(env_file.stat().st_mode & 0o777) == "0o600"
    assert os.access(tmp_path / "libexec" / "hnx-media-cleanup-downloads", os.X_OK)
    assert (tmp_path / "libexec" / "hnx-media-excluded-file-names.txt").is_file()
    assert (
        "ExecStart=/usr/local/libexec/homelabnext/hnx-media-cleanup-downloads"
        in (units / "hnx-media-automation-cleanup-downloads.service").read_text()
    )
    names = sorted(p.name for p in units.iterdir())
    assert names == sorted(
        f"hnx-media-automation-{h}.{k}"
        for h in ("cleanup-downloads", "stalled-repair", "rename-cleanup")
        for k in ("service", "timer")
    )
    svc = (units / "hnx-media-automation-cleanup-downloads.service").read_text()
    assert f"User={os.getuid()}" in svc
    assert "QBIT_PASS" not in svc and PASSWORD not in svc  # only the 0600 env file holds it
    lib, dl = tmp_path / "library", tmp_path / "library" / "downloads"
    # the cleanup may delete under downloads/ only: the library is read-only for it (B1)
    assert f"ReadOnlyPaths={lib}\n" in svc and f"ReadWritePaths={dl} " in svc
    assert f"ReadWritePaths={lib} " not in svc
    rename = (units / "hnx-media-automation-rename-cleanup.service").read_text()
    assert f"ReadWritePaths={lib} " in rename
    stalled = (units / "hnx-media-automation-stalled-repair.service").read_text()
    assert str(lib) not in stalled.split("ReadWritePaths=")[1].split("\n")[0]
    for u in (svc, rename, stalled):
        for d in (
            "CapabilityBoundingSet=\n", "RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX",
            "SystemCallFilter=@system-service", "ProtectSystem=strict", "NoNewPrivileges=yes",
            "PrivateDevices=yes", "ProtectKernelModules=yes", "RestrictNamespaces=yes",
            "LockPersonality=yes", "UMask=0077",
        ):  # fmt: skip
            assert d in u, d
    log = calls.read_text()
    assert "daemon-reload" in log and log.count("enable --now") == 3
