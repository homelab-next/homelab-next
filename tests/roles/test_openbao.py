# SPDX-License-Identifier: Apache-2.0
"""The secret store's server-mode role (ansible/roles/openbao, ADR-0042 decision 6).

Its install path fetches a release over the network and runs systemd, so it is proven on a real
host (the pull request that added it records that run); here every refusal is shown failing on a
bad input and passing on a good one, the configuration and unit are rendered and read back, the
start/restart decision runs against a fake ``systemctl``, the health and readiness hooks against
a fake HTTPS server behind a throwaway CA, and the snapshot hooks against a fake ``bao``."""

from __future__ import annotations

import functools
import grp
import hashlib
import http.server
import json
import os
import pwd
import re
import socket
import ssl
import subprocess
import threading
from contextlib import contextmanager
from pathlib import Path

import pytest
from rolerun import calls, fake, run_cases, run_role

pytestmark = pytest.mark.requires_tool("ansible-playbook", "openssl")

ROLE = "openbao"
USER = pwd.getpwuid(os.getuid()).pw_name
GROUP = grp.getgrgid(os.getgid()).gr_name
LOOPBACK = "localhost"  # the fake server and the fake listener bind loopback
HOST = "secrets-01.example.internal"
V6 = "2001:db8::20"  # the listen address (documentation range)
ADDR = f"https://{HOST}:8200"
CERT_PEM = "-----BEGIN CERTIFICATE-----\nMIIfake\n-----END CERTIFICATE-----\n"


@functools.cache
def key_pem() -> str:
    """A throwaway private key, made at run time (no key is ever written into the tree)."""
    return subprocess.run(
        ["openssl", "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:prime256v1"],
        check=True, capture_output=True, text=True,
    ).stdout  # fmt: skip


def base(tmp_path: Path, **kw) -> dict:
    v = {
        "openbao_logical_id": "secrets",
        "openbao_api_addr": ADDR,
        "openbao_listen_address": V6,
        "openbao_node_id": "secrets-01",
        "openbao_tls_cert_pem": CERT_PEM,
        "openbao_tls_private_key_pem": key_pem(),
        "openbao_tls_ca_pem": CERT_PEM,
        "openbao_user": USER,
        "openbao_group": GROUP,
        "openbao_owner": USER,
        "openbao_owner_group": GROUP,
        "openbao_config_dir": str(tmp_path / "etc"),
        "openbao_data_dir": str(tmp_path / "data" / "raft"),
        "openbao_audit_dir": str(tmp_path / "log"),
        "openbao_unit_dir": str(tmp_path / "units"),
        "openbao_logrotate_dir": str(tmp_path / "logrotate"),
        "openbao_state_dir": str(tmp_path / "state"),
        "openbao_backup_dir": str(tmp_path / "backup"),
        "openbao_export_dir": str(tmp_path / "export"),
        "openbao_install_dir": str(tmp_path / "opt"),
    }
    for d in ("units", "logrotate"):
        (tmp_path / d).mkdir(exist_ok=True)
    v.update(kw)
    return v


# ---------------------------------------------------------------- validate

BAD = [
    {"openbao_listen_address": "0.0.0.0"},  # a refused wildcard
    {"openbao_listen_address": "::"},
    {"openbao_listen_address": "secrets-01"},
    {"openbao_api_addr": ADDR.replace("https:", "http:")},
    {"openbao_api_addr": ADDR + "/v1"},
    {"openbao_api_addr": ADDR.replace("//", "//user@")},
    {"openbao_cluster_addr": f"http://{HOST}:8201"},
    {"openbao_version": "2.7"},
    {"openbao_version": "2.7.1\nevil"},
    {"openbao_checksums": {"amd64": "0" * 63}},
    {"openbao_checksums": {"riscv64": "0" * 64}},
    {"openbao_checksums": {}},
    {"openbao_release_repository": "http://mirror.example.internal/openbao"},
    {"openbao_user": "root"},
    {"openbao_group": "root"},
    {"openbao_user": "a b"},
    {"openbao_node_id": 'n"1'},
    {"openbao_log_level": "chatty"},
    {"openbao_tls_min_protocol": "tls10"},
    {"openbao_port": 8201},
    {"openbao_data_dir": "/"},
    {"openbao_data_dir": "relative/raft"},
    {"openbao_audit_dir": "/var/log"},
    {"openbao_config_dir": "/etc"},
    {"openbao_logical_id": "Secrets!"},
    # TLS is mandatory: no PEMs and no test option, a key that is not one, PEMs beside the option
    {"openbao_tls_cert_pem": ""},
    {"openbao_tls_private_key_pem": "not a key"},
    {"openbao_tls_ca_pem": ""},
    {"openbao_tls_selfsigned_for_tests": True},
    {
        "openbao_tls_selfsigned_for_tests": True,
        "openbao_tls_cert_pem": "",
        "openbao_tls_private_key_pem": "",
        "openbao_tls_selfsigned_sans": ["a,DNS:evil"],
    },
]


def test_validate_refuses_bad_inputs_and_accepts_good_ones(tmp_path):
    good = [
        {},
        {"openbao_cluster_addr": f"https://{HOST}:8201"},
        {
            "openbao_tls_selfsigned_for_tests": True,
            "openbao_tls_cert_pem": "",
            "openbao_tls_private_key_pem": "",
            "openbao_tls_ca_pem": "",
            "openbao_tls_selfsigned_sans": ["secrets.example.internal", "2001:db8::21"],
        },
    ]
    got = run_cases(tmp_path, ROLE, "validate", base(tmp_path), good + BAD, parallel=True)
    for over, (failed, msg) in zip(good, got[: len(good)], strict=True):
        assert not failed, (over, msg)
    for over, (failed, msg) in zip(BAD, got[len(good) :], strict=True):
        assert failed, over
        assert "openbao" in msg, (over, msg)
        assert "PRIVATE KEY" not in msg and "not a key" not in msg  # a key never reaches a message


def test_main_needs_its_required_inputs(tmp_path):
    v = base(tmp_path)
    del v["openbao_api_addr"], v["openbao_listen_address"]
    r = run_role(tmp_path, ROLE, "main", v)
    assert r.returncode != 0
    assert "openbao_api_addr" in r.stdout and "openbao_listen_address" in r.stdout


# ---------------------------------------------------------------- the rendered files


def test_config_renders_raft_tls_and_audit_and_a_hardened_unit(tmp_path):
    v = base(tmp_path)
    r = run_role(tmp_path, ROLE, "config", v)
    assert r.returncode == 0, r.stdout + r.stderr
    hcl = (tmp_path / "etc" / "openbao.hcl").read_text()
    etc = tmp_path / "etc"
    for line in (
        f'api_addr = "{ADDR}"',
        f'cluster_addr = "https://[{V6}]:8201"',
        f'path = "{tmp_path}/data/raft"',
        'node_id = "secrets-01"',
        f'address = "[{V6}]:8200"',
        f'cluster_address = "[{V6}]:8201"',
        f'tls_cert_file = "{etc}/tls/server.pem"',
        f'tls_key_file = "{etc}/tls/server-key.pem"',
        'tls_min_version = "tls12"',
        'audit "file" "file" {',
        f'file_path = "{tmp_path}/log/audit.log"',
        "ui = false",
    ):
        assert line in hcl, line
    assert 'storage "raft" {' in hcl and 'listener "tcp" {' in hcl
    # TLS cannot be switched off, and the release reads disable_mlock as an unknown field
    assert "tls_disable" not in hcl and "disable_mlock" not in hcl
    assert '\nseal "' not in hcl  # Shamir: no auto-unseal stanza, ever
    assert oct((etc / "openbao.hcl").stat().st_mode & 0o777) == "0o640"
    assert oct((tmp_path / "data" / "raft").stat().st_mode & 0o777) == "0o700"

    unit = (tmp_path / "units" / "openbao.service").read_text()
    for line in (
        f"User={USER}",
        f"Group={GROUP}",
        f"ExecStart=/usr/local/bin/bao server -config={etc}/openbao.hcl",
        "Type=notify",
        "NoNewPrivileges=yes",
        "CapabilityBoundingSet=",
        "AmbientCapabilities=",
        "ProtectSystem=strict",
        f"ReadWritePaths={tmp_path}/data/raft {tmp_path}/log",
        "ProtectHome=yes",
        "PrivateTmp=yes",
        "PrivateDevices=yes",
        "MemoryDenyWriteExecute=yes",
        "LimitCORE=0",
        "UMask=0077",
        "SystemCallFilter=@system-service",
    ):
        assert f"\n{line}\n" in unit, line
    assert "User=root" not in unit and "CAP_" not in unit
    rotate = (tmp_path / "logrotate" / "openbao").read_text()
    assert f"{tmp_path}/log/audit.log {{" in rotate and "kill --signal=HUP" in rotate


def test_config_quotes_every_string_it_writes(tmp_path):
    """A value is written JSON-quoted, so it cannot close its string and add a stanza."""
    evil = 'n1"\n}\nlistener "tcp" { tls_disable = true'
    r = run_role(tmp_path, ROLE, "config", base(tmp_path, openbao_node_id=evil))
    assert r.returncode == 0, r.stdout + r.stderr
    hcl = (tmp_path / "etc" / "openbao.hcl").read_text()
    assert f"node_id = {json.dumps(evil)}" in hcl
    assert hcl.count('listener "tcp" {') == 1 and "\ntls_disable" not in hcl


# ---------------------------------------------------------------- start, restart, owed restart


@contextmanager
def listener():
    """Something listening on loopback (the service hook waits for the API port)."""
    s = socket.socket()
    s.bind((LOOPBACK, 0))
    s.listen()
    try:
        yield s.getsockname()[1]
    finally:
        s.close()


SYSTEMCTL = r"""
import os, sys
open(LOG, "a").write("systemctl " + " ".join(sys.argv[1:]) + "\n")
if sys.argv[1] == "is-active":
    print("active" if os.path.exists(STATE + ".active") else "inactive")
    sys.exit(0 if os.path.exists(STATE + ".active") else 3)
if sys.argv[1] == "is-enabled":
    print("enabled")
"""


def service_vars(tmp_path: Path, port: int, active: bool, **kw) -> dict:
    marker = tmp_path / "unit"
    if active:
        Path(str(marker) + ".active").write_text("")
    body = SYSTEMCTL.replace("LOG", repr(str(tmp_path / "calls.log"))).replace(
        "STATE", repr(str(marker))
    )
    return base(
        tmp_path,
        openbao_listen_address=LOOPBACK,
        openbao_port=port,
        openbao_systemctl_cli=fake(tmp_path / "systemctl", body),
        **kw,
    )


def run_service(tmp_path, v, changed):
    """Run the start/restart step as main does, after a configuration run that changed or not
    (main hands service.yml the registered results of its earlier steps)."""
    (tmp_path / "calls.log").unlink(missing_ok=True)
    return run_role(tmp_path, ROLE, "service", dict(v, openbao_config={"changed": changed}))


def test_a_stopped_server_is_started_never_restarted(tmp_path):
    with listener() as port:
        r = run_service(tmp_path, service_vars(tmp_path, port, active=False), changed=True)
    assert r.returncode == 0, r.stdout + r.stderr
    log = calls(tmp_path)
    assert "systemctl start openbao.service" in log
    assert not any("restart" in c for c in log)


def test_a_running_server_is_not_restarted_but_the_restart_is_recorded(tmp_path):
    with listener() as port:
        r = run_service(tmp_path, service_vars(tmp_path, port, active=True), changed=True)
    assert r.returncode == 0, r.stdout + r.stderr
    assert not any(c.split()[1] in ("start", "restart") for c in calls(tmp_path))
    owed = json.loads((tmp_path / "state" / "restart-owed").read_text())
    assert owed == {"reasons": ["configuration"]}
    assert "A restart SEALS it" in r.stdout


def test_an_owed_restart_is_made_when_allowed_and_then_cleared(tmp_path):
    with listener() as port:
        v = service_vars(tmp_path, port, active=True)
        (tmp_path / "state").mkdir()
        (tmp_path / "state" / "restart-owed").write_text('{"reasons": ["configuration"]}\n')
        # nothing changed in this run: the restart an earlier run recorded is still owed
        r = run_service(tmp_path, v, changed=False)
        assert r.returncode == 0, r.stdout + r.stderr
        assert "systemctl restart openbao.service" not in calls(tmp_path)
        assert (tmp_path / "state" / "restart-owed").exists()
        r = run_service(tmp_path, dict(v, openbao_allow_restart=True), changed=False)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "systemctl restart openbao.service" in calls(tmp_path)
    assert not (tmp_path / "state" / "restart-owed").exists()


def test_an_unchanged_running_server_is_left_alone(tmp_path):
    with listener() as port:
        r = run_service(tmp_path, service_vars(tmp_path, port, active=True), changed=False)
    assert r.returncode == 0, r.stdout + r.stderr
    assert [c.split()[1] for c in calls(tmp_path)] == ["is-enabled", "is-active"]
    assert not (tmp_path / "state" / "restart-owed").exists()


# ---------------------------------------------------------------- health and readiness


@pytest.fixture(scope="module")
def pki(tmp_path_factory):
    """A throwaway CA and a loopback server certificate it issued."""
    d = tmp_path_factory.mktemp("pki")
    ec = ["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-days", "2"]
    subprocess.run(
        ["openssl", "req", "-x509", *ec, "-subj", "/CN=test ca", "-keyout", d / "ca-key.pem",
         "-out", d / "ca.pem", "-addext", "basicConstraints=critical,CA:TRUE",
         "-addext", "keyUsage=critical,keyCertSign,cRLSign"],
        check=True, capture_output=True,
    )  # fmt: skip
    subprocess.run(
        ["openssl", "req", "-x509", *ec, "-subj", "/CN=localhost", "-CA", d / "ca.pem",
         "-CAkey", d / "ca-key.pem", "-addext", "subjectAltName=DNS:localhost",
         "-addext", "basicConstraints=critical,CA:FALSE", "-addext", "extendedKeyUsage=serverAuth",
         "-keyout", d / "key.pem", "-out", d / "cert.pem"],
        check=True, capture_output=True,
    )  # fmt: skip
    return d


@contextmanager
def fake_openbao(pki, status: int, body: dict):
    """sys/health as the server answers it: ``status`` without the query, 200 with it."""

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            code = 200 if "sealedcode=200" in self.path else status
            raw = json.dumps(body).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def log_message(self, *a):
            pass

    srv = http.server.ThreadingHTTPServer((LOOPBACK, 0), Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(pki / "cert.pem", pki / "key.pem")
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        yield f"https://{LOOPBACK}:{srv.server_address[1]}"
    finally:
        srv.shutdown()
        srv.server_close()


def hook_vars(tmp_path, pki, url, **kw):
    v = base(tmp_path, openbao_api_addr=url, **kw)
    (tmp_path / "etc" / "tls").mkdir(parents=True, exist_ok=True)
    (tmp_path / "etc" / "tls" / "ca.pem").write_bytes((pki / "ca.pem").read_bytes())
    return v


ACTIVE = {"initialized": True, "sealed": False, "standby": False, "version": "2.7.1"}
STATES = {
    # name: (status without the query, body, health fails with, readiness says)
    "active": (200, ACTIVE, None, "unsealed-active"),
    "standby": (429, dict(ACTIVE, standby=True), None, "unsealed-standby"),
    "sealed": (503, dict(ACTIVE, sealed=True), "SEALED", "sealed"),
    "uninitialised": (501, dict(ACTIVE, initialized=False, sealed=True), "UNINITIALISED", "uninitialised"),
    "old release": (200, dict(ACTIVE, version="2.7.0"), "runs 2.7.0, the pin is 2.7.1", "unsealed-active"),
}  # fmt: skip


@pytest.mark.parametrize("state", STATES)
def test_health_fails_unless_unsealed_and_readiness_names_the_state(tmp_path, pki, state):
    status, body, health_fails, ready_says = STATES[state]
    with fake_openbao(pki, status, body) as url:
        v = hook_vars(tmp_path, pki, url)
        h = run_role(tmp_path, ROLE, "health", v)
        r = run_role(tmp_path, ROLE, "readiness", v)
    if health_fails:
        assert h.returncode != 0 and health_fails in h.stdout, h.stdout
    else:
        assert h.returncode == 0, h.stdout + h.stderr
    assert r.returncode == 0, r.stdout + r.stderr  # readiness fails only when the API is silent
    assert f"openbao secrets: {ready_says}, version" in r.stdout


def test_readiness_reports_an_owed_restart(tmp_path, pki):
    with fake_openbao(pki, 200, ACTIVE) as url:
        v = hook_vars(tmp_path, pki, url)
        (tmp_path / "state").mkdir()
        (tmp_path / "state" / "restart-owed").write_text("{}\n")
        r = run_role(tmp_path, ROLE, "readiness", v)
    assert r.returncode == 0 and "a restart is owed" in r.stdout, r.stdout


def test_readiness_fails_when_the_api_is_silent(tmp_path, pki):
    with listener() as port:  # accepts TCP, never speaks TLS or HTTP
        v = hook_vars(tmp_path, pki, f"https://{LOOPBACK}:{port}", openbao_health_timeout=2)
        r = run_role(tmp_path, ROLE, "readiness", v)
        h = run_role(tmp_path, ROLE, "health", v)
    assert r.returncode != 0 and "does not answer" in r.stdout
    assert h.returncode != 0


def test_health_refuses_a_server_its_ca_did_not_issue(tmp_path, pki, tmp_path_factory):
    other = tmp_path_factory.mktemp("other")
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
         "-nodes", "-days", "2", "-subj", "/CN=other", "-keyout", other / "k.pem",
         "-out", other / "ca.pem"],
        check=True, capture_output=True,
    )  # fmt: skip
    with fake_openbao(pki, 200, ACTIVE) as url:
        v = hook_vars(tmp_path, pki, url)
        (tmp_path / "etc" / "tls" / "ca.pem").write_bytes((other / "ca.pem").read_bytes())
        h = run_role(tmp_path, ROLE, "health", v)
    assert h.returncode != 0 and "CERTIFICATE_VERIFY_FAILED" in h.stdout


# ---------------------------------------------------------------- snapshots

TOKEN = "s.fake-snapshot-token-0123456789"

BAO = r"""
import os, sys
args = sys.argv[1:]
open(LOG, "a").write("bao " + " ".join(args) + " token=" + str(os.environ.get("BAO_TOKEN") == EXPECTED)
                     + " cacert=" + os.environ.get("BAO_CACERT", "") + "\n")
if args[:4] == ["operator", "raft", "snapshot", "save"]:
    open(args[4], "wb").write(b"raft-snapshot-bytes")
"""


def bao_vars(tmp_path, pki, url, **kw):
    body = BAO.replace("LOG", repr(str(tmp_path / "calls.log"))).replace("EXPECTED", repr(TOKEN))
    return hook_vars(tmp_path, pki, url, openbao_bin=fake(tmp_path / "bao", body), **kw)


@pytest.mark.parametrize(
    ("hook", "dirname", "name"),
    [("backup", "backup", "raft.snap"), ("export", "export", "secrets.snap")],
)
def test_snapshot_hooks_write_the_snapshot_and_a_manifest_naming_its_writer(
    tmp_path, pki, hook, dirname, name
):
    with fake_openbao(pki, 200, ACTIVE) as url:
        v = bao_vars(tmp_path, pki, url, openbao_snapshot_token=TOKEN)
        r = run_role(tmp_path, ROLE, hook, v)
    assert r.returncode == 0, r.stdout + r.stderr
    assert TOKEN not in r.stdout + r.stderr
    (call,) = calls(tmp_path)
    assert call.startswith(f"bao operator raft snapshot save {tmp_path}/{dirname}/{name}.partial ")
    assert call.endswith(f"token=True cacert={tmp_path}/etc/tls/ca.pem")
    snap = tmp_path / dirname / name
    assert snap.read_bytes() == b"raft-snapshot-bytes"
    assert not snap.with_name(name + ".partial").exists()
    manifest = json.loads(snap.with_name(name + ".json").read_text())
    assert manifest["written_by"] == "2.7.1" and manifest["kind"] == "raft-snapshot"
    assert manifest["sha256"] == hashlib.sha256(b"raft-snapshot-bytes").hexdigest()
    assert manifest["bytes"] == len(b"raft-snapshot-bytes") and manifest["service"] == "secrets"
    assert oct((tmp_path / dirname).stat().st_mode & 0o777) == "0o700"


def test_a_snapshot_needs_a_token(tmp_path, pki):
    with fake_openbao(pki, 200, ACTIVE) as url:
        v = bao_vars(tmp_path, pki, url)
        missing = run_role(tmp_path, ROLE, "backup", v)
        empty = run_role(tmp_path, ROLE, "backup", dict(v, openbao_snapshot_token=""))
    assert missing.returncode != 0 and "openbao_snapshot_token" in missing.stdout
    assert empty.returncode != 0
    assert calls(tmp_path) == []


@pytest.mark.parametrize("force", [False, True])
def test_restore_restores_the_named_snapshot(tmp_path, pki, force):
    src = tmp_path / "raft.snap"
    src.write_bytes(b"raft-snapshot-bytes")
    with fake_openbao(pki, 200, ACTIVE) as url:
        v = bao_vars(
            tmp_path, pki, url, openbao_snapshot_token=TOKEN, openbao_restore_source=str(src)
        )
        if force:
            v["openbao_restore_force"] = True
        r = run_role(tmp_path, ROLE, "restore", v)
    assert r.returncode == 0, r.stdout + r.stderr
    assert TOKEN not in r.stdout + r.stderr
    (call,) = calls(tmp_path)
    flag = " -force" if force else ""
    assert call.startswith(f"bao operator raft snapshot restore{flag} {src} token=True")


def test_restore_refuses_a_missing_or_empty_snapshot(tmp_path, pki):
    (tmp_path / "empty.snap").write_bytes(b"")
    with fake_openbao(pki, 200, ACTIVE) as url:
        for src in (tmp_path / "missing.snap", tmp_path / "empty.snap"):
            v = bao_vars(
                tmp_path, pki, url, openbao_snapshot_token=TOKEN, openbao_restore_source=str(src)
            )
            r = run_role(tmp_path, ROLE, "restore", v)
            assert r.returncode != 0 and "not a non-empty snapshot file" in r.stdout
    assert calls(tmp_path) == []


@pytest.mark.parametrize(
    "target",
    [
        {"openbao_target_version": "2.7.1"},  # a no-op
        {"openbao_target_version": "2.6.5"},  # a downgrade
        {"openbao_target_version": "2.8"},
        {"openbao_target_checksums": {"amd64": "z" * 64}},
        {"openbao_target_checksums": {"s390x": "a" * 64}},
    ],
)
def test_upgrade_refuses_a_downgrade_a_no_op_or_a_bad_checksum(tmp_path, pki, target):
    with fake_openbao(pki, 200, ACTIVE) as url:
        v = bao_vars(tmp_path, pki, url, openbao_snapshot_token=TOKEN)
        v.update(
            {"openbao_target_version": "2.7.2", "openbao_target_checksums": {"amd64": "a" * 64}}
        )
        v.update(target)
        r = run_role(tmp_path, ROLE, "upgrade", v)
    assert r.returncode != 0 and "is not a release newer than" in r.stdout, r.stdout
    assert calls(tmp_path) == []  # refused before the snapshot, before any download


def test_no_hook_ever_initialises_unseals_or_reads_a_share():
    """The role's whole task tree: the operator initialises and unseals, never the role."""
    text = "\n".join(
        p.read_text() for p in (Path(__file__).resolve().parents[2] / "ansible/roles/openbao").rglob("*")
        if p.is_file() and p.suffix in (".yml", ".j2")
    )  # fmt: skip
    forbidden = re.compile(
        r"operator\s+(init|unseal|generate-root)\b|sys/(init|unseal|generate-root)|unseal_keys|root_token"
    )
    assert forbidden.findall(text) == []
