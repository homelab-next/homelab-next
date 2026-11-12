# SPDX-License-Identifier: Apache-2.0
"""The secret store's server-mode role (ansible/roles/openbao, ADR-0042 decision 6).

Its install path fetches a release over the network and runs systemd, so it is proven on a real
host (the pull request that added it records that run); here every refusal is shown failing on a
bad input and passing on a good one, the configuration and unit are rendered and read back, the
start/restart decision runs against a fake ``systemctl``, the health and readiness hooks against
a fake HTTPS server behind a throwaway CA, and the snapshot hooks against that server's snapshot
endpoints with the two principals (snapshot: read only; restore: post only)."""

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
import sys
import threading
from contextlib import contextmanager
from pathlib import Path

import pytest
from rolerun import _invocation, calls, fake, run_cases, run_role

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
        "openbao_tls_selfsigned_confirm_throwaway": True,
        "openbao_tls_cert_pem": "",
        "openbao_tls_private_key_pem": "",
        "openbao_tls_ca_pem": "",
        "openbao_tls_selfsigned_sans": ["a,DNS:evil"],
    },
    # the test-only option: never without its second confirmation, never with a supplied CA
    {
        "openbao_tls_selfsigned_for_tests": True,
        "openbao_tls_cert_pem": "",
        "openbao_tls_private_key_pem": "",
        "openbao_tls_ca_pem": "",
    },
    {
        "openbao_tls_selfsigned_for_tests": True,
        "openbao_tls_selfsigned_confirm_throwaway": True,
        "openbao_tls_cert_pem": "",
        "openbao_tls_private_key_pem": "",
    },
    {"openbao_tls_selfsigned_confirm_throwaway": True},
    # checksums taken for another release than the pin
    {"openbao_checksums_version": "2.7.0"},
]


def test_validate_refuses_bad_inputs_and_accepts_good_ones(tmp_path):
    good = [
        {},
        {"openbao_cluster_addr": f"https://{HOST}:8201"},
        {
            "openbao_tls_selfsigned_for_tests": True,
            "openbao_tls_selfsigned_confirm_throwaway": True,
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
        'tls_cipher_suites = "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,'
        "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,"
        'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305"',
        'audit "file" "file" {',
        'audit "syslog" "syslog" {',
        'facility = "AUTH"',
        'tag = "openbao"',
        f'file_path = "{tmp_path}/log/audit.log"',
        "ui = false",
    ):
        assert line in hcl, line
    assert 'storage "raft" {' in hcl and 'listener "tcp" {' in hcl
    # TLS cannot be switched off, and the release reads disable_mlock as an unknown field
    assert "tls_disable" not in hcl and "disable_mlock" not in hcl
    assert '\nseal "' not in hcl  # Shamir: no auto-unseal stanza, ever
    assert not re.search(r"(?m)^\s*retry_join", hcl)  # a single node
    (suites,) = re.findall(r'tls_cipher_suites = "([^"]+)"', hcl)
    for suite in suites.split(","):  # TLS 1.2: forward secrecy and AEAD, nothing else
        assert suite.startswith("TLS_ECDHE_") and ("_GCM_" in suite or "CHACHA20_POLY1305" in suite)
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
        "MemorySwapMax=0",
        "SocketBindAllow=tcp:8200",
        "SocketBindAllow=tcp:8201",
        "SocketBindDeny=any",
        "ExecReload=/bin/kill --signal HUP $MAINPID",
    ):
        assert f"\n{line}\n" in unit, line
    assert "User=root" not in unit and "CAP_" not in unit
    rotate = (tmp_path / "logrotate" / "openbao").read_text()
    assert f"{tmp_path}/log/audit.log {{" in rotate and "kill --signal=HUP" in rotate
    assert f"\n    su {USER} {GROUP}\n" in rotate and "\n    maxsize " in rotate
    assert "|| true" not in rotate  # a failed SIGHUP to a running server fails the rotation


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


def test_owed_reasons_merge_with_what_an_earlier_run_recorded(tmp_path):
    with listener() as port:
        v = service_vars(tmp_path, port, active=True)
        (tmp_path / "state").mkdir()
        (tmp_path / "state" / "restart-owed").write_text('{"reasons": ["release"]}\n')
        r = run_service(tmp_path, v, changed=True)
    assert r.returncode == 0, r.stdout + r.stderr
    owed = json.loads((tmp_path / "state" / "restart-owed").read_text())
    assert owed == {"reasons": ["release", "configuration"]}
    assert "(release, configuration)" in r.stdout


TLS_RESULTS = ["openbao_tls_cert_copy", "openbao_tls_key_copy", "openbao_tls_test_cert"]


@pytest.mark.parametrize("allow", [False, True])
@pytest.mark.parametrize("which", TLS_RESULTS)
def test_a_new_tls_certificate_or_key_is_reloaded_never_restarted(tmp_path, which, allow):
    """The server reloads its listener's certificate and key on SIGHUP (ExecReload) and stays
    unsealed; a restart would seal it, so TLS alone never restarts it, even when allowed."""
    with listener() as port:
        v = service_vars(tmp_path, port, active=True, openbao_allow_restart=allow)
        r = run_service(tmp_path, dict(v, **{which: {"changed": True}}), changed=False)
    assert r.returncode == 0, r.stdout + r.stderr
    verbs = [c.split()[1] for c in calls(tmp_path)]
    assert verbs == ["is-enabled", "is-active", "reload"], verbs
    assert not (tmp_path / "state" / "restart-owed").exists()


def test_tls_with_a_restart_that_is_made_needs_no_reload(tmp_path):
    with listener() as port:
        v = service_vars(tmp_path, port, active=True, openbao_allow_restart=True)
        r = run_service(tmp_path, dict(v, openbao_tls_cert_copy={"changed": True}), changed=True)
    assert r.returncode == 0, r.stdout + r.stderr
    assert [c.split()[1] for c in calls(tmp_path)] == ["is-enabled", "is-active", "restart"]


def check_run(tmp_path, hook, v, env=None):
    """run_role with --check: what a dry run against the host would report."""
    cmd, env = _invocation(tmp_path, ROLE, hook, v, env)
    return subprocess.run([*cmd, "--check"], capture_output=True, text=True, env=env, cwd=tmp_path)


def test_check_mode_on_a_converged_server_changes_nothing_but_still_asks(tmp_path):
    with listener() as port:
        v = service_vars(tmp_path, port, active=True)
        (tmp_path / "state").mkdir(mode=0o750)  # as main left it
        r = check_run(tmp_path, "service", dict(v, openbao_config={"changed": False}))
    assert r.returncode == 0, r.stdout + r.stderr
    assert re.search(r"localhost\s*: ok=\d+\s+changed=0 ", r.stdout), r.stdout
    # the read-only probes ran (check_mode: false), so the decision was made on the real state
    assert [c.split()[1] for c in calls(tmp_path)] == ["is-enabled", "is-active"]


def test_check_mode_shows_the_restart_a_drift_would_owe_without_recording_it(tmp_path):
    with listener() as port:
        v = service_vars(tmp_path, port, active=True)
        (tmp_path / "state").mkdir()
        r = check_run(tmp_path, "service", dict(v, openbao_config={"changed": True}))
    assert r.returncode == 0, r.stdout + r.stderr
    assert re.search(
        r"TASK \[openbao : Record the restart a running server owes\][^\n]*\n+changed:", r.stdout
    ), r.stdout
    assert "A restart SEALS it" in r.stdout
    assert not (tmp_path / "state" / "restart-owed").exists()
    assert [c.split()[1] for c in calls(tmp_path)] == ["is-enabled", "is-active"]


def test_check_mode_on_a_fresh_host_skips_what_needs_the_archive(tmp_path, pki):
    """--check on a host that has no release yet: nothing is fetched, so the unpack and the
    version check (which need the archive and the command) are skipped, not failed."""
    with fake_openbao(pki, 200, ACTIVE) as mirror:  # a mirror that would answer, never asked
        v = base(
            tmp_path, openbao_release_repository=mirror, openbao_release_version="2.7.1",
            openbao_release_checksums={"amd64": "0" * 64}, openbao_arch="amd64",
        )  # fmt: skip
        r = check_run(tmp_path, "release", v, env={"SSL_CERT_FILE": str(pki / "ca.pem")})
    assert r.returncode == 0, r.stdout + r.stderr
    tasks = ("Fetch the release archive", "Unpack the command",
             "Ask the unpacked command for its version", "Refuse a command that is not")  # fmt: skip
    for task in tasks:
        assert re.search(rf"TASK \[openbao : {task}[^\n]*\n+skipping:", r.stdout), (task, r.stdout)


# ---------------------------------------------------------------- platform and downgrade


SWAPS = "Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n"


@pytest.mark.parametrize(
    ("swaps", "allow", "refused"),
    [
        ("", False, False),
        ("/dev/vda3   partition\t1048572\t\t0\t\t-2\n", False, True),
        ("/dev/vda3   partition\t1048572\t\t0\t\t-2\n", True, False),
    ],
)
def test_platform_refuses_active_swap_unless_allowed(tmp_path, swaps, allow, refused):
    (tmp_path / "swaps").write_text(SWAPS + swaps)
    v = base(tmp_path, openbao_proc_swaps=str(tmp_path / "swaps"), openbao_allow_swap=allow)
    r = run_role(tmp_path, ROLE, "platform", v)
    if refused:
        assert r.returncode != 0 and "swap is active (/dev/vda3)" in r.stdout, r.stdout
    else:
        assert r.returncode == 0, r.stdout + r.stderr


@pytest.mark.parametrize(
    ("running", "allow", "refused"),
    [
        ("2.8.0", False, True),  # the pin (2.7.1) is older than what runs
        ("2.8.0", True, False),
        ("2.7.1", False, False),
        ("2.7.0", False, False),  # an upgrade
        (None, False, False),  # nothing answers: a fresh host
    ],
)
def test_main_refuses_a_pin_older_than_the_running_release(tmp_path, pki, running, allow, refused):
    if running is None:
        with listener() as port:  # accepts TCP, never answers
            v = hook_vars(tmp_path, pki, f"https://{LOOPBACK}:{port}", openbao_health_timeout=2)
            r = run_role(tmp_path, ROLE, "downgrade", v)
    else:
        with fake_openbao(pki, 200, dict(ACTIVE, version=running)) as url:
            v = hook_vars(tmp_path, pki, url, openbao_allow_downgrade=allow)
            r = run_role(tmp_path, ROLE, "downgrade", v)
    if refused:
        assert r.returncode != 0 and "the server runs 2.8.0 and the pin" in r.stdout, r.stdout
    else:
        assert r.returncode == 0, r.stdout + r.stderr


def test_upgrade_refuses_a_target_older_than_the_running_release(tmp_path, pki):
    with fake_api(pki, dict(ACTIVE, version="2.9.0")) as (url, api):
        v = snap_vars(tmp_path, pki, url, openbao_snapshot_token=TOKEN)
        v.update(
            {"openbao_target_version": "2.8.0", "openbao_target_checksums": {"amd64": "a" * 64}}
        )
        r = run_role(tmp_path, ROLE, "upgrade", v)
    assert r.returncode != 0 and "the server runs 2.9.0" in r.stdout, r.stdout
    assert [q for q in api.requests if q[1] != "/v1/sys/health"] == []


# ---------------------------------------------------------------- the playbook


def test_the_playbook_runs_only_the_seven_entry_points(tmp_path):
    inv = tmp_path / "inv.ini"
    inv.write_text("[cap_secrets]\nlocalhost ansible_connection=local\n")
    root = Path(__file__).resolve().parents[2]
    env = dict(os.environ, ANSIBLE_CONFIG=str(root / "ansible/ansible.cfg"),
               ANSIBLE_HOME=str(tmp_path / ".ansible"), ANSIBLE_NOCOLOR="1")  # fmt: skip

    def play(*extra):
        return subprocess.run(
            ["ansible-playbook", "-i", str(inv), str(root / "ansible/playbooks/openbao.yml"),
             "-e", "ansible_become=false", "-e", f"ansible_python_interpreter={sys.executable}",
             *extra],
            capture_output=True, text=True, env=env, cwd=tmp_path,
        )  # fmt: skip

    for hook in ("snapshot", "validate", "service"):
        r = play("-e", f"openbao_hook={hook}")
        assert r.returncode != 0, r.stdout
        assert f"export (not {hook})" in r.stdout, r.stdout
    # no hook named: main, which gets past the gate (and fails later on its missing inputs)
    r = play()
    assert "Refuse a hook that is not one of the role's entry points" in r.stdout
    assert "All assertions passed" in r.stdout or "ok: [localhost]" in r.stdout, r.stdout
    assert "openbao_hook is one of" not in r.stdout


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
def fake_openbao(pki, status: int, body: dict, api=None):
    """sys/health as the server answers it: ``status`` without the query, 200 with it; and,
    with ``api`` (an :class:`Api`), the snapshot and login endpoints."""

    class Handler(http.server.BaseHTTPRequestHandler):
        def reply(self, code, payload):
            raw = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
            ctype = "application/octet-stream" if isinstance(payload, bytes) else "application/json"
            self.send_response(code)
            if payload is not None:
                self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(raw) if payload is not None else 0))
            self.end_headers()
            if payload is not None:
                self.wfile.write(raw)

        def do_GET(self):
            if self.path.startswith("/v1/sys/health"):
                if api is not None:
                    api.requests.append(("GET", "/v1/sys/health", "nobody"))
                return self.reply(200 if "sealedcode=200" in self.path else status, body)
            if api is None:
                return self.reply(404, {"errors": []})
            return self.reply(*api.handle(self, "GET"))

        def do_HEAD(self):  # a release mirror, asked whether the archive is there (get_url --check)
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def do_POST(self):
            if api is None:
                return self.reply(404, {"errors": []})
            return self.reply(*api.handle(self, "POST"))

        def log_message(self, *a):
            pass

    srv = http.server.ThreadingHTTPServer((LOOPBACK, 0), Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
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


def test_health_passes_but_warns_while_a_restart_is_owed(tmp_path, pki):
    with fake_openbao(pki, 200, ACTIVE) as url:
        v = hook_vars(tmp_path, pki, url)
        (tmp_path / "state").mkdir()
        (tmp_path / "state" / "restart-owed").write_text('{"reasons": ["release", "unit"]}\n')
        r = run_role(tmp_path, ROLE, "health", v)
        (tmp_path / "state" / "restart-owed").unlink()
        quiet = run_role(tmp_path, ROLE, "health", v)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "WARN openbao secrets: a restart is owed (release, unit)" in r.stdout
    assert quiet.returncode == 0 and "WARN" not in quiet.stdout


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

TOKEN = "s.fake-snapshot-token-0123456789"  # the snapshot principal's (read only)
RESTORE_TOKEN = "s.fake-restore-token-9876543210"  # the restore principal's
ROLE_ID = "fake-role-id-1111"
SECRET_ID = "fake-secret-id-2222-never-shown"
MINTED = "s.fake-minted-by-approle-login-3333"
SNAP = b"raft-snapshot-bytes"
SECRETS = (TOKEN, RESTORE_TOKEN, SECRET_ID, MINTED)


class Api:
    """The snapshot endpoints as the server answers them, with the split principals: the
    snapshot tokens (handed in, or minted by the AppRole login) may only read a snapshot, the
    restore token may only post one. Every request is recorded as (method, path, who)."""

    def __init__(self):
        self.requests: list[tuple[str, str, str]] = []
        self.restored: list[tuple[str, bytes]] = []
        self.save_fails = False  # the server fails the save mid-stream (an internal error)

    def who(self, h) -> str:
        return {TOKEN: "snapshot", MINTED: "minted", RESTORE_TOKEN: "restore"}.get(
            h.headers.get("X-Vault-Token", ""), "nobody"
        )

    def handle(self, h, method):
        path = h.path.split("?")[0]
        who = self.who(h)
        self.requests.append((method, path, who))
        n = int(h.headers.get("Content-Length") or 0)
        data = h.rfile.read(n) if n else b""
        if method == "POST" and path == "/v1/auth/approle/login":
            ok = json.loads(data) == {"role_id": ROLE_ID, "secret_id": SECRET_ID}
            return (200, {"auth": {"client_token": MINTED}}) if ok else (400, {"errors": ["x"]})
        if method == "GET" and path == "/v1/sys/storage/raft/snapshot" and self.save_fails:
            return 500, {"errors": ["internal error"]}
        if method == "GET" and path == "/v1/sys/storage/raft/snapshot":
            return (200, SNAP) if who in ("snapshot", "minted") else (403, {"errors": ["denied"]})
        if method == "POST" and path.startswith("/v1/sys/storage/raft/snapshot"):
            if who != "restore":
                return 403, {"errors": ["permission denied"]}
            self.restored.append((path.rsplit("/", 1)[1], data))
            return 204, None
        if method == "POST" and path == "/v1/auth/token/revoke-self":
            return (204, None) if who == "minted" else (403, {"errors": ["x"]})
        return 404, {"errors": []}


@contextmanager
def fake_api(pki, body=None):
    """The fake server with the snapshot endpoints; yields (url, api)."""
    api = Api()
    with fake_openbao(pki, 200, body or ACTIVE, api) as url:
        yield url, api


def snap_vars(tmp_path, pki, url, **kw):
    return hook_vars(tmp_path, pki, url, **kw)


@pytest.mark.parametrize(
    ("hook", "dirname", "name"),
    [("backup", "backup", "raft.snap"), ("export", "export", "secrets.snap")],
)
def test_snapshot_hooks_write_the_snapshot_and_a_manifest_naming_its_writer(
    tmp_path, pki, hook, dirname, name
):
    with fake_api(pki) as (url, api):
        r = run_role(
            tmp_path, ROLE, hook, snap_vars(tmp_path, pki, url, openbao_snapshot_token=TOKEN)
        )
    assert r.returncode == 0, r.stdout + r.stderr
    assert not any(x in r.stdout + r.stderr for x in SECRETS)
    assert ("GET", "/v1/sys/storage/raft/snapshot", "snapshot") in api.requests
    assert not api.restored
    snap = tmp_path / dirname / name
    assert snap.read_bytes() == SNAP
    assert oct(snap.stat().st_mode & 0o777) == "0o600"
    assert not snap.with_name(name + ".partial").exists()
    manifest = json.loads(snap.with_name(name + ".json").read_text())
    assert manifest["written_by"] == "2.7.1" and manifest["kind"] == "raft-snapshot"
    assert manifest["sha256"] == hashlib.sha256(SNAP).hexdigest()
    assert manifest["bytes"] == len(SNAP) and manifest["service"] == "secrets"
    assert "not an open format" in manifest["format"]
    assert oct((tmp_path / dirname).stat().st_mode & 0o777) == "0o700"
    if hook == "export":
        assert "not an open format" in r.stdout and "hnx secrets plan" in r.stdout


def test_a_snapshot_logs_in_with_the_approle_and_revokes_the_token_it_minted(tmp_path, pki):
    with fake_api(pki) as (url, api):
        v = snap_vars(
            tmp_path, pki, url,
            openbao_snapshot_approle_role_id=ROLE_ID, openbao_snapshot_approle_secret_id=SECRET_ID,
        )  # fmt: skip
        r = run_role(tmp_path, ROLE, "backup", v)
    assert r.returncode == 0, r.stdout + r.stderr
    assert not any(x in r.stdout + r.stderr for x in SECRETS)
    assert [q for q in api.requests if q[1] != "/v1/sys/health"] == [
        ("POST", "/v1/auth/approle/login", "nobody"),
        ("GET", "/v1/sys/storage/raft/snapshot", "minted"),
        ("POST", "/v1/auth/token/revoke-self", "minted"),
    ]


def test_a_failed_snapshot_leaves_no_partial_file_and_still_revokes(tmp_path, pki):
    with fake_api(pki) as (url, api):
        # a token the server refuses: the save fails, the partial file goes, the run fails
        v = snap_vars(tmp_path, pki, url, openbao_snapshot_token="s.not-a-snapshot-token")
        r = run_role(tmp_path, ROLE, "backup", v)
        assert r.returncode != 0
        assert list((tmp_path / "backup").iterdir()) == []
        # the AppRole path: the minted token is revoked even though the save failed
        api.requests.clear()
        api.save_fails = True
        v = snap_vars(
            tmp_path, pki, url,
            openbao_snapshot_approle_role_id=ROLE_ID, openbao_snapshot_approle_secret_id=SECRET_ID,
        )  # fmt: skip
        r = run_role(tmp_path, ROLE, "backup", v)
    assert r.returncode != 0
    assert list((tmp_path / "backup").iterdir()) == []
    assert ("POST", "/v1/auth/token/revoke-self", "minted") in api.requests
    assert not any(x in r.stdout + r.stderr for x in SECRETS)


def test_a_snapshot_needs_the_snapshot_principal(tmp_path, pki):
    with fake_api(pki) as (url, api):
        v = snap_vars(tmp_path, pki, url)
        missing = run_role(tmp_path, ROLE, "backup", v)
        half = run_role(tmp_path, ROLE, "backup", dict(v, openbao_snapshot_approle_role_id=ROLE_ID))
    for r in (missing, half):
        assert r.returncode != 0 and "needs the snapshot principal" in r.stdout, r.stdout
    assert [q for q in api.requests if q[1] != "/v1/sys/health"] == []


def verbose_run(tmp_path, hook, v):
    """run_role at -vvv: what an operator debugging a run would see (module arguments included,
    where a task is not under no_log, and every remote command line)."""
    cmd, env = _invocation(tmp_path, ROLE, hook, v)
    return subprocess.run([*cmd, "-vvv"], capture_output=True, text=True, env=env, cwd=tmp_path)


def test_no_token_reaches_a_command_line_or_the_output_even_at_vvv(tmp_path, pki):
    """The tokens travel in uri headers under no_log. At -vvv Ansible prints every remote command
    line (where an `environment:` token used to appear: BAO_TOKEN=... python3 AnsiballZ_...) and
    every module invocation not under no_log: none of them may carry a token or the secret_id."""
    src = tmp_path / "in" / "raft.snap"
    src.parent.mkdir()
    src.write_bytes(SNAP)
    src.with_name("raft.snap.json").write_text(
        json.dumps({"kind": "raft-snapshot", "sha256": hashlib.sha256(SNAP).hexdigest(), "written_by": "2.7.1"})
    )  # fmt: skip
    with fake_api(pki) as (url, api):
        runs = [
            verbose_run(tmp_path, "backup", snap_vars(tmp_path, pki, url, openbao_snapshot_token=TOKEN)),
            verbose_run(tmp_path, "backup", snap_vars(
                tmp_path, pki, url,
                openbao_snapshot_approle_role_id=ROLE_ID, openbao_snapshot_approle_secret_id=SECRET_ID)),
            verbose_run(tmp_path, "restore", snap_vars(
                tmp_path, pki, url, openbao_snapshot_token=TOKEN, openbao_restore_token=RESTORE_TOKEN,
                openbao_restore_source=str(src))),
        ]  # fmt: skip
    for r in runs:
        assert r.returncode == 0, r.stdout[-3000:] + r.stderr
        assert "EXEC" in r.stdout and "AnsiballZ_uri.py" in r.stdout  # really -vvv
        assert not [x for x in SECRETS if x in r.stdout + r.stderr]
        assert "BAO_TOKEN" not in r.stdout + r.stderr
    assert api.restored == [("snapshot", SNAP)]


# ---------------------------------------------------------------- restore


def restore_case(tmp_path, *, manifest="good", data=SNAP):
    src = tmp_path / "in" / "raft.snap"
    src.parent.mkdir(exist_ok=True)
    src.write_bytes(data)
    m = {"kind": "raft-snapshot", "sha256": hashlib.sha256(SNAP).hexdigest(), "written_by": "2.7.1"}
    if manifest == "newer":
        m["written_by"] = "2.8.0"
    if manifest != "missing":
        src.with_name("raft.snap.json").write_text(json.dumps(m))
    return src


@pytest.mark.parametrize("force", [False, True])
def test_restore_checks_the_manifest_takes_a_pre_restore_snapshot_then_restores(
    tmp_path, pki, force
):
    src = restore_case(tmp_path)
    with fake_api(pki) as (url, api):
        v = snap_vars(
            tmp_path, pki, url, openbao_snapshot_token=TOKEN, openbao_restore_token=RESTORE_TOKEN,
            openbao_restore_source=str(src), openbao_restore_force=force,
        )  # fmt: skip
        r = run_role(tmp_path, ROLE, "restore", v)
    assert r.returncode == 0, r.stdout + r.stderr
    assert not any(x in r.stdout + r.stderr for x in SECRETS)
    calls_ = [q for q in api.requests if q[1] != "/v1/sys/health"]
    endpoint = "snapshot-force" if force else "snapshot"
    # the pre-restore snapshot (snapshot principal) comes first, then the restore (restore principal)
    assert calls_ == [
        ("GET", "/v1/sys/storage/raft/snapshot", "snapshot"),
        ("POST", f"/v1/sys/storage/raft/{endpoint}", "restore"),
    ]
    assert api.restored == [(endpoint, SNAP)]
    (pre,) = (tmp_path / "backup").glob("pre-restore-*.snap")
    assert re.fullmatch(r"pre-restore-\d{8}T\d{6}Z\.snap", pre.name)
    assert pre.read_bytes() == SNAP and json.loads(pre.with_name(pre.name + ".json").read_text())
    assert f"the state before it is in {tmp_path}/backup/{pre.name}" in r.stdout


@pytest.mark.parametrize(
    ("case", "says"),
    [
        ({"manifest": "missing"}, "the snapshot's manifest, is missing"),
        ({"data": b"tampered-snapshot-bytes"}, "is not the one in its manifest"),
        ({"manifest": "newer"}, "release 2.8.0 wrote it and 2.7.1 runs"),
    ],
)
def test_restore_refuses_a_snapshot_without_a_matching_manifest_or_from_a_newer_release(
    tmp_path, pki, case, says
):
    src = restore_case(tmp_path, **case)
    with fake_api(pki) as (url, api):
        v = snap_vars(
            tmp_path, pki, url, openbao_snapshot_token=TOKEN, openbao_restore_token=RESTORE_TOKEN,
            openbao_restore_source=str(src),
        )  # fmt: skip
        r = run_role(tmp_path, ROLE, "restore", v)
    assert r.returncode != 0 and says in r.stdout, r.stdout
    assert [q for q in api.requests if q[1] != "/v1/sys/health"] == []  # no snapshot, no restore
    assert not (tmp_path / "backup").exists()


def test_restore_needs_the_restore_principal_not_the_snapshot_one(tmp_path, pki):
    src = restore_case(tmp_path)
    with fake_api(pki) as (url, api):
        v = snap_vars(
            tmp_path, pki, url, openbao_snapshot_token=TOKEN, openbao_restore_source=str(src)
        )
        missing = run_role(tmp_path, ROLE, "restore", v)
        same = run_role(tmp_path, ROLE, "restore", dict(v, openbao_restore_token=TOKEN))
        # a token that differs but is still only a snapshot principal's: the server refuses it
        other = run_role(
            tmp_path, ROLE, "restore",
            dict(v, openbao_restore_token=MINTED, openbao_snapshot_approle_role_id=ROLE_ID,
                 openbao_snapshot_approle_secret_id=SECRET_ID, openbao_snapshot_token=""),
        )  # fmt: skip
    assert missing.returncode != 0 and "openbao_restore_token" in missing.stdout
    assert same.returncode != 0 and "never the snapshot principal" in same.stdout, same.stdout
    assert other.returncode != 0
    assert api.restored == []
    assert ("POST", "/v1/sys/storage/raft/snapshot", "minted") in api.requests  # refused: 403


def test_restore_refuses_a_missing_or_empty_snapshot(tmp_path, pki):
    (tmp_path / "empty.snap").write_bytes(b"")
    with fake_api(pki) as (url, api):
        for src in (tmp_path / "missing.snap", tmp_path / "empty.snap"):
            v = snap_vars(
                tmp_path, pki, url, openbao_snapshot_token=TOKEN,
                openbao_restore_token=RESTORE_TOKEN, openbao_restore_source=str(src),
            )  # fmt: skip
            r = run_role(tmp_path, ROLE, "restore", v)
            assert r.returncode != 0 and "not a non-empty snapshot file" in r.stdout
    assert [q for q in api.requests if q[1] != "/v1/sys/health"] == []


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
    with fake_api(pki) as (url, api):
        v = snap_vars(tmp_path, pki, url, openbao_snapshot_token=TOKEN)
        v.update(
            {"openbao_target_version": "2.7.2", "openbao_target_checksums": {"amd64": "a" * 64}}
        )
        v.update(target)
        r = run_role(tmp_path, ROLE, "upgrade", v)
    assert r.returncode != 0 and "is not a release newer than" in r.stdout, r.stdout
    assert [q for q in api.requests if q[1] != "/v1/sys/health"] == []  # before the snapshot


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
