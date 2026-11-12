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
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
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
    {"openbao_checksums_release": "2.7.0"},
    {"openbao_tls_source": "letsencrypt"},
]

# openbao_tls_source: acme, over the provided-PEM base (validate needs the PEMs gone)
ACME = {
    "openbao_tls_source": "acme",
    "openbao_tls_cert_pem": "",
    "openbao_tls_private_key_pem": "",
    "openbao_tls_ca_pem": "",
    "openbao_acme_domains": [HOST],
    "openbao_acme_dns_token_ref": "secret:dns/token",
}
ACME_BAD = [
    {"openbao_tls_cert_pem": CERT_PEM},  # supplied PEMs beside ACME
    {"openbao_tls_selfsigned_for_tests": True, "openbao_tls_selfsigned_confirm_throwaway": True},
    {"openbao_acme_domains": []},
    {"openbao_acme_domains": "secrets-01.example.internal"},  # a string, not a list
    {"openbao_acme_domains": ["other.example.internal"]},  # the api host is not on it
    {"openbao_acme_domains": [HOST, "*.example.internal"]},  # no wildcard
    {"openbao_acme_domains": [HOST, HOST]},
    {"openbao_acme_domains": [HOST.upper()]},
    {"openbao_acme_dns_token_ref": ""},
    {"openbao_acme_dns_token_ref": "dns/token"},  # a value, not a reference
    {"openbao_acme_dns_provider": "route53"},
    {"openbao_acme_server": "http://acme.example.internal/directory"},
    {"openbao_acme_email": "a b@example.internal"},
    {"openbao_acme_propagation_wait": "30"},
    {"openbao_acme_propagation_wait": "0s"},
    {"openbao_acme_renew_days": 46},  # past the cap: a reissue loop on a shorter-lived certificate
    {"openbao_acme_email": "-x@example.internal"},
    {"openbao_acme_dir": "/var/lib/acme%n"},
    {"openbao_acme_health_min_days": 30},  # not below renew_days
    {"openbao_acme_key_type": "ec256"},
    {"openbao_acme_schedule": "daily"},
    {"openbao_acme_schedule": "*-*-* 03:17:00\nExecStart=/bin/sh UTC"},
    {"openbao_acme_on_failure": "page.service\nExecStart=/bin/sh"},
    {"openbao_acme_on_failure": "page"},
    {"openbao_acme_dir": "/var/lib"},
    {"openbao_lego_version": "5.6"},
    {"openbao_lego_checksums": {"amd64": "0" * 63}},
    {"openbao_lego_checksums_release": "5.5.2"},
    {"openbao_lego_release_repository": "http://mirror.example.internal/lego"},
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
    good.append(dict(ACME, openbao_acme_email="ops@example.internal",
                     openbao_acme_on_failure="hnx-page@%n.service"))  # fmt: skip
    bad = BAD + [dict(ACME, **b) for b in ACME_BAD]
    got = run_cases(tmp_path, ROLE, "validate", base(tmp_path), good + bad, parallel=True)
    for over, (failed, msg) in zip(good, got[: len(good)], strict=True):
        assert not failed, (over, msg)
    for over, (failed, msg) in zip(bad, got[len(good) :], strict=True):
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
    # what service.yml asks after the start (release_seen.yml): a refused port, not a DNS lookup
    kw.setdefault("openbao_api_addr", f"https://{LOOPBACK}:{closed_port()}")
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
        assert r.returncode != 0 and "older than what this host has run (running 2.8.0" in r.stdout
        assert "BOTH the restore" in r.stdout and "openbao_allow_downgrade: true" in r.stdout
    else:
        assert r.returncode == 0, r.stdout + r.stderr


def closed_port() -> int:
    """A loopback port nothing listens on: a request to it is refused at once."""
    with socket.socket() as sock:
        sock.bind((LOOPBACK, 0))
        return sock.getsockname()[1]


OLDER = "the pin is 2.7.1, older than what this host has run ("
NOT_A_RECORD = "highest-release is not a release record; remove or fix it"
STOPPED = [
    # (the release the command points at, the record's content, allow, refused with)
    ("2.8.0", None, False, OLDER + "linked 2.8.0"),  # the command points at a newer release
    (None, "2.8.0", False, OLDER + "recorded 2.8.0"),  # a newer release answered here once
    ("2.8.0", "2.9.0", True, None),  # the operator's explicit downgrade
    ("2.7.1", "2.7.1", False, None),  # the pin itself
    ("2.7.0", "2.7.0", False, None),  # an upgrade
    (None, None, False, None),  # a fresh host
    # a record that is not one fails by name, never read as "nothing recorded"
    (None, "not json at all", False, NOT_A_RECORD),
    (None, '{"version": "2.8"}', False, NOT_A_RECORD),
    (
        None,
        '{"version": "2.8.0", "by": "someone"}',
        True,
        NOT_A_RECORD,
    ),  # the switch waives no check
    (None, "", False, NOT_A_RECORD),
]


def test_a_stopped_server_does_not_let_a_lower_pin_through(tmp_path, pki):
    """sys/health says nothing while the server is stopped: the link and the record still do.
    One process for every case (run_cases); each case has its own link and state directory."""
    v = hook_vars(tmp_path, pki, f"https://{LOOPBACK}:{closed_port()}", openbao_health_timeout=2)
    cases = []
    for i, (linked, recorded, allow, _) in enumerate(STOPPED):
        d = tmp_path / f"case{i}"
        (d / "state").mkdir(parents=True)
        if linked:
            target = d / "opt" / linked / "bao"
            target.parent.mkdir(parents=True)
            target.write_text("")
            (d / "bao").symlink_to(target)
        if recorded is not None:
            plain = re.fullmatch(r"\d+\.\d+\.\d+", recorded)
            (d / "state" / "highest-release").write_text(
                json.dumps({"version": recorded}) if plain else recorded
            )
        cases.append(
            {"openbao_bin": str(d / "bao"), "openbao_state_dir": str(d / "state"),
             "openbao_allow_downgrade": allow}
        )  # fmt: skip
    got = run_cases(tmp_path, ROLE, "downgrade", v, cases)
    for (failed, message), (*_, refused) in zip(got, STOPPED, strict=True):
        if refused:
            assert failed and refused in message, (refused, message)
        else:
            assert not failed, message


def record(tmp_path):
    f = tmp_path / "state" / "highest-release"
    return json.loads(f.read_text())["version"] if f.exists() else None


def test_main_records_the_release_that_answered_and_an_explicit_rollback_lowers_it(tmp_path, pki):
    """main (service.yml, after the start) raises the record; health writes nothing (role
    interface v1: health changes no state). A rollback run (the pin answering, with
    openbao_allow_downgrade) lowers the record to the pin, so the next routine main passes without
    the switch; without the switch, an older release answering never lowers it."""
    with (
        fake_openbao(pki, 200, dict(ACTIVE, version="2.8.0")) as newer,
        fake_openbao(pki, 200, ACTIVE) as pinned,  # 2.7.1, the pin
    ):
        port = int(newer.rsplit(":", 1)[1])  # something listening for the service step's wait

        def service(url, **kw):
            v = service_vars(tmp_path, port, active=False, openbao_api_addr=url, **kw)
            return run_service(tmp_path, v, changed=False)

        def downgrade(url):
            return run_role(tmp_path, ROLE, "downgrade", hook_vars(tmp_path, pki, url))

        health = run_role(tmp_path, ROLE, "health", hook_vars(tmp_path, pki, newer))
        assert record(tmp_path) is None, health.stdout  # health recorded nothing
        steps = [
            (newer, {}, "2.8.0"),  # raised
            (pinned, {}, "2.8.0"),  # an older release answering, no switch: kept
            (pinned, {"openbao_allow_downgrade": True}, "2.7.1"),  # the explicit rollback
        ]
        for url, kw, want in steps:
            r = service(url, **kw)
            assert r.returncode == 0, (want, r.stdout + r.stderr)
            assert record(tmp_path) == want, (want, record(tmp_path))
        after = downgrade(pinned)  # the next routine main, without the switch
        assert after.returncode == 0, after.stdout + after.stderr
        # the switch with a newer release still answering (no restart made): the record stays
        r = service(newer, openbao_allow_downgrade=True)
        assert r.returncode == 0 and record(tmp_path) == "2.8.0", r.stdout
        (tmp_path / "state" / "highest-release").write_text("{oops")
        corrupt = service(pinned)
    assert corrupt.returncode != 0 and NOT_A_RECORD in corrupt.stdout, corrupt.stdout
    assert (tmp_path / "state" / "highest-release").read_text() == "{oops"  # never written over


def test_upgrade_refuses_a_target_older_than_the_running_release(tmp_path, pki):
    with fake_api(pki, dict(ACTIVE, version="2.9.0")) as (url, api):
        v = snap_vars(tmp_path, pki, url, openbao_snapshot_token=TOKEN)
        v.update(
            {"openbao_target_version": "2.8.0", "openbao_target_checksums": {"amd64": "a" * 64}}
        )
        r = run_role(tmp_path, ROLE, "upgrade", v)
    assert r.returncode != 0 and "older than what this host has run (running 2.9.0" in r.stdout, (
        r.stdout
    )
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
    assert list((tmp_path / "state").iterdir()) == []  # health changes nothing (role interface v1)


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
UNKNOWN = "s.fake-revoked-or-expired-4444"  # a token the server does not know
# restore-principal tokens minted wrongly (what lookup-self answers for each: Api.LOOKUP)
ODD_TOKENS = {
    "s.fake-restore-identity-5555": "identity",  # carries identity policies
    "s.fake-restore-unlimited-6666": "unlimited",  # no use limit
    "s.fake-restore-long-ttl-7777": "long",  # a TTL over 15 minutes
    "s.fake-restore-odd-policy-8888": "odd",  # a policy name a message must not print
    "s.fake-restore-spare-use-9999": "spare",  # -use-limit=3: a use would be left after the POST
}
ODD_POLICY = "evil\n{{ name }} <x>"
SNAP = b"raft-snapshot-bytes"
SECRETS = (TOKEN, RESTORE_TOKEN, SECRET_ID, MINTED)
# openbao_snapshot_approle_secret_id_ref (the overlay's secret:openbao/snapshot-secret-id) resolves
# through hnx_secret; without BAO_ADDR its backend is this environment variable
APPROLE_ENV = {"HNX_SECRET_OPENBAO_SNAPSHOT_SECRET_ID": SECRET_ID}
APPROLE = {
    "openbao_snapshot_approle_role_id": ROLE_ID,
    "openbao_snapshot_approle_secret_id_ref": "secret:openbao/snapshot-secret-id",
}


# what lookup-self answers, per principal (a restore token as README.md mints it, after a use)
LOOKUP = {
    "restore": {"policies": ["default", "hnx-restore"], "num_uses": 1, "ttl": 899},
    "minted": {"policies": ["default", "hnx-snapshot"], "num_uses": 1, "ttl": 299},
    "snapshot": {"policies": ["hnx-snapshot"], "num_uses": 0, "ttl": 600},
    "identity": {"policies": ["default", "hnx-restore"], "identity_policies": ["admin"],
                 "num_uses": 1, "ttl": 899},
    "unlimited": {"policies": ["default", "hnx-restore"], "num_uses": 0, "ttl": 899},
    "long": {"policies": ["default", "hnx-restore"], "num_uses": 1, "ttl": 86400},
    "odd": {"policies": ["default", "hnx-restore", ODD_POLICY], "num_uses": 1, "ttl": 899},
    "spare": {"policies": ["default", "hnx-restore"], "num_uses": 2, "ttl": 899},
}  # fmt: skip


class Api:
    """The snapshot endpoints as the server answers them, with the split principals: the
    snapshot tokens (handed in, or minted by the AppRole login) may only read a snapshot, the
    restore token may only post one. Every request is recorded as (method, path, who)."""

    def __init__(self):
        self.requests: list[tuple[str, str, str]] = []
        self.restored: list[tuple[str, bytes]] = []
        self.save_fails = False  # the server fails the save mid-stream (an internal error)
        self.on_save = None  # called before a snapshot is served (the swap test mutates a file)
        self.restore_fails = False  # the server fails the restore POST (it may have landed)
        self.revoke_status = None  # what revoke-self answers instead (503: sealed)

    def who(self, h) -> str:
        tokens = {TOKEN: "snapshot", MINTED: "minted", RESTORE_TOKEN: "restore", **ODD_TOKENS}
        return tokens.get(h.headers.get("X-Vault-Token", ""), "nobody")

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
            if who in ("snapshot", "minted") and self.on_save:
                self.on_save()
            return (200, SNAP) if who in ("snapshot", "minted") else (403, {"errors": ["denied"]})
        if method == "GET" and path == "/v1/auth/token/lookup-self":
            data = LOOKUP.get(who)
            return (
                (200, {"data": {"identity_policies": None, **data}})
                if data
                else (403, {"errors": ["x"]})
            )
        if method == "POST" and path.startswith("/v1/sys/storage/raft/snapshot"):
            if who != "restore":
                return 403, {"errors": ["permission denied"]}
            if self.restore_fails:
                return 500, {"errors": ["internal error"]}
            self.restored.append((path.rsplit("/", 1)[1], data))
            return 204, None
        if method == "POST" and path == "/v1/auth/token/revoke-self" and self.revoke_status:
            return self.revoke_status, {"errors": ["Vault is sealed"]}
        if method == "POST" and path == "/v1/auth/token/revoke-self":
            return (204, None) if who in ("minted", "restore") else (403, {"errors": ["x"]})
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
        v = snap_vars(tmp_path, pki, url, **APPROLE)
        r = run_role(tmp_path, ROLE, "backup", v, env=APPROLE_ENV)
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
        v = snap_vars(tmp_path, pki, url, **APPROLE)
        r = run_role(tmp_path, ROLE, "backup", v, env=APPROLE_ENV)
    assert r.returncode != 0
    assert list((tmp_path / "backup").iterdir()) == []
    assert ("POST", "/v1/auth/token/revoke-self", "minted") in api.requests
    assert not any(x in r.stdout + r.stderr for x in SECRETS)


def test_a_snapshot_needs_the_snapshot_principal(tmp_path, pki):
    with fake_api(pki) as (url, api):
        v = snap_vars(tmp_path, pki, url)
        missing = run_role(tmp_path, ROLE, "backup", v)
        no_ref = dict(v, **APPROLE)
        half = run_role(
            tmp_path, ROLE, "backup", dict(no_ref, openbao_snapshot_approle_secret_id_ref="")
        )
        raw = run_role(
            tmp_path, ROLE, "backup", dict(no_ref, openbao_snapshot_approle_secret_id_ref=SECRET_ID)
        )
    for r in (missing, half, raw):  # a value where the reference goes is refused, never sent
        assert r.returncode != 0 and "needs the snapshot principal" in r.stdout, r.stdout
    assert [q for q in api.requests if q[1] != "/v1/sys/health"] == []


def verbose_run(tmp_path, hook, v, env=None):
    """run_role at -vvv: what an operator debugging a run would see (module arguments included,
    where a task is not under no_log, and every remote command line)."""
    cmd, env = _invocation(tmp_path, ROLE, hook, v, env)
    return subprocess.run([*cmd, "-vvv"], capture_output=True, text=True, env=env, cwd=tmp_path)


def test_no_token_reaches_a_command_line_or_the_output_even_at_vvv(tmp_path, pki):
    """The tokens travel in uri headers under no_log. At -vvv Ansible prints every remote command
    line (where an `environment:` token used to appear: BAO_TOKEN=... python3 AnsiballZ_...) and
    every module invocation not under no_log: none of them may carry a token or the secret_id."""
    src = tmp_path / "export" / "raft.snap"
    src.parent.mkdir()
    src.write_bytes(SNAP)
    src.with_name("raft.snap.json").write_text(
        json.dumps({"kind": "raft-snapshot", "sha256": hashlib.sha256(SNAP).hexdigest(), "written_by": "2.7.1"})
    )  # fmt: skip
    with fake_api(pki) as (url, api):
        runs = [
            verbose_run(tmp_path, "backup", snap_vars(tmp_path, pki, url, openbao_snapshot_token=TOKEN)),
            verbose_run(tmp_path, "backup", snap_vars(
                tmp_path, pki, url, **APPROLE), env=APPROLE_ENV),
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
    src = tmp_path / "export" / "raft.snap"  # under openbao_export_dir
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
    stale = tmp_path / "backup" / ".restore-staging-killed"  # what a killed run left, a day ago
    running = tmp_path / "backup" / ".restore-staging-running"  # a concurrent restore's, just made
    for d in (stale, running):
        d.mkdir(parents=True)
        (d / "raft.snap").write_bytes(SNAP)
        d.chmod(0o700)
    os.utime(stale, (stale.stat().st_atime - 86400, stale.stat().st_mtime - 86400))
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
    # who the restore token is, the pre-restore snapshot (snapshot principal), then the restore
    assert calls_ == [
        ("GET", "/v1/auth/token/lookup-self", "restore"),
        ("GET", "/v1/sys/storage/raft/snapshot", "snapshot"),
        ("POST", f"/v1/sys/storage/raft/{endpoint}", "restore"),
    ]
    assert api.restored == [(endpoint, SNAP)]
    (pre,) = (tmp_path / "backup").glob("pre-restore-*.snap")
    assert re.fullmatch(r"pre-restore-\d{8}T\d{6}Z\.snap", pre.name)
    assert pre.read_bytes() == SNAP and json.loads(pre.with_name(pre.name + ".json").read_text())
    assert f"the state before it is in {tmp_path}/backup/{pre.name}" in r.stdout
    # the staged and the stale copies are gone; a concurrent restore's (younger than
    # 2 x openbao_snapshot_timeout + 10 x openbao_health_timeout) is left alone
    assert list((tmp_path / "backup").glob(".restore-staging-*")) == [running]


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
    # no lookup-self (the token is not spent on a restore a local check refuses), no snapshot,
    # no restore
    assert [q for q in api.requests if q[1] != "/v1/sys/health"] == []
    backup = tmp_path / "backup"
    assert not backup.exists() or list(backup.iterdir()) == []  # the staged copy is gone too


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
            dict(v, openbao_restore_token=MINTED, openbao_snapshot_token="", **APPROLE),
        )  # fmt: skip
    assert missing.returncode != 0 and "openbao_restore_token" in missing.stdout
    assert same.returncode != 0 and "never the snapshot principal" in same.stdout, same.stdout
    # the server says whose it is: hnx-snapshot, so it never reaches the restore endpoint
    # (only default and hnx-restore are ever named: anything else is counted)
    assert other.returncode != 0 and "its policies are default and 1 other)" in other.stdout
    assert api.restored == []
    assert [q for q in api.requests if q[0] == "POST" and "raft" in q[1]] == []


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
    assert [q for q in api.requests if "/raft/" in q[1]] == []


def restore_vars(tmp_path, pki, url, src, **kw):
    v = {"openbao_snapshot_token": TOKEN, "openbao_restore_token": RESTORE_TOKEN,
         "openbao_restore_source": str(src)}  # fmt: skip
    return snap_vars(tmp_path, pki, url, **{**v, **kw})


def test_the_bytes_restored_are_the_bytes_checked_even_if_the_source_is_swapped(tmp_path, pki):
    """The source is copied into a root-only staging directory before it is hashed, and that copy
    is what is posted: a source rewritten after the check (here: while the pre-restore snapshot is
    taken, between the check and the restore) never reaches the server."""
    src = restore_case(tmp_path)
    with fake_api(pki) as (url, api):
        api.on_save = lambda: src.write_bytes(b"swapped-after-the-check")
        r = run_role(tmp_path, ROLE, "restore", restore_vars(tmp_path, pki, url, src))
    assert r.returncode == 0, r.stdout + r.stderr
    assert src.read_bytes() == b"swapped-after-the-check"  # the swap really happened
    assert api.restored == [("snapshot", SNAP)]  # ...and what was posted is what was hashed
    assert not list((tmp_path / "backup").glob(".restore-staging-*"))


CP_THEN_TOUCH = r"""
import os, subprocess, sys
p = subprocess.run(["/bin/cp", *sys.argv[1:]])
src = sys.argv[-2]
if src.endswith(".snap"):  # the source is rewritten while it is copied: same bytes, a new mtime
    os.utime(src, (1, 1))
sys.exit(p.returncode)
"""


def test_a_source_changed_while_it_is_copied_is_refused(tmp_path, pki):
    """The source is stat'ed again after the copy: a change between the checks and the copy (here:
    a cp that touches it once it has copied) is refused before the token is spent."""
    src = restore_case(tmp_path)
    (tmp_path / "bin").mkdir()
    fake(tmp_path / "bin" / "cp", CP_THEN_TOUCH)
    env = {"PATH": f"{tmp_path / 'bin'}:{os.environ['PATH']}"}
    with fake_api(pki) as (url, api):
        r = run_role(tmp_path, ROLE, "restore", restore_vars(tmp_path, pki, url, src), env=env)
    assert r.returncode != 0 and "or its manifest changed while it was copied" in r.stdout, r.stdout
    assert [q for q in api.requests if q[1] != "/v1/sys/health"] == []
    assert not list((tmp_path / "backup").glob(".restore-staging-*"))


def test_a_confirmed_restore_token_is_revoked_when_the_restore_is_not_reached(tmp_path, pki):
    """lookup-self said it is the restore principal's, then the pre-restore snapshot failed: the
    token is revoked (its second use), never left live."""
    src = restore_case(tmp_path)
    with fake_api(pki) as (url, api):
        api.save_fails = True
        r = run_role(tmp_path, ROLE, "restore", restore_vars(tmp_path, pki, url, src))
    assert r.returncode != 0
    assert [q for q in api.requests if q[1] != "/v1/sys/health"] == [
        ("GET", "/v1/auth/token/lookup-self", "restore"),
        ("GET", "/v1/sys/storage/raft/snapshot", "snapshot"),
        ("POST", "/v1/auth/token/revoke-self", "restore"),
    ]
    assert api.restored == [] and not any(x in r.stdout + r.stderr for x in SECRETS)


def test_a_failed_restore_post_still_revokes_and_a_sealed_server_skips_no_cleanup(tmp_path, pki):
    """The restore POST fails (it may or may not have landed), so the token is not known spent:
    it is revoked. The server then answers the revoke sealed (503): that is reported, not fatal,
    and the staged copy is already gone (removed first)."""
    src = restore_case(tmp_path)
    with fake_api(pki) as (url, api):
        api.restore_fails = True
        api.revoke_status = 503
        r = run_role(tmp_path, ROLE, "restore", restore_vars(tmp_path, pki, url, src))
    assert r.returncode != 0
    assert [q for q in api.requests if q[1] != "/v1/sys/health"] == [
        ("GET", "/v1/auth/token/lookup-self", "restore"),
        ("GET", "/v1/sys/storage/raft/snapshot", "snapshot"),
        ("POST", "/v1/sys/storage/raft/snapshot", "restore"),
        ("POST", "/v1/auth/token/revoke-self", "restore"),
    ]
    assert "could not revoke the restore token (HTTP 503)" in r.stdout, r.stdout
    assert not list((tmp_path / "backup").glob(".restore-staging-*"))
    assert not any(x in r.stdout + r.stderr for x in SECRETS)


def test_an_unrestricted_source_on_another_filesystem_is_refused(tmp_path, pki):
    """openbao_restore_source_unrestricted waives the location, not the filesystem: a source on
    another one than openbao_backup_dir's (here: /dev/shm) is refused before the token is used."""
    shm = Path("/dev/shm")
    if not shm.is_dir() or shm.stat().st_dev == tmp_path.stat().st_dev:
        pytest.skip("no /dev/shm on a filesystem of its own")
    (tmp_path / "backup").mkdir()
    d = Path(tempfile.mkdtemp(prefix="hnx-openbao-", dir=shm))
    try:
        src = d / "raft.snap"
        src.write_bytes(SNAP)
        m = {
            "kind": "raft-snapshot",
            "sha256": hashlib.sha256(SNAP).hexdigest(),
            "written_by": "2.7.1",
        }
        src.with_name("raft.snap.json").write_text(json.dumps(m))
        with fake_api(pki) as (url, api):
            v = restore_vars(tmp_path, pki, url, src, openbao_restore_source_unrestricted=True)
            r = run_role(tmp_path, ROLE, "restore", v)
    finally:
        shutil.rmtree(d)
    assert r.returncode != 0 and f"is not on the filesystem of {tmp_path}/backup" in r.stdout, (
        r.stdout
    )
    assert [q for q in api.requests if q[1] != "/v1/sys/health"] == []


UNSAFE_DIR = "lies under a directory that is not owned by"
# findmnt as it answers for a FUSE and a user mount (a source under a directory so named); the real
# one for every other path
FINDMNT = r"""
import os, sys
path = sys.argv[-1]
mounts = {"/fuse-mount/": "fuse.sshfs rw,nosuid,nodev,user_id=1000,group_id=1000",
          "/user-mount/": "ext4 rw,nosuid,nodev,relatime,user=alice"}
for k, v in mounts.items():
    if k in path:
        print(v)
        sys.exit(0)
os.execv(REAL, [REAL, *sys.argv[1:]])
"""
REFUSED_SOURCES = {
    "world-writable": "writable by its group or by others (mode 0666)",
    "group-writable manifest": "writable by its group or by others (mode 0664)",
    "symlink": "is not a non-empty snapshot file on the host (a symbolic link is refused)",
    "through a linked directory": "is reached through a symbolic link",
    "outside": "is not under",
    "hard link": "or its manifest has more than one name (links: 2, 1)",
    "hard-linked manifest": "or its manifest has more than one name (links: 1, 2)",
    "group-writable directory": UNSAFE_DIR,
    "sticky directory not root's": UNSAFE_DIR,
    "unknown token": "the server does not know it",
    "identity": "it carries 1 identity policies",
    "unlimited": "it has no use limit (mint it with -use-limit=2)",
    "long": "its TTL is 86400 s, over 900",
    "odd": "its policies are default, hnx-restore and 1 other)",
    "spare": "it has 2 uses left after the lookup, not 1 (mint it with -use-limit=2)",
    "fuse mount": "is on a FUSE or user mount",
    "user mount": "is on a FUSE or user mount",
}


def test_restore_refuses_a_source_someone_else_could_have_written(tmp_path, pki):
    """Each case its own source (one process for all of them: run_cases); none reaches the
    snapshot endpoint. Outside the two directories is accepted only with the explicit switch."""
    exp = tmp_path / "export"
    cases = []
    for i, case in enumerate(REFUSED_SOURCES):
        d = exp / f"case{i}"
        d.mkdir(parents=True)
        src = d / "raft.snap"
        src.write_bytes(SNAP)
        m = {
            "kind": "raft-snapshot",
            "sha256": hashlib.sha256(SNAP).hexdigest(),
            "written_by": "2.7.1",
        }
        src.with_name("raft.snap.json").write_text(json.dumps(m))
        over = {}
        if case == "world-writable":
            src.chmod(0o666)
        elif case == "group-writable manifest":
            src.with_name("raft.snap.json").chmod(0o664)
        elif case == "symlink":
            src.rename(d / "real.snap")
            src.symlink_to(d / "real.snap")
        elif case == "through a linked directory":
            (d / "via").symlink_to(d)
            src = d / "via" / "raft.snap"
        elif case == "outside":
            out = tmp_path / "elsewhere"
            out.mkdir()
            for f in (src, src.with_name("raft.snap.json")):
                f.rename(out / f.name)
            src = out / "raft.snap"
        elif case == "hard link":
            os.link(src, d / "another-name.snap")
        elif case == "hard-linked manifest":
            os.link(src.with_name("raft.snap.json"), d / "another-name.json")
        elif case == "group-writable directory":
            d.chmod(0o775)
        elif case == "sticky directory not root's":
            d.chmod(0o1777)  # sticky protects names only in a directory root owns
        elif case == "unknown token":
            over["openbao_restore_token"] = UNKNOWN
        elif case in ODD_TOKENS.values():
            over["openbao_restore_token"] = next(t for t, w in ODD_TOKENS.items() if w == case)
        elif case in ("fuse mount", "user mount"):  # FINDMNT answers for these directories
            sub = d / case.replace(" ", "-")
            sub.mkdir(mode=0o700)
            for f in (src, src.with_name("raft.snap.json")):
                f.rename(sub / f.name)
            src = sub / "raft.snap"
            over["openbao_restore_source_unrestricted"] = True
        # vars/main.yml's openbao_owner outranks run_cases' play variables: set it per case
        owner = {"openbao_owner": USER, "openbao_owner_group": GROUP}
        cases.append({"openbao_restore_source": str(src), **owner, **over})
    (tmp_path / "bin").mkdir()
    fake(tmp_path / "bin" / "findmnt", FINDMNT.replace("REAL", repr(shutil.which("findmnt"))))
    env = {"PATH": f"{tmp_path / 'bin'}:{os.environ['PATH']}"}
    with fake_api(pki) as (url, api):
        v = restore_vars(tmp_path, pki, url, exp / "unset")
        got = run_cases(tmp_path, ROLE, "restore", v, cases, env=env)
        assert api.restored == []
        assert not [q for q in api.requests if q[1] == "/v1/sys/storage/raft/snapshot"]
        # only the location is waived, and only explicitly
        outside = cases[list(REFUSED_SOURCES).index("outside")]["openbao_restore_source"]
        ok = run_role(
            tmp_path, ROLE, "restore",
            restore_vars(tmp_path, pki, url, outside, openbao_restore_source_unrestricted=True),
        )  # fmt: skip
    for (failed, message), (case, says) in zip(got, REFUSED_SOURCES.items(), strict=True):
        assert failed and says in message, (case, message)
    said = "".join(m for _, m in got)
    assert UNKNOWN not in said and "evil" not in said and not [t for t in ODD_TOKENS if t in said]
    # a token the lookup did not confirm as the restore principal's is never revoked by the role
    assert not [q for q in api.requests if q[1] == "/v1/auth/token/revoke-self"]
    assert ok.returncode == 0, ok.stdout + ok.stderr
    assert api.restored == [("snapshot", SNAP)]


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


# ---------------------------------------------------------------- the real server (optional)


def free_port() -> int:
    with socket.socket() as s:
        s.bind((LOOPBACK, 0))
        return s.getsockname()[1]


@pytest.mark.requires_tool("bao")
def test_the_real_server_reads_the_configuration_and_the_hooks_work_against_it(tmp_path, pki):
    """With a `bao` on PATH (the role's own pinned release, checksum-verified: README.md), the
    rendered configuration starts the real server, both declared audit devices exist after the
    first unseal, the listener negotiates TLS 1.2 only with the AEAD suites it names, and the
    backup, restore, health and downgrade paths work against it: the snapshot principal's AppRole
    as README.md creates it (token_num_uses=2) logs in, saves and revokes its token, a two-use
    hnx-restore token passes lookup-self and restores the staged copy (an hnx-snapshot token is
    refused), and a stopped server with a lower pin is refused. A throwaway cluster: its share
    and root token live only in this process's memory (the share goes to `bao` on stdin, never
    argv; HOME and BAO_TOKEN are throwaway, so no ~/.vault-token is read or sent). CI has no
    `bao`, so this skips there."""
    bao = subprocess.run(["bao", "version"], capture_output=True, text=True, check=True).stdout
    assert bao.startswith("OpenBao v2.7.1 "), bao  # the pin, nothing else
    port, cport = free_port(), free_port()
    url = f"https://{LOOPBACK}:{port}"
    v = hook_vars(tmp_path, pki, url, openbao_listen_address=LOOPBACK, openbao_port=port,
                  openbao_cluster_port=cport, openbao_bin=str(tmp_path / "bin" / "bao"))  # fmt: skip
    r = run_role(tmp_path, ROLE, "config", v)
    assert r.returncode == 0, r.stdout + r.stderr
    tls = tmp_path / "etc" / "tls"
    (tls / "server.pem").write_bytes((pki / "cert.pem").read_bytes())
    (tls / "server-key.pem").write_bytes((pki / "key.pem").read_bytes())
    # a throwaway HOME and token: the CLI never reads (or sends) the user's ~/.vault-token
    (tmp_path / "home").mkdir()
    env = dict(os.environ, BAO_ADDR=url, BAO_CACERT=str(tls / "ca.pem"), HOME=str(tmp_path / "home"),
               BAO_TOKEN="s.throwaway-not-a-token")  # fmt: skip
    env.pop("VAULT_TOKEN", None)

    def cli(*args, token=None, data=None):
        e = dict(env, BAO_TOKEN=token) if token else env
        p = subprocess.run(["bao", *args], input=data, capture_output=True, text=True, env=e)
        assert p.returncode == 0, (args, p.stderr)
        return p.stdout.strip()

    server = subprocess.Popen(
        ["bao", "server", f"-config={tmp_path / 'etc' / 'openbao.hcl'}"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=env,
    )  # fmt: skip
    try:
        for _ in range(100):
            try:
                with socket.create_connection((LOOPBACK, port), timeout=1):
                    break
            except OSError:
                assert server.poll() is None, server.stdout.read()
                threading.Event().wait(0.1)
        # TLS 1.2: only the configured forward-secret AEAD suites
        ctx12 = ssl.create_default_context(cafile=str(tls / "ca.pem"))
        ctx12.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx12.maximum_version = ssl.TLSVersion.TLSv1_2
        with (
            socket.create_connection((LOOPBACK, port)) as raw,
            ctx12.wrap_socket(raw, server_hostname=LOOPBACK) as t,
        ):
            name, proto, _ = t.cipher()
        assert (
            proto == "TLSv1.2"
            and name.startswith("ECDHE-")
            and ("GCM" in name or "CHACHA20" in name)
        )
        ctx12.set_ciphers("ECDHE-ECDSA-AES128-SHA256")  # CBC, no AEAD: refused
        with pytest.raises(ssl.SSLError), socket.create_connection((LOOPBACK, port)) as raw:
            ctx12.wrap_socket(raw, server_hostname=LOOPBACK).close()

        init = json.loads(
            cli("operator", "init", "-key-shares=1", "-key-threshold=1", "-format=json")
        )
        # the share on stdin (key=-), never argv: `operator unseal` takes it only as an argument
        # or from a terminal
        cli("write", "sys/unseal", "key=-", data=init["unseal_keys_b64"][0])
        root = init["root_token"]
        threading.Event().wait(2)  # the node becomes active
        audit = json.loads(cli("audit", "list", "-format=json", token=root))
        assert set(audit) == {"file/", "syslog/"}, audit
        cli("secrets", "enable", "-path=secret", "-version=2", "kv", token=root)
        cli("policy", "write", "hnx-snapshot", "-", token=root,
            data='path "sys/storage/raft/snapshot" { capabilities = ["read"] }\n')  # fmt: skip
        cli("policy", "write", "hnx-restore", "-", token=root,
            data='path "sys/storage/raft/snapshot" { capabilities = ["update"] }\n')  # fmt: skip
        cli("kv", "put", "-mount=secret", "probe", "v=before", token=root)

        def token(policy, uses):
            return cli("token", "create", f"-policy={policy}", "-ttl=10m", "-orphan",
                       f"-use-limit={uses}", "-field=token", token=root)  # fmt: skip

        # the snapshot principal as README.md step 3 creates it (token_num_uses=2: save, revoke)
        cli("auth", "enable", "approle", token=root)
        cli("write", "auth/approle/role/hnx-snapshot", "token_policies=hnx-snapshot", "token_ttl=5m",
            "token_max_ttl=10m", "token_type=service", "token_num_uses=2", "secret_id_ttl=720h",
            "secret_id_num_uses=0", token=root)  # fmt: skip
        role_id = cli(
            "read", "-field=role_id", "auth/approle/role/hnx-snapshot/role-id", token=root
        )
        secret_id = cli(
            "write",
            "-f",
            "-field=secret_id",
            "auth/approle/role/hnx-snapshot/secret-id",
            token=root,
        )
        snap = {**v, **APPROLE, "openbao_snapshot_approle_role_id": role_id}
        r = run_role(
            tmp_path, ROLE, "backup", snap, env={"HNX_SECRET_OPENBAO_SNAPSHOT_SECRET_ID": secret_id}
        )
        assert r.returncode == 0, r.stdout + r.stderr
        assert secret_id not in r.stdout + r.stderr
        accessors = json.loads(cli("list", "-format=json", "auth/token/accessors", token=root))
        assert len(accessors) == 1  # the root token alone: the login's token revoked itself
        cli("kv", "put", "-mount=secret", "probe", "v=after", token=root)

        src = tmp_path / "backup" / "raft.snap"
        restore = dict(v, openbao_snapshot_token=token("hnx-snapshot", 1),
                       openbao_restore_token=token("hnx-restore", 2), openbao_restore_source=str(src))  # fmt: skip
        wrong = dict(restore, openbao_restore_token=token("hnx-snapshot", 2))
        r = run_role(tmp_path, ROLE, "restore", wrong)
        assert r.returncode != 0 and "its policies are default and 1 other)" in r.stdout, r.stdout
        # -use-limit=3: lookup-self answers 2 (it spent one), and a use would outlive the restore
        spare = dict(restore, openbao_restore_token=token("hnx-restore", 3))
        r = run_role(tmp_path, ROLE, "restore", spare)
        assert r.returncode != 0 and "it has 2 uses left after the lookup, not 1" in r.stdout, (
            r.stdout
        )
        r = run_role(tmp_path, ROLE, "restore", restore)
        assert r.returncode == 0, r.stdout + r.stderr
        threading.Event().wait(2)
        assert cli("kv", "get", "-mount=secret", "-field=v", "probe", token=root) == "before"

        r = run_role(tmp_path, ROLE, "health", v)
        assert r.returncode == 0, r.stdout + r.stderr
        assert not (tmp_path / "state" / "highest-release").exists()  # health writes nothing
    finally:
        server.terminate()
        server.wait(timeout=30)
    # the server is stopped: sys/health says nothing; the command still points at 2.7.1 (as main
    # links it: <install_dir>/<version>/bao), which refuses a lower pin
    (tmp_path / "opt" / "2.7.1").mkdir(parents=True)
    (tmp_path / "opt" / "2.7.1" / "bao").write_text("")
    (tmp_path / "bin").mkdir(exist_ok=True)
    (tmp_path / "bin" / "bao").symlink_to(tmp_path / "opt" / "2.7.1" / "bao")
    r = run_role(
        tmp_path, ROLE, "downgrade", dict(v, openbao_version="2.7.0", openbao_health_timeout=2)
    )
    assert r.returncode != 0 and "older than what this host has run (linked 2.7.1" in r.stdout, (
        r.stdout
    )


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


# ---------------------------------------------------------------- a public certificate (ACME)

STAGING = "https://acme-staging-v02.api.letsencrypt.org/directory"  # never contacted: lego is faked
DNS_TOKEN = "fake-dns-token-0123456789abcdef"  # what secret:dns/token resolves to
DNS_ENV = {"HNX_SECRET_DNS_TOKEN": DNS_TOKEN}

# lego as the role runs it: --version, and `run`, which "issues" a certificate from the test CA
# for the --domains it is given (unless one is stored and FORCE is absent: not due), logging its
# arguments and whether the token reached it in its environment.
FAKE_LEGO = r"""
import os, subprocess, sys
if sys.argv[1:] == ["--version"]:
    print("lego version 5.6.0 linux/amd64")
    sys.exit(0)
a = sys.argv[1:]
# the flags `lego --help` and `lego run --help` of the real 5.6.0 list (the ones the role uses):
# any other spelling is refused, as the real binary refuses it
KNOWN = {"--log.format", "run", "--accept-tos", "--server", "--path", "--cert.name", "--key-type",
         "--dns", "--dns.propagation.wait", "--renew-days", "--no-random-sleep", "--email",
         "--domains"}
unknown = [x for x in a if x.startswith("-") and x not in KNOWN]
if unknown or a[2:3] != ["run"]:
    sys.exit("lego: flag provided but not defined: " + " ".join(unknown or a[:3]))
token = os.environ.get("CF_DNS_API_TOKEN", "")
open(LOG, "a").write("lego " + " ".join(a) + (" TOKEN-IN-ENV" if token else "") + "\n")
if os.path.exists(MARK + ".fail"):
    sys.exit(1)
path = a[a.index("--path") + 1]
names = [a[i + 1] for i, x in enumerate(a) if x == "--domains"]
if os.path.exists(MARK + ".wrong"):
    names = ["wrong.example.internal"]
d = os.path.join(path, "certificates")
crt = os.path.join(d, a[a.index("--cert.name") + 1] + ".crt")
if os.path.exists(crt) and not os.path.exists(MARK + ".force"):
    sys.exit(0)  # not due
os.makedirs(d, mode=0o700, exist_ok=True)
san = ",".join("DNS:" + n for n in names)
subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
                "-nodes", "-days", "90", "-subj", "/CN=" + names[0], "-CA", CA_FILE, "-CAkey", CA_KEY_FILE,
                "-addext", "subjectAltName=" + san, "-addext", "basicConstraints=critical,CA:FALSE",
                "-addext", "extendedKeyUsage=serverAuth", "-keyout", crt[:-4] + ".key",
                "-out", crt + ".leaf"], check=True, capture_output=True)
with open(crt, "w") as f:
    f.write(open(crt + ".leaf").read() + open(CA_FILE).read())
os.unlink(crt + ".leaf")
"""

# systemctl as the ACME tasks and the renewal script use it: `start` of the renewal unit runs its
# ExecStart= with its EnvironmentFile= (as systemd would); openbao.service is active with MARK.
FAKE_SYSTEMCTL = r"""
import os, subprocess, sys
a = sys.argv[1:]
open(LOG, "a").write("systemctl " + " ".join(a) + "\n")
if a[0] == "is-active":
    sys.exit(0 if os.path.exists(MARK + ".active") else 3)
if a[0] == "reload":
    sys.exit(1 if os.path.exists(MARK + ".reloadfail") else 0)
if a[0] == "start":
    unit = open(os.path.join(UNITS, a[1])).read().splitlines()
    val = lambda k: [l.split("=", 1)[1] for l in unit if l.startswith(k + "=")][-1]
    assert not [l for l in unit if l.startswith("EnvironmentFile=")]  # the script reads the token
    env = {"PATH": os.environ["PATH"], "SSL_CERT_FILE": os.environ.get("SSL_CERT_FILE", "")}
    assert val("ExecStart") == "/usr/local/libexec/homelabnext/openbao-acme-renew"
    sys.exit(subprocess.run([sys.executable, SCRIPT], env=env).returncode)  # installed under tmp
"""


@contextmanager
def lego_mirror(pki, tmp_path):
    """A release mirror serving a lego archive whose `lego` is FAKE_LEGO; yields (url, sha256)."""
    import tarfile

    body = (FAKE_LEGO.replace("LOG", repr(str(tmp_path / "calls.log")))
            .replace("MARK", repr(str(tmp_path / "lego")))
            .replace("CA_KEY_FILE", repr(str(pki / "ca-key.pem"))).replace("CA_FILE", repr(str(pki / "ca.pem"))))  # fmt: skip
    src = tmp_path / "lego-src"
    src.mkdir()
    fake(src / "lego", body)
    (src / "LICENSE").write_text("MIT\n")
    archive = tmp_path / "lego.tar.gz"
    with tarfile.open(archive, "w:gz") as t:
        t.add(src / "lego", "lego")
        t.add(src / "LICENSE", "LICENSE")
    data = archive.read_bytes()

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            ok = self.path == "/v5.6.0/lego_v5.6.0_linux_amd64.tar.gz"
            self.send_response(200 if ok else 404)
            self.send_header("Content-Length", str(len(data) if ok else 0))
            self.end_headers()
            if ok:
                self.wfile.write(data)

        def log_message(self, *a):
            pass

    srv = http.server.ThreadingHTTPServer((LOOPBACK, 0), Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(pki / "cert.pem", pki / "key.pem")
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        yield f"https://{LOOPBACK}:{srv.server_address[1]}", hashlib.sha256(data).hexdigest()
    finally:
        srv.shutdown()
        srv.server_close()


def acme_vars(tmp_path, pki, mirror, sha, **kw):
    body = (FAKE_SYSTEMCTL.replace("LOG", repr(str(tmp_path / "calls.log")))
            .replace("MARK", repr(str(tmp_path / "openbao"))).replace("UNITS", repr(str(tmp_path / "units")))
            .replace("SCRIPT", repr(str(tmp_path / "bin" / "openbao-acme-renew"))))  # fmt: skip
    return base(tmp_path, **dict(
        ACME,
        openbao_acme_server=STAGING,
        openbao_acme_trust_bundle=str(pki / "ca.pem"),
        openbao_acme_dir=str(tmp_path / "acme"),
        openbao_acme_script=str(tmp_path / "bin" / "openbao-acme-renew"),
        openbao_acme_on_failure="hnx-page@%n.service",
        openbao_last_run_dir=str(tmp_path / "records"),
        openbao_last_run_group=GROUP,
        openbao_last_run_writer=str(tmp_path / "bin" / "hnx-last-run"),
        openbao_lego_release_repository=mirror,
        openbao_lego_checksums={"amd64": sha},
        openbao_arch="amd64",
        openbao_systemctl_cli=fake(tmp_path / "systemctl", body),
        **kw,
    ))  # fmt: skip


def acme_env(pki):
    return dict(DNS_ENV, SSL_CERT_FILE=str(pki / "ca.pem"))


def test_acme_obtains_installs_and_reloads_and_a_rerun_changes_nothing(tmp_path, pki):
    """The whole ACME path against a fake lego and systemd: the pinned client is fetched and
    checked, the token lands in a root-only environment file and nowhere else, the renewal unit
    obtains the certificate from the staging directory with a fixed propagation wait, the
    certificate and key are installed for the service account and a running server is RELOADED
    (never restarted); a second run with a valid certificate changes nothing."""
    (tmp_path / "openbao.active").write_text("")
    with lego_mirror(pki, tmp_path) as (mirror, sha):
        v = acme_vars(tmp_path, pki, mirror, sha)
        dry = run_role(tmp_path, ROLE, "tls", v, env=acme_env(pki), check=True)
        assert dry.returncode == 0, dry.stdout[-4000:] + dry.stderr
        assert "would start hnx-openbao-acme.service" in dry.stdout  # a fresh host is not converged
        assert not [c for c in calls(tmp_path) if c.startswith("lego --log")]
        r = verbose_run(tmp_path, "tls", v, env=acme_env(pki))
        assert r.returncode == 0, r.stdout[-4000:] + r.stderr
        log = calls(tmp_path)
        (tmp_path / "calls.log").unlink()
        again = run_role(tmp_path, ROLE, "tls", v, env=acme_env(pki))
    assert again.returncode == 0, again.stdout + again.stderr
    assert re.search(r"localhost\s*: ok=\d+\s+changed=0 ", again.stdout), again.stdout
    assert [
        c for c in calls(tmp_path) if not c.startswith("systemctl is-")
    ] == []  # no lego, no start

    assert DNS_TOKEN not in r.stdout + r.stderr  # -vvv: no command line or module output carries it
    (lego,) = [c for c in log if c.startswith("lego --log.format text run ")]
    assert DNS_TOKEN not in lego and lego.endswith(" TOKEN-IN-ENV")  # the environment, not argv
    for arg in (f"--server {STAGING}", "--dns cloudflare", "--dns.propagation.wait 30s",
                "--renew-days 30", f"--domains {HOST}", "--key-type EC256", "--cert.name openbao"):  # fmt: skip
        assert arg in lego, arg
    verbs = [c.split()[1] for c in log if c.startswith("systemctl")]
    assert "start" in verbs and "reload" in verbs and "restart" not in verbs, verbs
    assert "systemctl reload openbao.service" in log

    env = tmp_path / "etc" / "acme" / "dns.env"
    assert env.read_text() == f"CF_DNS_API_TOKEN={DNS_TOKEN}\n"
    assert stat_mode(env) == 0o600 and stat_mode(env.parent) == 0o700
    assert stat_mode(tmp_path / "acme") == 0o700
    tls = tmp_path / "etc" / "tls"
    assert stat_mode(tls / "server-key.pem") == 0o640 and stat_mode(tls / "server.pem") == 0o644
    assert (tls / "server.pem").read_bytes() == (
        tmp_path / "acme/certificates/openbao.crt"
    ).read_bytes()
    assert not (tls / "ca.pem").exists()  # ACME clients verify against the public chain

    unit = (tmp_path / "units" / "hnx-openbao-acme.service").read_text()
    for line in (
        "ExecStart=/usr/local/libexec/homelabnext/openbao-acme-renew",
        "OnFailure=hnx-page@%n.service",
        "Type=oneshot",
        "NoNewPrivileges=yes",
        "ProtectSystem=strict",
        "CapabilityBoundingSet=CAP_CHOWN",
        "ProtectProc=invisible",
        "SystemCallFilter=@system-service",
        f"ReadWritePaths={tmp_path}/acme {tls} {tmp_path}/records",
    ):
        assert f"\n{line}\n" in unit, line
    assert DNS_TOKEN not in unit
    timer = (tmp_path / "units" / "hnx-openbao-acme.timer").read_text()
    assert "\nOnCalendar=*-*-* 03:17:00 UTC\n" in timer and "\nPersistent=true\n" in timer
    assert DNS_TOKEN not in (tmp_path / "bin" / "openbao-acme-renew").read_text()


def stat_mode(p: Path) -> int:
    return p.stat().st_mode & 0o777


def test_the_renewal_script_installs_only_a_valid_certificate(tmp_path, pki):
    """The renewal unit's script on its own: a renewed certificate is installed and a running
    server reloaded; a failed lego run, a certificate for other names, or a missing token install
    nothing and fail the unit (exit 2), so the failure is visible."""
    with lego_mirror(pki, tmp_path) as (mirror, sha):
        v = acme_vars(tmp_path, pki, mirror, sha)
        r = run_role(tmp_path, ROLE, "tls", v, env=acme_env(pki))
    assert r.returncode == 0, r.stdout[-4000:] + r.stderr
    script = str(tmp_path / "bin" / "openbao-acme-renew")
    cert = tmp_path / "etc" / "tls" / "server.pem"
    first = cert.read_bytes()

    def renew(env=None):
        (tmp_path / "calls.log").unlink(missing_ok=True)
        e = {"PATH": os.environ["PATH"]} if env is None else env
        return subprocess.run([sys.executable, script], env=e, capture_output=True, text=True)

    assert subprocess.run([sys.executable, script, "--check"], capture_output=True).returncode == 0
    (tmp_path / "lego.fail").write_text("")
    r = renew()
    assert r.returncode == 2 and "lego failed" in r.stdout and cert.read_bytes() == first
    (tmp_path / "lego.fail").unlink()
    (tmp_path / "lego.force").write_text("")
    (tmp_path / "lego.wrong").write_text("")
    r = renew()
    assert r.returncode == 2 and f"does not verify for {HOST}" in r.stdout, r.stdout
    assert cert.read_bytes() == first
    (tmp_path / "lego.wrong").unlink()
    dns_env = tmp_path / "etc" / "acme" / "dns.env"
    dns_env.rename(dns_env.with_suffix(".off"))
    r = renew()
    assert r.returncode == 2 and "no CF_DNS_API_TOKEN in" in r.stdout, r.stdout
    dns_env.with_suffix(".off").rename(dns_env)
    # a renewal: installed; the server is stopped, so nothing is reloaded
    r = renew()
    assert r.returncode == 0 and "installed a new certificate" in r.stdout, r.stdout
    assert cert.read_bytes() != first
    assert not [c for c in calls(tmp_path) if "reload" in c]
    # the server running and its reload failing: exit 3, and the reload stays owed
    (tmp_path / "openbao.active").write_text("")
    (tmp_path / "openbao.reloadfail").write_text("")
    r = renew()
    assert r.returncode == 3 and "retried next run" in r.stdout, r.stdout
    check = subprocess.run([sys.executable, script, "--check"], capture_output=True, text=True)
    assert check.returncode == 1 and "has not reloaded" in check.stdout, check.stdout
    (tmp_path / "openbao.reloadfail").unlink()
    (tmp_path / "lego.force").unlink()  # nothing new from lego: the owed reload alone is retried
    r = renew()
    assert r.returncode == 0 and "retrying" in r.stdout and "reloaded openbao.service" in r.stdout
    assert subprocess.run([sys.executable, script, "--check"], capture_output=True).returncode == 0
    # a renewal with the server running: reloaded, never restarted
    (tmp_path / "lego.force").write_text("")
    r = renew()
    assert r.returncode == 0 and "reloaded openbao.service" in r.stdout, r.stdout
    assert "systemctl reload openbao.service" in calls(tmp_path)
    assert not [c for c in calls(tmp_path) if "restart" in c]
    assert DNS_TOKEN not in r.stdout + r.stderr


def acme_installed(tmp_path, pki, **kw):
    """The role's ACME path run once (lego and systemd faked): a certificate installed and the
    renewal script rendered; returns the script loaded as a module, so a test can fail one of
    its steps (an I/O error) and call the rest as the unit would."""
    from importlib.machinery import SourceFileLoader
    from importlib.util import module_from_spec, spec_from_loader

    with lego_mirror(pki, tmp_path) as (mirror, sha):
        r = run_role(tmp_path, ROLE, "tls", acme_vars(tmp_path, pki, mirror, sha, **kw),
                     env=acme_env(pki))  # fmt: skip
    assert r.returncode == 0, r.stdout[-4000:] + r.stderr
    loader = SourceFileLoader(
        f"acme_renew_{id(tmp_path)}", str(tmp_path / "bin" / "openbao-acme-renew")
    )
    mod = module_from_spec(spec_from_loader(loader.name, loader))
    loader.exec_module(mod)
    return mod


def staged_leftovers(tmp_path) -> list[str]:
    return sorted(p.name for p in (tmp_path / "etc" / "tls").glob(".acme-*"))


@pytest.mark.parametrize("owed_before", [True, False])
def test_a_rolled_back_pair_keeps_a_reload_an_earlier_run_owed(tmp_path, pki, owed_before):
    """N1: a run whose new pair fails its check puts the old pair back. If an earlier run's reload
    of that old pair had failed, the reload is still owed (the server serves an even older
    certificate): the marker stays. Without an earlier owed reload, none is left behind."""
    mod = acme_installed(tmp_path, pki)
    owed = Path(mod.RELOAD_OWED)
    if owed_before:
        owed.write_text("")
    (tmp_path / "lego.force").write_text("")  # lego stores a new pair: the script installs it
    mod.install_pair = lambda: "the installed pair did not verify"
    assert mod.renew() == 2
    assert owed.exists() is owed_before
    check = subprocess.run(
        [sys.executable, mod.__file__, "--check"], capture_output=True, text=True
    )
    assert (check.returncode, "has not reloaded" in check.stdout) == (
        (1, True) if owed_before else (0, False)
    ), check.stdout


def test_acme_hooks_verify_the_public_chain_by_name_and_health_watches_expiry(
    tmp_path, pki, tmp_path_factory
):
    """With ACME the hooks verify the server against the trust bundle (no CA file of the role's)
    and by the name in openbao_api_addr; health fails when the installed certificate is inside
    openbao_acme_health_min_days (renewal has been failing)."""
    other = tmp_path_factory.mktemp("other-ca")
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
         "-nodes", "-days", "2", "-subj", "/CN=other", "-keyout", other / "k.pem",
         "-out", other / "ca.pem"],
        check=True, capture_output=True,
    )  # fmt: skip
    with fake_openbao(pki, 200, ACTIVE) as url:
        v = base(tmp_path, **dict(ACME, openbao_api_addr=url, openbao_acme_domains=[LOOPBACK],
                                  openbao_acme_trust_bundle=str(pki / "ca.pem")))  # fmt: skip
        (tmp_path / "etc" / "tls").mkdir(parents=True)
        (tmp_path / "etc" / "tls" / "server.pem").write_bytes(
            (pki / "cert.pem").read_bytes()
        )  # 2 days
        got = run_cases(tmp_path, ROLE, "health", v, [
            {"openbao_acme_health_min_days": 1},
            {},  # 14 days: inside the margin
            {"openbao_acme_health_min_days": 1, "openbao_acme_trust_bundle": str(other / "ca.pem")},
        ])  # fmt: skip
        ready = run_role(tmp_path, ROLE, "readiness", v)
    assert got[0][0] is False, got[0]
    assert got[1][0] and "expires within 14 days" in got[1][1], got[1]
    assert got[2][0] and "CERTIFICATE_VERIFY_FAILED" in got[2][1], got[2]
    assert ready.returncode == 0 and "unsealed-active" in ready.stdout, ready.stdout


def test_going_back_to_supplied_pems_removes_the_acme_renewal(tmp_path, pki):
    """Left in place, the renewal timer would overwrite the supplied PEMs and keep the DNS token
    on the host: switching back to provided stops and removes the timer, units, script and token."""
    with lego_mirror(pki, tmp_path) as (mirror, sha):
        v = acme_vars(tmp_path, pki, mirror, sha)
        r = run_role(tmp_path, ROLE, "tls", v, env=acme_env(pki))
        assert r.returncode == 0, r.stdout[-4000:] + r.stderr
    (tmp_path / "calls.log").unlink()
    back = {
        k: base(tmp_path)[k]
        for k in ("openbao_tls_cert_pem", "openbao_tls_private_key_pem", "openbao_tls_ca_pem")
    }
    r = run_role(tmp_path, ROLE, "tls", dict(v, openbao_tls_source="provided", **back))
    assert r.returncode == 0, r.stdout[-4000:] + r.stderr
    assert "systemctl disable --now hnx-openbao-acme.timer" in calls(tmp_path)
    for gone in ("units/hnx-openbao-acme.timer", "units/hnx-openbao-acme.service",
                 "bin/openbao-acme-renew", "etc/acme"):  # fmt: skip
        assert not (tmp_path / gone).exists(), gone
    assert (tmp_path / "etc" / "tls" / "ca.pem").read_text() == CERT_PEM
