# SPDX-License-Identifier: Apache-2.0
"""Role ``lake_mcp`` (modules/lake-mcp/roles/lake_mcp), run on localhost against fakes (CI is
unprivileged): bad settings and an options-carrying key are refused before anything is written, the
reader's password is a 0600 file that never reaches the settings or the output, the settings load
into the server's own loader, every key is installed restricted to the forced command, and health
refuses a key line that is not."""

from __future__ import annotations

import os
import pwd
import stat
from pathlib import Path

import pytest
from rolerun import run_role

from homelabnext.lake.mcp_tools import load_settings

ROOT = Path(__file__).resolve().parents[2]
ROLE = str(ROOT / "modules" / "lake-mcp" / "roles" / "lake_mcp")
USER = pwd.getpwuid(os.getuid()).pw_name
PASSWORD = "pw" * 4
CA = "-----BEGIN CERTIFICATE-----\nMIIfake\n-----END CERTIFICATE-----"
KEY = "ssh-ed25519 " + "A" * 68 + " operator@workstation"
ENV = {
    "HNX_SECRET_LAKE_MCP_READER_PASSWORD": PASSWORD,
    "HNX_SECRET_PKI_INTERNAL_CA": CA,
}


def role_vars(tmp_path: Path, **kw) -> dict:
    v = {
        "lake_mcp_logical_id": "lake-mcp",
        "lake_mcp_catalog": "lake_ro",
        "lake_mcp_schemas": ["soc", "cti"],
        "lake_mcp_endpoint": "https://lake-query.example.internal",
        "lake_mcp_user": USER,
        "lake_mcp_group": USER,
        "lake_mcp_ssh_group": "",
        "lake_mcp_home": str(tmp_path / "home"),
        "lake_mcp_config_dir": str(tmp_path / "etc"),
        "lake_mcp_root_owner": USER,
        "lake_mcp_hnx_bin": str(tmp_path / "bin" / "hnx"),
        "lake_mcp_authorized_keys": [KEY],
        "lake_mcp_ssh_from": ["2001:db8::10"],
        "lake_mcp_ca_ref": "secret:pki/internal-ca",
        "lake_mcp_check_as_user": False,
    }
    v.update(kw)
    return v


def converge(tmp_path: Path, **kw):
    """The role's main without ``dirs.yml`` (a system account needs root, and CI has none)."""
    for d, mode in (("home/.ssh", 0o700), ("etc/credentials", 0o700)):
        (tmp_path / d).mkdir(parents=True, exist_ok=True)
        (tmp_path / d).chmod(mode)
    v = role_vars(tmp_path, **kw)
    out = [
        run_role(tmp_path, ROLE, hook, v, env=ENV) for hook in ("credentials", "config", "access")
    ]
    return v, out


def _fake_hnx(tmp_path: Path, check_rc: int = 0) -> None:
    b = tmp_path / "bin"
    b.mkdir(exist_ok=True)
    (b / "hnx").write_text(
        "#!/bin/sh\n"
        'case "$*" in *--check*) echo "hnx lake mcp: ok, signed in as lake-mcp"; exit '
        f"{check_rc};; *) exit 0;; esac\n"
    )
    (b / "hnx").chmod(0o755)


def test_validate_passes_for_good_settings(tmp_path):
    r = run_role(tmp_path, ROLE, "validate", role_vars(tmp_path))
    assert r.returncode == 0, r.stdout + r.stderr


@pytest.mark.parametrize(
    "over",
    [
        {"lake_mcp_catalog": "Lake RO"},
        {"lake_mcp_schemas": []},
        {"lake_mcp_schemas": "soc"},
        {"lake_mcp_schemas": ["soc", "x;y"]},
        {"lake_mcp_lake_user": "a b"},
        {"lake_mcp_endpoint": "http://lake-query.example.internal"},
        {"lake_mcp_reader_cred": "a-value-not-a-reference"},
        {"lake_mcp_ca_ref": "secret:Bad Name"},
        {"lake_mcp_max_rows": 0},
        {"lake_mcp_max_rows": 5001},
        {"lake_mcp_timeout_s": 301},
        {"lake_mcp_hnx_bin": "bin/hnx"},
        {"lake_mcp_home": "/var/lib/../etc"},
        # a key that brings its own options (or a second key on one line) would escape the forced command
        {"lake_mcp_authorized_keys": ['command="/bin/sh" ' + KEY]},
        {"lake_mcp_authorized_keys": ["no-pty " + KEY]},
        {"lake_mcp_authorized_keys": [KEY + "\n" + KEY]},
        {"lake_mcp_authorized_keys": ["ssh-dss AAAAB3Nza"]},
        {"lake_mcp_authorized_keys": KEY},
        {"lake_mcp_ssh_from": ['2001:db8::10",command="x']},
    ],
)
def test_validate_refuses_what_cannot_be_honoured(tmp_path, over):
    r = run_role(tmp_path, ROLE, "validate", {**role_vars(tmp_path), **over})
    assert r.returncode != 0, r.stdout


def test_converge_writes_the_password_0600_and_settings_the_server_loads(tmp_path):
    v, results = converge(tmp_path)
    for r in results:
        assert r.returncode == 0, r.stdout + r.stderr
        assert PASSWORD not in r.stdout + r.stderr  # no_log: a value never reaches the output
    cred = tmp_path / "etc" / "credentials" / "reader-password"
    assert stat.S_IMODE(cred.stat().st_mode) == 0o600 and cred.read_text().strip() == PASSWORD
    settings_file = tmp_path / "etc" / "lake-mcp.yml"
    assert PASSWORD not in settings_file.read_text()
    s = load_settings(settings_file)  # the very loader `hnx lake mcp` uses
    assert s.endpoint == v["lake_mcp_endpoint"] and s.user == "lake-mcp" and s.catalog == "lake_ro"
    assert s.schemas == ("soc", "cti") and s.max_rows == 500 and s.timeout_s == 60
    assert s.credential_file == str(cred) and s.ca_file == str(tmp_path / "etc" / "lake-ca.pem")
    assert (tmp_path / "etc" / "lake-ca.pem").read_text().strip() == CA


def test_every_key_is_restricted_to_the_forced_command(tmp_path):
    v, results = converge(tmp_path)
    assert all(r.returncode == 0 for r in results)
    keys = tmp_path / "home" / ".ssh" / "authorized_keys"
    assert stat.S_IMODE(keys.stat().st_mode) == 0o600
    lines = [ln for ln in keys.read_text().splitlines() if ln and not ln.startswith("#")]
    command = f"{v['lake_mcp_hnx_bin']} lake mcp --config {tmp_path / 'etc' / 'lake-mcp.yml'}"
    assert lines == [f'restrict,command="{command}",from="2001:db8::10" {KEY}']
    _, results = converge(tmp_path, lake_mcp_authorized_keys=[], lake_mcp_ssh_from=[])
    assert all(r.returncode == 0 for r in results)
    assert [ln for ln in keys.read_text().splitlines() if ln and not ln.startswith("#")] == []


def test_health_passes_converged_and_refuses_an_unrestricted_key_line(tmp_path):
    _fake_hnx(tmp_path)
    v, results = converge(tmp_path)
    assert all(r.returncode == 0 for r in results)
    r = run_role(tmp_path, ROLE, "health", v, env=ENV)
    assert r.returncode == 0, r.stdout + r.stderr
    keys = tmp_path / "home" / ".ssh" / "authorized_keys"
    keys.write_text(keys.read_text() + KEY + "\n")  # a hand-added key with no restriction
    r = run_role(tmp_path, ROLE, "health", v, env=ENV)
    assert r.returncode != 0 and "not restricted" in r.stdout


def test_health_fails_when_the_server_cannot_read_the_lake(tmp_path):
    _fake_hnx(tmp_path, check_rc=100)
    v, results = converge(tmp_path)
    assert all(r.returncode == 0 for r in results)
    r = run_role(tmp_path, ROLE, "health", v, env=ENV)
    assert r.returncode != 0


@pytest.mark.static
def test_health_runs_the_check_as_the_account_without_become_user():
    """Becoming an unprivileged user needs ACL tools a guest may lack; the check runs under runuser instead."""
    text = (Path(ROLE) / "tasks" / "health.yml").read_text()
    assert "become_user:" not in text and "'runuser', '-u', lake_mcp_user, '--'" in text


def test_readiness_needs_the_command_and_the_secret(tmp_path):
    v = role_vars(tmp_path)
    r = run_role(tmp_path, ROLE, "readiness", v, env=ENV)
    assert r.returncode != 0 and "is missing" in r.stdout
    _fake_hnx(tmp_path)
    assert run_role(tmp_path, ROLE, "readiness", v, env=ENV).returncode == 0
    r = run_role(tmp_path, ROLE, "readiness", v, env={"HNX_SECRET_PKI_INTERNAL_CA": CA})
    assert r.returncode != 0 and "lake-mcp/reader-password" in r.stdout
    assert PASSWORD not in r.stdout + r.stderr
