# SPDX-License-Identifier: Apache-2.0
"""The endpoint-forensics client baseline control (its module's ``roles/<id>_client``), run on
localhost against fakes (CI is unprivileged):

* main installs the pinned binary (a copy held to its sha256), the client configuration (0600) and
  the unit, waits for the client's identity, and a second run is ``changed=0``;
* a configuration that is empty, a placeholder, not YAML, without server URLs, an authority or a
  nonce, with a URL that is not https or wss, or that carries a private key is refused before
  anything is installed;
* a binary that is not the pinned release, and a release with no pinned checksum, are refused;
* a client that runs but never enrols fails the run, and health tells the same.
"""

from __future__ import annotations

import grp
import hashlib
import os
import pwd
import stat
from pathlib import Path

import pytest
import yaml
from rolerun import fake, first_run, run_role

from tests.modules.endpoint_forensics_module import CLIENT, CP, MID, env_for, ref

ROLE = str(CLIENT)
USER = pwd.getpwuid(os.getuid()).pw_name
GROUP = grp.getgrgid(os.getgid()).gr_name
VERSION = "9.9.9"
BINARY = b"#!/bin/sh\n# a stand-in release\n"
SHA = hashlib.sha256(BINARY).hexdigest()
CONFIG_ENV = env_for(ref("client-config"))
IDENTITY = "client_id: C.0123456789abcdef\n"

FAKE_SYSTEMCTL = r"""
import os, sys
a = sys.argv[1:]
open(LOG, "a").write(" ".join(a) + "\n")
if a[0] == "enable":
    open(STATE + ".active", "w").close()
elif a[0] == "is-active":
    ok = os.path.exists(STATE + ".active")
    print("active" if ok else "inactive")
    sys.exit(0 if ok else 3)
"""


def pem(tail: str = "") -> str:
    return (
        "-----BEGIN CERTIFICATE-----\n"
        + ("QUJD" * 60 + "\n") * 3
        + tail
        + "-----END CERTIFICATE-----\n"
    )


def client_config(tmp_path: Path, **over) -> str:
    doc = {
        "Client": {
            "server_urls": ["wss://frontend.example.internal/"],
            "ca_certificate": pem(),
            "nonce": "nonce-value",
            "writeback_linux": str(tmp_path / "writeback.yaml"),
        }
    }
    doc["Client"].update(over)
    return yaml.safe_dump(doc)


def cv(tmp_path: Path, **kw) -> dict:
    (tmp_path / "bin").mkdir(exist_ok=True)
    (tmp_path / "given").write_bytes(BINARY)
    sc = fake(
        tmp_path / "bin" / "systemctl",
        FAKE_SYSTEMCTL.replace("LOG", repr(str(tmp_path / "sc.log"))).replace(
            "STATE", repr(str(tmp_path / "sc"))
        ),
    )
    (tmp_path / "units").mkdir(exist_ok=True)
    v = {
        f"{CP}logical_id": "endpoint-forensics",
        f"{CP}version": VERSION,
        f"{CP}checksums": {VERSION: SHA},
        f"{CP}binary_src": str(tmp_path / "given"),
        f"{CP}owner": USER,
        f"{CP}group": GROUP,
        f"{CP}install_path": str(tmp_path / "bin" / "agent"),
        f"{CP}config_dir": str(tmp_path / "etc"),
        f"{CP}unit_dir": str(tmp_path / "units"),
        f"{CP}systemctl_cli": sc,
        f"{CP}start": False,
        f"{CP}ready_timeout": 10,
    }
    v.update(kw)
    return v


def _first_main_installs_the_pinned_binary_the_configuration_and_the_unit(tmp_path):
    v = cv(tmp_path)
    return {"role": ROLE, "tasks_from": "main", "extra_vars": v,
            "env": {CONFIG_ENV: client_config(tmp_path)}, "setup": {"v": v}}  # fmt: skip


@first_run(_first_main_installs_the_pinned_binary_the_configuration_and_the_unit)
def test_main_installs_the_pinned_binary_the_configuration_and_the_unit(first):
    r, tmp_path = first
    v = first.setup["v"]
    assert r.returncode == 0, r.stdout + r.stderr
    agent = tmp_path / "bin" / "agent"
    assert agent.read_bytes() == BINARY and agent.stat().st_mode & stat.S_IXUSR
    conf = tmp_path / "etc" / "client.config.yaml"
    assert oct(conf.stat().st_mode & 0o777) == "0o600"
    assert "nonce-value" in conf.read_text()
    unit = (tmp_path / "units" / f"{MID}-client.service").read_text()
    assert f"ExecStart={agent} --config {conf} client" in unit
    assert "nonce-value" not in r.stdout
    again = run_role(tmp_path, ROLE, "main", v, env={CONFIG_ENV: client_config(tmp_path)})
    assert again.returncode == 0 and "changed=0" in again.stdout, again.stdout


def test_a_configuration_file_on_the_controller_is_used_instead_of_the_reference(tmp_path):
    f = tmp_path / "given.yaml"
    f.write_text(client_config(tmp_path))
    v = cv(tmp_path, **{f"{CP}config_file": str(f)})
    r = run_role(tmp_path, ROLE, "main", v, env={})
    assert r.returncode == 0, r.stdout + r.stderr
    assert "nonce-value" in (tmp_path / "etc" / "client.config.yaml").read_text()


def _private_key_marker() -> str:
    return "-----BEGIN " + "RSA PRIVATE" + " KEY-----"


def _configs(tmp_path):
    good = client_config(tmp_path)
    return {
        "empty": "",
        "whitespace": "   \n",
        "not yaml": "key: [unclosed",
        "a list": "- a\n- b\n",
        "no urls": client_config(tmp_path, server_urls=[]),
        "a url that is not https or wss": client_config(
            tmp_path, server_urls=["http://frontend.example.internal/"]
        ),
        "no authority": client_config(tmp_path, ca_certificate=""),
        "a short authority": client_config(
            tmp_path,
            ca_certificate="-----BEGIN CERTIFICATE-----\nQUJD\n-----END CERTIFICATE-----\n",
        ),
        "no nonce": client_config(tmp_path, nonce=""),
        "a placeholder nonce": client_config(tmp_path, nonce="REPLACE_ME"),
        "a placeholder url": client_config(tmp_path, server_urls=["wss://<server>:8000/"]),
        "a private key": good + "x: |\n  " + _private_key_marker() + "\n",
    }


@pytest.mark.parametrize(
    "case",
    [
        "empty",
        "whitespace",
        "not yaml",
        "a list",
        "no urls",
        "a url that is not https or wss",
        "no authority",
        "a short authority",
        "no nonce",
        "a placeholder nonce",
        "a placeholder url",
        "a private key",
    ],
)
def test_a_configuration_that_is_not_the_servers_generated_one_is_refused_before_anything_is_installed(
    tmp_path, case
):
    v = cv(tmp_path)
    r = run_role(tmp_path, ROLE, "main", v, env={CONFIG_ENV: _configs(tmp_path)[case]})
    assert r.returncode != 0, case
    assert not (tmp_path / "bin" / "agent").exists() and not (tmp_path / "etc").exists()
    assert not list((tmp_path / "units").iterdir())
    assert "nonce-value" not in r.stdout


def test_a_binary_that_is_not_the_pinned_release_is_refused(tmp_path):
    (tmp_path / "given").write_bytes(b"something else")
    v = cv(tmp_path)
    (tmp_path / "given").write_bytes(b"something else")
    r = run_role(tmp_path, ROLE, "main", v, env={CONFIG_ENV: client_config(tmp_path)})
    assert r.returncode != 0 and "not the pinned release" in (r.stdout + r.stderr)
    assert not (tmp_path / "bin" / "agent").exists()


def test_a_release_with_no_pinned_checksum_is_refused(tmp_path):
    v = cv(tmp_path, **{f"{CP}version": "1.2.3"})
    r = run_role(tmp_path, ROLE, "main", v, env={CONFIG_ENV: client_config(tmp_path)})
    assert r.returncode != 0 and "pinned" in (r.stdout + r.stderr)


@pytest.mark.parametrize(
    "over",
    [
        {f"{CP}release_repository": "http://releases.example.internal"},
        {f"{CP}install_path": "relative/agent"},
        {f"{CP}config_ref": "not-a-ref"},
        {f"{CP}service": "Bad Name"},
    ],
)
def test_malformed_inputs_are_refused(tmp_path, over):
    v = cv(tmp_path, **over)
    r = run_role(tmp_path, ROLE, "main", v, env={CONFIG_ENV: client_config(tmp_path)})
    assert r.returncode != 0
    assert not (tmp_path / "etc").exists()


def test_a_client_that_enrols_passes_and_one_that_never_does_fails(tmp_path):
    (tmp_path / "writeback.yaml").write_text(IDENTITY)
    v = cv(tmp_path, **{f"{CP}start": True})
    env = {CONFIG_ENV: client_config(tmp_path)}
    ok = run_role(tmp_path, ROLE, "main", v, env=env)
    assert ok.returncode == 0, ok.stdout + ok.stderr
    assert "enable --now" in (tmp_path / "sc.log").read_text()
    assert run_role(tmp_path, ROLE, "health", v, env=env).returncode == 0
    (tmp_path / "writeback.yaml").unlink()
    r = run_role(tmp_path, ROLE, "health", v, env=env)
    assert r.returncode != 0 and "did not enrol" in (r.stdout + r.stderr)


def test_health_fails_on_a_loose_configuration_a_wrong_binary_and_a_stopped_unit(tmp_path):
    (tmp_path / "writeback.yaml").write_text(IDENTITY)
    v = cv(tmp_path, **{f"{CP}start": True})
    env = {CONFIG_ENV: client_config(tmp_path)}
    assert run_role(tmp_path, ROLE, "main", v, env=env).returncode == 0
    conf = tmp_path / "etc" / "client.config.yaml"
    conf.chmod(0o644)
    assert "0600" in (run_role(tmp_path, ROLE, "health", v, env=env).stdout)
    conf.chmod(0o600)
    agent = tmp_path / "bin" / "agent"
    agent.write_bytes(b"tampered")
    r = run_role(tmp_path, ROLE, "health", v, env=env)
    assert r.returncode != 0 and "pinned release" in (r.stdout + r.stderr)
    agent.write_bytes(BINARY)
    (tmp_path / "sc.active").unlink()
    assert run_role(tmp_path, ROLE, "health", v, env=env).returncode != 0


def test_readiness_refuses_a_placeholder_and_passes_the_real_configuration(tmp_path):
    v = cv(tmp_path)
    assert (
        run_role(
            tmp_path, ROLE, "readiness", v, env={CONFIG_ENV: client_config(tmp_path)}
        ).returncode
        == 0
    )
    r = run_role(
        tmp_path, ROLE, "readiness", v, env={CONFIG_ENV: client_config(tmp_path, nonce="CHANGEME")}
    )
    assert r.returncode != 0


def test_the_hooks_with_no_data_say_so_and_upgrade_checks_the_pin(tmp_path):
    v = cv(tmp_path)
    env = {CONFIG_ENV: client_config(tmp_path)}
    assert run_role(tmp_path, ROLE, "backup", v, env=env).returncode == 0
    assert run_role(tmp_path, ROLE, "export", v, env=env).returncode == 0
    r = run_role(tmp_path, ROLE, "restore", v, env=env)
    assert r.returncode != 0 and "nothing to restore" in (r.stdout + r.stderr)
    assert (
        run_role(
            tmp_path, ROLE, "upgrade", {**v, f"{CP}target_version": VERSION}, env=env
        ).returncode
        == 0
    )
    bad = run_role(tmp_path, ROLE, "upgrade", {**v, f"{CP}target_version": "1.2.3"}, env=env)
    assert bad.returncode != 0 and "no pinned sha256" in (bad.stdout + bad.stderr)
    assert os.path.exists(tmp_path / "given")


def test_a_second_client_on_a_host_gets_its_own_identity_file_and_nothing_else_changes(tmp_path):
    own = tmp_path / "second.writeback.yaml"
    own.write_text(IDENTITY)
    v = cv(tmp_path, **{f"{CP}start": True, f"{CP}writeback": str(own)})
    env = {CONFIG_ENV: client_config(tmp_path)}  # names the default identity file, which is absent
    r = run_role(tmp_path, ROLE, "main", v, env=env)
    assert r.returncode == 0, r.stdout + r.stderr
    installed = yaml.safe_load((tmp_path / "etc" / "client.config.yaml").read_text())
    given = yaml.safe_load(client_config(tmp_path))
    assert installed["Client"]["writeback_linux"] == str(own)
    installed["Client"]["writeback_linux"] = given["Client"]["writeback_linux"]
    assert installed == given  # the authority, the URLs and the nonce are the server's, untouched
    assert run_role(tmp_path, ROLE, "health", v, env=env).returncode == 0
    again = run_role(tmp_path, ROLE, "main", v, env=env)
    assert again.returncode == 0 and "changed=0" in again.stdout, again.stdout
