# SPDX-License-Identifier: Apache-2.0
"""``hnx ssh-ca`` (homelabnext/sshca.py): the SSH user-certificate roles as code.  The template
renders to a policy that may only sign with its role, a user-certificate-only SSH role with the
spec's principals, TTLs and extensions, and (a person's role) an OIDC login role bound to the
groups claim; anything wider than the caps is refused before a write is printed, and the shell
form hands the store's CLI exactly the JSON the writes hold."""

from __future__ import annotations

import copy
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from homelabnext import cli
from homelabnext.sshca import SpecError, load, main, parse, render_sh, writes

ROOT = Path(__file__).resolve().parents[2]
TEMPLATE = ROOT / "examples" / "private-overlay" / "lab" / "ssh-ca.yml"
SOURCE = "198.51.100.0/24"  # no-raw-endpoint: allow RFC 5737, the template's deploy source range
NOT_A_NETWORK = "198.51.100.1/24"  # no-raw-endpoint: allow RFC 5737 with host bits set


def doc():
    return yaml.safe_load(TEMPLATE.read_text())


def test_the_template_renders_least_privilege_writes():
    w = writes(load(TEMPLATE))
    assert [x["path"] for x in w] == [
        "sys/policies/acl/hnx-ssh-hnx-deploy",
        "ssh/roles/hnx-deploy",
        "sys/policies/acl/hnx-ssh-hnx-admin",
        "ssh/roles/hnx-admin",
        "auth/oidc/role/hnx-admin",
    ]
    policy = w[0]["data"]["policy"]
    assert policy == 'path "ssh/sign/hnx-deploy" {\n  capabilities = ["update"]\n}\n'
    deploy = w[1]["data"]
    assert deploy["key_type"] == "ca" and deploy["allow_user_certificates"] is True
    assert deploy["allow_host_certificates"] is False and deploy["allow_user_key_ids"] is False
    assert deploy["allowed_users"] == "hnx-deploy" == deploy["default_user"]
    assert deploy["allowed_extensions"] == "" and deploy["default_extensions"] == {}
    assert deploy["default_critical_options"] == {"source-address": SOURCE}
    assert (deploy["ttl"], deploy["max_ttl"]) == ("1h", "1h")
    admin = w[3]["data"]
    assert admin["default_extensions"] == {"permit-pty": ""}
    assert admin["default_critical_options"] == {}
    login = w[4]["data"]
    assert login["bound_claims"] == {"groups": ["hnx-admins"]}
    assert login["bound_audiences"] == ["hnx-secrets"]
    assert login["token_policies"] == ["hnx-ssh-hnx-admin"]
    assert (login["token_ttl"], login["token_max_ttl"]) == ("10m", "10m")
    # a deploy role never gets an OIDC login: it signs with the deploy's AppRole token
    assert not any(x["path"].startswith("auth/") and "deploy" in x["path"] for x in w)


def _set(d, path, value):
    *head, last = path
    for k in head:
        d = d[k]
    if value is KeyError:
        del d[last]
    else:
        d[last] = value


@pytest.mark.parametrize(
    "path,value,why",
    [
        (("ssh_ca_version",), 2, "ssh_ca_version: 1"),
        (("extra",), 1, "unknown key"),
        (("roles", 0, "colour"), "red", "unknown key"),
        (("roles", 1, "name"), "hnx-deploy", "used twice"),
        (("roles", 0, "principals"), ["root"], "root is never a principal"),
        (("roles", 0, "principals"), [], "at least one"),
        (("roles", 0, "principals"), ["hnx deploy"], "plain names"),
        (("roles", 0, "ttl"), "90m", "longer than max_ttl"),
        (("roles", 0, "max_ttl"), "2h", "longer than a deploy certificate"),
        (("roles", 1, "max_ttl"), "25h", "longer than a human certificate"),
        (("roles", 0, "ttl"), "15", "duration"),
        (("roles", 0, "extensions"), ["permit-port-forwarding"], "no forwarding"),
        (("roles", 0, "extensions"), ["permit-user-rc"], "no forwarding"),
        (("roles", 1, "extensions"), ["permit-everything"], "extensions are some of"),
        (("roles", 1, "groups"), [], "at least one"),
        (("roles", 1, "groups"), KeyError, "at least one"),
        (("roles", 0, "groups"), ["hnx-admins"], "not for groups"),
        (("roles", 0, "source_addresses"), [NOT_A_NETWORK], "not a network"),
        (("roles", 0, "for"), "robot", "for is one of"),
        (("oidc", "audience"), KeyError, "oidc.audience"),
        (("oidc", "login_ttl"), "2h", "at most 1h"),
        (("oidc", "redirect_uris"), ["javascript:alert(1)"], "http(s) URLs"),
        (("oidc", "groups_claim"), "groups claim", "claim name"),
        (("ssh_mount",), "ssh/../sys", "mount name"),
    ],
)
def test_wider_than_the_caps_is_refused(path, value, why):
    d = copy.deepcopy(doc())
    _set(d, path, value)
    with pytest.raises(SpecError) as exc:
        parse(d)
    assert why in str(exc.value), exc.value


def test_a_deploy_only_spec_needs_no_oidc():
    d = doc()
    d["roles"] = d["roles"][:1]
    del d["oidc"]
    assert [x["path"] for x in writes(parse(d))] == [
        "sys/policies/acl/hnx-ssh-hnx-deploy",
        "ssh/roles/hnx-deploy",
    ]


FAKE_CLI = r"""
import json, os, sys
with open(os.environ["LOG"], "a") as f:
    f.write(json.dumps({"argv": sys.argv[1:], "data": json.load(sys.stdin)}) + "\n")
"""


def test_the_shell_form_writes_exactly_the_json(tmp_path):
    spec = load(TEMPLATE)
    fake = tmp_path / "store-cli"
    fake.write_text(f"#!{sys.executable}\n{FAKE_CLI}")
    fake.chmod(0o755)
    log = tmp_path / "log"
    env = {**os.environ, "BAO_CLI": str(fake), "LOG": str(log)}
    r = subprocess.run(["sh"], input=render_sh(spec), text=True, env=env, capture_output=True)
    assert r.returncode == 0, r.stderr
    got = [json.loads(line) for line in log.read_text().splitlines()]
    assert [g["argv"] for g in got] == [["write", w["path"], "-"] for w in writes(spec)]
    assert [g["data"] for g in got] == [w["data"] for w in writes(spec)]
    # without the CLI named, nothing runs
    env.pop("BAO_CLI")
    r = subprocess.run(["sh"], input=render_sh(spec), text=True, env=env, capture_output=True)
    assert r.returncode != 0 and "BAO_CLI" in r.stderr


def test_the_cli(tmp_path, capsys):
    assert "ssh-ca" in cli.COMMANDS
    assert main(["check", str(TEMPLATE)]) == 0
    assert "hnx-admin: human" in capsys.readouterr().out
    assert main(["render", str(TEMPLATE)]) == 0
    assert json.loads(capsys.readouterr().out) == writes(load(TEMPLATE))
    bad = tmp_path / "bad.yml"
    bad.write_text("ssh_ca_version: 1\nroles: []\n")
    assert main(["check", str(bad)]) == 1
    assert "roles is a non-empty list" in capsys.readouterr().err
    assert main(["check", str(tmp_path / "missing.yml")]) == 1
    assert main(["render"]) == 2


def test_an_unreadable_or_duplicate_keyed_spec_is_a_spec_error(tmp_path):
    with pytest.raises(SpecError, match=r"cannot read .*missing\.yml") as err:
        load(tmp_path / "missing.yml")
    assert isinstance(err.value.__cause__, OSError)
    dup = tmp_path / "dup.yml"
    dup.write_text("ssh_ca_version: 1\nssh_ca_version: 1\n")
    with pytest.raises(SpecError, match="duplicate key 'ssh_ca_version'") as err:
        load(dup)
    assert isinstance(err.value.__cause__, yaml.YAMLError)
