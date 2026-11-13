# SPDX-License-Identifier: Apache-2.0
"""Role ``ntfy`` (modules/ntfy/roles/ntfy), run on localhost against fakes (CI is unprivileged):
main renders deny-all ntfy through compose_app with the credentials only in the env_file and a
second run is ``changed=0``; malformed inputs and credentials are refused; health passes against
a deny-all stand-in and fails when anonymous publishing is open or the admin cannot sign in;
export writes an object-tree with a sha256 listing and restore refuses a tampered one."""

from __future__ import annotations

import grp
import json
import os
import pwd
import sqlite3
from pathlib import Path

import pytest
import yaml
from rolerun import fake, run_role

from conformance.fakes.ntfy_api import FakeNtfy
from tests.modules.ntfy_front import DenyAllNtfy

ROOT = Path(__file__).resolve().parents[2]
ROLE = str(ROOT / "modules" / "ntfy" / "roles" / "ntfy")
_ME = pwd.getpwuid(os.getuid())
USER = _ME.pw_name
GROUP = grp.getgrgid(_ME.pw_gid).gr_name
GUEST = "192.0.2.40"  # no-raw-endpoint: allow a documentation-range guest address
TOKEN = "tk_fakefakefakefakefakefakefake0"
PASSWORD = "admin-password-fake"
HASH = "$2b$10$" + "f" * 53
SECRETS = {
    "HNX_SECRET_NTFY_ADMIN_PASSWORD": PASSWORD,
    "HNX_SECRET_NTFY_ADMIN_PASSWORD_HASH": HASH,
    "HNX_SECRET_NTFY_PUBLISHER_TOKEN": TOKEN,
}

pytestmark = pytest.mark.skipif(os.getuid() < 1000, reason="the role holds the uid to >= 1000")


def ntfy_vars(tmp_path: Path, **kw) -> dict:
    v = {
        "ntfy_logical_id": "notify",
        "ansible_host": GUEST,
        "ntfy_dir": str(tmp_path / "app"),
        "ntfy_data_root": str(tmp_path / "data"),
        "ntfy_owner": USER,
        "ntfy_group": GROUP,
        "ntfy_uid": os.getuid(),
        "ntfy_gid": os.getgid(),
        "ntfy_start": False,
        "ntfy_validate_with_docker": False,
    }
    v.update(kw)
    return v


def test_main_renders_deny_all_with_the_credentials_only_in_the_env_file(tmp_path):
    v = ntfy_vars(tmp_path)
    r = run_role(tmp_path, ROLE, "main", v, env=SECRETS)
    assert r.returncode == 0, r.stdout + r.stderr
    doc = yaml.safe_load((tmp_path / "app" / "docker-compose.yml").read_text())
    svc = doc["services"]["ntfy"]
    assert svc["image"].startswith("docker.io/binwiederhier/ntfy:v")
    assert svc["user"] == f"{os.getuid()}:{os.getgid()}"
    assert svc["cap_drop"] == ["ALL"] and svc["security_opt"] == ["no-new-privileges:true"]
    assert svc["ports"] == [GUEST + ":80:8080"]
    env = svc["environment"]
    assert env["NTFY_AUTH_DEFAULT_ACCESS"] == "deny-all"
    assert env["NTFY_AUTH_ACCESS"] == "publisher:*:wo,publisher:hnxconf-*:rw"
    for off in ("ENABLE_SIGNUP", "ENABLE_LOGIN", "ENABLE_RESERVATIONS", "ENABLE_METRICS",
                "BEHIND_PROXY"):  # fmt: skip
        assert env["NTFY_" + off] == "false"
    assert env["NTFY_WEB_ROOT"] == "disable"
    # nothing that calls out of the guest
    assert not any(k.startswith(("NTFY_UPSTREAM", "NTFY_SMTP", "NTFY_WEB_PUSH", "NTFY_FIREBASE",
                                 "NTFY_TWILIO", "NTFY_ATTACHMENT", "NTFY_STRIPE")) for k in env)  # fmt: skip
    text = (tmp_path / "app" / "docker-compose.yml").read_text()
    assert TOKEN not in text and HASH not in text and PASSWORD not in text
    secrets = (tmp_path / "app" / "secrets" / "ntfy.env").read_text()
    assert f"NTFY_AUTH_TOKENS='publisher:{TOKEN}:notify-publisher'" in secrets
    assert f"NTFY_AUTH_USERS='admin:{HASH}:admin,publisher:$2b$10$" in secrets
    assert PASSWORD not in secrets  # the server is given the hash only
    assert oct((tmp_path / "app" / "secrets" / "ntfy.env").stat().st_mode & 0o777) == "0o600"
    assert oct((tmp_path / "data" / "db").stat().st_mode & 0o777) == "0o700"
    assert TOKEN not in r.stdout and HASH not in r.stdout
    again = run_role(tmp_path, ROLE, "main", v, env=SECRETS)
    assert again.returncode == 0 and "changed=0" in again.stdout, again.stdout


@pytest.mark.parametrize(
    "over, env",
    [
        ({"ntfy_image": "docker.io/binwiederhier/ntfy:latest"}, {}),
        ({"ansible_host": "0.0.0.0"}, {}),  # no-raw-endpoint: allow a refused input
        ({"ansible_host": "ntfy.example.internal"}, {}),
        ({"ntfy_admin_user": "publisher"}, {}),
        ({"ntfy_publisher_key_ref": "secret:ntfy/admin-password"}, {}),
        ({"ntfy_publisher_topics": ["alerts/x"]}, {}),
        ({"ntfy_scratch_prefix": "hnx*"}, {}),
        ({"ntfy_uid": 0}, {}),
        ({}, {"HNX_SECRET_NTFY_PUBLISHER_TOKEN": "tk_short"}),
        ({}, {"HNX_SECRET_NTFY_ADMIN_PASSWORD_HASH": "plain-password"}),
        ({}, {"HNX_SECRET_NTFY_ADMIN_PASSWORD_HASH": "$2b$04$" + "f" * 53}),  # cost under 10
    ],
)
def test_main_refuses_bad_inputs_and_credentials(tmp_path, over, env):
    r = run_role(tmp_path, ROLE, "main", ntfy_vars(tmp_path, **over), env={**SECRETS, **env})
    assert r.returncode != 0, r.stdout
    assert not (tmp_path / "app" / "docker-compose.yml").exists()
    assert TOKEN not in r.stdout


def _docker(tmp_path: Path, health: str = "healthy") -> dict:
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    state = json.dumps({"Service": "ntfy", "State": "running", "Health": health})
    fake(bindir / "docker", f"import sys\nsys.stdout.write({state + chr(10)!r})\n")
    return {"PATH": f"{bindir}:{os.environ['PATH']}"}


def _health(tmp_path, srv, **env):
    host, port = srv._httpd.server_address[:2]
    v = ntfy_vars(tmp_path, ntfy_bind=host, ntfy_port=port)
    return run_role(tmp_path, ROLE, "health", v, env={**SECRETS, **_docker(tmp_path), **env})


def test_health_passes_against_a_deny_all_server(tmp_path):
    with DenyAllNtfy(token=TOKEN, admin=("admin", PASSWORD)) as srv:
        r = _health(tmp_path, srv)
        kept = list(srv.messages)
    assert r.returncode == 0, r.stdout + r.stderr
    (m,) = kept  # the round trip published one message, on a scratch topic
    assert m["topic"].startswith("hnxconf-health-")
    assert TOKEN not in r.stdout and PASSWORD not in r.stdout


def test_health_fails_when_anonymous_publishing_is_open(tmp_path):
    with FakeNtfy() as srv:  # no auth at all: the anonymous publish is accepted
        r = _health(tmp_path, srv)
    assert r.returncode != 0
    assert "An anonymous publish is refused" in r.stdout


def test_health_fails_when_the_admin_cannot_sign_in(tmp_path):
    with DenyAllNtfy(token=TOKEN, admin=("admin", "another-password-fake")) as srv:
        r = _health(tmp_path, srv)
    assert r.returncode != 0 and "The admin signs in" in r.stdout


def _databases(root: Path) -> None:
    (root / "db").mkdir(parents=True, exist_ok=True)
    for name in ("auth.db", "cache.db"):
        c = sqlite3.connect(root / "db" / name)
        c.execute("create table t (x)")
        c.execute("insert into t values (?)", (name,))
        c.commit()
        c.close()


def test_export_writes_an_object_tree_and_restore_checks_it(tmp_path):
    v = ntfy_vars(tmp_path)
    _databases(tmp_path / "data")
    r = run_role(tmp_path, ROLE, "export", v)
    assert r.returncode == 0, r.stdout + r.stderr
    export = tmp_path / "data" / "export"
    listing = [json.loads(x) for x in (export / "listing.jsonl").read_text().splitlines()]
    assert [x["key"] for x in listing] == ["auth.db", "cache.db"]
    c = sqlite3.connect(export / "cache.db")
    assert c.execute("select x from t").fetchall() == [("cache.db",)]
    c.close()
    # restore from a copy: checked, the server stopped and started around the copy
    src = tmp_path / "src"
    src.mkdir()
    for p in export.iterdir():
        (src / p.name).write_bytes(p.read_bytes())
    env = _docker(tmp_path)
    log = tmp_path / "docker.log"
    fake(tmp_path / "bin" / "docker",
         f"import sys\nopen({str(log)!r}, 'a').write(' '.join(sys.argv[1:]) + '\\n')\n")  # fmt: skip
    ok = run_role(tmp_path, ROLE, "restore", {**v, "ntfy_restore_source": str(src)}, env=env)
    assert ok.returncode == 0, ok.stdout + ok.stderr
    calls = log.read_text().splitlines()
    assert calls[0].endswith(" stop") and calls[-1].endswith(" up -d")
    # a tampered file, or one the listing does not name, is refused before anything changes
    log.unlink()
    with open(src / "cache.db", "ab") as f:
        f.write(b"x")
    bad = run_role(tmp_path, ROLE, "restore", {**v, "ntfy_restore_source": str(src)}, env=env)
    assert bad.returncode != 0 and "not a single-link regular file" in bad.stdout
    assert not log.exists()
    (src / "cache.db").write_bytes((export / "cache.db").read_bytes())
    (src / "extra.db").write_bytes(b"")
    bad = run_role(tmp_path, ROLE, "restore", {**v, "ntfy_restore_source": str(src)}, env=env)
    assert bad.returncode != 0 and "the listing does not name" in bad.stdout


def test_upgrade_refuses_an_unpinned_target_and_records_a_pinned_one(tmp_path):
    v = ntfy_vars(tmp_path)
    assert run_role(tmp_path, ROLE, "main", v, env=SECRETS).returncode == 0
    bad = run_role(
        tmp_path, ROLE, "upgrade", {**v, "ntfy_target_image": "docker.io/binwiederhier/ntfy:v9"}
    )
    assert bad.returncode != 0
    target = "docker.io/binwiederhier/ntfy:v9.9.9@sha256:" + "a" * 64
    ok = run_role(tmp_path, ROLE, "upgrade", {**v, "ntfy_target_image": target})
    assert ok.returncode == 0, ok.stdout + ok.stderr
    pending = json.loads((tmp_path / "app" / "pending-upgrade.json").read_text())
    assert pending == {"service": "ntfy", "tag": "v9.9.9", "digest": "sha256:" + "a" * 64}
