# SPDX-License-Identifier: Apache-2.0
"""The roles of the three lake modules (modules/garage, modules/iceberg-rest, modules/trino), run on
localhost against fakes (CI is unprivileged).

* main renders the compose project with no secret in it (the credentials only in the 0600
  env_file), and a second run is ``changed=0``;
* a malformed input, or a malformed or UNSET credential, is refused before anything is rendered,
  naming the ``secret:`` reference (Review Focus 3: never a half-configured service);
* the query engine's role writes the retention floors the maintenance procedures need, and installs
  the maintenance timer with its retention values (Review Focus 4), run end to end against a
  stand-in engine and notify channel, with the failure alert state-diffed;
* the catalog role restores a catalog file only from a checked export.
"""

from __future__ import annotations

import hashlib
import http.server
import json
import os
import pwd
import re
import signal
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

import pytest
import yaml
from rolerun import fake, first_run, last_run_vars, run_role

ROOT = Path(__file__).resolve().parents[2]
USER = pwd.getpwuid(os.getuid()).pw_name
GUEST = "192.0.2.50"  # no-raw-endpoint: allow a documentation-range guest address
S3_URL = "http://store.example.internal:3900"  # no-raw-endpoint: allow a fixture URL
CATALOG_URL = "http://catalog.example.internal:8181"  # no-raw-endpoint: allow a fixture URL
SELF_URL = "https://query.example.internal:8443"  # no-raw-endpoint: allow a fixture URL
NOTIFY_URL = "https://notify.example.internal:443"  # no-raw-endpoint: allow a fixture URL
PLAIN_NOTIFY_URL = "http://notify.example.internal:80"  # no-raw-endpoint: allow a fixture URL
KEY_ID = "GK" + "ab12" * 6
KEY_SECRET = "c0de" * 16
BCRYPT = "$2y$10$" + "f" * 53
MAINT_PW = "maintenance-pass-1234"
NOTIFY_TOKEN = "tk_notifytoken1234"


def _pki() -> tuple[str, str]:
    """A throwaway self-signed certificate and its private key (PEM), made once per run, so the
    tests carry no key material of their own."""
    with tempfile.TemporaryDirectory() as d:
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
                        "-subj", "/CN=stand-in", "-keyout", f"{d}/k.pem", "-out", f"{d}/c.pem"],
                       check=True, capture_output=True)  # fmt: skip
        return Path(d, "c.pem").read_text().strip(), Path(d, "k.pem").read_text().strip()


CERT, PKEY = _pki()


# ----------------------------------------------------------------------------- the object store

GARAGE = str(ROOT / "modules" / "garage" / "roles" / "garage")
GARAGE_SECRETS = {
    "HNX_SECRET_GARAGE_RPC_SECRET": "1f" * 32,
    "HNX_SECRET_GARAGE_ADMIN_TOKEN": "admin-token-0123456789abcdef0123456789",
    "HNX_SECRET_GARAGE_ACCESS_KEY": KEY_ID,
    "HNX_SECRET_GARAGE_SECRET_KEY": KEY_SECRET,
}


def garage_vars(tmp: Path, **kw) -> dict:
    v = {
        "garage_logical_id": "object-store",
        "ansible_host": GUEST,
        "garage_dir": str(tmp / "app"),
        "garage_data_root": str(tmp / "data"),
        "garage_export_dir": str(tmp / "export"),
        "garage_owner": USER,
        "garage_uid": os.getuid(),
        "garage_gid": os.getgid(),
        "garage_start": False,
        "garage_validate_with_docker": False,
    }
    v.update(kw)
    return v


def _first_garage_main_renders_the_bucket_and_key_with_the_secrets_only_in_the_env_file(tmp_path):
    v = garage_vars(tmp_path)
    return {
        "role": GARAGE,
        "tasks_from": "main",
        "extra_vars": v,
        "env": GARAGE_SECRETS,
        "setup": {"v": v},
    }


@first_run(_first_garage_main_renders_the_bucket_and_key_with_the_secrets_only_in_the_env_file)
def test_garage_main_renders_the_bucket_and_key_with_the_secrets_only_in_the_env_file(first):
    r, tmp_path = first
    v = first.setup["v"]
    assert r.returncode == 0, r.stdout + r.stderr
    text = (tmp_path / "app" / "docker-compose.yml").read_text()
    svc = yaml.safe_load(text)["services"]["garage"]
    assert svc["image"].startswith("docker.io/dxflrs/garage:v2.")
    assert svc["command"] == ["/garage", "server", "--single-node", "--default-bucket"]
    assert svc["user"] == f"{os.getuid()}:{os.getgid()}"
    assert svc["cap_drop"] == ["ALL"] and svc["security_opt"] == ["no-new-privileges:true"]
    # the S3 API on the guest's own address, nothing else published (the admin API stays inside)
    assert svc["ports"] == [GUEST + ":3900:3900"]
    # the bucket is fixed: the table metadata embeds s3://iceberg-warehouse/ paths
    assert svc["environment"]["GARAGE_DEFAULT_BUCKET"] == "iceberg-warehouse"
    for value in GARAGE_SECRETS.values():
        assert value not in text
    env = (tmp_path / "app" / "secrets" / "garage.env").read_text()
    for name in ("GARAGE_RPC_SECRET", "GARAGE_ADMIN_TOKEN", "GARAGE_DEFAULT_ACCESS_KEY",
                 "GARAGE_DEFAULT_SECRET_KEY"):  # fmt: skip
        assert name + "=" in env
    assert oct((tmp_path / "app" / "secrets" / "garage.env").stat().st_mode & 0o777) == "0o600"
    conf = (tmp_path / "app" / "garage.toml").read_text()
    assert 's3_region = "garage"' in conf and "replication_factor = 1" in conf
    assert not any(value in conf for value in GARAGE_SECRETS.values())
    assert oct((tmp_path / "data" / "meta").stat().st_mode & 0o777) == "0o700"
    assert KEY_SECRET not in r.stdout
    again = run_role(tmp_path, GARAGE, "main", v, env=GARAGE_SECRETS)
    assert again.returncode == 0 and "changed=0" in again.stdout, again.stdout


def _first_garage_main_refuses_bad_inputs_and_credentials(tmp_path, over, env):
    return {
        "role": GARAGE,
        "tasks_from": "main",
        "extra_vars": garage_vars(tmp_path, **over),
        "env": {**GARAGE_SECRETS, **env},
    }


@pytest.mark.parametrize(
    "over, env",
    [
        ({"garage_image": "docker.io/dxflrs/garage:latest"}, {}),
        ({"ansible_host": "0.0.0.0"}, {}),
        ({"garage_bucket": "Bad_Bucket"}, {}),
        ({"garage_uid": 0}, {}),
        ({"garage_data_root": "/var/lib/../etc"}, {}),
        ({"garage_export_dir": "relative"}, {}),
        ({"garage_signing_ref": "secret:garage/access-key"}, {}),
        ({}, {"HNX_SECRET_GARAGE_RPC_SECRET": "short"}),
        ({}, {"HNX_SECRET_GARAGE_SECRET_KEY": "not-hex"}),
        ({}, {"HNX_SECRET_GARAGE_ACCESS_KEY": "AK123"}),
        ({}, {"HNX_SECRET_GARAGE_ADMIN_TOKEN": "has space in it and is long enough to pass"}),
    ],
)
@first_run(_first_garage_main_refuses_bad_inputs_and_credentials)
def test_garage_main_refuses_bad_inputs_and_credentials(first, over, env):
    r, tmp_path = first
    assert r.returncode != 0, r.stdout
    assert not (tmp_path / "app" / "docker-compose.yml").exists()
    assert KEY_SECRET not in r.stdout


def _first_garage_main_refuses_an_unset_secret_naming_its_reference(tmp_path):
    env = {k: v for k, v in GARAGE_SECRETS.items() if k != "HNX_SECRET_GARAGE_RPC_SECRET"}
    return {"role": GARAGE, "tasks_from": "main", "extra_vars": garage_vars(tmp_path), "env": env}


@first_run(_first_garage_main_refuses_an_unset_secret_naming_its_reference)
def test_garage_main_refuses_an_unset_secret_naming_its_reference(first):
    r, tmp_path = first
    assert r.returncode != 0
    assert "secret:garage/rpc-secret" in r.stdout + r.stderr
    assert not (tmp_path / "app" / "docker-compose.yml").exists()


def _first_garage_upgrade_refuses_another_repository_and_another_major_version(tmp_path):
    digest = "sha256:" + "a" * 64
    return {
        "role": GARAGE,
        "tasks_from": "main",
        "extra_vars": garage_vars(tmp_path),
        "env": GARAGE_SECRETS,
        "setup": {"digest": digest},
    }


@first_run(_first_garage_upgrade_refuses_another_repository_and_another_major_version)
def test_garage_upgrade_refuses_another_repository_and_another_major_version(first):
    first_result, tmp_path = first
    digest = first.setup["digest"]
    assert first_result.returncode == 0
    for target in (f"docker.io/dxflrs/other:v2.6.0@{digest}", f"docker.io/dxflrs/garage:v3.0.0@{digest}",
                   "docker.io/dxflrs/garage:v2.6.0"):  # fmt: skip
        v = garage_vars(tmp_path, garage_target_image=target)
        assert run_role(tmp_path, GARAGE, "upgrade", v).returncode != 0, target
    v = garage_vars(tmp_path, garage_target_image=f"docker.io/dxflrs/garage:v2.6.0@{digest}")
    r = run_role(tmp_path, GARAGE, "upgrade", v)
    assert r.returncode == 0, r.stdout + r.stderr
    pending = json.loads((tmp_path / "app" / "pending-upgrade.json").read_text())
    assert pending["tag"] == "v2.6.0" and pending["digest"] == digest


# ----------------------------------------------------------------------------- the catalog

CATALOG = str(ROOT / "modules" / "iceberg-rest" / "roles" / "iceberg_rest")
CATALOG_SECRETS = {
    "HNX_SECRET_ICEBERG_REST_S3_ACCESS_KEY": KEY_ID,
    "HNX_SECRET_ICEBERG_REST_S3_SECRET_KEY": KEY_SECRET,
}


def catalog_vars(tmp: Path, **kw) -> dict:
    v = {
        "iceberg_rest_logical_id": "lake-catalog",
        "ansible_host": GUEST,
        "iceberg_rest_dir": str(tmp / "app"),
        "iceberg_rest_data_root": str(tmp / "data"),
        "iceberg_rest_export_dir": str(tmp / "export"),
        "iceberg_rest_owner": USER,
        "iceberg_rest_uid": os.getuid(),
        "iceberg_rest_gid": os.getgid(),
        "iceberg_rest_s3_url": S3_URL,
        "iceberg_rest_start": False,
        "iceberg_rest_validate_with_docker": False,
    }
    v.update(kw)
    return v


def _first_catalog_main_renders_the_sqlite_catalog_over_the_fixed_warehouse(tmp_path):
    v = catalog_vars(tmp_path)
    return {
        "role": CATALOG,
        "tasks_from": "main",
        "extra_vars": v,
        "env": CATALOG_SECRETS,
        "setup": {"v": v},
    }


@first_run(_first_catalog_main_renders_the_sqlite_catalog_over_the_fixed_warehouse)
def test_catalog_main_renders_the_sqlite_catalog_over_the_fixed_warehouse(first):
    r, tmp_path = first
    v = first.setup["v"]
    assert r.returncode == 0, r.stdout + r.stderr
    text = (tmp_path / "app" / "docker-compose.yml").read_text()
    svc = yaml.safe_load(text)["services"]["iceberg-rest"]
    # pinned by digest: the very build the old lake's catalog was written with
    assert svc["image"].endswith(":2026.4.29-b0df3ca") or ":2026.4.29-b0df3ca" in svc["image"]
    assert "sha256:db8de90b5b7693d4ac334c336f91d9bbe320d7b19f4f514d26de84cdfbcbfe8d" in text
    env = svc["environment"]
    assert env["CATALOG_WAREHOUSE"] == "s3://iceberg-warehouse/"
    # one SQLite file, with a busy timeout so a contending writer waits instead of dropping its batch
    assert env["CATALOG_URI"] == "jdbc:sqlite:/data/iceberg_catalog.db?busy_timeout=30000"
    assert env["CATALOG_S3_ENDPOINT"] == S3_URL and env["AWS_REGION"] == "garage"
    assert env["AWS_REQUEST_CHECKSUM_CALCULATION"] == "WHEN_REQUIRED"
    assert env["CATALOG_S3_PATH__STYLE__ACCESS"] == "true"
    assert svc["ports"] == [GUEST + ":8181:8181"]
    assert svc["user"] == f"{os.getuid()}:{os.getgid()}"
    assert KEY_SECRET not in text
    senv = (tmp_path / "app" / "secrets" / "iceberg-rest.env").read_text()
    assert "AWS_ACCESS_KEY_ID=" in senv and "AWS_SECRET_ACCESS_KEY=" in senv
    assert oct((tmp_path / "data" / "catalog").stat().st_mode & 0o777) == "0o700"
    again = run_role(tmp_path, CATALOG, "main", v, env=CATALOG_SECRETS)
    assert again.returncode == 0 and "changed=0" in again.stdout, again.stdout


def _first_catalog_main_refuses_bad_inputs_and_credentials(tmp_path, over, env):
    return {
        "role": CATALOG,
        "tasks_from": "main",
        "extra_vars": catalog_vars(tmp_path, **over),
        "env": {**CATALOG_SECRETS, **env},
    }


@pytest.mark.parametrize(
    "over, env",
    [
        ({"iceberg_rest_image": "docker.io/apache/iceberg-rest-fixture:latest"}, {}),
        ({"iceberg_rest_warehouse": "s3://Bad_Bucket/"}, {}),
        ({"iceberg_rest_warehouse": "s3://iceberg-warehouse"}, {}),
        ({"iceberg_rest_busy_timeout_ms": 10}, {}),
        ({"iceberg_rest_s3_url": "store.example.internal"}, {}),
        ({"iceberg_rest_uid": 0}, {}),
        ({}, {"HNX_SECRET_ICEBERG_REST_S3_SECRET_KEY": "short"}),
        ({}, {"HNX_SECRET_ICEBERG_REST_S3_ACCESS_KEY": "not-a-key"}),
    ],
)
@first_run(_first_catalog_main_refuses_bad_inputs_and_credentials)
def test_catalog_main_refuses_bad_inputs_and_credentials(first, over, env):
    r, tmp_path = first
    assert r.returncode != 0, r.stdout
    assert not (tmp_path / "app" / "docker-compose.yml").exists()


def _first_catalog_main_refuses_an_unset_secret_naming_its_reference(tmp_path):
    return {"role": CATALOG, "tasks_from": "main", "extra_vars": catalog_vars(tmp_path), "env": {}}


@first_run(_first_catalog_main_refuses_an_unset_secret_naming_its_reference)
def test_catalog_main_refuses_an_unset_secret_naming_its_reference(first):
    r, tmp_path = first
    assert r.returncode != 0
    assert "secret:iceberg-rest/s3-access-key" in r.stdout + r.stderr
    assert not (tmp_path / "app" / "docker-compose.yml").exists()


def _first_catalog_refuses_a_registry_row_that_is_not_an_object_store(tmp_path):
    v = catalog_vars(tmp_path, iceberg_rest_s3_url="", iceberg_rest_object_store_id="lake-catalog")
    return {"role": CATALOG, "tasks_from": "main", "extra_vars": v, "env": CATALOG_SECRETS}


@first_run(_first_catalog_refuses_a_registry_row_that_is_not_an_object_store)
def test_catalog_refuses_a_registry_row_that_is_not_an_object_store(first):
    r, _ = first
    assert r.returncode != 0 and "not an object-store" in r.stdout + r.stderr


def _fake_docker(tmp_path: Path, *, has_image: bool) -> dict:
    """A docker that knows the pinned digest only when has_image (or after `docker load`) and
    logs its calls."""
    bindir = tmp_path / "dbin"
    bindir.mkdir(exist_ok=True)
    flag, log = tmp_path / "image-present", tmp_path / "docker.log"
    if has_image:
        flag.touch()
    fake(
        bindir / "docker",
        "import os, sys\n"
        f"open({str(log)!r}, 'a').write(' '.join(sys.argv[1:]) + '\\n')\n"
        f"flag = {str(flag)!r}\n"
        "if sys.argv[1:3] == ['image', 'inspect']:\n    sys.exit(0 if os.path.exists(flag) else 1)\n"
        "if sys.argv[1] == 'load':\n    open(flag, 'w').close()\n",
    )
    return {"PATH": f"{bindir}:{os.environ['PATH']}"}


def _first_catalog_loads_the_pinned_image_from_the_archive_only_when_the_daemon_lacks_it(tmp_path):
    archive = tmp_path / "image.tar.zst"
    archive.write_bytes(b"not read by the fake")
    v = catalog_vars(tmp_path, iceberg_rest_image_archive=str(archive))
    env = {**CATALOG_SECRETS, **_fake_docker(tmp_path, has_image=False)}
    return {
        "role": CATALOG,
        "tasks_from": "main",
        "extra_vars": v,
        "env": env,
        "setup": {"archive": archive, "env": env, "v": v},
    }


@first_run(_first_catalog_loads_the_pinned_image_from_the_archive_only_when_the_daemon_lacks_it)
def test_catalog_loads_the_pinned_image_from_the_archive_only_when_the_daemon_lacks_it(first):
    first_result, tmp_path = first
    archive = first.setup["archive"]
    env = first.setup["env"]
    v = first.setup["v"]
    assert first_result.returncode == 0
    log = (tmp_path / "docker.log").read_text()
    assert f"load -i {archive}" in log
    (tmp_path / "docker.log").unlink()
    assert run_role(tmp_path, CATALOG, "main", v, env=env).returncode == 0  # present now: no load
    assert "load" not in (tmp_path / "docker.log").read_text()


def _first_catalog_refuses_when_the_archive_is_missing_or_does_not_bring_the_digest(tmp_path):
    v = catalog_vars(tmp_path, iceberg_rest_image_archive=str(tmp_path / "absent.tar.zst"))
    env = {**CATALOG_SECRETS, **_fake_docker(tmp_path, has_image=False)}
    return {"role": CATALOG, "tasks_from": "main", "extra_vars": v, "env": env}


@first_run(_first_catalog_refuses_when_the_archive_is_missing_or_does_not_bring_the_digest)
def test_catalog_refuses_when_the_archive_is_missing_or_does_not_bring_the_digest(first):
    r, tmp_path = first
    assert r.returncode != 0 and "not a regular file" in r.stdout + r.stderr
    assert not (tmp_path / "app" / "docker-compose.yml").exists()


def _catalog_db(path: Path) -> None:
    c = sqlite3.connect(path)
    c.execute("CREATE TABLE iceberg_tables (name TEXT)")
    c.execute("INSERT INTO iceberg_tables VALUES ('t')")
    c.commit()
    c.close()


def _catalog_script(name: str) -> str:
    vars_ = yaml.safe_load((Path(CATALOG) / "vars" / "main.yml").read_text())
    return vars_[name]


def _first_catalog_export_is_a_consistent_listed_copy(tmp_path):
    v = catalog_vars(tmp_path)
    return {
        "role": CATALOG,
        "tasks_from": "main",
        "extra_vars": v,
        "env": CATALOG_SECRETS,
        "setup": {"v": v},
    }


@first_run(_first_catalog_export_is_a_consistent_listed_copy)
def test_catalog_export_is_a_consistent_listed_copy(first):
    first_result, tmp_path = first
    v = first.setup["v"]
    assert first_result.returncode == 0
    _catalog_db(tmp_path / "data" / "catalog" / "iceberg_catalog.db")
    r = run_role(tmp_path, CATALOG, "export", v)
    assert r.returncode == 0, r.stdout + r.stderr
    export = tmp_path / "export"
    listing = json.loads((export / "listing.jsonl").read_text().splitlines()[0])
    assert listing["key"] == "iceberg_catalog.db"
    assert (
        listing["sha256"]
        == hashlib.sha256((export / "iceberg_catalog.db").read_bytes()).hexdigest()
    )
    assert sqlite3.connect(export / "iceberg_catalog.db").execute(
        "SELECT name FROM iceberg_tables"
    ).fetchall() == [("t",)]


def _restore(mode_args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-I", "-c", _catalog_script("iceberg_rest_restore_script"), *mode_args],
                          capture_output=True, text=True)  # fmt: skip


def _first_catalog_restore_installs_a_checked_export_and_refuses_a_tampered_one(tmp_path):
    v = catalog_vars(tmp_path)
    return {
        "role": CATALOG,
        "tasks_from": "main",
        "extra_vars": v,
        "env": CATALOG_SECRETS,
        "setup": {"v": v},
    }


@first_run(_first_catalog_restore_installs_a_checked_export_and_refuses_a_tampered_one)
def test_catalog_restore_installs_a_checked_export_and_refuses_a_tampered_one(first):
    first_result, tmp_path = first
    v = first.setup["v"]
    assert first_result.returncode == 0
    _catalog_db(tmp_path / "data" / "catalog" / "iceberg_catalog.db")
    assert run_role(tmp_path, CATALOG, "export", v).returncode == 0
    export, dest = tmp_path / "export", tmp_path / "restored"
    dest.mkdir()
    uid, gid = str(os.getuid()), str(os.getgid())
    assert _restore(["check", str(export), "iceberg_catalog.db", uid]).returncode == 0
    r = _restore(["apply", str(export), str(dest), uid, gid, "iceberg_catalog.db"])
    assert r.returncode == 0, r.stdout + r.stderr
    got = (
        sqlite3.connect(dest / "iceberg_catalog.db")
        .execute("SELECT name FROM iceberg_tables")
        .fetchall()
    )
    assert got == [("t",)]
    assert oct((dest / "iceberg_catalog.db").stat().st_mode & 0o777) == "0o600"
    # a stale write-ahead file next to the target must not survive into the restored database
    (dest / "iceberg_catalog.db-wal").write_text("stale")
    assert (
        _restore(["apply", str(export), str(dest), uid, gid, "iceberg_catalog.db"]).returncode == 0
    )
    assert not (dest / "iceberg_catalog.db-wal").exists()
    (export / "iceberg_catalog.db").write_bytes(b"tampered")
    for args in (["check", str(export), "iceberg_catalog.db", uid],
                 ["apply", str(export), str(dest), uid, gid, "iceberg_catalog.db"]):  # fmt: skip
        bad = _restore(args)
        assert bad.returncode != 0 and "restore refused" in bad.stderr + bad.stdout


def _first_catalog_restore_refuses_a_link_and_a_file_the_listing_does_not_name(tmp_path):
    v = catalog_vars(tmp_path)
    return {
        "role": CATALOG,
        "tasks_from": "main",
        "extra_vars": v,
        "env": CATALOG_SECRETS,
        "setup": {"v": v},
    }


@first_run(_first_catalog_restore_refuses_a_link_and_a_file_the_listing_does_not_name)
def test_catalog_restore_refuses_a_link_and_a_file_the_listing_does_not_name(first):
    first_result, tmp_path = first
    v = first.setup["v"]
    assert first_result.returncode == 0
    _catalog_db(tmp_path / "data" / "catalog" / "iceberg_catalog.db")
    assert run_role(tmp_path, CATALOG, "export", v).returncode == 0
    export = tmp_path / "export"
    uid = str(os.getuid())
    (export / "extra").write_text("x")
    assert _restore(["check", str(export), "iceberg_catalog.db", uid]).returncode != 0
    (export / "extra").unlink()
    link = tmp_path / "link"
    link.symlink_to(export)
    assert _restore(["check", str(link), "iceberg_catalog.db", uid]).returncode != 0


# ----------------------------------------------------------------------------- the query engine

TRINO = str(ROOT / "modules" / "trino" / "roles" / "trino")
TRINO_SECRETS = {
    "HNX_SECRET_TRINO_S3_ACCESS_KEY": KEY_ID,
    "HNX_SECRET_TRINO_S3_SECRET_KEY": KEY_SECRET,
    "HNX_SECRET_TRINO_TLS_CERT": CERT,
    "HNX_SECRET_TRINO_TLS_KEY": PKEY,
    "HNX_SECRET_TRINO_CA": CERT,
    "HNX_SECRET_TRINO_PASSWORD_DB": f"maintenance:{BCRYPT}\nalice:{BCRYPT}\n",
    "HNX_SECRET_TRINO_INTERNAL_SECRET": "s" * 40,
    "HNX_SECRET_TRINO_MAINTENANCE_PASSWORD": MAINT_PW,
    "HNX_SECRET_TRINO_NOTIFY_TOKEN": NOTIFY_TOKEN,
}


def trino_vars(tmp: Path, **kw) -> dict:
    bindir = tmp / "bin"
    bindir.mkdir(exist_ok=True)
    flag = tmp / "timer-enabled"
    fake(
        bindir / "systemctl",
        "import os, sys\n"
        f"flag = {str(flag)!r}\n"
        f"open({str(tmp / 'systemctl.log')!r}, 'a').write(' '.join(sys.argv[1:]) + '\\n')\n"
        f"active = {str(tmp / 'timer-active')!r}\n"
        "def touch(f):\n    open(f, 'w').close()\n"
        "def rm(f):\n    os.path.exists(f) and os.remove(f)\n"
        "if sys.argv[1:2] == ['enable']:\n    touch(flag)\n    '--now' in sys.argv and touch(active)\n"
        "if sys.argv[1:2] == ['disable']:\n    rm(flag)\n    '--now' in sys.argv and rm(active)\n"
        "if sys.argv[1:3] == ['stop', 'hnx-lake-maintenance.timer']:\n    rm(active)\n"
        "if sys.argv[1:2] == ['is-enabled']:\n"
        "    ok = os.path.exists(flag)\n    print('enabled' if ok else 'disabled')\n    sys.exit(0 if ok else 1)\n"
        "if sys.argv[1:2] == ['is-active']:\n"
        "    ok = os.path.exists(active)\n    print('active' if ok else 'inactive')\n    sys.exit(0 if ok else 3)\n",
    )
    v = {
        "trino_logical_id": "lake-query",
        "ansible_host": GUEST,
        "trino_dir": str(tmp / "app"),
        "trino_data_root": str(tmp / "data"),
        "trino_owner": USER,
        "trino_uid": os.getuid(),
        "trino_gid": os.getgid(),
        "trino_catalog_url": CATALOG_URL,
        "trino_s3_url": S3_URL,
        "trino_self_url": SELF_URL,
        "trino_notify_url": NOTIFY_URL,
        "trino_access_unrestricted": True,
        "trino_start": False,
        "trino_validate_with_docker": False,
        "trino_maintenance_acknowledged_restore": True,
        "trino_maintenance_script": str(tmp / "libexec" / "hnx-lake-maintenance"),
        "trino_maintenance_state_dir": str(tmp / "state"),
        "trino_maintenance_env_file": str(tmp / "etc-hnx" / "maintenance.env"),
        "trino_unit_dir": str(tmp / "units"),
        "trino_systemctl_cli": str(bindir / "systemctl"),
        **last_run_vars(tmp, "trino"),
        "trino_maintenance_owner": USER,
        "trino_maintenance_group": pwd.getpwuid(os.getuid()).pw_name,
    }
    (tmp / "units").mkdir(exist_ok=True)
    v.update(kw)
    return v


def _first_trino_main_renders_the_catalog_with_the_retention_floors_and_no_secret_in_a_file(
    tmp_path,
):
    v = trino_vars(tmp_path)
    return {
        "role": TRINO,
        "tasks_from": "main",
        "extra_vars": v,
        "env": TRINO_SECRETS,
        "setup": {"v": v},
    }


@first_run(_first_trino_main_renders_the_catalog_with_the_retention_floors_and_no_secret_in_a_file)
def test_trino_main_renders_the_catalog_with_the_retention_floors_and_no_secret_in_a_file(first):
    r, tmp_path = first
    v = first.setup["v"]
    assert r.returncode == 0, r.stdout + r.stderr
    etc = tmp_path / "app" / "etc"
    cat = (etc / "catalog" / "iceberg.properties").read_text()
    assert (
        "connector.name=iceberg" in cat
        and "iceberg.rest-catalog.warehouse=s3://iceberg-warehouse/" in cat
    )
    assert f"iceberg.rest-catalog.uri={CATALOG_URL}" in cat and f"s3.endpoint={S3_URL}" in cat
    # the engine's own floors under the maintenance procedures: 7 days to expire, 3 to remove orphans
    assert "iceberg.expire-snapshots.min-retention=7d" in cat
    assert "iceberg.remove-orphan-files.min-retention=3d" in cat
    assert "s3.aws-access-key=${ENV:TRINO_S3_ACCESS_KEY}" in cat
    conf = (etc / "config.properties").read_text()
    assert (
        "http-server.authentication.type=PASSWORD" in conf
        and "http-server.https.enabled=true" in conf
    )
    assert "sql.forced-session-time-zone=UTC" in conf
    assert "internal-communication.shared-secret=${ENV:TRINO_INTERNAL_SECRET}" in conf
    assert "access-control" not in conf  # no rules file given
    text = (tmp_path / "app" / "docker-compose.yml").read_text()
    svc = yaml.safe_load(text)["services"]["trino"]
    assert svc["ports"] == [GUEST + ":8443:8443"]  # only the HTTPS listener is published
    assert svc["image"].startswith("docker.io/trinodb/trino:484")
    for secret in (KEY_SECRET, MAINT_PW, "s" * 40, NOTIFY_TOKEN):
        assert secret not in text
        for f in etc.rglob("*"):
            if f.is_file() and f.name != "password.db":
                assert secret not in f.read_text(), f
    senv = (tmp_path / "app" / "secrets" / "trino.env").read_text()
    assert "TRINO_S3_SECRET_KEY=" in senv and "TRINO_INTERNAL_SECRET=" in senv
    # the key is the container's group's to read (LL-500), nobody else's
    pem = etc / "tls" / "server.pem"
    assert oct(pem.stat().st_mode & 0o777) == "0o640" and pem.stat().st_gid == os.getgid()
    assert pem.read_text().index("BEGIN CERTIFICATE") < pem.read_text().index("PRIVATE KEY")
    again = run_role(tmp_path, TRINO, "main", v, env=TRINO_SECRETS)
    assert again.returncode == 0 and "changed=0" in again.stdout, again.stdout


def _first_trino_main_installs_the_maintenance_timer_with_the_lake_retention_values(tmp_path):
    v = trino_vars(tmp_path)
    return {"role": TRINO, "tasks_from": "main", "extra_vars": v, "env": TRINO_SECRETS}


@first_run(_first_trino_main_installs_the_maintenance_timer_with_the_lake_retention_values)
def test_trino_main_installs_the_maintenance_timer_with_the_lake_retention_values(first):
    r, tmp_path = first
    assert r.returncode == 0, r.stdout + r.stderr
    timer = (tmp_path / "units" / "hnx-lake-maintenance.timer").read_text()
    assert "OnCalendar=*-*-* 03:30:00 UTC" in timer and "Persistent=false" in timer
    assert "OnBootSec" not in timer and "OnUnitActiveSec" not in timer  # LL-041
    service = (tmp_path / "units" / "hnx-lake-maintenance.service").read_text()
    assert "ExecStart=/usr/local/libexec/homelabnext/hnx-lake-maintenance" in service
    assert f"EnvironmentFile={tmp_path}/etc-hnx/maintenance.env" in service
    # the timer reports its runs like every role timer (role last_run), and a failed write is
    # visible: the writer is installed, the unit names it, and the record directory is writable
    assert "ExecStartPre=-/usr/local/libexec/homelabnext/hnx-last-run start" in service
    assert "ExecStopPost=-/usr/local/libexec/homelabnext/hnx-last-run finish" in service
    assert (
        "--job timer:trino/lake-maintenance" in service and f"--dir {tmp_path}/last-run" in service
    )
    assert os.access(tmp_path / "bin" / "hnx-last-run", os.X_OK)
    assert (tmp_path / "last-run").is_dir()
    env_file = tmp_path / "etc-hnx" / "maintenance.env"
    assert oct(env_file.stat().st_mode & 0o777) == "0o600"
    assert f"HNX_LAKE_MAINT_PASSWORD={MAINT_PW}" in env_file.read_text()
    out = subprocess.run([sys.executable, str(tmp_path / "libexec" / "hnx-lake-maintenance"), "--dry-run"],
                         capture_output=True, text=True, env={**os.environ, "HNX_LAKE_MAINT_PASSWORD": MAINT_PW})  # fmt: skip
    script = (tmp_path / "libexec" / "hnx-lake-maintenance").read_text()
    # the retention values the lake keeps: expire older than 7 days keeping the last 10, orphans older than 3 days
    assert (
        '"expire": "7d"' in script and '"retain_last": 10' in script and '"orphan": "3d"' in script
    )
    assert "retain_last => " in script and "remove_orphan_files(retention_threshold" in script
    assert out.returncode != 0  # no engine is listening: the run must say so, not pass
    assert MAINT_PW not in script and NOTIFY_TOKEN not in script


def _first_trino_main_names_a_catalog_that_serves_its_api_under_a_path_by_warehouse_name(tmp_path):
    v = trino_vars(tmp_path, trino_catalog_path="/catalog", trino_warehouse="lake")
    return {"role": TRINO, "tasks_from": "main", "extra_vars": v, "env": TRINO_SECRETS}


@first_run(_first_trino_main_names_a_catalog_that_serves_its_api_under_a_path_by_warehouse_name)
def test_trino_main_names_a_catalog_that_serves_its_api_under_a_path_by_warehouse_name(first):
    r, tmp_path = first
    assert r.returncode == 0, r.stdout + r.stderr
    cat = (tmp_path / "app" / "etc" / "catalog" / "iceberg.properties").read_text()
    assert f"iceberg.rest-catalog.uri={CATALOG_URL}/catalog\n" in cat
    assert "iceberg.rest-catalog.warehouse=lake\n" in cat
    assert (
        "iceberg.rest-catalog.vended-credentials-enabled=false" in cat
    )  # the engine keeps its own key


def _first_trino_main_refuses_bad_inputs_and_credentials(tmp_path, over, env):
    return {
        "role": TRINO,
        "tasks_from": "main",
        "extra_vars": trino_vars(tmp_path, **over),
        "env": {**TRINO_SECRETS, **env},
    }


@pytest.mark.parametrize(
    "over, env",
    [
        ({"trino_image": "docker.io/trinodb/trino:latest"}, {}),
        ({"trino_catalog_name": "lake"}, {}),
        ({"trino_catalog_path": "catalog"}, {}),  # a path starts with a slash
        ({"trino_catalog_path": "//catalog"}, {}),
        ({"trino_catalog_path": "/a b"}, {}),
        ({"trino_warehouse": "Bad Name"}, {}),
        ({"trino_uid": 0}, {}),
        (
            {"trino_expire_retention": "3d"},
            {},
        ),  # below the engine's floor: it would refuse every run
        ({"trino_orphan_retention": "1d"}, {}),
        ({"trino_retain_last": 0}, {}),
        (
            {"trino_heap": "4G", "trino_query_max_memory": "9GB"},
            {},
        ),  # per-query bound over 70% of the heap
        ({"trino_mem_limit": "15g"}, {}),  # container limit under heap + 2 GB
        (
            {"trino_notify_url": PLAIN_NOTIFY_URL},
            {},
        ),
        ({}, {"HNX_SECRET_TRINO_PASSWORD_DB": "alice:plaintext\n"}),
        ({}, {"HNX_SECRET_TRINO_PASSWORD_DB": f"alice:{BCRYPT}\n"}),  # no maintenance user
        ({}, {"HNX_SECRET_TRINO_TLS_KEY": "not a key"}),
        ({}, {"HNX_SECRET_TRINO_INTERNAL_SECRET": "short"}),
        ({}, {"HNX_SECRET_TRINO_S3_SECRET_KEY": "short"}),
    ],
)
@first_run(_first_trino_main_refuses_bad_inputs_and_credentials)
def test_trino_main_refuses_bad_inputs_and_credentials(first, over, env):
    r, tmp_path = first
    assert r.returncode != 0, r.stdout
    assert not (tmp_path / "app" / "docker-compose.yml").exists()
    assert MAINT_PW not in r.stdout and KEY_SECRET not in r.stdout


def _first_trino_main_refuses_an_unset_secret_naming_its_reference(tmp_path):
    env = {k: v for k, v in TRINO_SECRETS.items() if k != "HNX_SECRET_TRINO_PASSWORD_DB"}
    return {"role": TRINO, "tasks_from": "main", "extra_vars": trino_vars(tmp_path), "env": env}


@first_run(_first_trino_main_refuses_an_unset_secret_naming_its_reference)
def test_trino_main_refuses_an_unset_secret_naming_its_reference(first):
    r, tmp_path = first
    assert r.returncode != 0
    assert "secret:trino/password-db" in r.stdout + r.stderr
    assert not (tmp_path / "app" / "docker-compose.yml").exists()


def _first_trino_notify_token_over_plain_http_needs_the_site_opt_in(tmp_path):
    plain = PLAIN_NOTIFY_URL
    return {
        "role": TRINO,
        "tasks_from": "main",
        "extra_vars": trino_vars(tmp_path, trino_notify_url=plain),
        "env": TRINO_SECRETS,
        "setup": {"plain": plain},
    }


@first_run(_first_trino_notify_token_over_plain_http_needs_the_site_opt_in)
def test_trino_notify_token_over_plain_http_needs_the_site_opt_in(first):
    r, tmp_path = first
    plain = first.setup["plain"]
    assert r.returncode != 0 and "trino_notify_allow_plain_http" in r.stdout + r.stderr
    ok = run_role(tmp_path, TRINO, "main",
                  trino_vars(tmp_path, trino_notify_url=plain, trino_notify_allow_plain_http=True),
                  env=TRINO_SECRETS)  # fmt: skip
    assert ok.returncode == 0, ok.stdout + ok.stderr


def _first_trino_refuses_to_run_without_access_rules_unless_unrestricted_is_said(tmp_path):
    v = trino_vars(tmp_path, trino_access_unrestricted=False)
    return {
        "role": TRINO,
        "tasks_from": "main",
        "extra_vars": v,
        "env": TRINO_SECRETS,
        "setup": {"v": v},
    }


@first_run(_first_trino_refuses_to_run_without_access_rules_unless_unrestricted_is_said)
def test_trino_refuses_to_run_without_access_rules_unless_unrestricted_is_said(first):
    r, tmp_path = first
    v = first.setup["v"]
    assert r.returncode != 0 and "trino_access_unrestricted" in r.stdout + r.stderr
    assert not (tmp_path / "app" / "docker-compose.yml").exists()
    rules = Path(TRINO) / "files" / "lake-access.example.json"
    ok = run_role(
        tmp_path, TRINO, "main", {**v, "trino_access_rules_src": str(rules)}, env=TRINO_SECRETS
    )
    assert ok.returncode == 0, ok.stdout + ok.stderr


@pytest.mark.static
def test_the_shipped_example_rules_let_only_the_maintenance_user_change_the_lake():
    rules = json.loads((Path(TRINO) / "files" / "lake-access.example.json").read_text())
    tables = rules["tables"]
    assert (
        tables[0]["user"] == "maintenance" and "OWNERSHIP" in tables[0]["privileges"]
    )  # the maintenance user owns the tables
    assert tables[-1] == {"privileges": ["SELECT"]}  # everyone else reads only
    assert {"catalog": "iceberg", "allow": "read-only"} in rules["catalogs"]
    assert {"owner": False} in rules["schemas"]


def _first_trino_renders_a_read_only_reader_catalog_only_when_asked(tmp_path):
    cat = tmp_path / "app" / "etc" / "catalog"
    return {
        "role": TRINO,
        "tasks_from": "main",
        "extra_vars": trino_vars(tmp_path),
        "env": TRINO_SECRETS,
        "setup": {"cat": cat},
    }


@first_run(_first_trino_renders_a_read_only_reader_catalog_only_when_asked)
def test_trino_renders_a_read_only_reader_catalog_only_when_asked(first):
    first_result, tmp_path = first
    cat = first.setup["cat"]
    assert first_result.returncode == 0
    assert sorted(p.name for p in cat.iterdir()) == ["iceberg.properties"]
    assert "iceberg.security" not in (cat / "iceberg.properties").read_text()
    v = trino_vars(tmp_path, trino_reader_catalog="iceberg_ro")
    assert run_role(tmp_path, TRINO, "main", v, env=TRINO_SECRETS).returncode == 0
    ro = (cat / "iceberg_ro.properties").read_text()
    assert (
        "iceberg.security=read-only" in ro
        and "iceberg.rest-catalog.warehouse=s3://iceberg-warehouse/" in ro
    )
    assert (
        "iceberg.security" not in (cat / "iceberg.properties").read_text()
    )  # writers keep iceberg
    for bad in ("iceberg", "Bad-Name"):
        r = run_role(
            tmp_path,
            TRINO,
            "main",
            trino_vars(tmp_path, trino_reader_catalog=bad),
            env=TRINO_SECRETS,
        )
        assert r.returncode != 0, bad


def _first_trino_installs_the_access_rules_when_given_and_removes_them_when_not(tmp_path):
    rules = tmp_path / "rules.json"
    rules.write_text('{"catalogs": []}\n')
    v = trino_vars(tmp_path, trino_access_rules_src=str(rules))
    return {"role": TRINO, "tasks_from": "main", "extra_vars": v, "env": TRINO_SECRETS}


@first_run(_first_trino_installs_the_access_rules_when_given_and_removes_them_when_not)
def test_trino_installs_the_access_rules_when_given_and_removes_them_when_not(first):
    first_result, tmp_path = first
    assert first_result.returncode == 0
    etc = tmp_path / "app" / "etc"
    assert (etc / "lake-access.json").read_text() == '{"catalogs": []}\n'
    assert (
        "security.config-file=/etc/trino/lake-access.json"
        in (etc / "access-control.properties").read_text()
    )
    assert (
        "access-control.config-files=/etc/trino/access-control.properties"
        in (etc / "config.properties").read_text()
    )
    assert (
        run_role(tmp_path, TRINO, "main", trino_vars(tmp_path), env=TRINO_SECRETS).returncode == 0
    )
    assert (
        not (etc / "lake-access.json").exists() and not (etc / "access-control.properties").exists()
    )


def _first_trino_without_the_maintenance_timer_installs_none_and_needs_none_of_its_secrets(
    tmp_path,
):
    v = trino_vars(tmp_path, trino_maintenance_enabled=False, trino_notify_url="")
    env = {k: x for k, x in TRINO_SECRETS.items() if "MAINTENANCE" not in k and "NOTIFY" not in k}
    return {"role": TRINO, "tasks_from": "main", "extra_vars": v, "env": env}


@first_run(_first_trino_without_the_maintenance_timer_installs_none_and_needs_none_of_its_secrets)
def test_trino_without_the_maintenance_timer_installs_none_and_needs_none_of_its_secrets(first):
    r, tmp_path = first
    assert r.returncode == 0, r.stdout + r.stderr
    assert not (tmp_path / "units" / "hnx-lake-maintenance.timer").exists()
    assert not (tmp_path / "libexec").exists()


# ----------------------------------------------------------------------------- the maintenance script


class _Engine(http.server.ThreadingHTTPServer):
    """A stand-in for the engine's statement protocol: tables listed, each statement logged, and
    the statements named in ``fail`` answered with a query error."""

    def __init__(self, tables, fail=(), list_fails=False, hang=(), stuck=False):
        super().__init__(("localhost", 0), _EngineHandler)
        self.tables, self.fail, self.list_fails = tables, set(fail), list_fails
        self.hang = set(hang)  # statements containing one of these never finish (nextUri forever)
        self.statements: list[str] = []
        self.deletes: list[str] = []
        self.stuck = stuck  # a cancel and kill_query do not stop the hung query
        self.killed: set[str] = set()
        self.users: list[str] = []


class _EngineHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _json(self, body):
        raw = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):  # polling a hung query: never done
        self._json(
            {"id": "q_hung_1", "nextUri": f"http://localhost:{self.server.server_port}{self.path}"}
        )

    def do_DELETE(self):
        self.server.deletes.append(self.path)
        if not self.server.stuck:
            self.server.killed.add(self.path.split("/")[3])
        self.send_response(204)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_POST(self):
        sql = self.rfile.read(int(self.headers["Content-Length"])).decode()
        self.server.statements.append(sql)
        self.server.users.append(self.headers.get("X-Trino-User", ""))
        body: dict
        if "kill_query" in sql:
            if not self.server.stuck:
                self.server.killed.add(sql.split("query_id => '")[1].split("'")[0])
            body = {"id": "kill", "columns": [], "data": []}
        elif "system.runtime.queries" in sql:
            qid = sql.split("query_id = '")[1].split("'")[0]
            state = "FAILED" if qid in self.server.killed else "RUNNING"
            body = {"id": "poll", "columns": [{"name": "state"}], "data": [[state]]}
        elif any(h in sql for h in self.server.hang):
            body = {
                "id": "q_hung_1",
                "nextUri": f"http://localhost:{self.server.server_port}/v1/statement/q_hung_1/1",
            }
        elif "information_schema.tables" in sql:
            body = {"error": {"message": "engine down"}} if self.server.list_fails else {
                "columns": [{"name": "table_schema"}, {"name": "table_name"}],
                "data": [list(t) for t in self.server.tables]}  # fmt: skip
        elif any(f in sql for f in self.server.fail):
            body = {"error": {"message": "Java heap space", "errorName": "GENERIC_INTERNAL_ERROR"}}
        else:
            body = {"columns": [{"name": "metric"}], "data": [["processed_manifests_count"]]}
        raw = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


class _Notify(http.server.ThreadingHTTPServer):
    def __init__(self):
        super().__init__(("localhost", 0), _NotifyHandler)
        self.messages: list[dict] = []


class _NotifyHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"])).decode()
        self.server.messages.append({"path": self.path, "title": self.headers.get("Title"),
                                     "auth": self.headers.get("Authorization"), "body": body})  # fmt: skip
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()


def _serve(server):
    threading.Thread(
        target=server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True
    ).start()
    return server


@pytest.fixture
def maintenance(tmp_path):
    """The role's rendered maintenance script, pointed at stand-in engine and notify servers."""
    env = dict(TRINO_SECRETS)
    v = trino_vars(tmp_path)
    assert run_role(tmp_path, TRINO, "main", v, env=env).returncode == 0
    script = tmp_path / "libexec" / "hnx-lake-maintenance"
    text = script.read_text()
    engine_pins = []

    def prepare(engine, notify, cfg_over):
        cfg_line = next(line for line in text.splitlines() if line.startswith("CONFIG = "))
        cfg = json.loads(cfg_line[len("CONFIG = ") :])
        cfg["url"] = f"http://localhost:{engine.server_port}"
        cfg["notify_url"] = f"http://localhost:{notify.server_port}"
        cfg.update(cfg_over)
        patched = tmp_path / "run-maintenance.py"
        patched.write_text(text.replace(cfg_line, "CONFIG = " + json.dumps(cfg)))
        engine_pins.append(cfg)
        return patched

    child_env = {**os.environ, "HNX_LAKE_MAINT_PASSWORD": MAINT_PW,
                 "HNX_LAKE_MAINT_NOTIFY_TOKEN": NOTIFY_TOKEN}  # fmt: skip

    def run(engine, notify, *args, cfg=None):
        patched = prepare(engine, notify, cfg or {})
        return subprocess.run([sys.executable, str(patched), *args], capture_output=True, text=True,
                              env=child_env)  # fmt: skip

    def start(engine, notify, *args, cfg=None):
        patched = prepare(engine, notify, cfg or {})
        return subprocess.Popen([sys.executable, str(patched), *args], stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True, env=child_env)  # fmt: skip

    run.start = start
    run.config = lambda: json.loads(
        next(ln for ln in text.splitlines() if ln.startswith("CONFIG = "))[len("CONFIG = ") :]
    )
    run.state = tmp_path / "state" / "state.json"
    return run


def test_maintenance_expires_then_removes_orphans_on_every_table_with_the_lake_retention(
    maintenance,
):
    engine, notify = _serve(_Engine([("cti", "nrd"), ("rba", "rule_runs")])), _serve(_Notify())
    try:
        r = maintenance(engine, notify)
    finally:
        engine.shutdown(), notify.shutdown()
    assert r.returncode == 0, r.stdout + r.stderr
    sql = [s for s in engine.statements if s.startswith("ALTER TABLE")]
    assert sql == [
        'ALTER TABLE iceberg."cti"."nrd" EXECUTE expire_snapshots(retention_threshold => \'7d\', retain_last => 10, clean_expired_metadata => true)',
        'ALTER TABLE iceberg."cti"."nrd" EXECUTE remove_orphan_files(retention_threshold => \'3d\')',
        'ALTER TABLE iceberg."rba"."rule_runs" EXECUTE expire_snapshots(retention_threshold => \'7d\', retain_last => 10, clean_expired_metadata => true)',
        'ALTER TABLE iceberg."rba"."rule_runs" EXECUTE remove_orphan_files(retention_threshold => \'3d\')',
    ]  # fmt: skip
    # the listing skips the engine's own system schema and views (a procedure on either fails)
    listing = next(s for s in engine.statements if "information_schema.tables" in s)
    assert "BASE TABLE" in listing and "'system'" in listing
    assert set(engine.users) == {"maintenance"}
    assert notify.messages == []  # nothing failed: nothing is said


def test_maintenance_alerts_once_per_change_of_the_failing_set_and_once_when_it_recovers(
    maintenance,
):
    engine, notify = _serve(_Engine([("cti", "nrd")], fail=["expire_snapshots"])), _serve(_Notify())
    try:
        first = maintenance(engine, notify)
        second = maintenance(engine, notify)  # the same failure again: silent
        assert first.returncode == 1 and second.returncode == 1
        assert len(notify.messages) == 1
        m = notify.messages[0]
        assert m["path"] == "/lake-maintenance" and m["auth"] == f"Bearer {NOTIFY_TOKEN}"
        assert "cti.nrd:expire_snapshots" in m["body"] and "Java heap space" in m["body"]
        state = json.loads(maintenance.state.read_text())
        assert state["alerted"] == ["cti.nrd:expire_snapshots"]
        assert oct(maintenance.state.stat().st_mode & 0o777) == "0o600"
        engine.fail = set()  # fixed
        third = maintenance(engine, notify)
        assert third.returncode == 0
        assert len(notify.messages) == 2 and "recovered" in notify.messages[1]["title"]
        assert maintenance(engine, notify).returncode == 0 and len(notify.messages) == 2
    finally:
        engine.shutdown(), notify.shutdown()
    for r in (first, second, third):
        assert MAINT_PW not in r.stdout + r.stderr and NOTIFY_TOKEN not in r.stdout + r.stderr


def test_maintenance_that_cannot_list_the_tables_exits_two_and_says_so_once(maintenance):
    engine, notify = _serve(_Engine([], list_fails=True)), _serve(_Notify())
    try:
        a, b = maintenance(engine, notify), maintenance(engine, notify)
    finally:
        engine.shutdown(), notify.shutdown()
    assert a.returncode == 2 and b.returncode == 2
    assert len(notify.messages) == 1 and "run:list-tables" in notify.messages[0]["body"]


def test_maintenance_never_puts_an_unsafe_table_name_in_a_statement(maintenance):
    engine, notify = (
        _serve(_Engine([("cti", 'x"; DROP TABLE y; --'), ("cti", "ok")])),
        _serve(_Notify()),
    )
    try:
        r = maintenance(engine, notify)
    finally:
        engine.shutdown(), notify.shutdown()
    assert r.returncode == 1
    assert not any("DROP" in s for s in engine.statements)
    assert any('"ok"' in s for s in engine.statements)
    assert len(notify.messages) == 1


def test_maintenance_test_notify_sends_one_low_priority_message(maintenance):
    engine, notify = _serve(_Engine([])), _serve(_Notify())
    try:
        r = maintenance(engine, notify, "--test-notify")
    finally:
        engine.shutdown(), notify.shutdown()
    assert r.returncode == 0 and len(notify.messages) == 1 and engine.statements == []


@pytest.mark.static
def test_no_rendered_file_names_the_workstation_or_wsl():
    """Review Focus 5: nothing the lake modules render may call the operator's workstation."""
    for module in ("garage", "iceberg-rest", "trino"):
        for f in (ROOT / "modules" / module).rglob("*"):
            if f.is_file():
                text = f.read_text()
                assert not re.search(r"192\.168\.20\.150|wsl", text, re.I), f


# ----------------------------------------------------------------------------- the maintenance guards (RCA 2026-11-17)


def _with(engine, notify, fn):
    try:
        return fn()
    finally:
        engine.shutdown(), notify.shutdown()


def test_maintenance_cancels_the_query_on_the_engine_at_the_deadline(maintenance):
    engine = _serve(_Engine([("cti", "nrd")], hang=["expire_snapshots"]))
    notify = _serve(_Notify())
    r = _with(
        engine,
        notify,
        lambda: maintenance(engine, notify, cfg={"expire_timeout": 1, "cancel_poll": 0.1}),
    )
    assert r.returncode == 1, r.stdout + r.stderr
    # the engine was told to stop the query (the protocol's DELETE), then asked to kill it by id
    assert engine.deletes == ["/v1/statement/q_hung_1/1"]
    assert any("kill_query(query_id => 'q_hung_1'" in s for s in engine.statements)
    assert "no result within 1 s" in notify.messages[0]["body"]
    # and the next step was not started behind it: orphan removal never ran after the failed expire
    assert not any("remove_orphan_files" in s for s in engine.statements)


def test_maintenance_cancels_the_running_query_and_alerts_on_sigterm(maintenance):
    engine = _serve(_Engine([("cti", "a"), ("cti", "b")], hang=["expire_snapshots"]))
    notify = _serve(_Notify())
    proc = maintenance.start(engine, notify)
    try:
        for _ in range(100):
            if any("expire_snapshots" in s for s in engine.statements):
                break
            time.sleep(0.1)
        else:
            pytest.fail("the expire statement never reached the engine")
        proc.send_signal(signal.SIGTERM)
        out, err = proc.communicate(timeout=30)
    finally:
        proc.kill()
        engine.shutdown(), notify.shutdown()
    assert proc.returncode == 143, out + err
    assert engine.deletes, "the in-flight query was not cancelled"
    assert any("kill_query" in s for s in engine.statements)
    state = json.loads(maintenance.state.read_text())
    assert state["terminated"] is True and state["unfinished"] == ["cti.a", "cti.b"]
    assert len(notify.messages) == 1
    assert "cti.a" in notify.messages[0]["body"] and "cti.b" in notify.messages[0]["body"]


def test_maintenance_skips_a_table_with_unreadable_history_and_marks_the_run_degraded(maintenance):
    engine = _serve(
        _Engine([("cti", "dangling"), ("cti", "fine")], fail=['"dangling$all_manifests"'])
    )
    notify = _serve(_Notify())
    r = _with(engine, notify, lambda: maintenance(engine, notify))
    assert r.returncode == 3, r.stdout + r.stderr  # degraded, not a clean run
    assert "cti.dangling: skipped: unreadable history" in r.stderr
    alters = [s for s in engine.statements if s.startswith("ALTER")]
    assert alters and all('"fine"' in s for s in alters)  # nothing was done to the unreadable table
    assert any('"dangling$snapshots"' in s for s in engine.statements)
    assert any('"fine$all_manifests"' in s for s in engine.statements)
    state = json.loads(maintenance.state.read_text())
    assert state["degraded"] is True and "cti.dangling:preflight" in state["failed"]
    assert len(notify.messages) == 1 and "cti.dangling:preflight" in notify.messages[0]["body"]
    assert "unreadable history" in notify.messages[0]["body"]


def test_maintenance_never_removes_orphans_after_an_expire_that_did_not_succeed(maintenance):
    engine = _serve(_Engine([("cti", "a"), ("cti", "b")], fail=['"a" EXECUTE expire_snapshots']))
    notify = _serve(_Notify())
    r = _with(engine, notify, lambda: maintenance(engine, notify))
    assert r.returncode == 1
    orphans = [s for s in engine.statements if "remove_orphan_files" in s]
    assert orphans == [
        'ALTER TABLE iceberg."cti"."b" EXECUTE remove_orphan_files(retention_threshold => \'3d\')'
    ]
    state = json.loads(maintenance.state.read_text())
    assert state["skipped"]["cti.a:remove_orphan_files"].startswith(
        "expire_snapshots did not succeed"
    )


def test_maintenance_allow_and_deny_globs_pick_the_tables_and_deny_wins(maintenance):
    tables = [
        ("cti", "a"),
        ("cti", "secret_tbl"),
        ("rba", "x"),
        ("cape", "ioc"),
        ("honeypot", "events"),
    ]
    engine, notify = _serve(_Engine(tables)), _serve(_Notify())
    cfg = {"allow": ["cti", "cape.*", "honeypot.events", "rba"], "skip": ["rba", "cti.secret_*"]}
    r = _with(engine, notify, lambda: maintenance(engine, notify, cfg=cfg))
    assert r.returncode == 0, r.stdout + r.stderr
    touched = {
        s.split('"')[1] + "." + s.split('"')[3] for s in engine.statements if s.startswith("ALTER")
    }
    assert touched == {"cti.a", "cape.ioc", "honeypot.events"}


def test_maintenance_per_schema_overrides_set_retention_and_can_turn_orphans_off(maintenance):
    engine, notify = _serve(_Engine([("cti", "a"), ("rba", "x")])), _serve(_Notify())
    cfg = {"overrides": {"cti": {"expire": "90d", "retain_last": 50, "orphan_retention": "9d"},
                         "rba": {"orphan": False}}}  # fmt: skip
    r = _with(engine, notify, lambda: maintenance(engine, notify, cfg=cfg))
    assert r.returncode == 0, r.stdout + r.stderr
    alters = [s for s in engine.statements if s.startswith("ALTER")]
    assert alters == [
        'ALTER TABLE iceberg."cti"."a" EXECUTE expire_snapshots(retention_threshold => \'90d\', retain_last => 50, clean_expired_metadata => true)',
        'ALTER TABLE iceberg."cti"."a" EXECUTE remove_orphan_files(retention_threshold => \'9d\')',
        'ALTER TABLE iceberg."rba"."x" EXECUTE expire_snapshots(retention_threshold => \'7d\', retain_last => 10, clean_expired_metadata => true)',
    ]  # fmt: skip


def _first_the_rendered_config_carries_the_allow_skip_and_override_lists(tmp_path):
    v = trino_vars(
        tmp_path,
        trino_maintenance_schemas=["cti", "cape.*"],
        trino_maintenance_skip=["rba"],
        trino_maintenance_overrides={"cti": {"expire": "90d", "retain_last": 50}},
        trino_preflight_timeout=42,
    )
    return {"role": TRINO, "tasks_from": "main", "extra_vars": v, "env": TRINO_SECRETS}


@first_run(_first_the_rendered_config_carries_the_allow_skip_and_override_lists)
def test_the_rendered_config_carries_the_allow_skip_and_override_lists(first):
    r, tmp_path = first
    assert r.returncode == 0, r.stdout + r.stderr
    line = next(
        ln for ln in (tmp_path / "libexec" / "hnx-lake-maintenance").read_text().splitlines()
        if ln.startswith("CONFIG = ")
    )  # fmt: skip
    cfg = json.loads(line[len("CONFIG = ") :])
    assert cfg["allow"] == ["cti", "cape.*"] and cfg["skip"] == ["rba"]
    assert cfg["overrides"] == {"cti": {"expire": "90d", "retain_last": 50}}
    assert cfg["preflight_timeout"] == 42


def _first_trino_refuses_unsafe_maintenance_lists_and_overrides(tmp_path, over):
    return {
        "role": TRINO,
        "tasks_from": "main",
        "extra_vars": trino_vars(tmp_path, **over),
        "env": TRINO_SECRETS,
    }


@pytest.mark.parametrize(
    "over",
    [
        {"trino_maintenance_schemas": []},
        {"trino_maintenance_schemas": ["cti; DROP"]},
        {"trino_maintenance_skip": ["a.b.c"]},
        {"trino_maintenance_skip": ["RBA"]},  # upper case would silently match nothing
        {"trino_maintenance_schemas": ["CTI"]},
        {"trino_maintenance_overrides": {"CTI": {"expire": "30d"}}},
        {"trino_cancel_confirm_timeout": 1},
        {"trino_maintenance_catch_up": "sometimes"},
        {"trino_maintenance_skip": ["bad name"]},
        {"trino_maintenance_overrides": {"cti": {"expire": "2d"}}},  # under the engine's floor
        {"trino_maintenance_overrides": {"cti": {"orphan_retention": "1d"}}},
        {"trino_maintenance_overrides": {"cti": {"retain_last": 0}}},
        {"trino_maintenance_overrides": {"cti": {"retain_last": 5000}}},
        {"trino_maintenance_overrides": {"cti": {"orphan": "maybe"}}},
        {"trino_maintenance_overrides": {"cti": {"bogus": 1}}},
        {"trino_maintenance_overrides": {"bad schema": {"expire": "30d"}}},
        {"trino_maintenance_overrides": {"cti": "30d"}},
        {"trino_maintenance_overrides": ["cti"]},
        {"trino_preflight_timeout": 1},
    ],
)
@first_run(_first_trino_refuses_unsafe_maintenance_lists_and_overrides)
def test_trino_refuses_unsafe_maintenance_lists_and_overrides(first, over):
    r, tmp_path = first
    assert r.returncode != 0
    assert not (tmp_path / "units" / "hnx-lake-maintenance.timer").exists()


def _first_trino_is_not_armed_on_a_lake_nobody_acknowledged_and_arms_once_acknowledged(tmp_path):
    log = tmp_path / "systemctl.log"
    v = trino_vars(tmp_path, trino_maintenance_acknowledged_restore=False)
    return {
        "role": TRINO,
        "tasks_from": "main",
        "extra_vars": v,
        "env": TRINO_SECRETS,
        "setup": {"log": log, "v": v},
    }


@first_run(_first_trino_is_not_armed_on_a_lake_nobody_acknowledged_and_arms_once_acknowledged)
def test_trino_is_not_armed_on_a_lake_nobody_acknowledged_and_arms_once_acknowledged(first):
    r, tmp_path = first
    log = first.setup["log"]
    v = first.setup["v"]
    assert r.returncode == 0, r.stdout + r.stderr
    # installed (so it can be armed later) but never enabled or started
    assert (tmp_path / "units" / "hnx-lake-maintenance.timer").exists()
    assert not (tmp_path / "timer-enabled").exists()
    assert not any(ln.startswith("enable") for ln in log.read_text().splitlines())
    v["trino_maintenance_acknowledged_restore"] = True
    again = run_role(tmp_path, TRINO, "main", v, env=TRINO_SECRETS)
    assert again.returncode == 0, again.stdout + again.stderr
    assert "enable --now hnx-lake-maintenance.timer" in log.read_text()
    assert (tmp_path / "timer-enabled").exists()


def test_trino_default_is_not_armed_until_the_operator_acknowledges(tmp_path):
    v = trino_vars(tmp_path)
    del v["trino_maintenance_acknowledged_restore"]
    r = run_role(tmp_path, TRINO, "main", v, env=TRINO_SECRETS)
    assert r.returncode == 0, r.stdout + r.stderr
    assert not (tmp_path / "timer-enabled").exists()


def _first_trino_disarms_an_installed_timer_when_it_loses_its_acknowledgement(tmp_path):
    v = trino_vars(tmp_path)
    return {
        "role": TRINO,
        "tasks_from": "main",
        "extra_vars": v,
        "env": TRINO_SECRETS,
        "setup": {"v": v},
    }


@first_run(_first_trino_disarms_an_installed_timer_when_it_loses_its_acknowledgement)
def test_trino_disarms_an_installed_timer_when_it_loses_its_acknowledgement(first):
    first_result, tmp_path = first
    v = first.setup["v"]
    assert first_result.returncode == 0
    assert (tmp_path / "timer-enabled").exists()
    v["trino_maintenance_acknowledged_restore"] = False
    r = run_role(tmp_path, TRINO, "main", v, env=TRINO_SECRETS)
    assert r.returncode == 0, r.stdout + r.stderr
    log = (tmp_path / "systemctl.log").read_text()
    assert "disable --now hnx-lake-maintenance.timer" in log
    assert "stop hnx-lake-maintenance.service" in log
    assert not (tmp_path / "timer-enabled").exists()


def _first_trino_with_maintenance_disabled_stops_and_disables_an_installed_timer(tmp_path):
    v = trino_vars(tmp_path)
    return {"role": TRINO, "tasks_from": "main", "extra_vars": v, "env": TRINO_SECRETS}


@first_run(_first_trino_with_maintenance_disabled_stops_and_disables_an_installed_timer)
def test_trino_with_maintenance_disabled_stops_and_disables_an_installed_timer(first):
    first_result, tmp_path = first
    assert first_result.returncode == 0
    assert (tmp_path / "timer-enabled").exists()
    off = trino_vars(tmp_path, trino_maintenance_enabled=False, trino_notify_url="")
    env = {k: x for k, x in TRINO_SECRETS.items() if "MAINTENANCE" not in k and "NOTIFY" not in k}
    r = run_role(tmp_path, TRINO, "main", off, env=env)
    assert r.returncode == 0, r.stdout + r.stderr
    log = (tmp_path / "systemctl.log").read_text()
    assert "disable --now hnx-lake-maintenance.timer" in log
    assert not (tmp_path / "timer-enabled").exists()
    # and a host that never had the timer is left alone: no systemctl call at all
    fresh = tmp_path / "fresh"
    fresh.mkdir()
    r2 = run_role(
        fresh,
        TRINO,
        "main",
        trino_vars(fresh, trino_maintenance_enabled=False, trino_notify_url=""),
        env=env,
    )
    assert r2.returncode == 0, r2.stdout + r2.stderr
    assert (
        "disable" not in (fresh / "systemctl.log").read_text()
        if (fresh / "systemctl.log").exists()
        else True
    )


# ----------------------------------------------------------------------------- review follow-ups (PR 466)

FAST_CANCEL = {"cancel_wait": 1, "cancel_poll": 0.1}


def test_a_cancelled_query_is_confirmed_gone_in_the_engines_query_list_before_the_run_goes_on(
    maintenance,
):
    engine = _serve(_Engine([("cti", "a"), ("cti", "b")], hang=['"a" EXECUTE expire_snapshots']))
    notify = _serve(_Notify())
    cfg = {"expire_timeout": 1, **FAST_CANCEL}
    r = _with(engine, notify, lambda: maintenance(engine, notify, cfg=cfg))
    assert r.returncode == 1, r.stdout + r.stderr  # a's expire failed; the run went on to b
    polls = [x for x in engine.statements if "system.runtime.queries" in x]
    assert polls and "query_id = 'q_hung_1'" in polls[0]
    assert any('"b" EXECUTE expire_snapshots' in x for x in engine.statements)
    assert "run:aborted" not in json.loads(maintenance.state.read_text())["failed"]


def test_a_cancelled_query_still_running_stops_the_whole_run_degraded_with_one_alert(maintenance):
    engine = _serve(
        _Engine([("cti", "a"), ("cti", "b"), ("cti", "c")], hang=['"a" EXECUTE expire_snapshots'], stuck=True)
    )  # fmt: skip
    notify = _serve(_Notify())
    cfg = {"expire_timeout": 1, **FAST_CANCEL}
    r = _with(engine, notify, lambda: maintenance(engine, notify, cfg=cfg))
    assert r.returncode == 1, r.stdout + r.stderr
    # no table after the stuck one is touched: no preflight, no procedure for b or c
    assert not any('"b"' in x or '"c"' in x for x in engine.statements)
    assert not any("remove_orphan_files" in x for x in engine.statements)
    state = json.loads(maintenance.state.read_text())
    assert state["degraded"] is True
    assert "still running" in state["failed"]["run:aborted"]
    assert "cti.b" in state["failed"]["run:aborted"] and "cti.c" in state["failed"]["run:aborted"]
    assert len(notify.messages) == 1 and "run:aborted" in notify.messages[0]["body"]


def test_sigterm_while_listing_the_tables_writes_state_and_alerts(maintenance):
    engine = _serve(_Engine([("cti", "a")], hang=["information_schema.tables"]))
    notify = _serve(_Notify())
    proc = maintenance.start(engine, notify, cfg=FAST_CANCEL)
    try:
        for _ in range(100):
            if any("information_schema.tables" in x for x in engine.statements):
                break
            time.sleep(0.1)
        else:
            pytest.fail("the listing never reached the engine")
        proc.send_signal(signal.SIGTERM)
        out, err = proc.communicate(timeout=30)
    finally:
        proc.kill()
        engine.shutdown(), notify.shutdown()
    assert proc.returncode == 143, out + err
    state = json.loads(maintenance.state.read_text())
    assert state["terminated"] is True and "listing" in state["failed"]["run:terminated"]
    assert len(notify.messages) == 1
    assert engine.deletes  # the listing query was cancelled too


def _first_trino_timer_does_not_catch_up_a_missed_run_unless_asked(tmp_path):
    return {
        "role": TRINO,
        "tasks_from": "main",
        "extra_vars": trino_vars(tmp_path),
        "env": TRINO_SECRETS,
    }


@first_run(_first_trino_timer_does_not_catch_up_a_missed_run_unless_asked)
def test_trino_timer_does_not_catch_up_a_missed_run_unless_asked(first):
    first_result, tmp_path = first
    assert first_result.returncode == 0
    unit = tmp_path / "units" / "hnx-lake-maintenance.timer"
    assert "Persistent=false" in unit.read_text()  # arming never starts a run by itself
    on = trino_vars(tmp_path, trino_maintenance_catch_up=True)
    assert run_role(tmp_path, TRINO, "main", on, env=TRINO_SECRETS).returncode == 0
    assert "Persistent=true" in unit.read_text()


def _health_gate(tmp_path, enabled_flag, active_flag, **over):
    if enabled_flag:
        (tmp_path / "timer-enabled").touch()
    if active_flag:
        (tmp_path / "timer-active").touch()
    v = trino_vars(tmp_path, **over)
    return run_role(tmp_path, TRINO, "unarmed_check", v, env=TRINO_SECRETS)


@pytest.mark.parametrize(
    "enabled, active, over, ok",
    [
        (False, False, {"trino_maintenance_acknowledged_restore": False}, True),
        (True, False, {"trino_maintenance_acknowledged_restore": False}, False),  # re-arms at boot
        (False, True, {"trino_maintenance_acknowledged_restore": False}, False),
        (True, True, {"trino_maintenance_enabled": False}, False),
        (True, False, {"trino_maintenance_enabled": False}, False),  # enabled=false too
        (False, False, {"trino_maintenance_enabled": False}, True),
    ],
)
def test_health_fails_an_unarmed_timer_that_is_enabled_or_running(
    tmp_path, enabled, active, over, ok
):
    r = _health_gate(tmp_path, enabled, active, **over)
    assert (r.returncode == 0) is ok, r.stdout + r.stderr


def test_health_never_asks_about_an_unarmed_timer_when_it_is_armed(tmp_path):
    src = (Path(TRINO) / "tasks" / "health.yml").read_text()
    assert "unarmed_check.yml" in src and "not (trino_maintenance_armed | bool)" in src
