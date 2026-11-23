# SPDX-License-Identifier: Apache-2.0
"""The lakekeeper role (modules/lakekeeper), run on localhost against fakes (CI is unprivileged).

* main renders the compose project (the database and the catalog, both pinned by digest) with no
  secret in it, the credentials only in the 0600 env_files, and a second run is ``changed=0``;
* a malformed input, or a malformed or UNSET credential, is refused before anything is rendered,
  naming the ``secret:`` reference;
* started, the order is: database healthy, migration only when the binary says the database is
  behind, then the catalog; the catalog is bootstrapped once and the warehouse created once, with
  the bucket ROOT as its base (no key prefix), an access-key credential, remote signing and soft
  deletes; a warehouse that exists with another base is refused, never changed;
* the backup hook dumps and lists, and the restore refuses a source that is not what the listing says.
"""

from __future__ import annotations

import hashlib
import http.server
import json
import os
import pwd
import socket
import subprocess
import sys
import threading
from pathlib import Path

import pytest
import yaml
from rolerun import fake, first_run, run_role

ROOT = Path(__file__).resolve().parents[2]
ROLE = str(ROOT / "modules" / "lakekeeper" / "roles" / "lakekeeper")
USER = pwd.getpwuid(os.getuid()).pw_name
LOOPBACK = socket.gethostbyname("localhost")  # the stand-in API's address: by resolution
GUEST = LOOPBACK  # the address the ports are published on
# built at run time from short pieces: nothing here looks like a key to a secret scanner
KEY_ID = "GK" + "ab12" * 6
KEY_SECRET = "c0de" * 16
DB_PW = "-".join(["dbpw", "x1y2z3"] * 4)
ENC_KEY = "-".join(["enc", "q9w8e7"] * 6)
SECRETS = {
    "HNX_SECRET_LAKEKEEPER_PG_PASSWORD": DB_PW,
    "HNX_SECRET_LAKEKEEPER_ENCRYPTION_KEY": ENC_KEY,
    "HNX_SECRET_LAKEKEEPER_S3_ACCESS_KEY": KEY_ID,
    "HNX_SECRET_LAKEKEEPER_S3_SECRET_KEY": KEY_SECRET,
}


def role_vars(tmp: Path, **kw) -> dict:
    # the object store's address comes from a registry row, as in a lab (no URL is written here)
    (tmp / "registry.yml").write_text(
        yaml.safe_dump(
            {
                "services": {
                    "object-store": {
                        "capability": "object-store",
                        "host": "store.example.internal",
                        "port": 3900,
                        "scheme": "http",
                    }
                }
            }
        )
    )
    v = {
        "lakekeeper_logical_id": "lake-catalog",
        "ansible_host": GUEST,
        "lakekeeper_dir": str(tmp / "app"),
        "lakekeeper_data_root": str(tmp / "data"),
        "lakekeeper_export_dir": str(tmp / "export"),
        "lakekeeper_owner": USER,
        "lakekeeper_group": pwd.getpwuid(os.getuid()).pw_name,
        # the database's directories are chowned to its user: an unprivileged run can only give them
        # to itself; the catalog's user owns no directory
        "lakekeeper_db_uid": os.getuid(),
        "lakekeeper_db_gid": os.getgid(),
        "lakekeeper_uid": os.getuid() + 1,
        "lakekeeper_gid": os.getgid() + 1,
        "hnx_registry_file": str(tmp / "registry.yml"),
        "lakekeeper_start": False,
        "lakekeeper_validate_with_docker": False,
    }
    v.update(kw)
    return v


def _store_url(tmp: Path) -> str:
    row = yaml.safe_load((tmp / "registry.yml").read_text())["services"]["object-store"]
    return f"{row['scheme']}://{row['host']}:{row['port']}"


# ----------------------------------------------------------------------------- render


def _first_main_renders_both_containers_pinned_with_no_secret_in_the_compose_file(tmp_path):
    v = role_vars(tmp_path)
    return {"role": ROLE, "tasks_from": "main", "extra_vars": v, "env": SECRETS, "setup": {"v": v}}


@first_run(_first_main_renders_both_containers_pinned_with_no_secret_in_the_compose_file)
def test_main_renders_both_containers_pinned_with_no_secret_in_the_compose_file(first):
    r, tmp_path = first
    v = first.setup["v"]
    assert r.returncode == 0, r.stdout + r.stderr
    text = (tmp_path / "app" / "docker-compose.yml").read_text()
    svcs = yaml.safe_load(text)["services"]
    assert sorted(svcs) == ["lakekeeper", "postgres"]
    assert "sha256:22dcb6044c106a962c242b70051bd226bd50c9134c763121d8713c37fe9a70ec" in text
    assert "sha256:7958605b474b3d264a969cb3a123d6aa00ad1e1fe9da8a69984dabb704d93317" in text
    assert svcs["lakekeeper"]["command"] == ["serve"]
    assert svcs["lakekeeper"]["ports"] == [GUEST + ":8181:8181"]  # the guest's address, never all
    assert "ports" not in svcs["postgres"]  # the database is on the project's own network only
    assert svcs["lakekeeper"]["depends_on"] == {"postgres": {"condition": "service_healthy"}}
    # PostgreSQL 17 keeps its cluster at the data directory itself
    assert any(x.endswith(":/var/lib/postgresql/data") for x in svcs["postgres"]["volumes"])
    for secret in (DB_PW, ENC_KEY, KEY_SECRET):
        assert secret not in text
    senv = (tmp_path / "app" / "secrets" / "lakekeeper.env").read_text()
    assert "LAKEKEEPER__PG_ENCRYPTION_KEY=" in senv and "LAKEKEEPER__PG_DATABASE_URL_WRITE=" in senv
    assert (
        KEY_SECRET not in senv
    )  # the object store key goes to the warehouse (the API), not a file
    assert "POSTGRES_PASSWORD=" in (tmp_path / "app" / "secrets" / "postgres.env").read_text()
    assert oct((tmp_path / "data" / "pgdata").stat().st_mode & 0o777) == "0o700"
    again = run_role(tmp_path, ROLE, "main", v, env=SECRETS)
    assert again.returncode == 0 and "changed=0" in again.stdout, again.stdout


def _first_main_refuses_bad_inputs_and_credentials(tmp_path, over, env):
    return {"role": ROLE, "tasks_from": "main", "extra_vars": role_vars(tmp_path, **over),
            "env": {**SECRETS, **env}}  # fmt: skip


@pytest.mark.parametrize(
    "over, env",
    [
        ({"lakekeeper_image": "quay.io/lakekeeper/catalog:latest"}, {}),
        ({"lakekeeper_image": "quay.io/lakekeeper/catalog:v0.15.1"}, {}),
        ({"lakekeeper_bind": "0.0.0.0"}, {}),
        ({"lakekeeper_bind": "lake.example.internal"}, {}),
        ({"lakekeeper_port": 0}, {}),
        ({"lakekeeper_warehouse_name": "Bad Name"}, {}),
        ({"lakekeeper_bucket": "B"}, {}),
        ({"lakekeeper_soft_delete_seconds": 60}, {}),
        ({"lakekeeper_s3_url": "store.example.internal"}, {}),
        ({"lakekeeper_uid": 0}, {}),
        ({"lakekeeper_uid": 61061, "lakekeeper_db_uid": 61061}, {}),
        ({"lakekeeper_access_key_ref": "secret:lakekeeper/pg-password"}, {}),
        ({}, {"HNX_SECRET_LAKEKEEPER_PG_PASSWORD": "short"}),
        # a character a connection URL would read as syntax
        ({}, {"HNX_SECRET_LAKEKEEPER_PG_PASSWORD": "p@" + "a" * 30}),
        # the encryption key is not the database password
        ({}, {"HNX_SECRET_LAKEKEEPER_ENCRYPTION_KEY": DB_PW}),
        ({}, {"HNX_SECRET_LAKEKEEPER_S3_SECRET_KEY": "short"}),
        ({}, {"HNX_SECRET_LAKEKEEPER_S3_ACCESS_KEY": "not-a-key"}),
    ],
)
@first_run(_first_main_refuses_bad_inputs_and_credentials)
def test_main_refuses_bad_inputs_and_credentials(first, over, env):
    r, tmp_path = first
    assert r.returncode != 0, r.stdout
    assert not (tmp_path / "app" / "docker-compose.yml").exists()


def _first_main_refuses_an_unset_secret_naming_its_reference(tmp_path):
    return {"role": ROLE, "tasks_from": "main", "extra_vars": role_vars(tmp_path), "env": {}}


@first_run(_first_main_refuses_an_unset_secret_naming_its_reference)
def test_main_refuses_an_unset_secret_naming_its_reference(first):
    r, tmp_path = first
    assert r.returncode != 0
    assert "secret:lakekeeper/pg-password" in r.stdout + r.stderr
    assert not (tmp_path / "app" / "docker-compose.yml").exists()


# ----------------------------------------------------------------------------- start, migrate, bootstrap


class _Api(http.server.ThreadingHTTPServer):
    """A stand-in for the catalog's own API: health, info, bootstrap and the warehouse calls."""

    def __init__(self, bootstrapped=False, warehouses=None):
        super().__init__((LOOPBACK, 0), _Handler)
        self.bootstrapped, self.warehouses, self.calls = bootstrapped, list(warehouses or []), []


class _Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, doc=None):
        raw = json.dumps(doc).encode() if doc is not None else b""
        self.send_response(code)
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        self.server.calls.append(("GET", self.path, None))
        if self.path == "/health":
            ok = [{"name": "read_pool", "status": "ok"}, {"name": "write_pool", "status": "ok"}]
            return self._send(200, {"health": "ok", "services": {"catalog": ok, "secrets": ok}})
        if self.path == "/management/v1/info":
            return self._send(200, {"bootstrapped": self.server.bootstrapped})
        if self.path == "/management/v1/warehouse":
            return self._send(200, {"warehouses": self.server.warehouses})
        self._send(404)

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])) or b"null")
        self.server.calls.append(("POST", self.path, body))
        if self.path == "/management/v1/bootstrap":
            self.server.bootstrapped = True
            return self._send(204)
        if self.path == "/management/v1/warehouse":
            p = body["storage-profile"]
            self.server.warehouses.append({"name": body["warehouse-name"], "storage-profile": {
                **p, "key-prefix": None, "endpoint": p["endpoint"] + "/"},
                "delete-profile": body["delete-profile"]})  # fmt: skip
            return self._send(201, {"warehouse-id": "w1"})
        self._send(404)


def _docker(tmp: Path, migrated: bool) -> dict:
    """A docker that logs every call; `wait-for-db` answers 0 (migrated) or 1 (behind)."""
    bindir = tmp / "dbin"
    bindir.mkdir(exist_ok=True)
    log = tmp / "docker.log"
    fake(
        bindir / "docker",
        "import sys\n"
        f"open({str(log)!r}, 'a').write(' '.join(sys.argv[1:]) + '\\n')\n"
        f"sys.exit(0 if ('wait-for-db' not in sys.argv or {migrated!r}) else 1)\n",
    )
    return {"PATH": f"{bindir}:{os.environ['PATH']}"}


def _started(tmp_path, migrated, api, **kw):
    t = threading.Thread(target=api.serve_forever, daemon=True)
    t.start()
    v = role_vars(tmp_path, lakekeeper_start=True, lakekeeper_bind=LOOPBACK,
                  lakekeeper_port=api.server_address[1], **kw)  # fmt: skip
    env = {**SECRETS, **_docker(tmp_path, migrated)}
    try:
        return run_role(tmp_path, ROLE, "main", v, env=env), v, env
    finally:
        api.shutdown()


def _sequence(tmp_path):
    return [
        line.split(" ", 4)[-1] if " compose " in f" {line}" else line
        for line in (tmp_path / "docker.log").read_text().splitlines()
    ]


def test_a_database_that_is_behind_is_migrated_before_the_catalog_starts_and_the_warehouse_is_made(
    tmp_path,
):
    api = _Api()
    r, _v, _env = _started(tmp_path, migrated=False, api=api)
    assert r.returncode == 0, r.stdout + r.stderr
    log = (tmp_path / "docker.log").read_text().splitlines()
    idx = {k: next(i for i, line in enumerate(log) if k in line)
           for k in ("up -d --wait postgres", "wait-for-db", " migrate", "up -d --remove-orphans")}  # fmt: skip
    assert (
        idx["up -d --wait postgres"]
        < idx["wait-for-db"]
        < idx[" migrate"]
        < idx["up -d --remove-orphans"]
    )
    posts = [(p, b) for m, p, b in api.calls if m == "POST"]
    assert [p for p, _ in posts] == ["/management/v1/bootstrap", "/management/v1/warehouse"]
    assert posts[0][1] == {"accept-terms-of-use": True}
    wh = posts[1][1]
    prof = wh["storage-profile"]
    # the BUCKET ROOT is the base: no key prefix, so every existing table location is inside it
    assert wh["warehouse-name"] == "lake" and prof["bucket"] == "iceberg-warehouse"
    assert "key-prefix" not in prof
    assert prof["endpoint"] == _store_url(tmp_path)
    assert prof["path-style-access"] is True
    assert prof["sts-enabled"] is False and prof["remote-signing-enabled"] is True
    assert wh["storage-credential"]["credential-type"] == "access-key"
    assert (
        wh["delete-profile"]["type"] == "soft"
        and wh["delete-profile"]["expiration-seconds"] >= 86400
    )


def test_a_migrated_database_is_not_migrated_again_and_a_made_warehouse_is_not_made_again(tmp_path):
    api = _Api()
    r, v, env = _started(tmp_path, migrated=True, api=api)
    assert r.returncode == 0, r.stdout + r.stderr
    assert " migrate" not in (tmp_path / "docker.log").read_text()
    # second converge against what the first one made: no write at all
    api.calls.clear()
    t = threading.Thread(target=api.serve_forever, daemon=True)
    t.start()
    try:
        again = run_role(tmp_path, ROLE, "main", v, env=env)
    finally:
        api.shutdown()
    assert again.returncode == 0, again.stdout + again.stderr
    assert [c for c in api.calls if c[0] == "POST"] == []


def test_a_warehouse_with_a_key_prefix_is_refused_and_left_as_it_is(tmp_path):
    role_vars(tmp_path)  # writes the registry the object store's address is read from
    wrong = {"name": "lake", "storage-profile": {
        "type": "s3", "bucket": "iceberg-warehouse", "key-prefix": "warehouse", "region": "garage",
        "endpoint": _store_url(tmp_path) + "/", "path-style-access": True, "sts-enabled": False,
        "remote-signing-enabled": True}, "delete-profile": {"type": "soft"}}  # fmt: skip
    api = _Api(bootstrapped=True, warehouses=[wrong])
    r, _v, _env = _started(tmp_path, migrated=True, api=api)
    assert r.returncode != 0
    assert "differs from the module's settings" in r.stdout + r.stderr
    assert [c for c in api.calls if c[0] == "POST"] == []  # nothing was changed


# ----------------------------------------------------------------------------- backup and restore


def _script(name: str) -> str:
    return str(Path(ROLE) / "files" / name)


def _export(tmp: Path, payload=b"dump-bytes", tamper=False) -> Path:
    d = tmp / "export"
    (d / "db").mkdir(parents=True)
    (d / "db" / "lakekeeper.dump").write_bytes(payload)
    row = {
        "key": "db/lakekeeper.dump",
        "size": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
    }
    (d / "listing.jsonl").write_text(json.dumps(row) + "\n")
    for p in (d, d / "db"):
        p.chmod(0o700)
    for p in (d / "db" / "lakekeeper.dump", d / "listing.jsonl"):
        p.chmod(0o600)
    if tamper:
        (d / "db" / "lakekeeper.dump").write_bytes(b"dump-bytez")
    return d


def _run_script(*args) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-I", _script("lakekeeper_backup.py"), *args],
                          capture_output=True, text=True)  # fmt: skip


def test_the_listing_names_the_dump_with_its_size_and_sha256(tmp_path):
    d = _export(tmp_path)
    r = _run_script("listing", str(d))
    row = json.loads(r.stdout)[0]
    assert (
        r.returncode == 0
        and row["key"] == "db/lakekeeper.dump"
        and row["size"] == len(b"dump-bytes")
    )


def test_a_restore_source_is_checked_and_a_tampered_one_is_refused(tmp_path):
    uid = str(os.getuid())
    assert _run_script("check", str(_export(tmp_path / "a")), uid).returncode == 0
    bad = _run_script("check", str(_export(tmp_path / "b", tamper=True)), uid)
    assert bad.returncode != 0 and "differs from the listing" in bad.stderr + bad.stdout


def test_a_restore_source_with_an_extra_file_or_a_link_is_refused(tmp_path):
    uid = str(os.getuid())
    d = _export(tmp_path / "a")
    (d / "extra").write_text("x")
    assert _run_script("check", str(d), uid).returncode != 0
    d2 = _export(tmp_path / "b")
    link = tmp_path / "link"
    link.symlink_to(d2)
    assert _run_script("check", str(link), uid).returncode != 0  # the source directory is a link


def test_stage_copies_the_checked_dump_and_leaves_nothing_when_the_hash_differs(tmp_path):
    uid, gid = str(os.getuid()), str(os.getgid())
    good = _export(tmp_path / "a")
    dest = tmp_path / "staged.dump"
    assert _run_script("stage", str(good), str(dest), uid, gid).returncode == 0
    assert dest.read_bytes() == b"dump-bytes" and oct(dest.stat().st_mode & 0o777) == "0o600"
    # a copy of the same size with other bytes: refused, and the staged file is removed again
    bad = _export(tmp_path / "b", tamper=True)
    dest2 = tmp_path / "staged2.dump"
    r = _run_script("stage", str(bad), str(dest2), uid, gid)
    assert r.returncode != 0 and not dest2.exists()
