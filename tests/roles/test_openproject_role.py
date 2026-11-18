# SPDX-License-Identifier: Apache-2.0
"""Role ``openproject`` (modules/openproject/roles/openproject), run on localhost against fakes (CI is
unprivileged): main renders the web app, the worker, the database and the cache through
compose_app with every credential only in the env_files and a second run is ``changed=0``; a
reference with no value in the secret store, or a malformed input or credential, is refused by
name before anything is written; with the containers "started" (a fake docker) the seeder runs
once per image, before the app is started, and a second run does not run it again; health passes
against a stand-in and fails when the app's database check does; export writes an object-tree with
a sha256 listing, restore refuses a tampered one and, on an intact one, stops the app, restores
and starts it again (a second restore replaces the first: the final delta); upgrade records only
a pinned target."""

from __future__ import annotations

import grp
import json
import os
import pwd
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
import yaml
from rolerun import fake, first_run, run_role

from tests.modules.keycloak_stand_in import LOOPBACK

ROOT = Path(__file__).resolve().parents[2]
ROLE = str(ROOT / "modules" / "openproject" / "roles" / "openproject")
USER = pwd.getpwuid(os.getuid()).pw_name
#: the example registry's edge address (a documentation-range address, never connected to)
GUEST = yaml.safe_load((ROOT / "examples" / "services.yml").read_text())["hosts"]["edge-core"][
    "address"
]
HOSTNAME = "projects.example.internal"
DB_PASSWORD = "db-password-fake-0123456789abc"
ADMIN_PASSWORD = "Admin-password-fake-01"
SESSION_KEY = "k" * 80
SECRETS = {
    "HNX_SECRET_OPENPROJECT_DB_PASSWORD": DB_PASSWORD,
    "HNX_SECRET_OPENPROJECT_SECRET_KEY_BASE": SESSION_KEY,
    "HNX_SECRET_OPENPROJECT_ADMIN_PASSWORD": ADMIN_PASSWORD,
}
REFS = {
    "HNX_SECRET_OPENPROJECT_DB_PASSWORD": "secret:openproject/db-password",
    "HNX_SECRET_OPENPROJECT_SECRET_KEY_BASE": "secret:openproject/secret-key-base",
    "HNX_SECRET_OPENPROJECT_ADMIN_PASSWORD": "secret:openproject/admin-password",
}
PINNED = "docker.io/library/memcached:1.6.44-alpine@sha256:" + "a" * 64


def pv(tmp_path: Path, **kw) -> dict:
    v = {
        "openproject_logical_id": "projects",
        "openproject_hostname": HOSTNAME,
        "ansible_host": GUEST,
        "openproject_dir": str(tmp_path / "app"),
        "openproject_owner": USER,
        "openproject_data_root": str(tmp_path / "data"),
        # the unprivileged test's own ids (the role requires 1000 or more): it can chown to no other
        "openproject_group": grp.getgrgid(os.getgid()).gr_name,
        "openproject_app_uid": os.getuid(),
        "openproject_app_gid": os.getgid(),
        "openproject_db_uid": os.getuid(),
        "openproject_db_gid": os.getgid(),
        "openproject_start": False,
        "openproject_validate_with_docker": False,
    }
    v.update(kw)
    return v


# ----------------------------------------------------------------------------- render


def _first_main_renders_four_containers_with_the_credentials_only_in_the_env_files(tmp_path):
    v = pv(tmp_path)
    return {"role": ROLE, "tasks_from": "main", "extra_vars": v, "env": SECRETS, "setup": {"v": v}}


@first_run(_first_main_renders_four_containers_with_the_credentials_only_in_the_env_files)
def test_main_renders_four_containers_with_the_credentials_only_in_the_env_files(first):
    r, tmp_path = first
    v = first.setup["v"]
    assert r.returncode == 0, r.stdout + r.stderr
    text = (tmp_path / "app" / "docker-compose.yml").read_text()
    doc = yaml.safe_load(text)
    svc = doc["services"]
    assert sorted(svc) == ["cache", "postgres", "web", "worker"]
    assert svc["web"]["image"].startswith("docker.io/openproject/openproject:15.5.1-slim@sha256:")
    assert svc["postgres"]["image"].startswith("docker.io/library/postgres:17.")
    assert svc["cache"]["image"].startswith("docker.io/library/memcached:1.6.")
    assert svc["web"]["image"] == svc["worker"]["image"]  # one image, two commands
    assert svc["web"]["command"] == ["./docker/prod/web"]
    assert svc["worker"]["command"] == ["./docker/prod/worker"]
    assert svc["web"]["ports"] == [f"{GUEST}:8080:8080"]
    for name in ("postgres", "cache", "worker"):
        assert "ports" not in svc[name]  # only the web app is published
    for s in svc.values():
        assert s["cap_drop"] == ["ALL"] and s["security_opt"] == ["no-new-privileges:true"]
    assert svc["web"]["user"] == f"{os.getuid()}:{os.getgid()}"
    env = svc["web"]["environment"]
    assert env["OPENPROJECT_HTTPS"] == "true" and env["OPENPROJECT_HOST__NAME"] == HOSTNAME
    assert env["OPENPROJECT_CACHE__MEMCACHE__SERVER"] == "cache:11211"
    assert svc["web"]["volumes"] == [f"{tmp_path}/data/assets:/var/openproject/assets"]
    for value in (DB_PASSWORD, ADMIN_PASSWORD, SESSION_KEY):
        assert value not in text and value not in r.stdout
    web = (tmp_path / "app" / "secrets" / "web.env").read_text()
    assert "@postgres/openproject?pool=20" in web and f"SECRET_KEY_BASE='{SESSION_KEY}'" in web
    assert ADMIN_PASSWORD not in web  # only the seeder run is given it
    assert ADMIN_PASSWORD not in (tmp_path / "app" / "secrets" / "worker.env").read_text()
    for f in ("postgres", "web", "worker"):
        mode = (tmp_path / "app" / "secrets" / f"{f}.env").stat().st_mode & 0o777
        assert oct(mode) == "0o600", f
    assert oct((tmp_path / "data" / "pgdata").stat().st_mode & 0o777) == "0o700"
    again = run_role(tmp_path, ROLE, "main", v, env=SECRETS)
    assert again.returncode == 0 and "changed=0" in again.stdout, again.stdout


def _first_main_puts_the_containers_in_the_role_slice_the_module_play_names(tmp_path):
    v = pv(tmp_path, hnx_module_slice="hnx-openproject-server.slice")
    return {"role": ROLE, "tasks_from": "main", "extra_vars": v, "env": SECRETS}


@first_run(_first_main_puts_the_containers_in_the_role_slice_the_module_play_names)
def test_main_puts_the_containers_in_the_role_slice_the_module_play_names(first):
    r, tmp_path = first
    assert r.returncode == 0, r.stdout + r.stderr
    doc = yaml.safe_load((tmp_path / "app" / "docker-compose.yml").read_text())
    assert {s["cgroup_parent"] for s in doc["services"].values()} == {
        "hnx-openproject-server.slice"
    }


def _first_main_refuses_an_unset_secret_naming_the_reference_and_writes_nothing(tmp_path, unset):
    env = {k: v for k, v in SECRETS.items() if k != unset}
    return {
        "role": ROLE,
        "tasks_from": "main",
        "extra_vars": pv(tmp_path),
        "env": {**env, unset: ""},
    }


@pytest.mark.parametrize(
    "unset",
    ["HNX_SECRET_OPENPROJECT_DB_PASSWORD", "HNX_SECRET_OPENPROJECT_SECRET_KEY_BASE",
     "HNX_SECRET_OPENPROJECT_ADMIN_PASSWORD"],
)  # fmt: skip
@first_run(_first_main_refuses_an_unset_secret_naming_the_reference_and_writes_nothing)
def test_main_refuses_an_unset_secret_naming_the_reference_and_writes_nothing(first, unset):
    """Review Focus 3: a module deployed before its secret exists is refused, by name."""
    r, tmp_path = first
    assert r.returncode != 0, r.stdout
    ref = REFS[unset]
    assert ref in r.stdout + r.stderr
    assert not (tmp_path / "app").exists() and not (tmp_path / "data").exists()
    for value in (DB_PASSWORD, ADMIN_PASSWORD, SESSION_KEY):
        assert value not in r.stdout + r.stderr


def _first_main_refuses_bad_inputs_and_credentials(tmp_path, over, env):
    return {
        "role": ROLE,
        "tasks_from": "main",
        "extra_vars": pv(tmp_path, **over),
        "env": {**SECRETS, **env},
    }


@pytest.mark.parametrize(
    "over, env",
    [
        ({"openproject_image": "docker.io/openproject/openproject:latest"}, {}),
        ({"openproject_postgres_image": "docker.io/library/postgres:17.10"}, {}),
        ({"openproject_cache_image": "docker.io/library/memcached:1.6.44-alpine"}, {}),
        ({"ansible_host": "0.0.0.0"}, {}),
        ({"ansible_host": "projects.example.internal"}, {}),
        ({"openproject_hostname": "Projects"}, {}),
        ({"openproject_logical_id": "Projects"}, {}),
        ({"openproject_db_login_ref": "secret:openproject/admin-password"}, {}),
        ({"openproject_data_root": "/var/lib/../etc"}, {}),
        ({"openproject_dir": "relative/dir"}, {}),
        ({"openproject_app_uid": 0}, {}),
        ({"openproject_mem_limit": "lots"}, {}),
        ({}, {"HNX_SECRET_OPENPROJECT_DB_PASSWORD": "short"}),
        ({}, {"HNX_SECRET_OPENPROJECT_DB_PASSWORD": "has'quote-0123456789abcdefgh"}),
        ({}, {"HNX_SECRET_OPENPROJECT_DB_PASSWORD": "has@at-sign-0123456789abcdef"}),
        ({}, {"HNX_SECRET_OPENPROJECT_SECRET_KEY_BASE": "k" * 20}),
        ({}, {"HNX_SECRET_OPENPROJECT_ADMIN_PASSWORD": "alllowercaseletters"}),
        ({}, {"HNX_SECRET_OPENPROJECT_ADMIN_PASSWORD": DB_PASSWORD}),
    ],
)  # fmt: skip
@first_run(_first_main_refuses_bad_inputs_and_credentials)
def test_main_refuses_bad_inputs_and_credentials(first, over, env):
    r, tmp_path = first
    assert r.returncode != 0, r.stdout
    assert not (tmp_path / "app" / "docker-compose.yml").exists()


# ----------------------------------------------------------------------------- started


class Front:
    """A loopback stand-in for the app's health checks: 200 for each, 503 for the ones listed."""

    def __init__(self, failing=()):
        outer = self
        outer.failing = set(failing)
        outer.requests = []

        class H(BaseHTTPRequestHandler):
            def do_GET(self):
                outer.requests.append((self.path, self.headers.get("Host")))
                name = self.path.rsplit("/", 1)[-1]
                code = (
                    503
                    if name in outer.failing or not self.path.startswith("/health_checks/")
                    else 200
                )
                self.send_response(code)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *a):
                pass

        self.httpd = ThreadingHTTPServer((LOOPBACK, 0), H)
        self.port = self.httpd.server_address[1]

    def __enter__(self):
        threading.Thread(
            target=self.httpd.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True
        ).start()
        return self

    def __exit__(self, *a):
        self.httpd.shutdown()
        self.httpd.server_close()


def _docker(tmp_path: Path, health: str = "healthy") -> dict:
    """A fake docker: ``compose ps`` lists the four services in ``health``; ``exec ... pg_dump -f F``
    writes a dump at F's host path (the export mount), ``mv`` moves it, ``run`` (the seeder) fails
    while ``seeder.fails`` exists; everything else succeeds.  Every call is logged."""
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    rows = "".join(
        json.dumps({"Service": s, "State": "running", "Health": health}) + "\n"
        for s in ("postgres", "cache", "web", "worker")
    )
    export = tmp_path / "data" / "export" / "db"
    body = f"""
import os, shutil, sys
a = sys.argv[1:]
open({str(tmp_path / "docker.log")!r}, "a").write(" ".join(a) + "\\n")
def host(p):
    return os.path.join({str(export)!r}, os.path.basename(p))
if "ps" in a:
    sys.stdout.write({rows!r})
elif "pg_dump" in a:
    open(host(a[len(a) - 1 - a[::-1].index("-f") + 1]), "wb").write(b"PGDMP fake dump")
elif "mv" in a:
    shutil.move(host(a[-2]), host(a[-1]))
elif "pg_restore" in a:
    sys.exit(0 if os.path.exists(host(a[-1])) else 3)
elif "run" in a:
    envfile = {str(tmp_path / "app" / "secrets" / "web.env")!r}
    open({str(tmp_path / "seed-env.log")!r}, "a").write(
        ("had-password" if os.path.exists(envfile) and "OPENPROJECT_SEED_ADMIN_USER_PASSWORD=" in open(envfile).read() else "no-password") + "\\n")
    if os.path.exists({str(tmp_path / "seeder.fails")!r}):
        sys.exit(1)
"""
    fake(bindir / "docker", body)
    return {"PATH": f"{bindir}:{os.environ['PATH']}"}


def _calls(tmp_path: Path) -> list[str]:
    log = tmp_path / "docker.log"
    return log.read_text().splitlines() if log.exists() else []


def _live(tmp_path, front, **kw):
    return pv(tmp_path, openproject_bind=LOOPBACK, openproject_port=front.port, openproject_start=True,
              openproject_ready_timeout=10, **kw)  # fmt: skip


def test_the_seeder_runs_before_the_app_starts_and_once_per_image(tmp_path):
    with Front() as front:
        env = {**SECRETS, **_docker(tmp_path)}
        v = _live(tmp_path, front)
        r = run_role(tmp_path, ROLE, "main", v, env=env)
        assert r.returncode == 0, r.stdout + r.stderr
        calls = _calls(tmp_path)
        seeded = [i for i, c in enumerate(calls) if " run " in f" {c} " and "seeder" in c]
        started = [i for i, c in enumerate(calls) if "--remove-orphans" in c]
        assert len(seeded) == 1 and len(started) == 1 and seeded[0] < started[0]
        assert "up -d --wait postgres cache" in " ".join(calls[: seeded[0] + 1])
        assert (tmp_path / "data" / "seeded").read_text().startswith("sha256:")
        # the seed password reached the web env_file for the seeder run only, then was removed
        assert (tmp_path / "seed-env.log").read_text().split() == ["had-password"]
        web_env = (tmp_path / "app" / "secrets" / "web.env").read_text()
        assert ADMIN_PASSWORD not in web_env and "SEED_ADMIN" not in web_env
        # the app is asked for its health with the public name as the Host header
        assert ("/health_checks/default", HOSTNAME) in front.requests
        (tmp_path / "docker.log").unlink()
        again = run_role(tmp_path, ROLE, "main", v, env=env)
        assert again.returncode == 0 and "changed=0" in again.stdout, again.stdout
        assert not [c for c in _calls(tmp_path) if " run " in f" {c} "]  # same image: no seeder


def test_a_new_app_image_runs_the_seeder_again(tmp_path):
    with Front() as front:
        env = {**SECRETS, **_docker(tmp_path)}
        assert run_role(tmp_path, ROLE, "main", _live(tmp_path, front), env=env).returncode == 0
        new = "docker.io/openproject/openproject:15.5.2-slim@sha256:" + "b" * 64
        r = run_role(tmp_path, ROLE, "main", _live(tmp_path, front, openproject_image=new), env=env)
        assert r.returncode == 0, r.stdout + r.stderr
        assert len([c for c in _calls(tmp_path) if " run " in f" {c} "]) == 2
        assert (tmp_path / "data" / "seeded").read_text().strip() == "sha256:" + "b" * 64


def test_a_failed_seeder_stops_the_run_before_the_app_is_started(tmp_path):
    with Front() as front:
        env = {**SECRETS, **_docker(tmp_path)}
        (tmp_path / "seeder.fails").write_text("")
        r = run_role(tmp_path, ROLE, "main", _live(tmp_path, front), env=env)
        assert r.returncode != 0
        assert not [c for c in _calls(tmp_path) if "--remove-orphans" in c]
        assert not (tmp_path / "data" / "seeded").exists()  # retried next run


def test_health_passes_and_fails_on_the_apps_database_check(tmp_path):
    env = {**SECRETS, **_docker(tmp_path)}
    with Front() as front:
        v = _live(tmp_path, front)
        assert run_role(tmp_path, ROLE, "main", v, env=env).returncode == 0
        ok = run_role(tmp_path, ROLE, "health", v, env=env)
        assert ok.returncode == 0, ok.stdout + ok.stderr
        paths = [p for p, _ in front.requests]
        assert "/health_checks/default" in paths and "/health_checks/database" in paths
    with Front(failing={"database"}) as front:
        bad = run_role(tmp_path, ROLE, "health", _live(tmp_path, front), env=env)
        assert bad.returncode != 0 and "503" in bad.stdout + bad.stderr
    with Front() as front:
        env2 = {**SECRETS, **_docker(tmp_path, health="unhealthy")}
        bad = run_role(tmp_path, ROLE, "health", _live(tmp_path, front), env=env2)
        assert bad.returncode != 0 and "unhealthy" in bad.stdout + bad.stderr


# ----------------------------------------------------------------------------- export, restore


def _export(tmp_path, env, v):
    (tmp_path / "data" / "assets").mkdir(parents=True, exist_ok=True)
    (tmp_path / "data" / "assets" / "files").mkdir(exist_ok=True)
    (tmp_path / "data" / "assets" / "files" / "a.txt").write_text("attachment")
    r = run_role(tmp_path, ROLE, "export", v, env=env)
    assert r.returncode == 0, r.stdout + r.stderr
    return tmp_path / "data" / "export"


def test_export_writes_an_object_tree_with_a_sha256_listing(tmp_path):
    env = {**SECRETS, **_docker(tmp_path)}
    exp = _export(tmp_path, env, pv(tmp_path))
    assert (exp / "db" / "projects.dump").read_bytes() == b"PGDMP fake dump"
    assert (exp / "attachments.tar").stat().st_size > 0
    rows = [json.loads(line) for line in (exp / "listing.jsonl").read_text().splitlines()]
    assert sorted(r["key"] for r in rows) == ["attachments.tar", "db/projects.dump"]
    import hashlib

    for r in rows:
        data = (exp / r["key"]).read_bytes()
        assert r["size"] == len(data) and r["sha256"] == hashlib.sha256(data).hexdigest()
    dump = next(c for c in _calls(tmp_path) if "pg_dump" in c)
    assert "-Fc" in dump and "--no-owner" in dump
    assert not list(Path("/tmp").glob("*projects*dump*"))  # nothing staged in /tmp


def _first_restore_refuses_a_tampered_export_and_writes_nothing(tmp_path):
    env = {**SECRETS, **_docker(tmp_path)}
    v = pv(tmp_path)
    exp = _export(tmp_path, env, v)
    (exp / "db" / "projects.dump").write_bytes(b"PGDMP tampered")
    (tmp_path / "docker.log").unlink()
    return {
        "role": ROLE,
        "tasks_from": "restore",
        "extra_vars": {**v, "openproject_restore_source": str(exp)},
        "env": env,
    }


@first_run(_first_restore_refuses_a_tampered_export_and_writes_nothing)
def test_restore_refuses_a_tampered_export_and_writes_nothing(first):
    r, tmp_path = first
    assert r.returncode != 0 and "not an intact export" in r.stdout + r.stderr
    assert not [c for c in _calls(tmp_path) if "pg_restore" in c or " stop " in f" {c} "]


def test_restore_stops_the_app_restores_and_starts_it_again_and_can_be_repeated(tmp_path):
    with Front() as front:
        env = {**SECRETS, **_docker(tmp_path)}
        v = _live(tmp_path, front)
        exp = _export(tmp_path, env, v)
        # a later file on the target that the export does not hold: the restore replaces
        (tmp_path / "data" / "assets" / "files" / "stale.txt").write_text("deleted at source")
        for _ in range(2):  # the second is the final delta after a freeze
            (tmp_path / "docker.log").write_text("")
            r = run_role(tmp_path, ROLE, "restore",
                         {**v, "openproject_restore_source": str(exp)}, env=env)  # fmt: skip
            assert r.returncode == 0, r.stdout + r.stderr
            calls = _calls(tmp_path)
            order = [next(i for i, c in enumerate(calls) if k in c)
                     for k in (" stop web worker", "pg_restore", " run ", " up -d web worker")]  # fmt: skip
            assert order == sorted(order), calls
            assert "--clean" in next(c for c in calls if "pg_restore" in c)
            assert not (tmp_path / "data" / "export" / "db" / ".restore.dump").exists()
            assert (tmp_path / "data" / "assets" / "files" / "a.txt").read_text() == "attachment"
            assert not (tmp_path / "data" / "assets" / "files" / "stale.txt").exists()


# ----------------------------------------------------------------------------- upgrade


def _first_upgrade_records_only_a_pinned_target_of_the_same_repository(tmp_path):
    v = pv(tmp_path)
    return {"role": ROLE, "tasks_from": "main", "extra_vars": v, "env": SECRETS, "setup": {"v": v}}


@first_run(_first_upgrade_records_only_a_pinned_target_of_the_same_repository)
def test_upgrade_records_only_a_pinned_target_of_the_same_repository(first):
    first_result, tmp_path = first
    v = first.setup["v"]
    assert first_result.returncode == 0
    good = "docker.io/openproject/openproject:15.5.2-slim@sha256:" + "c" * 64
    r = run_role(tmp_path, ROLE, "upgrade", {**v, "openproject_target_image": good}, env=SECRETS)
    assert r.returncode == 0, r.stdout + r.stderr
    rec = json.loads((tmp_path / "app" / "pending-upgrade.json").read_text())
    assert rec == {"service": "web", "tag": "15.5.2-slim", "digest": "sha256:" + "c" * 64}
    for bad in (
        {"openproject_target_image": "docker.io/openproject/openproject:15.5.2-slim"},
        {"openproject_target_image": "docker.io/other/app:1@sha256:" + "c" * 64},
        {"openproject_target_postgres_image": "docker.io/library/postgres:18.1@sha256:" + "d" * 64},
        {"openproject_target_cache_image": PINNED, "openproject_target_image": good},
        {},
    ):
        (tmp_path / "app" / "pending-upgrade.json").unlink(missing_ok=True)
        r = run_role(tmp_path, ROLE, "upgrade", {**v, **bad}, env=SECRETS)
        assert r.returncode != 0, bad
        assert not (tmp_path / "app" / "pending-upgrade.json").exists()


# ------------------------------------------------------------ migrated short session key

SHORT_KEY = "Ab1" * 4  # 12 characters, like the source's effective value


def _key_run(tmp_path, key, migrated):
    v = pv(tmp_path)
    if migrated is not None:
        v["openproject_secret_key_base_migrated"] = migrated
    return run_role(
        tmp_path, ROLE, "main", v, env={**SECRETS, "HNX_SECRET_OPENPROJECT_SECRET_KEY_BASE": key}
    )


def test_a_short_key_is_refused_by_default(tmp_path):
    r = _key_run(tmp_path, SHORT_KEY, None)
    assert r.returncode != 0, r.stdout
    assert not (tmp_path / "app" / "docker-compose.yml").exists()
    assert SHORT_KEY not in r.stdout + r.stderr


def test_a_short_key_is_accepted_with_the_opt_in_and_warns(tmp_path):
    r = _key_run(tmp_path, SHORT_KEY, True)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "ROTATE" in r.stdout and "secret:openproject/secret-key-base" in r.stdout
    web = (tmp_path / "app" / "secrets" / "web.env").read_text()
    assert f"SECRET_KEY_BASE='{SHORT_KEY}'" in web
    assert SHORT_KEY not in r.stdout


def test_a_strong_key_does_not_warn_without_the_opt_in(tmp_path):
    r = _key_run(tmp_path, SESSION_KEY, None)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "ROTATE" not in r.stdout


@pytest.mark.parametrize(
    "key",
    ["", "has space", "tab\tinside", "has'quote", 'has"quote', "k" * 257, "line\nbreak", "caf\u00e9"],
)  # fmt: skip
def test_the_opt_in_still_refuses_unsafe_or_out_of_range_keys(tmp_path, key):
    r = _key_run(tmp_path, key, True)
    assert r.returncode != 0, r.stdout
    assert not (tmp_path / "app" / "docker-compose.yml").exists()


def test_the_opt_in_accepts_the_longest_key(tmp_path):
    r = _key_run(tmp_path, "k" * 256, True)
    assert r.returncode == 0, r.stdout + r.stderr
