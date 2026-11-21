# SPDX-License-Identifier: Apache-2.0
"""The case-management module's role (modules/<id>/roles/<role>), run on localhost against fakes (CI
is unprivileged): main renders the broker, the database, the app, the worker and the TLS front through
compose_app with every credential only in the env_files and a second run is ``changed=0``; a reference
with no value in the secret store, or a malformed input or credential, is refused by name before
anything is written; with the containers "started" (a fake docker) main waits for the API, health
passes against a stand-in HTTPS service and fails on an open API, a refused key, another version, an
unverifiable certificate and an unhealthy container, and the API key reaches curl on its standard
input, never in an argument; export writes an object-tree with a sha256 listing, restore refuses a
tampered one and, on an intact one, stops the app, restores and starts it again (a second restore
replaces the first: the final delta); upgrade records only a pinned target that is not older."""

from __future__ import annotations

import grp
import hashlib
import json
import os
import pwd
import shutil
from pathlib import Path

import pytest
import yaml
from case_management_front import Front
from forge_front import LOOPBACK, make_pki, pem
from rolerun import fake, first_run, run_role

from tests.modules.case_management_module import ROLE_DIR, P, defaults, env_for, ref

ROOT = Path(__file__).resolve().parents[2]
ROLE = str(ROLE_DIR)
USER = pwd.getpwuid(os.getuid()).pw_name
DEFAULTS = defaults()
#: the example registry's edge address (a documentation-range address, never connected to)
GUEST = yaml.safe_load((ROOT / "examples" / "services.yml").read_text())["hosts"]["edge-core"][
    "address"
]
HOSTNAME = "cases.example.internal"
DB_LOGIN = "p" * 30
DB_ADMIN_LOGIN = "q" * 30
SESSION_KEY = "s" * 40
SALT = "t" * 40
ADMIN_LOGIN = "Admin-" + "x" * 12 + "-01"
ACCESS = "k" * 48
CERT = pem("CERTIFICATE")
KEY = pem("PRIVATE|KEY")
VALUES = {
    "db-password": DB_LOGIN,
    "db-admin-password": DB_ADMIN_LOGIN,
    "session-key": SESSION_KEY,
    "password-salt": SALT,
    "admin-password": ADMIN_LOGIN,
    "api-key": ACCESS,
    "tls-cert": CERT,
    "tls-key": KEY,
    "ca": CERT,
}
SECRETS = {env_for(ref(n)): v for n, v in VALUES.items()}
PLAIN = [DB_LOGIN, DB_ADMIN_LOGIN, SESSION_KEY, SALT, ADMIN_LOGIN, ACCESS]
SERVICES = ["app", "broker", "db", "nginx", "worker"]
VERSION = DEFAULTS[P + "app_image"].split("@")[0].rsplit(":", 1)[1]


def pv(tmp_path: Path, **kw) -> dict:
    v = {
        "logical_id": "cases",
        "hostname": HOSTNAME,
        "dir": str(tmp_path / "app"),
        "owner": USER,
        "group": grp.getgrgid(os.getgid()).gr_name,
        "data_root": str(tmp_path / "data"),
        # the unprivileged test's own ids: it can chown to no other
        "app_uid": os.getuid(),
        "app_gid": os.getgid(),
        "db_uid": os.getuid(),
        "db_gid": os.getgid(),
        "broker_uid": os.getuid(),
        "broker_gid": os.getgid(),
        "front_uid": os.getuid(),
        "front_gid": os.getgid(),
        "start": False,
        "validate_with_docker": False,
    }
    v.update(kw)
    out = {"ansible_host": GUEST}
    out.update({k if k.startswith(("hnx_", "ansible_")) else P + k: x for k, x in v.items()})
    return out


# ----------------------------------------------------------------------------- render


def _first_main_renders_five_containers_with_the_credentials_only_in_the_env_files(tmp_path):
    v = pv(tmp_path)
    return {"role": ROLE, "tasks_from": "main", "extra_vars": v, "env": SECRETS, "setup": {"v": v}}


@first_run(_first_main_renders_five_containers_with_the_credentials_only_in_the_env_files)
def test_main_renders_five_containers_with_the_credentials_only_in_the_env_files(first):
    r, tmp_path = first
    v = first.setup["v"]
    assert r.returncode == 0, r.stdout + r.stderr
    text = (tmp_path / "app" / "docker-compose.yml").read_text()
    svc = yaml.safe_load(text)["services"]
    assert sorted(svc) == SERVICES
    for name in ("app", "worker", "db", "nginx"):
        assert "@sha256:" in svc[name]["image"]
    assert svc["app"]["image"] == svc["worker"]["image"]  # one image, two commands
    assert svc["app"]["command"][-2:] == ["./iris-entrypoint.sh", "iriswebapp"]
    assert svc["worker"]["command"][-1] == "iris-worker"
    # only the TLS front publishes a port, on the guest's own address
    assert svc["nginx"]["ports"] == [f"{GUEST}:8443:8443"]
    for name in ("app", "worker", "db", "broker"):
        assert "ports" not in svc[name]
    for s in svc.values():
        assert s["cap_drop"] == ["ALL"] and s["security_opt"] == ["no-new-privileges:true"]
        assert s["user"].split(":")[0] != "0"  # no container runs as root
    assert svc["nginx"]["environment"]["SERVER_NAME"] == HOSTNAME
    assert svc["nginx"]["volumes"] == [f"{tmp_path}/data/tls:/www/certs:ro"]
    # the worker is not told it is a worker: the product would skip its start-up and its keys
    assert "IRIS_WORKER" not in svc["worker"]["environment"]
    assert svc["worker"]["environment"]["CELERY_BROKER"] == "amqp://broker"
    for value in PLAIN:
        assert value not in text and value not in r.stdout
    secrets = tmp_path / "app" / "secrets"
    envs = {n: (secrets / f"{n}.env").read_text() for n in ("app", "db", "worker")}
    assert f"POSTGRES_PASSWORD='{DB_LOGIN}'" in envs["db"] and "IRIS_" not in envs["db"]
    # the real administrator password is in no file: the first start gets a throwaway one
    assert "IRIS_ADM_PASSWORD='" in envs["app"] and ADMIN_LOGIN not in envs["app"]
    assert all(ADMIN_LOGIN not in text for text in envs.values())
    # the API key reaches no container: the role sets it in the database (see below)
    assert all(ACCESS not in text for text in envs.values())
    assert f"IRIS_SECRET_KEY='{SESSION_KEY}'" in envs["worker"]
    # the worker never holds an administrator credential
    assert "IRIS_ADM" not in envs["worker"]
    for n in envs:
        assert oct((secrets / f"{n}.env").stat().st_mode & 0o777) == "0o600", n
    tls = tmp_path / "data" / "tls"
    assert (tls / "chain.pem").read_text().startswith("-----BEGIN CERTIFICATE-----")
    assert oct((tls / "server.key").stat().st_mode & 0o777) == "0o440"
    assert oct((tmp_path / "data" / "pgdata").stat().st_mode & 0o777) == "0o700"
    for sub in ("server_data", "user_templates", "downloads"):
        assert (tmp_path / "data" / "files" / sub).is_dir()
    again = run_role(tmp_path, ROLE, "main", v, env=SECRETS)
    assert again.returncode == 0 and "changed=0" in again.stdout, again.stdout


def _first_main_puts_the_containers_in_the_role_slice_the_module_play_names(tmp_path):
    v = pv(tmp_path, hnx_module_slice="hnx-case-server.slice")
    return {"role": ROLE, "tasks_from": "main", "extra_vars": v, "env": SECRETS}


@first_run(_first_main_puts_the_containers_in_the_role_slice_the_module_play_names)
def test_main_puts_the_containers_in_the_role_slice_the_module_play_names(first):
    r, tmp_path = first
    assert r.returncode == 0, r.stdout + r.stderr
    doc = yaml.safe_load((tmp_path / "app" / "docker-compose.yml").read_text())
    assert {s["cgroup_parent"] for s in doc["services"].values()} == {"hnx-case-server.slice"}


SECRET_NAMES = sorted(VALUES)


def _first_main_refuses_an_unset_secret_naming_the_reference_and_writes_nothing(tmp_path, name):
    env = {**SECRETS, env_for(ref(name)): ""}
    return {"role": ROLE, "tasks_from": "main", "extra_vars": pv(tmp_path), "env": env}


@pytest.mark.parametrize("name", SECRET_NAMES)
@first_run(_first_main_refuses_an_unset_secret_naming_the_reference_and_writes_nothing)
def test_main_refuses_an_unset_secret_naming_the_reference_and_writes_nothing(first, name):
    """Review Focus 3: a module deployed before its secret exists is refused, by name."""
    r, tmp_path = first
    assert r.returncode != 0, r.stdout
    assert ref(name) in r.stdout + r.stderr
    assert not (tmp_path / "app").exists() and not (tmp_path / "data").exists()
    for value in PLAIN:
        assert value not in r.stdout + r.stderr


def _first_main_refuses_bad_inputs_and_credentials(tmp_path, over, env):
    return {
        "role": ROLE,
        "tasks_from": "main",
        "extra_vars": pv(tmp_path, **over),
        "env": {**SECRETS, **{env_for(ref(n)): v for n, v in env.items()}},
    }


PINNED = "ghcr.io/example/app:v1.2.3@sha256:" + "a" * 64


@pytest.mark.parametrize(
    "over, env",
    [
        ({"app_image": PINNED.replace("@sha256:" + "a" * 64, "")}, {}),
        ({"app_image": PINNED.replace("v1.2.3", "latest")}, {}),
        ({"db_image": "ghcr.io/example/db:v1.2.3"}, {}),
        ({"nginx_image": "ghcr.io/example/front:main@sha256:" + "a" * 64}, {}),
        ({"broker_image": "docker.io/library/broker:3"}, {}),
        ({"ansible_host": "0.0.0.0"}, {}),
        ({"ansible_host": "cases.example.internal"}, {}),
        ({"hostname": "Cases"}, {}),
        ({"logical_id": "Cases"}, {}),
        ({"db_login_ref": ref("admin-password")}, {}),
        ({"data_root": "/var/lib/../etc"}, {}),
        ({"dir": "relative/dir"}, {}),
        ({"app_uid": 0}, {}),
        ({"front_gid": 0}, {}),
        ({"admin_email": "not an address"}, {}),
        ({"worker_mem_limit": "lots"}, {}),
        ({}, {"db-password": "short"}),
        ({}, {"db-password": "has'quote-0123456789abcdefgh"}),
        ({}, {"db-password": "has@at-sign-0123456789abcdef"}),
        ({}, {"api-key": "short"}),
        ({}, {"session-key": "short"}),
        ({}, {"password-salt": "has a space in the salt value"}),
        ({}, {"admin-password": "a" * 20 + "-01"}),
        ({}, {"admin-password": "Aa1" * 7}),
        ({}, {"admin-password": "p" * 30}),
        ({}, {"tls-cert": "not a certificate"}),
        ({}, {"tls-key": CERT}),
        ({}, {"ca": "not a certificate"}),
    ],
)  # fmt: skip
@first_run(_first_main_refuses_bad_inputs_and_credentials)
def test_main_refuses_bad_inputs_and_credentials(first, over, env):
    r, tmp_path = first
    assert r.returncode != 0, r.stdout
    assert not (tmp_path / "app" / "docker-compose.yml").exists()


# ----------------------------------------------------------------------------- started

PKI: dict = {}


@pytest.fixture(scope="module")
def pki(tmp_path_factory):
    if not PKI:
        d = tmp_path_factory.mktemp("pki")
        PKI["chain"], PKI["key"], PKI["ca"] = make_pki(d, HOSTNAME)
        PKI["other_ca"] = make_pki(tmp_path_factory.mktemp("pki2"), HOSTNAME)[2]
    return PKI


def _env(pki, **extra):
    return {
        **SECRETS,
        env_for(ref("tls-cert")): pki["chain"],
        env_for(ref("tls-key")): pki["key"],
        env_for(ref("ca")): pki["ca"],
        **extra,
    }


def _front(tmp_path, pki, **kw):
    return Front(
        pki["chain"], pki["key"], tmp_path, **{"api_key": ACCESS, "version": VERSION, **kw}
    )


def _docker(tmp_path: Path, health: str = "healthy") -> dict:
    """A fake docker: ``compose ps`` lists the five services in ``health``; ``exec ... psql`` logs its
    standard input and answers one updated row the first time only; ``exec ... pg_dump -f F``
    writes a dump at F's host path (the export mount) unless ``dump.empty`` exists, ``mv`` moves
    it, ``pg_restore`` needs the staged file; everything else succeeds.  Every call is logged. A
    fake curl logs its arguments and standard input, then runs the real one."""
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    rows = "".join(
        json.dumps({"Service": s, "State": "running", "Health": health}) + "\n" for s in SERVICES
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
elif "up" in a and os.path.exists({str(tmp_path / "app" / "secrets" / "app.env")!r}):
    open({str(tmp_path / "appenv.log")!r}, "a").write(
        "--force-recreate " if "--force-recreate" in a else "")
    open({str(tmp_path / "appenv.log")!r}, "a").write(
        open({str(tmp_path / "app" / "secrets" / "app.env")!r}).read() + "----\\n")
elif "psql" in a and "-c" in a:
    sys.stdout.write("t\\n")
elif "psql" in a:
    open({str(tmp_path / "psql.stdin.log")!r}, "a").write(sys.stdin.read())
    marker = {str(tmp_path / "key.set")!r}
    if not os.path.exists(marker):
        open(marker, "w").write("")
        sys.stdout.write("1\\n")
elif "pg_dump" in a:
    path = host(a[len(a) - 1 - a[::-1].index("-f") + 1])
    open(path, "wb").write(b"" if os.path.exists({str(tmp_path / "dump.empty")!r}) else b"PGDMP fake dump")
elif "mv" in a:
    shutil.move(host(a[-2]), host(a[-1]))
elif "pg_restore" in a:
    sys.exit(0 if os.path.exists(host(a[-1])) else 3)
"""
    fake(bindir / "docker", body)
    real = shutil.which("curl")
    fake(
        bindir / "curl",
        f"""
import os, sys
open({str(tmp_path / "curl.log")!r}, "a").write(" ".join(sys.argv[1:]) + "\\n")
os.execv({real!r}, [{real!r}] + sys.argv[1:])
""",
    )
    return {"PATH": f"{bindir}:{os.environ['PATH']}"}


def _installed_ca(tmp_path: Path, ca: str) -> None:
    """The CA file an install (main) leaves in the data root, for a hook run on its own."""
    (tmp_path / "data" / "tls").mkdir(parents=True, exist_ok=True)
    (tmp_path / "data" / "tls" / "ca.pem").write_text(ca)


def _calls(tmp_path: Path) -> list[str]:
    log = tmp_path / "docker.log"
    return log.read_text().splitlines() if log.exists() else []


def _live(tmp_path, front, **kw):
    # the name resolves to the stand-in by curl's --resolve: the guest's address is the loopback one
    over = {"ansible_host": LOOPBACK, "port": front.port, "start": True, "ready_timeout": 10}
    return pv(tmp_path, **{**over, **kw})


def test_main_waits_for_the_api_and_a_second_run_changes_nothing(tmp_path, pki):
    with _front(tmp_path, pki) as front:
        env = _env(pki, **_docker(tmp_path))
        v = _live(tmp_path, front)
        r = run_role(tmp_path, ROLE, "main", v, env=env)
        assert r.returncode == 0, r.stdout + r.stderr
        calls = _calls(tmp_path)
        assert (
            len([c for c in calls if "--remove-orphans" in c]) == 2
        )  # the start and the re-render
        assert ("/api/ping", f"Bearer {ACCESS}") in front.requests
        again = run_role(tmp_path, ROLE, "main", v, env=env)
        assert again.returncode == 0 and "changed=0" in again.stdout, again.stdout


def test_the_api_key_is_set_in_the_database_through_standard_input_only(tmp_path, pki):
    with _front(tmp_path, pki) as front:
        env = _env(pki, **_docker(tmp_path))
        v = _live(tmp_path, front)
        r = run_role(tmp_path, ROLE, "main", v, env=env)
        assert r.returncode == 0, r.stdout + r.stderr
        sql = (tmp_path / "psql.stdin.log").read_text()
        assert f"SET api_key = '{ACCESS}'" in sql and "IS DISTINCT FROM" in sql
        assert "WHERE \"user\" = 'administrator'" in sql
        # in no argument, no environment file, no output
        assert ACCESS not in " ".join(_calls(tmp_path))
        assert ACCESS not in r.stdout + r.stderr
        calls = _calls(tmp_path)
        order = [
            next(i for i, c in enumerate(calls) if k in c) for k in ("--remove-orphans", " psql ")
        ]
        assert order == sorted(order)
        # the key is set once; the second run finds it already so and changes nothing
        again = run_role(tmp_path, ROLE, "main", v, env=env)
        assert again.returncode == 0 and "changed=0" in again.stdout, again.stdout


def test_the_real_administrator_password_never_reaches_the_app_or_its_log(tmp_path, pki):
    with _front(tmp_path, pki) as front:
        env = _env(pki, **_docker(tmp_path))
        v = _live(tmp_path, front)
        r = run_role(tmp_path, ROLE, "main", v, env=env)
        assert r.returncode == 0, r.stdout + r.stderr
        snaps = (tmp_path / "appenv.log").read_text().split("----\n")
        snaps = [x for x in snaps if x.strip()]
        # the first start carries a throwaway password, the later render none; the real one is in neither
        assert "IRIS_ADM_PASSWORD=" in snaps[0] and ADMIN_LOGIN not in "".join(snaps)
        assert "IRIS_ADM_PASSWORD" not in snaps[-1] and snaps[-1].startswith("--force-recreate ")
        assert "IRIS_ADM_PASSWORD" not in (tmp_path / "app" / "secrets" / "app.env").read_text()
        calls = _calls(tmp_path)
        assert [c for c in calls if "--force-recreate --no-deps app" in c]
        assert ADMIN_LOGIN not in " ".join(calls)
        # the real password was set through the API, on curl's standard input
        assert [p for p, _ in front.posts] == ["/manage/users/update/1"]
        assert json.loads(front.posts[0][1]) == {"user_password": ADMIN_LOGIN}
        assert ADMIN_LOGIN not in (tmp_path / "curl.log").read_text()
        assert (tmp_path / "data" / "bootstrapped").exists()
        # a second run does none of it
        (tmp_path / "docker.log").write_text("")
        again = run_role(tmp_path, ROLE, "main", v, env=env)
        assert again.returncode == 0 and "changed=0" in again.stdout, again.stdout
        assert not [c for c in _calls(tmp_path) if "--force-recreate" in c]
        assert len(front.posts) == 1


def test_a_refused_password_stops_main_before_the_marker(tmp_path, pki):
    with _front(tmp_path, pki) as front:
        env = _env(pki, **_docker(tmp_path))
        (tmp_path / "data").mkdir()
        v = _live(tmp_path, front, ready_timeout=5)
        # a front that refuses the update: nothing is recorded as set up
        front.httpd.RequestHandlerClass.do_POST = lambda h: h._send(500, {"status": "error"})
        r = run_role(tmp_path, ROLE, "main", v, env=env)
        assert r.returncode != 0 and "refused the administrator's password" in r.stdout + r.stderr
        assert not (tmp_path / "data" / "bootstrapped").exists()


def test_a_service_that_never_answers_stops_main_naming_the_wait(tmp_path, pki):
    with _front(tmp_path, pki, ping_status=503) as front:
        env = _env(pki, **_docker(tmp_path))
        r = run_role(tmp_path, ROLE, "main", _live(tmp_path, front, ready_timeout=5), env=env)
        assert r.returncode != 0
        assert "did not answer its ping" in r.stdout + r.stderr


def test_a_changed_certificate_restarts_the_front(tmp_path, pki):
    with _front(tmp_path, pki) as front:
        env = _env(pki, **_docker(tmp_path))
        v = _live(tmp_path, front)
        assert run_role(tmp_path, ROLE, "main", v, env=env).returncode == 0
        (tmp_path / "docker.log").write_text("")
        assert run_role(tmp_path, ROLE, "main", v, env=env).returncode == 0
        assert not [c for c in _calls(tmp_path) if " restart " in f" {c} "]
        env2 = {**env, env_for(ref("tls-cert")): pki["chain"].replace("MII", "MIJ", 1)}
        r = run_role(tmp_path, ROLE, "main", v, env=env2)
        assert [c for c in _calls(tmp_path) if " restart nginx" in c], r.stdout


def test_health_passes_and_the_key_reaches_curl_on_its_standard_input_only(tmp_path, pki):
    env = _env(pki, **_docker(tmp_path))
    with _front(tmp_path, pki) as front:
        v = _live(tmp_path, front)
        assert run_role(tmp_path, ROLE, "main", v, env=env).returncode == 0
        ok = run_role(tmp_path, ROLE, "health", v, env=env)
        assert ok.returncode == 0, ok.stdout + ok.stderr
        paths = [p for p, _ in front.requests]
        assert "/api/ping" in paths and "/api/versions" in paths
        # one call with no key was made, and refused
        assert ("/api/ping", None) in front.requests
        argv = (tmp_path / "curl.log").read_text()
        assert ACCESS not in argv and "--config -" in argv
        assert "--cacert" in argv and f"--resolve {HOSTNAME}:{front.port}:{LOOPBACK}" in argv
        assert "-k" not in argv.split() and "--insecure" not in argv
        for out in (ok.stdout, ok.stderr):
            assert ACCESS not in out
        assert ACCESS not in " ".join(_calls(tmp_path))


@pytest.mark.parametrize(
    "front_kw, health, want",
    [
        ({"open_api": True}, "healthy", "refuse"),
        ({"refuse_key": True}, "healthy", "401"),
        ({"version": "v0.0.1"}, "healthy", "must report"),
        ({}, "unhealthy", "unhealthy"),
    ],
)  # fmt: skip
def test_health_fails_on_an_open_api_a_refused_key_another_version_and_an_unhealthy_container(
    tmp_path, pki, front_kw, health, want
):
    env = _env(pki, **_docker(tmp_path, health=health))
    _installed_ca(tmp_path, pki["ca"])
    with _front(tmp_path, pki, **front_kw) as front:
        bad = run_role(tmp_path, ROLE, "health", _live(tmp_path, front), env=env)
        assert bad.returncode != 0
        assert want in bad.stdout + bad.stderr, bad.stdout


def test_health_fails_when_the_certificate_does_not_verify_against_the_ca(tmp_path, pki):
    env = _env(pki, **_docker(tmp_path))
    _installed_ca(tmp_path, pki["other_ca"])
    with _front(tmp_path, pki) as front:
        bad = run_role(tmp_path, ROLE, "health", _live(tmp_path, front), env=env)
        assert bad.returncode != 0
        assert "certificate must verify" in bad.stdout + bad.stderr


# ----------------------------------------------------------------------------- export, restore


def _export(tmp_path, env, v):
    (tmp_path / "data" / "files" / "server_data").mkdir(parents=True, exist_ok=True)
    (tmp_path / "data" / "files" / "server_data" / "a.txt").write_text("evidence")
    r = run_role(tmp_path, ROLE, "export", v, env=env)
    assert r.returncode == 0, r.stdout + r.stderr
    return tmp_path / "data" / "export"


def test_export_writes_an_object_tree_with_a_sha256_listing(tmp_path):
    env = {**SECRETS, **_docker(tmp_path)}
    exp = _export(tmp_path, env, pv(tmp_path))
    assert (exp / "db" / "iris.dump").read_bytes() == b"PGDMP fake dump"
    assert (exp / "files.tar").stat().st_size > 0
    rows = [json.loads(line) for line in (exp / "listing.jsonl").read_text().splitlines()]
    assert sorted(r["key"] for r in rows) == ["db/iris.dump", "files.tar", "version.txt"]
    assert (exp / "version.txt").read_text().strip() == VERSION
    for r in rows:
        data = (exp / r["key"]).read_bytes()
        assert r["size"] == len(data) and r["sha256"] == hashlib.sha256(data).hexdigest()
    dump = next(c for c in _calls(tmp_path) if "pg_dump" in c)
    assert "-Fc" in dump and "--no-owner" in dump
    assert oct((exp).stat().st_mode & 0o777) == "0o700"
    assert not list(Path("/tmp").glob("*iris*dump*"))  # nothing staged in /tmp


def test_export_refuses_an_empty_dump_and_lists_nothing(tmp_path):
    env = {**SECRETS, **_docker(tmp_path)}
    (tmp_path / "dump.empty").write_text("")
    r = run_role(tmp_path, ROLE, "export", pv(tmp_path), env=env)
    assert r.returncode != 0 and "dump is empty" in r.stdout + r.stderr
    assert not (tmp_path / "data" / "export" / "listing.jsonl").exists()


def _first_restore_refuses_a_tampered_export_and_writes_nothing(tmp_path):
    env = {**SECRETS, **_docker(tmp_path)}
    v = pv(tmp_path)
    exp = _export(tmp_path, env, v)
    (exp / "db" / "iris.dump").write_bytes(b"PGDMP tampered")
    (tmp_path / "docker.log").unlink()
    return {
        "role": ROLE,
        "tasks_from": "restore",
        "extra_vars": {**v, P + "restore_source": str(exp)},
        "env": env,
    }


@first_run(_first_restore_refuses_a_tampered_export_and_writes_nothing)
def test_restore_refuses_a_tampered_export_and_writes_nothing(first):
    r, tmp_path = first
    assert r.returncode != 0 and "not an intact export" in r.stdout + r.stderr
    assert not [c for c in _calls(tmp_path) if "pg_restore" in c or " stop " in f" {c} "]


def test_restore_stops_the_app_restores_and_starts_it_again_and_can_be_repeated(tmp_path, pki):
    with _front(tmp_path, pki) as front:
        env = _env(pki, **_docker(tmp_path))
        v = _live(tmp_path, front)
        assert run_role(tmp_path, ROLE, "main", v, env=env).returncode == 0  # an installed service
        exp = _export(tmp_path, env, v)
        # a later file on the target that the export does not hold: the restore replaces
        (tmp_path / "data" / "files" / "server_data" / "stale.txt").write_text("deleted at source")
        for _ in range(2):  # the second is the final delta after a freeze
            (tmp_path / "docker.log").write_text("")
            r = run_role(tmp_path, ROLE, "restore", {**v, P + "restore_source": str(exp)}, env=env)
            assert r.returncode == 0, r.stdout + r.stderr
            calls = _calls(tmp_path)
            order = [next(i for i, c in enumerate(calls) if k in c)
                     for k in (" stop nginx worker app", "pg_restore", " up -d app worker nginx", "--file -")]  # fmt: skip
            assert order == sorted(order), calls
            # a safety export of the populated database came first, beside the source
            safety = next(i for i, c in enumerate(calls) if "pre-restore-iris.dump.tmp" in c)
            assert safety < order[0]
            assert (tmp_path / "data" / "export" / "pre-restore-listing.jsonl").is_file()
            assert (tmp_path / "data" / "export" / "db" / "pre-restore-iris.dump").is_file()
            assert (tmp_path / "data" / "export" / "pre-restore-version.txt").is_file()
            assert "--clean" in next(c for c in calls if "pg_restore" in c)
            assert "--single-transaction" in next(c for c in calls if "pg_restore" in c)
            assert not (tmp_path / "data" / "export" / "db" / ".restore.dump").exists()
            assert (tmp_path / "data" / "files" / "server_data" / "a.txt").read_text() == "evidence"
            assert not (tmp_path / "data" / "files" / "server_data" / "stale.txt").exists()


def _relist(exp: Path) -> None:
    """Rewrite the listing so it matches the files as they are now (a source made by hand)."""
    rows = []
    for key in ("db/iris.dump", "files.tar", "version.txt"):
        data = (exp / key).read_bytes()
        rows.append({"key": key, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()})
    (exp / "listing.jsonl").write_text("".join(json.dumps(r, sort_keys=True) + "\n" for r in rows))


@pytest.mark.parametrize(
    "newer", ["v99.0.0", "v" + VERSION[1:].rsplit(".", 1)[0] + ".99", "latest"]
)
def test_restore_refuses_a_dump_from_a_newer_version_and_writes_nothing(tmp_path, newer):
    env = {**SECRETS, **_docker(tmp_path)}
    v = pv(tmp_path)
    exp = _export(tmp_path, env, v)
    (exp / "version.txt").write_text(newer + "\n")
    _relist(exp)  # a listing that is intact: only the version is wrong
    (tmp_path / "docker.log").unlink()
    r = run_role(tmp_path, ROLE, "restore", {**v, P + "restore_source": str(exp)}, env=env)
    assert r.returncode != 0 and "newer than" in r.stdout + r.stderr
    assert not [
        c for c in _calls(tmp_path) if "pg_restore" in c or " stop " in f" {c} " or "pg_dump" in c
    ]


def test_restore_accepts_an_older_version_and_a_fresh_database_takes_no_safety_export(
    tmp_path, pki
):
    with _front(tmp_path, pki) as front:
        env = _env(pki, **_docker(tmp_path))
        v = _live(tmp_path, front)
        assert run_role(tmp_path, ROLE, "main", v, env=env).returncode == 0
        exp = _export(tmp_path, env, v)
        (exp / "version.txt").write_text("v0.0.1\n")
        _relist(exp)
        # no schema yet: the database answers f to the schema question
        docker = tmp_path / "bin" / "docker"
        docker.write_text(
            docker.read_text().replace('sys.stdout.write("t\\n")', 'sys.stdout.write("f\\n")')
        )
        shutil.rmtree(exp / "db" / "pre-restore-iris.dump", ignore_errors=True)
        (tmp_path / "docker.log").write_text("")
        r = run_role(tmp_path, ROLE, "restore", {**v, P + "restore_source": str(exp)}, env=env)
        assert r.returncode == 0, r.stdout + r.stderr
        assert not [c for c in _calls(tmp_path) if "pre-restore" in c]
        assert any("pg_restore" in c for c in _calls(tmp_path))


# ----------------------------------------------------------------------------- upgrade


def _first_upgrade_records_only_a_pinned_target_that_is_not_older(tmp_path):
    v = pv(tmp_path)
    return {"role": ROLE, "tasks_from": "main", "extra_vars": v, "env": SECRETS, "setup": {"v": v}}


@first_run(_first_upgrade_records_only_a_pinned_target_that_is_not_older)
def test_upgrade_records_only_a_pinned_target_that_is_not_older(first):
    first_result, tmp_path = first
    v = first.setup["v"]
    assert first_result.returncode == 0
    app = DEFAULTS[P + "app_image"]
    repo, tag = app.split("@")[0].rsplit(":", 1)
    major, minor, patch = tag[1:].split(".")
    newer = f"{repo}:v{major}.{minor}.{int(patch) + 1}@sha256:" + "c" * 64
    r = run_role(tmp_path, ROLE, "upgrade", {**v, P + "target_image": newer}, env=SECRETS)
    assert r.returncode == 0, r.stdout + r.stderr
    rec = json.loads((tmp_path / "app" / "pending-upgrade.json").read_text())
    assert rec == {
        "service": "app",
        "tag": f"v{major}.{minor}.{int(patch) + 1}",
        "digest": "sha256:" + "c" * 64,
    }
    older = f"{repo}:v{major}.{minor}.{max(int(patch) - 1, 0)}@sha256:" + "d" * 64
    for bad in (
        {P + "target_image": older},
        {P + "target_image": newer.split("@")[0]},
        {P + "target_image": "ghcr.io/example/other:v9.9.9@sha256:" + "c" * 64},
        {
            P + "target_nginx_image": f"{DEFAULTS[P + 'nginx_image'].split(':')[0]}:v0.0.1@sha256:"
            + "e" * 64
        },
        {P + "target_broker_image": "docker.io/library/broker:9.0.0@sha256:" + "e" * 64},
        {P + "target_image": newer, P + "target_db_image": newer},
        {},
    ):
        (tmp_path / "app" / "pending-upgrade.json").unlink(missing_ok=True)
        r = run_role(tmp_path, ROLE, "upgrade", {**v, **bad}, env=SECRETS)
        assert r.returncode != 0, bad
        assert not (tmp_path / "app" / "pending-upgrade.json").exists()
