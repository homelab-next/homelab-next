# SPDX-License-Identifier: Apache-2.0
"""The threat-intel module's role (modules/<id>/roles/<id>), run on localhost against fakes (CI is
unprivileged): main renders the four containers through compose_app with no secret in the compose
file and a second run is ``changed=0``; a reference with no value in the secret store, or a malformed
input or credential, is refused by name before anything is written; with the containers "started" (a
fake docker holding the application's state) the workers are started and every account's key is set
through the environment of one command, never an argument, and only when the API does not already
accept it; health passes against the fake and fails on an open API, a refused key, another version, a
worker that is not running, an unhealthy container and a database holding fewer rows than expected;
export writes a whole dump with a manifest and a sha256 listing, keeps the previous one when it fails
and always starts the application and its workers again; restore refuses a dump that is not the
pinned file, a database that holds data and a source with too few counts, loads an intact one and
compares the counts to the source's BEFORE the application starts (and leaves it stopped when they
differ); the helper refuses a files tarball that holds a link and never overwrites a file; upgrade
refuses an unpinned, foreign or older target."""

from __future__ import annotations

import grp
import hashlib
import io
import json
import os
import pwd
import socket
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest
import yaml
from rolerun import fake, run_cases, run_role

from tests.modules.threat_intel_module import MID, ROLE_DIR, P, defaults, env_for, ref

LOOPBACK = socket.gethostbyname("localhost")  # the fake listens here; resolved, never a literal

ROOT = Path(__file__).resolve().parents[2]
ROLE = str(ROLE_DIR)
HELPER = ROLE_DIR / "files" / f"hnx_{MID}.py"
APP, MODS, WORK = (
    f"{MID}-core",
    f"{MID}-modules",
    f"{MID}-workers",
)  # the compose services, the supervisor group
VARS = yaml.safe_load((ROLE_DIR / "vars" / "main.yml").read_text())
USER = pwd.getpwuid(os.getuid()).pw_name
DEFAULTS = defaults()
CORE_IMAGE = DEFAULTS[P + "core_image"]
CORE_REPO = CORE_IMAGE.split("@")[0].rsplit(":", 1)[0]
MODULES_IMAGE = DEFAULTS[P + "modules_image"]
MODULES_REPO = MODULES_IMAGE.split("@")[0].rsplit(":", 1)[0]
#: the example registry's edge address (a documentation-range address, never connected to)
GUEST = yaml.safe_load((ROOT / "examples" / "services.yml").read_text())["hosts"]["edge-core"][
    "address"
]
VERSION = CORE_IMAGE.split("@")[0].rsplit(":", 1)[1][1:]

# stand-in secrets: short obviously-fake words, padded at run time (never key-looking literals)
PW = lambda n: f"Fake-{n}-" + "x" * 12  # noqa: E731
KEY = lambda c: c * 40  # noqa: E731  (a 40 character API key of one letter)
NAMES = {
    "admin-password": PW("admin"),
    "admin-api-key": KEY("a"),
    "mysql-password": PW("db"),
    "mysql-root-password": PW("root"),
    "redis-password": PW("cache"),
    "encryption-key": PW("enc"),
    "gpg-passphrase": PW("gpg"),
}
SECRETS = {env_for(ref(n)): v for n, v in NAMES.items()}
CONSUMER_ENV = "HNX_SECRET_CONSUMER_ENRICH_KEY"
CONSUMER_REF = "secret:consumer/enrich-key"
SECRETS[CONSUMER_ENV] = KEY("b")
CONSUMERS = [{"email": "enrich@example.internal", "key_ref": CONSUMER_REF}]
ALL_VALUES = list(SECRETS.values())
COUNTS = {"events": 8, "attributes": 41, "objects": 5, "galaxy_clusters": 3, "feeds": 2, "users": 1}
EMPTY = {"events": 0, "attributes": 0, "objects": 0, "galaxy_clusters": 3, "feeds": 0, "users": 1}


def dv(tmp_path: Path, **kw) -> dict:
    """The role's variables for a test: ``kw`` names the role's own variables without their prefix
    (``hnx_`` and ``ansible_`` ones as they are)."""
    v = {
        "logical_id": "intel",
        "admin_email": "admin@example.internal",
        "admin_org": "Example Org",
        "dir": str(tmp_path / "app"),
        "owner": USER,
        "group": grp.getgrgid(os.getgid()).gr_name,
        "data_root": str(tmp_path / "data"),
        "consumers": CONSUMERS,
        "start": False,
        "validate_with_docker": False,
    }
    v.update(kw)
    out = {"ansible_host": GUEST}
    out.update({k if k.startswith(("hnx_", "ansible_")) else P + k: x for k, x in v.items()})
    return out


def compose(tmp_path: Path) -> dict:
    return yaml.safe_load((tmp_path / "app" / "docker-compose.yml").read_text())


# ----------------------------------------------------------------------------- render


def test_main_renders_four_narrow_containers_with_no_secret_in_the_compose_file(tmp_path):
    v = dv(tmp_path, hnx_module_slice=f"hnx-{MID}-server.slice")
    r = run_role(tmp_path, ROLE, "main", v, env=SECRETS)
    assert r.returncode == 0, r.stdout + r.stderr
    doc = compose(tmp_path)
    # the footprint's CPU quota and memory limit are the slice (LL-504)
    assert {sv["cgroup_parent"] for sv in doc["services"].values()} == {f"hnx-{MID}-server.slice"}
    assert sorted(doc["services"]) == sorted(["db", APP, MODS, "redis"])
    for name, svc in doc["services"].items():
        assert "@sha256:" in svc["image"], name
        assert svc["cap_drop"] == ["ALL"] and svc["security_opt"] == ["no-new-privileges:true"]
        assert "privileged" not in svc and svc["mem_limit"], name
    assert doc["services"][APP]["image"] == CORE_IMAGE
    published = {n: s["ports"] for n, s in doc["services"].items() if "ports" in s}
    assert published == {APP: [f"{GUEST}:443:443"]}  # the guest's own address, one port
    root = str(tmp_path / "data")
    assert f"{root}/mysql:/var/lib/mysql" in doc["services"]["db"]["volumes"]
    assert f"{root}/files:{VARS[P + 'container_files']}" in doc["services"][APP]["volumes"]
    assert any(c == "--innodb-buffer-pool-size=10G" for c in doc["services"]["db"]["command"])
    core_env = doc["services"][APP]["environment"]
    assert core_env["BASE_URL"] == f"https://{GUEST}" and core_env["ADMIN_ORG"] == "Example Org"
    env_file = (tmp_path / "app" / "secrets" / f"{APP}.env").read_text()
    assert (
        "DISABLE_PRINTING_PLAINTEXT_CREDENTIALS='true'" in env_file
    )  # the first start prints no key
    # the credentials are in the 0600 env files and in no other file the role wrote
    compose_text = (tmp_path / "app" / "docker-compose.yml").read_text()
    for p in tmp_path.rglob("*"):
        if not p.is_file() or p.name in ("vars.json", "play.yml"):
            continue
        body = p.read_text(errors="ignore")
        if p.parent == tmp_path / "app" / "secrets":
            assert oct(p.stat().st_mode & 0o777) == "0o600"
            continue
        assert not [s for s in ALL_VALUES if s in body], p
    assert sorted(p.name for p in (tmp_path / "app" / "secrets").iterdir()) == [
        "db.env", f"{APP}.env", "redis.env"
    ]  # fmt: skip
    assert "ADMIN_KEY" not in compose_text
    assert oct((tmp_path / "data").stat().st_mode & 0o777) == "0o750"
    assert oct((tmp_path / "data" / "export").stat().st_mode & 0o777) == "0o700"
    # the directories the containers mount are created, and never held to an owner or a mode a
    # second run would fight the entrypoints over
    for name in ("mysql", "cache", "configs", "logs", "files", "gnupg", "ssl"):
        assert (tmp_path / "data" / name).is_dir()
    (tmp_path / "data" / "configs").chmod(0o770)
    again = run_role(tmp_path, ROLE, "main", v, env=SECRETS)
    assert again.returncode == 0 and "changed=0" in again.stdout, again.stdout
    assert oct((tmp_path / "data" / "configs").stat().st_mode & 0o777) == "0o770"


BAD = [
    ({"logical_id": "Intel"}, "registry id"),
    ({"core_image": CORE_REPO + ":v2.5.44"}, "pinned by tag and digest"),
    ({"core_image": CORE_REPO + ":latest@sha256:" + "a" * 64}, "pinned by tag and digest"),
    ({"modules_image": MODULES_REPO + ":3.0.9@sha256:" + "a" * 64}, "pinned by tag and digest"),
    ({"bind": "0.0.0.0"}, "not all interfaces"),
    ({"bind": "intel.example.internal"}, "not all interfaces"),
    ({"port": 0}, "a port"),
    ({"data_root": "/srv"}, "canonical directories"),
    ({"data_root": "/var/lib/../etc/x"}, "canonical directories"),
    ({"base_url": "http://x.example.internal"}, "https base URL"),
    ({"admin_email": "not an email"}, "administrator email"),
    ({"admin_org": "-bad"}, "administrator email"),
    ({"consumers": [{"email": "a@example.internal"}]}, "consumers that are mappings"),
    ({"consumers": [{"key_ref": "secret:a/b"}]}, "consumers that are mappings"),
    ({"consumers": [{**CONSUMERS[0], "extra": 1}]}, "consumers that are mappings"),
    ({"consumers": [{**CONSUMERS[0], "key_ref": "not-a-ref"}]}, "distinct secret"),
    ({"consumers": [CONSUMERS[0], CONSUMERS[0]]}, "distinct secret"),
    (
        {"consumers": [{**CONSUMERS[0], "email": "admin@example.internal"}]},
        "consumers that are mappings",
    ),
    ({"tls_cert_ref": "secret:a/cert"}, "both or neither"),
    ({"innodb_buffer_pool_size": "lots"}, "buffer pool"),
    ({"db_mem_limit": "lots"}, "memory limits"),
    ({"expected_min_counts": {"events": -1}}, "counts that are whole numbers"),
    ({"expected_min_counts": {"widgets": 1}}, "counts that are whole numbers"),
]


def test_readiness_credentials_pass_with_every_reference_and_name_a_missing_one(tmp_path):
    ok = run_role(tmp_path, ROLE, "credentials", dv(tmp_path), env=SECRETS)
    assert ok.returncode == 0, ok.stdout + ok.stderr
    env = {k: v for k, v in SECRETS.items() if k != CONSUMER_ENV}
    bad = run_role(tmp_path, ROLE, "credentials", dv(tmp_path), env=env)
    assert bad.returncode != 0 and CONSUMER_REF in bad.stdout + bad.stderr


# ----------------------------------------------------------------------------- the fake application


def _fakes(tmp_path: Path, health: str = "healthy", counts: dict | None = None) -> dict:
    """A fake docker holding the application's state in files under ``st/`` (so a second run sees what
    the first did), and a fake zstd that is a plain copy.  ``compose ps`` lists the four services in
    ``health``.  ``exec`` answers by what it is asked: a status call by the key's presence in
    ``accepted`` (a key the application knows), the version call (``version``), the key-setting
    command (adds the key to ``accepted``; logs the address, never the key), the supervisor (the lines
    of ``workers`` once started; ``started`` marks it), the database client (the counts: the contents
    of ``counts``, the tables: 104, a load: stdin to ``loaded.sql``, which then replaces the counts
    with ``after``) and the dump (a text with the completion line).  Every call is logged."""
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    st = tmp_path / "st"
    st.mkdir(exist_ok=True)
    (st / "counts").write_text(json.dumps(counts if counts is not None else COUNTS))
    rows = "".join(
        json.dumps({"Service": s, "State": "running", "Health": health}) + "\n"
        for s in ("db", APP, MODS, "redis")
    )
    body = f"""
import json, os, sys
a = sys.argv[1:]
St = {str(st)!r}
open({str(tmp_path / "docker.log")!r}, "a").write(" ".join(a).replace(chr(10), " ") + "\\n")
def read(name, default=""):
    p = St + "/" + name
    return open(p).read() if os.path.exists(p) else default
def have(name):
    return os.path.exists(St + "/" + name)
env = os.environ
KEYS = ["events", "attributes", "objects", "galaxy_clusters", "feeds", "users"]
if "inspect" in a:
    sys.stdout.write(json.dumps([{{"State": {{"StartedAt": "2026-01-01T00:00:00.000000000Z"}}}}]))
elif "logs" in a:
    if not have("init_pending"):
        sys.stdout.write("INIT | Configure PHP ...\\nINIT | Done ...\\n")
elif "restart" in a:
    open({str(tmp_path / "restart.log")!r}, "a").write("restart\\n")
    for f in ("api500",):
        if have(f):
            os.remove(St + "/" + f)
elif "ps" in a and "-q" in a:
    sys.stdout.write("0123abcd\\n")
elif "ps" in a:
    sys.stdout.write({rows!r})
elif "exec" in a:
    if "mariadb-dump" in a:
        open(St + "/dump.env", "w").write("pwd=" + ("yes" if env.get("MYSQL_PWD") else "no"))
        sys.stdout.write("-- MariaDB dump\\nCREATE TABLE t (i int);\\n-- Dump completed on 2026-01-01\\n")
        sys.exit(1 if have("dump.fails") else 0)
    if "mariadb" in a:
        i = a.index("mariadb")
        if "-e" in a[i:]:
            sql = a[a.index("-e", i) + 1]
            if "UNION ALL" in sql:
                c = json.loads(read("counts"))
                sys.stdout.write("".join(k + chr(9) + str(c[k]) + chr(10) for k in KEYS))
            else:
                sys.stdout.write(read("tables", "104") + chr(10))
        else:
            open(St + "/loaded.sql", "w").write(sys.stdin.read())
            open(St + "/load.env", "w").write("pwd=" + ("yes" if env.get("MYSQL_PWD") else "no"))
            if have("load.fails"):
                sys.exit(1)
            if have("after"):
                open(St + "/counts", "w").write(read("after"))
        sys.exit(0)
    k = a.index("-c")
    code, rest = a[k + 1], a[k + 3:]
    path, key = env.get("HNX_PATH", ""), env.get("HNX_KEY", "")
    accepted = read("accepted").split()
    if "supervisorctl" in code:
        if have("sup.down"):
            sys.stdout.write("the control port refused" + chr(10)); sys.exit(1)
        lines = read("workers", "".join({WORK!r} + ":w" + n + "   RUNNING   pid 1, uptime 0:01:00" + chr(10) for n in "12345"))
        if rest[0] == "start":
            sys.stdout.write({WORK!r} + ":w1: " + ("already started" if have("started") else "started") + chr(10))
            open(St + "/started", "w").write("1")
        else:
            sys.stdout.write(lines)
        sys.exit(0)
    if "change_authkey" in code:
        open({str(tmp_path / "keys.log")!r}, "a").write(env["HNX_EMAIL"] + chr(10))
        open(St + "/accepted", "a").write(key + chr(10))
        sys.exit(0)
    if "-X POST" in code:
        open({str(tmp_path / "post.log")!r}, "a").write(path + " " + ("key" if key else "nokey") + chr(10))
        sys.stdout.write(read("post", "200")); sys.exit(0)
    if "-w" in code:
        if path in ("/users/heartbeat", "/users/login"):
            code_ = "200"
        elif have("api500") and key and key in accepted:
            code_ = "500"
        elif have("open_api"):
            code_ = "200"
        elif key and key in accepted:
            code_ = "200"
        else:
            code_ = "403"
        sys.stdout.write(code_); sys.exit(0)
    if "curl -ksf" in code:
        if key and key in accepted:
            sys.stdout.write(json.dumps({{"version": read("version", {VERSION!r})}})); sys.exit(0)
        sys.exit(22)
sys.exit(0)
"""
    fake(bindir / "docker", body)
    # zstd as a plain copy: -dc -- FILE writes FILE, -o OUT writes stdin to OUT
    fake(
        bindir / "zstd",
        """
import sys
a = sys.argv[1:]
if "-dc" in a:
    sys.stdout.buffer.write(open(a[-1], "rb").read())
elif "-o" in a:
    open(a[a.index("-o") + 1], "wb").write(sys.stdin.buffer.read())
""",
    )
    return {"PATH": f"{bindir}:{os.environ['PATH']}"}


def _calls(tmp_path: Path) -> list[str]:
    log = tmp_path / "docker.log"
    return log.read_text().splitlines() if log.exists() else []


def _st(tmp_path: Path, name: str, text: str) -> None:
    (tmp_path / "st").mkdir(exist_ok=True)
    (tmp_path / "st" / name).write_text(text)


def _listener():
    s = socket.socket()
    s.bind((LOOPBACK, 0))
    s.listen(5)
    return s


def _live(tmp_path, port=443, **kw):
    kw.setdefault("ready_timeout", 10)
    return dv(tmp_path, bind=LOOPBACK, port=port, start=True, **kw)


def test_main_starts_the_workers_and_sets_every_key_through_the_environment(tmp_path):
    env = {**SECRETS, **_fakes(tmp_path)}
    r = run_role(tmp_path, ROLE, "main", _live(tmp_path), env=env)
    assert r.returncode == 0, r.stdout + r.stderr
    calls = _calls(tmp_path)
    assert any("--remove-orphans" in c for c in calls)  # compose_app started the project
    assert any("supervisorctl" in c and "start" in c and f"{WORK}:*" in c for c in calls)
    assert (tmp_path / "keys.log").read_text().splitlines() == [
        "admin@example.internal", "enrich@example.internal"
    ]  # fmt: skip
    setting = [c for c in calls if "change_authkey" in c]
    assert len(setting) == 2 and all(
        "-u www-data" in c and "-e HNX_EMAIL -e HNX_KEY" in c for c in setting
    )
    blob = "\n".join(calls)
    assert not [s for s in ALL_VALUES if s in blob]  # never an argument


def test_a_second_run_changes_nothing_and_a_key_the_api_accepts_is_not_set_again(tmp_path):
    env = {**SECRETS, **_fakes(tmp_path)}
    v = _live(tmp_path)
    assert run_role(tmp_path, ROLE, "main", v, env=env).returncode == 0
    (tmp_path / "keys.log").unlink()
    again = run_role(tmp_path, ROLE, "main", v, env=env)
    assert again.returncode == 0 and "changed=0" in again.stdout, again.stdout
    assert not (tmp_path / "keys.log").exists()


def test_a_first_start_that_left_the_application_broken_is_restarted_once_and_a_good_one_is_not(
    tmp_path,
):
    env = {**SECRETS, **_fakes(tmp_path)}
    _st(tmp_path, "accepted", KEY("a") + "\n")
    _st(tmp_path, "api500", "")  # every API call is an internal error until the restart
    r = run_role(tmp_path, ROLE, "main", _live(tmp_path), env=env)
    assert r.returncode == 0, r.stdout + r.stderr
    assert (tmp_path / "restart.log").read_text().splitlines() == ["restart"]
    assert any(f"restart {APP}" in c for c in _calls(tmp_path))
    (tmp_path / "restart.log").unlink()
    again = run_role(tmp_path, ROLE, "main", _live(tmp_path), env=env)
    assert again.returncode == 0 and not (tmp_path / "restart.log").exists()


def test_main_fails_when_the_start_never_finishes(tmp_path):
    env = {**SECRETS, **_fakes(tmp_path)}
    _st(tmp_path, "init_pending", "")
    r = run_role(tmp_path, ROLE, "main", _live(tmp_path, ready_timeout=10), env=env)
    assert r.returncode != 0 and "start did not finish" in r.stdout


# ----------------------------------------------------------------------------- health


def _health(tmp_path, listener, health="healthy", counts=None, **kw):
    env = {**SECRETS, **_fakes(tmp_path, health, counts)}
    _st(tmp_path, "accepted", "\n".join([KEY("a"), KEY("b")]) + "\n")
    v = _live(tmp_path, port=listener.getsockname()[1], **kw)
    return run_role(tmp_path, ROLE, "health", v, env=env)


def test_health_passes_and_only_reads(tmp_path):
    with _listener() as ls:
        r = _health(tmp_path, ls, expected_min_counts=COUNTS)
    assert r.returncode == 0, r.stdout + r.stderr
    calls = "\n".join(_calls(tmp_path))
    assert "change_authkey" not in calls and " up " not in calls and "stop" not in calls
    assert not [s for s in ALL_VALUES if s in calls]
    assert not (tmp_path / "keys.log").exists()


def test_health_fails_when_the_api_is_open_to_any_caller(tmp_path):
    with _listener() as ls:
        _st(tmp_path, "open_api", "")
        r = _health(tmp_path, ls)
    assert r.returncode != 0 and "an open API is refused here" in r.stdout


def test_health_fails_on_a_key_the_application_does_not_accept(tmp_path):
    with _listener() as ls:
        env = {**SECRETS, **_fakes(tmp_path)}
        _st(tmp_path, "accepted", KEY("a") + "\n")  # the consumer's key is not one it holds
        r = run_role(tmp_path, ROLE, "health", _live(tmp_path, port=ls.getsockname()[1]), env=env)
    assert r.returncode != 0 and "account 1's key is refused" in r.stdout


def test_health_fails_on_another_version_than_the_pinned_one(tmp_path):
    with _listener() as ls:
        env = {**SECRETS, **_fakes(tmp_path)}
        _st(tmp_path, "accepted", "\n".join([KEY("a"), KEY("b")]) + "\n")
        _st(tmp_path, "version", "2.4.1")
        r = run_role(tmp_path, ROLE, "health", _live(tmp_path, port=ls.getsockname()[1]), env=env)
    assert r.returncode != 0 and f"another version than {VERSION}" in r.stdout


def test_health_fails_when_a_container_is_unhealthy(tmp_path):
    with _listener() as ls:
        r = _health(tmp_path, ls, health="unhealthy")
    assert r.returncode != 0 and "unhealthy" in r.stdout + r.stderr


def test_health_fails_when_the_database_holds_fewer_rows_than_expected(tmp_path):
    with _listener() as ls:
        r = _health(tmp_path, ls, counts={**COUNTS, "attributes": 40}, expected_min_counts=COUNTS)
    assert r.returncode != 0 and "holds 40 attributes, fewer than the 41 expected" in r.stdout


# ----------------------------------------------------------------------------- export


def _export(tmp_path, v, **env):
    return run_role(tmp_path, ROLE, "export", v, env={**SECRETS, **_fakes(tmp_path), **env})


def test_export_writes_a_whole_dump_a_manifest_and_a_listing_and_restarts_the_application(tmp_path):
    v = dv(tmp_path, start=True, expected_min_counts=COUNTS)
    r = _export(tmp_path, v)
    assert r.returncode == 0, r.stdout + r.stderr
    latest = tmp_path / "data" / "export" / "latest"
    assert sorted(p.name for p in latest.iterdir()) == [
        "dump.sql.zst",
        "listing.jsonl",
        "manifest.json",
    ]
    manifest = json.loads((latest / "manifest.json").read_text())
    assert manifest["format"] == f"{MID}-export-1" and manifest["version"] == VERSION
    assert manifest["counts"] == COUNTS and manifest["tables"] == 104
    assert manifest["excluded_tables"] == ["audit_logs"]
    rows = [json.loads(x) for x in (latest / "listing.jsonl").read_text().splitlines()]
    assert sorted(x["key"] for x in rows) == ["dump.sql.zst", "manifest.json"]
    for x in rows:
        data = (latest / x["key"]).read_bytes()
        assert x["size"] == len(data) and x["sha256"] == hashlib.sha256(data).hexdigest()
    assert manifest["dump"]["sha256"] == next(
        x["sha256"] for x in rows if x["key"] == "dump.sql.zst"
    )
    assert oct((latest / "manifest.json").stat().st_mode & 0o777) == "0o600"
    assert not (tmp_path / "data" / "export" / ".new").exists()
    calls = _calls(tmp_path)
    dump = next(c for c in calls if "mariadb-dump" in c)
    assert f"--ignore-table={MID}.audit_logs" in dump and "--single-transaction" in dump
    assert "-e MYSQL_PWD" in dump and not [s for s in ALL_VALUES if s in "\n".join(calls)]
    assert (tmp_path / "st" / "dump.env").read_text() == "pwd=yes"
    # the application is stopped for the dump, started after it, and its workers started again
    stop = next(i for i, c in enumerate(calls) if f" stop {APP}" in c)
    up = max(i for i, c in enumerate(calls) if f"up -d --wait {APP}" in c)
    dump_i = next(i for i, c in enumerate(calls) if "mariadb-dump" in c)
    assert stop < dump_i < up
    assert any("supervisorctl" in c and "start" in c for c in calls[up:])
    # a second export replaces the first, whole
    again = _export(tmp_path, v)
    assert again.returncode == 0 and not (tmp_path / "data" / "export" / ".previous").exists()


def test_an_export_that_is_not_whole_fails_keeps_the_previous_and_still_starts_the_application(
    tmp_path,
):
    v = dv(tmp_path, start=True, expected_min_counts=COUNTS)
    assert _export(tmp_path, v).returncode == 0
    latest = tmp_path / "data" / "export" / "latest"
    before = (latest / "manifest.json").read_text()
    (tmp_path / "docker.log").unlink()
    _st(tmp_path, "counts", json.dumps({**COUNTS, "events": 7}))  # fewer than the site expects
    r = run_role(
        tmp_path,
        ROLE,
        "export",
        v,
        env={**SECRETS, **_fakes(tmp_path, counts={**COUNTS, "events": 7})},
    )
    assert r.returncode != 0 and "the export is not whole" in r.stdout + r.stderr
    assert (latest / "manifest.json").read_text() == before  # the previous copy is untouched
    calls = _calls(tmp_path)
    assert any(f"up -d --wait {APP}" in c for c in calls)  # the application is not left stopped
    assert any("supervisorctl" in c and "start" in c for c in calls)


@pytest.mark.parametrize(
    ("what", "why"), [("dump.fails", "dump failed"), ("tables", "the export is not whole")]
)
def test_a_failing_dump_or_a_database_with_too_few_tables_writes_no_copy(tmp_path, what, why):
    v = dv(tmp_path, start=True)
    env = {**SECRETS, **_fakes(tmp_path)}
    _st(tmp_path, what, "" if what == "dump.fails" else "12")
    r = run_role(tmp_path, ROLE, "export", v, env=env)
    assert r.returncode != 0 and why in r.stdout + r.stderr
    assert not (tmp_path / "data" / "export" / "latest").exists()
    assert any(f"up -d --wait {APP}" in c for c in _calls(tmp_path))


# ----------------------------------------------------------------------------- restore

DUMP_TEXT = "-- MariaDB dump\nCREATE TABLE t (i int);\n-- Dump completed on 2026-01-01\n"
SOURCE_COUNTS = {
    "events": 8085,
    "attributes": 41071239,
    "objects": 5172748,
    "galaxy_clusters": 55392,
    "feeds": 14,
    "users": 1,
}


def _dump_file(tmp_path: Path, text: str = DUMP_TEXT) -> tuple[str, str]:
    p = tmp_path / "import" / "dump.sql.zst"
    p.parent.mkdir(exist_ok=True)
    p.write_text(text)
    return str(p), hashlib.sha256(text.encode()).hexdigest()


def _restore(tmp_path, *, counts=EMPTY, after=None, dump=None, **kw):
    path, sha = dump or _dump_file(tmp_path)
    env = {**SECRETS, **_fakes(tmp_path, counts=counts)}
    if after is not None:
        _st(tmp_path, "after", json.dumps(after))
    _st(tmp_path, "accepted", "")
    v = dv(
        tmp_path,
        start=True,
        restore_dump=path,
        restore_sha256=sha,
        restore_counts=SOURCE_COUNTS,
        **kw,
    )
    return run_role(tmp_path, ROLE, "restore", v, env=env)


def test_restore_loads_the_dump_proves_the_counts_before_starting_and_sets_the_keys(tmp_path):
    r = _restore(tmp_path, after=SOURCE_COUNTS)
    assert r.returncode == 0, r.stdout + r.stderr
    assert (tmp_path / "st" / "loaded.sql").read_text() == DUMP_TEXT
    assert (tmp_path / "st" / "load.env").read_text() == "pwd=yes"
    calls = _calls(tmp_path)
    stop = next(i for i, c in enumerate(calls) if f" stop {APP}" in c)
    load = next(
        i for i, c in enumerate(calls) if " exec " in c and f"mariadb --user=root {MID}" in c
    )
    start = max(i for i, c in enumerate(calls) if f"up -d --wait {APP}" in c)
    assert stop < load < start
    assert any("supervisorctl" in c and "start" in c for c in calls[start:])
    assert (tmp_path / "keys.log").read_text().splitlines()[0] == "admin@example.internal"
    assert not [s for s in ALL_VALUES if s in "\n".join(calls)]


def test_restore_leaves_the_application_stopped_when_the_counts_differ_from_the_sources(tmp_path):
    r = _restore(tmp_path, after={**SOURCE_COUNTS, "attributes": 41071238})
    assert (
        r.returncode != 0
        and "after the load the database holds 41071238 attributes where the source had 41071239"
        in r.stdout
    )
    assert "left STOPPED" in r.stdout
    assert not any(f"up -d --wait {APP}" in c for c in _calls(tmp_path))
    assert not (tmp_path / "keys.log").exists()


def test_restore_refuses_a_database_that_already_holds_data_and_loads_nothing(tmp_path):
    r = _restore(tmp_path, counts={**EMPTY, "events": 1}, after=SOURCE_COUNTS)
    assert r.returncode != 0 and "the import is not a merge" in r.stdout
    assert not (tmp_path / "st" / "loaded.sql").exists()
    assert not any(f" stop {APP}" in c for c in _calls(tmp_path))


def test_restore_refuses_a_dump_that_is_not_the_pinned_file_before_anything_runs(tmp_path):
    path, _sha = _dump_file(tmp_path)
    r = _restore(tmp_path, after=SOURCE_COUNTS, dump=(path, "0" * 64))
    assert r.returncode != 0 and "is not the pinned dump" in r.stdout
    assert not _calls(tmp_path) or not any("mariadb" in c for c in _calls(tmp_path))
    link = tmp_path / "import" / "link.sql.zst"
    link.symlink_to(path)
    r = _restore(
        tmp_path / "b" if (tmp_path / "b").mkdir() is None else tmp_path,
        after=SOURCE_COUNTS,
        dump=(str(link), hashlib.sha256(DUMP_TEXT.encode()).hexdigest()),
    )
    assert r.returncode != 0 and "is not the pinned dump" in r.stdout


# ----------------------------------------------------------------------------- the attachments


def _tar(tmp_path: Path, members: list[tuple[str, bytes | None, str]]) -> tuple[str, str]:
    """A tarball of (name, data, kind) members: kind ``f`` file, ``d`` directory, ``l`` link to data."""
    p = tmp_path / "import" / "files.tar"
    p.parent.mkdir(exist_ok=True)
    with tarfile.open(p, "w") as t:
        for name, data, kind in members:
            ti = tarfile.TarInfo(name)
            if kind == "d":
                ti.type = tarfile.DIRTYPE
                t.addfile(ti)
            elif kind == "l":
                ti.type = tarfile.SYMTYPE
                ti.linkname = (data or b"").decode()
                t.addfile(ti)
            else:
                ti.size = len(data or b"")
                t.addfile(ti, io.BytesIO(data or b""))
    return str(p), hashlib.sha256(p.read_bytes()).hexdigest()


GOOD_TAR = [
    ("files/", None, "d"),
    ("files/1313/", None, "d"),
    ("files/1313/5699623", b"sample one", "f"),
    ("files/1514/5757162", b"sample two", "f"),
    ("files/system-content/clusters/x.json", b"{}", "f"),  # system content: never extracted
    ("configs/config.php", b"<?php", "f"),  # configuration: never extracted
]


def _helper(cmd: str, cfg: dict) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-I", str(HELPER), cmd],
        input=json.dumps(cfg),
        capture_output=True,
        text=True,
    )


def test_the_helper_extracts_only_the_event_directories_and_counts_them(tmp_path):
    tar, _ = _tar(tmp_path, GOOD_TAR)
    dest = tmp_path / "files"
    dest.mkdir()
    r = _helper("files", {"tar": tar, "dest": str(dest)})
    assert r.returncode == 0, r.stderr
    assert json.loads(r.stdout) == {"listed": 2, "found": 2}
    assert sorted(p.relative_to(dest).as_posix() for p in dest.rglob("*") if p.is_file()) == [
        "1313/5699623",
        "1514/5757162",
    ]
    assert (dest / "1313" / "5699623").read_bytes() == b"sample one"
    # owner-only: the application's entrypoint gives the tree to its own user at its next start
    assert oct((dest / "1313" / "5699623").stat().st_mode & 0o777) == "0o600"
    assert oct((dest / "1313").stat().st_mode & 0o777) == "0o750"
    assert not (dest / "system-content").exists() and not (tmp_path / "configs").exists()


@pytest.mark.parametrize(
    "bad",
    [
        ("files/1313/link", b"/etc/passwd", "l"),
        ("files/1313/../../escape", b"x", "f"),
        ("files/1313/odd name", b"x", "f"),
    ],
    ids=["link", "dotdot", "odd-name"],
)
def test_the_helper_refuses_a_link_or_an_odd_name_and_extracts_nothing(tmp_path, bad):
    tar, _ = _tar(tmp_path, [*GOOD_TAR, bad])
    dest = tmp_path / "files"
    dest.mkdir()
    r = _helper("files", {"tar": tar, "dest": str(dest)})
    assert r.returncode == 1 and "files:" in r.stderr
    assert not list(dest.iterdir()) and not (tmp_path / "escape").exists()


def test_the_helper_never_overwrites_a_file_and_never_follows_a_link(tmp_path):
    tar, _ = _tar(tmp_path, GOOD_TAR)
    dest = tmp_path / "files"
    (dest / "1313").mkdir(parents=True)
    (dest / "1313" / "5699623").write_text("mine")
    r = _helper("files", {"tar": tar, "dest": str(dest)})
    assert r.returncode == 1 and (dest / "1313" / "5699623").read_text() == "mine"


@pytest.mark.parametrize("bad", ["relative/path", "/a/../b", "/a//b", ""])
def test_the_helper_refuses_a_path_that_is_not_absolute_and_canonical(tmp_path, bad):
    r = _helper("verify", {"path": bad})
    assert r.returncode == 1 and "path" in r.stderr


def test_restore_extracts_the_attachments_after_the_counts_are_proved(tmp_path):
    tar, sha = _tar(tmp_path, GOOD_TAR)
    r = _restore(tmp_path, after=SOURCE_COUNTS, restore_files_tar=tar, restore_files_sha256=sha)
    assert r.returncode == 0, r.stdout + r.stderr
    assert (tmp_path / "data" / "files" / "1313" / "5699623").read_bytes() == b"sample one"


def test_restore_refuses_a_files_tarball_that_is_not_the_pinned_one(tmp_path):
    tar, _ = _tar(tmp_path, GOOD_TAR)
    r = _restore(
        tmp_path, after=SOURCE_COUNTS, restore_files_tar=tar, restore_files_sha256="0" * 64
    )
    assert r.returncode != 0 and "is not the pinned tarball" in r.stdout
    assert not (tmp_path / "data" / "files" / "1313").exists()


# ----------------------------------------------------------------------------- feeds, upgrade


def test_feeds_resync_queues_the_fetch_and_the_cache_as_the_administrator(tmp_path):
    env = {**SECRETS, **_fakes(tmp_path)}
    r = run_role(tmp_path, ROLE, "feeds_resync", dv(tmp_path, start=True), env=env)
    assert r.returncode == 0, r.stdout + r.stderr
    assert (tmp_path / "post.log").read_text().splitlines() == [
        "/feeds/fetchFromAllFeeds key", "/feeds/cacheFeeds/all key"
    ]  # fmt: skip
    assert not [s for s in ALL_VALUES if s in "\n".join(_calls(tmp_path))]


def _upgrade(tmp_path, core=None, modules=None):
    (tmp_path / "app").mkdir(exist_ok=True)  # the project directory an installed module has
    v = dv(tmp_path, target_core=None)
    v.pop(P + "target_core")
    v[P + "target_core_image"] = core or CORE_REPO + ":v2.5.45@sha256:" + "b" * 64
    v[P + "target_modules_image"] = modules or MODULES_REPO + ":v3.0.9@sha256:" + "c" * 64
    return run_role(tmp_path, ROLE, "upgrade", v, env=SECRETS)


def test_upgrade_records_a_newer_pinned_bump(tmp_path):
    r = _upgrade(tmp_path)
    assert r.returncode == 0, r.stdout + r.stderr
    pending = json.loads((tmp_path / "app" / "pending-upgrade.json").read_text())
    assert pending["service"] == APP and pending["tag"] == "v2.5.45"


# ----------------------------------------------------------------------------- keys never on argv, TLS

DASHES = "-" * 5
PEM_CERT = f"{DASHES}BEGIN CERTIFICATE{DASHES}\nZmFrZQ==\n{DASHES}END CERTIFICATE{DASHES}"
PEM_KEY = f"{DASHES}BEGIN PRIVATE KEY{DASHES}\nZmFrZQ==\n{DASHES}END PRIVATE KEY{DASHES}"
TLS = {"tls_cert_ref": "secret:pki/intel-cert", "tls_key_ref": "secret:pki/intel-key"}
TLS_ENV = {"HNX_SECRET_PKI_INTEL_CERT": PEM_CERT, "HNX_SECRET_PKI_INTEL_KEY": PEM_KEY}


@pytest.mark.static
def test_no_script_the_role_runs_in_a_container_puts_a_key_in_an_argument():
    # a process's argv is readable by every user of the container: keys go to curl's config on
    # standard input and to the console through the environment of a wrapper
    text = (ROLE_DIR / "vars" / "main.yml").read_text()
    assert '-H "Authorization' not in text and "-H 'Authorization" not in text
    assert 'change_authkey "$HNX_EMAIL" "$HNX_KEY"' not in text
    for name in ("status", "body", "post"):
        script = VARS[P + f"api_{name}_script"]
        assert "-K -" in script and "Authorization: %s" in script and '"$HNX_KEY"' in script
        assert script.count("$HNX_KEY") == 1 and "curl" in script
    wrapper = VARS[P + "set_key_script"]
    assert 'getenv("HNX_KEY")' in wrapper and "cake.php" in wrapper
    assert "change_authkey" in wrapper and '$HNX_KEY"' not in wrapper.replace(
        'getenv("HNX_KEY")', ""
    )


def test_a_tls_pair_is_written_to_ssl_and_a_change_restarts_the_application(tmp_path):
    env = {**SECRETS, **TLS_ENV, **_fakes(tmp_path)}
    v = _live(tmp_path, **TLS)
    r = run_role(tmp_path, ROLE, "main", v, env=env)
    assert r.returncode == 0, r.stdout + r.stderr
    ssl_dir = tmp_path / "data" / "ssl"
    assert (ssl_dir / "cert.pem").read_text() == PEM_CERT + "\n"
    assert (ssl_dir / "key.pem").read_text() == PEM_KEY + "\n"
    assert oct((ssl_dir / "key.pem").stat().st_mode & 0o777) == "0o600"
    assert not [s for s in (PEM_KEY,) if s in "\n".join(_calls(tmp_path))]
    again = run_role(tmp_path, ROLE, "main", v, env=env)
    assert again.returncode == 0 and "changed=0" in again.stdout, again.stdout


def test_a_tls_value_that_is_not_pem_or_a_missing_one_is_refused_and_nothing_is_written(tmp_path):
    bad = {**SECRETS, **TLS_ENV, "HNX_SECRET_PKI_INTEL_KEY": "not a key"}
    r = run_role(tmp_path, ROLE, "main", dv(tmp_path, **TLS), env=bad)
    assert r.returncode != 0 and "PEM" in r.stdout + r.stderr
    assert not (tmp_path / "app").exists()
    gone = {k: v for k, v in {**SECRETS, **TLS_ENV}.items() if k != "HNX_SECRET_PKI_INTEL_CERT"}
    r = run_role(tmp_path, ROLE, "main", dv(tmp_path, **TLS), env=gone)
    assert r.returncode != 0 and TLS["tls_cert_ref"] in r.stdout + r.stderr


# ----------------------------------------------------------------------------- batched refusals
# one ansible-playbook for many cases (rolerun.run_cases): each case is a refusal that writes nothing


def test_main_refuses_bad_inputs_and_writes_nothing(tmp_path):
    base = dv(tmp_path)
    cases = [{P + k: x for k, x in over.items()} for over, _ in BAD]
    results = run_cases(tmp_path, ROLE, "main", base, cases, env=SECRETS)
    bad = [
        (o, m)
        for (o, why), (failed, m) in zip(BAD, results, strict=True)
        if not failed or why not in m
    ]
    assert not bad, bad
    assert not (tmp_path / "app").exists() and not (tmp_path / "data").exists()


def test_a_reference_with_no_value_is_named_and_a_malformed_or_repeated_credential_is_refused(
    tmp_path,
):
    env = {k: v for k, v in SECRETS.items() if k != CONSUMER_ENV}
    r = run_role(tmp_path, ROLE, "main", dv(tmp_path), env=env)
    assert r.returncode != 0 and CONSUMER_REF in r.stdout + r.stderr
    assert not (tmp_path / "app").exists() and not (tmp_path / "data").exists()
    for name, value in (
        (env_for(ref("mysql-password")), "short"),
        (env_for(ref("admin-api-key")), "a" * 39),
        (CONSUMER_ENV, KEY("a")),  # the administrator's key reused for a consumer
        (env_for(ref("redis-password")), PW("db")),  # one password twice
    ):
        r = run_role(tmp_path, ROLE, "credentials", dv(tmp_path), env={**SECRETS, name: value})
        assert r.returncode != 0 and value not in r.stdout + r.stderr, name


def test_restore_refuses_an_import_that_expects_nothing_or_names_no_sha(tmp_path):
    path, sha = _dump_file(tmp_path)
    env = {**SECRETS, **_fakes(tmp_path, counts=EMPTY)}
    base = dv(
        tmp_path, start=True, restore_dump=path, restore_sha256=sha, restore_counts=SOURCE_COUNTS
    )
    counts = [{}, {"events": 1}, {**SOURCE_COUNTS, "events": 0}, {**SOURCE_COUNTS, "attributes": 0},
              {k: v for k, v in SOURCE_COUNTS.items() if k != "feeds"}]  # fmt: skip
    cases = [{P + "restore_counts": c} for c in counts] + [{P + "restore_sha256": ""}]
    results = run_cases(tmp_path, ROLE, "restore", base, cases, env=env)
    assert all(failed for failed, _ in results), results
    assert all("proves nothing" in m for _, m in results[:-1]), results
    assert not _calls(tmp_path)


def test_upgrade_refuses_an_unpinned_foreign_or_older_target(tmp_path):
    (tmp_path / "app").mkdir(exist_ok=True)
    new_core = CORE_REPO + ":v2.5.45@sha256:" + "b" * 64
    new_mods = MODULES_REPO + ":v3.0.9@sha256:" + "c" * 64
    base = dv(tmp_path)
    base[P + "target_core_image"], base[P + "target_modules_image"] = new_core, new_mods
    cases = [
        {P + "target_core_image": CORE_REPO + ":v2.5.45"},  # unpinned
        {P + "target_core_image": CORE_REPO + ":v2.5.43@sha256:" + "b" * 64},  # older
        {P + "target_core_image": f"docker.io/other/{MID}:v2.5.45@sha256:" + "b" * 64},  # foreign
        {P + "target_modules_image": MODULES_REPO + ":v3.0.8@sha256:" + "c" * 64},  # modules older
    ]
    results = run_cases(tmp_path, ROLE, "upgrade", base, cases, env=SECRETS)
    assert all(f and "the targets must be" in m for f, m in results), results
    assert not (tmp_path / "app" / "pending-upgrade.json").exists()
