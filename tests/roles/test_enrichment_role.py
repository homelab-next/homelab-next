# SPDX-License-Identifier: Apache-2.0
"""The enrichment provider's role, run on localhost against fakes (CI is
unprivileged): main renders the seven containers through compose_app with every credential only in
the env_files and a second run is ``changed=0``; a reference with no value in the secret store, or a
malformed input, credential or analyzer list, is refused by name before anything is written; with the
containers "started" (a fake docker) the log files are created before the first boot only, the first
administrator, the API token and the optional key are written by one command each, a changed setting
file restarts the two containers that read it; health passes against a stand-in and fails on an
unknown analyzer name, a disabled one, an uncovered observable class, a bad token and counts below
the expected; export writes a sha256 listing, restore refuses a source that is not what was named
and a restored database whose counts differ (leaving the application stopped), and otherwise stops
the application, restores, counts, starts it, clears the stored keys and proves health; upgrade
records only a pinned target.

The Django snippets the role runs in the application container (state, token, key clearing,
administrator) are run here against stand-ins for the product's models."""

from __future__ import annotations

import grp
import hashlib
import json
import os
import pwd
import sys
import types
from pathlib import Path

import pytest
import yaml
from rolerun import fake, first_run, run_role

from tests.modules.enrichment_front import TOKEN, Server

ROOT = Path(__file__).resolve().parents[2]


def _provider(slot: str) -> str:
    """The id of the module that provides ``slot``: the tests name the slot, never the product."""
    found = [
        d.name
        for d in (ROOT / "modules").iterdir()
        if (d / "module.yml").is_file()
        and slot
        in (yaml.safe_load((d / "module.yml").read_text()).get("provides") or {}).get("slots", {})
    ]
    assert len(found) == 1, found
    return found[0]


ID = _provider("enrichment")  # the module's id: its role's name and its variables' prefix
UP = ID.upper()
ROLE = str(ROOT / "modules" / ID / "roles" / ID)
DEFAULTS = yaml.safe_load((Path(ROLE) / "defaults" / "main.yml").read_text())


def P(d: dict) -> dict:
    """Role variables from their short names (the role's prefix added; ansible_/hnx_ ones as they are)."""
    return {k if k.startswith(("ansible_", "hnx_")) else f"{ID}_{k}": v for k, v in d.items()}


def repo(key: str) -> str:
    return DEFAULTS[f"{ID}_{key}"].split("@")[0].rsplit(":", 1)[0]


USER = pwd.getpwuid(os.getuid()).pw_name
#: the example registry's edge address (a documentation-range address, never connected to)
GUEST = yaml.safe_load((ROOT / "examples" / "services.yml").read_text())["hosts"]["edge-core"][
    "address"
]
DB_PASSWORD = "db-password-fake-0123456789abc"
DJANGO_VALUE = "d" * 50
ADMIN_PASSWORD = "Admin-password-fake-01"
OTX_VALUE = "o" * 40
SECRETS = {
    f"HNX_SECRET_{UP}_DB_PASSWORD": DB_PASSWORD,
    f"HNX_SECRET_{UP}_DJANGO_SECRET": DJANGO_VALUE,
    f"HNX_SECRET_{UP}_ADMIN_PASSWORD": ADMIN_PASSWORD,
    f"HNX_SECRET_{UP}_API_TOKEN": TOKEN,
}
REFS = {
    f"HNX_SECRET_{UP}_DB_PASSWORD": f"secret:{ID}/db-password",
    f"HNX_SECRET_{UP}_DJANGO_SECRET": f"secret:{ID}/django-secret",
    f"HNX_SECRET_{UP}_ADMIN_PASSWORD": f"secret:{ID}/admin-password",
    f"HNX_SECRET_{UP}_API_TOKEN": f"secret:{ID}/api-token",
}
SERVICES = ["beat", "daphne", "nginx", "postgres", "redis", "uwsgi", "worker"]
TABLES = {
    "jobs": "api_app_job",
    "analyzer_configs": "analyzers_manager_analyzerconfig",
    "playbooks": "playbooks_manager_playbookconfig",
    "users": "certego_saas_user_user",
}
COUNTS = {"jobs": 12, "analyzer_configs": 219, "playbooks": 16, "users": 6}
PINNED = "docker.io/library/redis:7.2.16@sha256:" + "a" * 64
ANALYZERS = {"ip": ["Abusix"], "hash": ["MalwareBazaar_Get_Observable", "ThreatFox"]}


def pv(tmp_path: Path, **kw) -> dict:
    v = {
        "logical_id": "enrichment",
        "ansible_host": GUEST,
        "dir": str(tmp_path / "app"),
        "owner": USER,
        "data_root": str(tmp_path / "data"),
        # the unprivileged test's own ids (the role requires 1000 or more): it can chown to no other
        "group": grp.getgrgid(os.getgid()).gr_name,
        "db_uid": os.getuid(),
        "db_gid": os.getgid(),
        "broker_uid": os.getuid() + 1,
        "broker_gid": os.getgid() + 1,
        "start": False,
        "validate_with_docker": False,
        "required_analyzers": ANALYZERS,
    }
    v.update(kw)
    return P(v)


# ----------------------------------------------------------------------------- render


def _first_main_renders_seven_containers_with_the_credentials_only_in_the_env_files(tmp_path):
    v = pv(tmp_path)
    return {"role": ROLE, "tasks_from": "main", "extra_vars": v, "env": SECRETS, "setup": {"v": v}}


@first_run(_first_main_renders_seven_containers_with_the_credentials_only_in_the_env_files)
def test_main_renders_seven_containers_with_the_credentials_only_in_the_env_files(first):
    r, tmp_path = first
    v = first.setup["v"]
    assert r.returncode == 0, r.stdout + r.stderr
    text = (tmp_path / "app" / "docker-compose.yml").read_text()
    svc = yaml.safe_load(text)["services"]
    assert sorted(svc) == SERVICES
    app = svc["uwsgi"]["image"]
    assert app.startswith(repo("image") + ":v") and "@sha256:" in app
    for name in ("daphne", "beat", "worker"):
        assert svc[name]["image"] == app  # one image, four processes
    assert svc["nginx"]["image"].split("@")[0].endswith(app.split("@")[0].rsplit(":", 1)[1])
    assert svc["postgres"]["image"].startswith("docker.io/library/postgres:17.")
    assert svc["redis"]["image"].startswith("docker.io/library/redis:7.")
    assert svc["uwsgi"]["command"] == ["./docker/entrypoints/uwsgi.sh"]
    assert svc["nginx"]["ports"] == [f"{GUEST}:8080:80"]  # only the front is published
    for name in ("postgres", "redis", "uwsgi", "daphne", "beat", "worker"):
        assert "ports" not in svc[name]
    for s in svc.values():
        assert s["cap_drop"] == ["ALL"] and s["security_opt"] == ["no-new-privileges:true"]
    assert svc["uwsgi"]["cap_add"] == ["CHOWN", "DAC_OVERRIDE", "FOWNER", "SETGID", "SETUID"]
    assert "NET_BIND_SERVICE" in svc["nginx"]["cap_add"]
    assert "cap_add" not in svc["postgres"] and "cap_add" not in svc["redis"]
    assert svc["postgres"]["user"] == f"{os.getuid()}:{os.getgid()}"
    env = svc["uwsgi"]["environment"]
    assert env["DB_HOST"] == "postgres" and env["DB_USER"] == DEFAULTS[f"{ID}_db_user"]
    assert env["BROKER_URL"] == "redis://redis/1" and env["DEBUG"] == "False"
    assert env[f"{UP}_WEB_CLIENT_DOMAIN"] == GUEST
    assert svc["redis"]["command"][:3] == ["redis-server", "--save", ""]  # a queue, not a store
    for value in (DB_PASSWORD, DJANGO_VALUE, ADMIN_PASSWORD, TOKEN):
        assert value not in text and value not in r.stdout
    for name in ("uwsgi", "daphne", "beat", "worker"):
        body = (tmp_path / "app" / "secrets" / f"{name}.env").read_text()
        assert f"DB_PASSWORD='{DB_PASSWORD}'" in body and f"DJANGO_SECRET='{DJANGO_VALUE}'" in body
    assert (
        f"POSTGRES_PASSWORD='{DB_PASSWORD}'"
        in (tmp_path / "app" / "secrets" / "postgres.env").read_text()
    )
    assert not (tmp_path / "app" / "secrets" / "nginx.env").exists()
    for f in ("postgres", "uwsgi", "daphne", "beat", "worker"):
        mode = (tmp_path / "app" / "secrets" / f"{f}.env").stat().st_mode & 0o777
        assert oct(mode) == "0o600", f
    assert oct((tmp_path / "data" / "pgdata").stat().st_mode & 0o777) == "0o700"
    # the settings the front and the server read are rendered under config/, read-only mounts
    cfg = tmp_path / "app" / "config"
    assert "processes = 4" in (cfg / "intel_owl.ini").read_text()
    assert "location /hc" in (cfg / "nginx" / "locations.conf").read_text()
    assert "proxy_pass " in (cfg / "nginx" / "websocket.conf").read_text()
    assert all(
        m.endswith(":ro") for m in svc["nginx"]["volumes"] if "/config/" in m or "static" in m
    )
    again = run_role(tmp_path, ROLE, "main", v, env=SECRETS)
    assert again.returncode == 0 and "changed=0" in again.stdout, again.stdout


def _first_main_puts_the_containers_in_the_role_slice_the_module_play_names(tmp_path):
    v = pv(tmp_path, hnx_module_slice=f"hnx-{ID}-server.slice")
    return {"role": ROLE, "tasks_from": "main", "extra_vars": v, "env": SECRETS}


@first_run(_first_main_puts_the_containers_in_the_role_slice_the_module_play_names)
def test_main_puts_the_containers_in_the_role_slice_the_module_play_names(first):
    r, tmp_path = first
    assert r.returncode == 0, r.stdout + r.stderr
    doc = yaml.safe_load((tmp_path / "app" / "docker-compose.yml").read_text())
    assert {s["cgroup_parent"] for s in doc["services"].values()} == {f"hnx-{ID}-server.slice"}


def _first_main_refuses_an_unset_secret_naming_the_reference_and_writes_nothing(tmp_path, unset):
    env = {k: v for k, v in SECRETS.items() if k != unset}
    return {
        "role": ROLE,
        "tasks_from": "main",
        "extra_vars": pv(tmp_path),
        "env": {**env, unset: ""},
    }


@pytest.mark.parametrize("unset", sorted(SECRETS))
@first_run(_first_main_refuses_an_unset_secret_naming_the_reference_and_writes_nothing)
def test_main_refuses_an_unset_secret_naming_the_reference_and_writes_nothing(first, unset):
    """Review Focus 3: a module deployed before its secret exists is refused, by name."""
    r, tmp_path = first
    assert r.returncode != 0, r.stdout
    assert REFS[unset] in r.stdout + r.stderr
    assert not (tmp_path / "app").exists() and not (tmp_path / "data").exists()
    for value in (DB_PASSWORD, DJANGO_VALUE, ADMIN_PASSWORD, TOKEN):
        assert value not in r.stdout + r.stderr


def _first_main_does_not_read_the_admin_password_or_the_key_unless_asked(tmp_path):
    env = {k: v for k, v in SECRETS.items() if k != f"HNX_SECRET_{UP}_ADMIN_PASSWORD"}
    v = pv(tmp_path, admin_bootstrap=False)
    return {"role": ROLE, "tasks_from": "main", "extra_vars": v, "env": env}


@first_run(_first_main_does_not_read_the_admin_password_or_the_key_unless_asked)
def test_main_does_not_read_the_admin_password_or_the_key_unless_asked(first):
    """A restored database brings its accounts: no admin password is needed; no key is ever read by
    default (the module is keyless)."""
    r, tmp_path = first
    assert r.returncode == 0, r.stdout + r.stderr
    assert (tmp_path / "app" / "docker-compose.yml").exists()


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
        ({"image": repo("image") + ":latest"}, {}),
        ({"nginx_image": repo("nginx_image") + ":v6.7.0"}, {}),
        # the application and its front are one release
        ({"nginx_image": repo("nginx_image") + ":v6.6.0@sha256:" + "a" * 64}, {}),
        ({"image": repo("image") + ":6.7.0@sha256:" + "a" * 64}, {}),
        ({"postgres_image": "docker.io/library/postgres:17.10"}, {}),
        ({"redis_image": "docker.io/library/redis:7.2.16"}, {}),
        ({"ansible_host": "0.0.0.0"}, {}),
        ({"ansible_host": "enrichment.example.internal"}, {}),
        ({"logical_id": "Enrichment"}, {}),
        ({"db_login_ref": f"secret:{ID}/admin-password"}, {}),
        ({"otx_key_ref": f"secret:{ID}/db-password"}, {}),
        ({"data_root": "/var/lib/../etc"}, {}),
        ({"dir": "relative/dir"}, {}),
        ({"db_uid": 0}, {}),
        ({"broker_uid": os.getuid()}, {}),
        ({"mem_limit": "lots"}, {}),
        ({"web_domain": "Not A Name"}, {}),
        ({"admin_email": "nobody"}, {}),
        # the analyzer lists the consumers request
        ({"required_analyzers": {}}, {}),
        ({"required_analyzers": {"ip": []}}, {}),
        ({"required_analyzers": {"sha256": ["ThreatFox"]}}, {}),
        ({"required_analyzers": {"ip": ["Not-A-Name"]}}, {}),
        ({"required_analyzers": {"ip": "Abusix"}}, {}),
        ({}, {f"HNX_SECRET_{UP}_DB_PASSWORD": "short"}),
        ({}, {f"HNX_SECRET_{UP}_DB_PASSWORD": "has'quote-0123456789abcdefgh"}),
        ({}, {f"HNX_SECRET_{UP}_DJANGO_SECRET": "k" * 20}),
        ({}, {f"HNX_SECRET_{UP}_API_TOKEN": "t" * 32}),
        ({}, {f"HNX_SECRET_{UP}_ADMIN_PASSWORD": "short"}),
        ({}, {f"HNX_SECRET_{UP}_DJANGO_SECRET": DB_PASSWORD}),
    ],
)  # fmt: skip
@first_run(_first_main_refuses_bad_inputs_and_credentials)
def test_main_refuses_bad_inputs_and_credentials(first, over, env):
    r, tmp_path = first
    assert r.returncode != 0, r.stdout
    assert not (tmp_path / "app" / "docker-compose.yml").exists()


# ----------------------------------------------------------------------------- a fake docker

STATE_OK = {"ok": True, "missing": [], "disabled": [], "uncovered": [], "counts":
            {"analyzer_configs": 219, "jobs": 12, "playbooks": 16, "users": 6}}  # fmt: skip
TOC = "".join(f"{i}; 0 {i} TABLE DATA public {t} owner\n" for i, t in enumerate(TABLES.values(), 1))


def _docker(tmp_path: Path, health: str = "healthy") -> dict:
    """A fake docker: ``compose ps`` lists the seven services in ``health``; ``exec ... pg_dump -f F``
    writes a dump at F's host path (the export mount), ``mv`` moves it, ``pg_restore --list`` prints a
    table of contents (``toc.txt`` when it exists), ``pg_restore`` succeeds when the dump is staged,
    ``psql ... select count(*) from T`` answers from ``counts.json``, ``manage.py shell -c CODE`` prints
    the line the snippet's kind expects (the state from ``state.json``); everything else succeeds. Every
    call is logged with the HNX_* names of its environment (never the values)."""
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    rows = "".join(
        json.dumps({"Service": s, "State": "running", "Health": health}) + "\n" for s in SERVICES
    )
    export = tmp_path / "data" / "export" / "db"
    body = f"""
import json, os, shutil, sys
a = sys.argv[1:]
names = sorted(k for k in os.environ if k.startswith("HNX_") and not k.startswith("HNX_SECRET"))
open({str(tmp_path / "docker.log")!r}, "a").write(" ".join(a) + "  [" + ",".join(names) + "]\\n")
def host(p):
    return os.path.join({str(export)!r}, os.path.basename(p))
def read(name, default):
    p = os.path.join({str(tmp_path)!r}, name)
    return open(p).read() if os.path.exists(p) else default
if "ps" in a:
    sys.stdout.write({rows!r})
elif "pg_dump" in a:
    open(host(a[len(a) - 1 - a[::-1].index("-f") + 1]), "wb").write(b"PGDMP fake dump")
elif "mv" in a:
    shutil.move(host(a[-2]), host(a[-1]))
elif "pg_restore" in a and "--list" in a:
    sys.stdout.write(read("toc.txt", {TOC!r}))
elif "pg_restore" in a:
    sys.exit(0 if os.path.exists(host(a[-1])) else 3)
elif "psql" in a:
    table = a[-1].rsplit(" ", 1)[-1]
    counts = json.loads(read("counts.json", {json.dumps(COUNTS)!r}))
    key = {{v: k for k, v in {TABLES!r}.items()}}[table]
    sys.stdout.write(str(counts[key]) + "\\n")
elif "manage.py" in a:
    code = a[-1]
    if "create_superuser" in code:
        print("HNX-ADMIN created")
    elif "authtoken" in code:
        print(read("token.state", "HNX-TOKEN created"))
    elif "HNX-OTX" in code:
        print("HNX-OTX 2")
    elif "HNX-STRIP" in code:
        print("HNX-STRIP 3 OTXQuery,Shodan_Search,ThreatFox")
    elif "HNX-STATE" in code:
        print("HNX-STATE " + read("state.json", {json.dumps(STATE_OK)!r}))
    else:
        print("check ok")
elif "run" in a:
    sys.exit(1 if os.path.exists({str(tmp_path / "prime.fails")!r}) else 0)
"""
    fake(bindir / "docker", body)
    return {"PATH": f"{bindir}:{os.environ['PATH']}"}


def _calls(tmp_path: Path) -> list[str]:
    log = tmp_path / "docker.log"
    return log.read_text().splitlines() if log.exists() else []


def _live(tmp_path, front, **kw):
    return pv(tmp_path, bind=front.addr[0], port=front.addr[1], start=True,
              ready_timeout=10, **kw)  # fmt: skip


# ----------------------------------------------------------------------------- start


def test_the_log_files_are_created_before_the_first_boot_only_and_the_first_start_seeds(tmp_path):
    with Server() as front:
        env = {**SECRETS, **_docker(tmp_path)}
        v = _live(tmp_path, front)
        r = run_role(tmp_path, ROLE, "main", v, env=env)
        assert r.returncode == 0, r.stdout + r.stderr
        calls = _calls(tmp_path)
        primed = [i for i, c in enumerate(calls) if " run " in f" {c} "]
        started = [i for i, c in enumerate(calls) if "--remove-orphans" in c]
        shell = [i for i, c in enumerate(calls) if "manage.py shell" in c]
        assert len(primed) == 1 and len(started) == 1 and primed[0] < started[0] < shell[0]
        assert "mkdir -p /var/log/intel_owl/django" in calls[primed[0]]
        # the administrator (bootstrap is on by default) and the token: one command each, by environment
        assert any(
            "HNX_ADMIN_PASSWORD" in calls[i] and "create_superuser" not in calls[i] for i in shell
        )
        token_call = next(calls[i] for i in shell if "HNX_API_TOKEN" in calls[i])
        assert "HNX_API_USER" in token_call
        for value in (DB_PASSWORD, DJANGO_VALUE, ADMIN_PASSWORD, TOKEN, OTX_VALUE):
            assert not [c for c in calls if value in c]  # never in an argument
        # no key was read or applied by default
        assert not [c for c in calls if "HNX_OTX_KEY" in c]
        (tmp_path / "docker.log").unlink()
        (tmp_path / "token.state").write_text("HNX-TOKEN unchanged")
        again = run_role(tmp_path, ROLE, "main", v, env=env)
        assert again.returncode == 0 and "changed=0" in again.stdout, again.stdout
        assert not [c for c in _calls(tmp_path) if " run " in f" {c} "]  # not a first boot


def test_a_failed_log_file_step_stops_the_run_before_the_containers_start(tmp_path):
    with Server() as front:
        (tmp_path / "prime.fails").write_text("")
        r = run_role(
            tmp_path, ROLE, "main", _live(tmp_path, front), env={**SECRETS, **_docker(tmp_path)}
        )
        assert r.returncode != 0
        assert not [c for c in _calls(tmp_path) if "--remove-orphans" in c]


def test_the_admin_is_not_created_when_the_database_is_to_be_restored(tmp_path):
    with Server() as front:
        env = {**SECRETS, **_docker(tmp_path)}
        v = _live(tmp_path, front, admin_bootstrap=False)
        assert run_role(tmp_path, ROLE, "main", v, env=env).returncode == 0
        assert not [c for c in _calls(tmp_path) if "HNX_ADMIN_USER" in c]
        assert [c for c in _calls(tmp_path) if "HNX_API_TOKEN" in c]


def test_the_optional_key_is_applied_only_when_a_reference_names_it(tmp_path):
    with Server() as front:
        env = {**SECRETS, **_docker(tmp_path), f"HNX_SECRET_{UP}_OTX_KEY": OTX_VALUE}
        v = _live(tmp_path, front, otx_key_ref=f"secret:{ID}/otx-key")
        r = run_role(tmp_path, ROLE, "main", v, env=env)
        assert r.returncode == 0, r.stdout + r.stderr
        calls = _calls(tmp_path)
        assert [c for c in calls if "HNX_OTX_KEY" in c]
        assert not [c for c in calls if OTX_VALUE in c] and OTX_VALUE not in r.stdout
    # a malformed key is refused before anything is rendered
    other = tmp_path / "other"
    other.mkdir()
    bad = run_role(other, ROLE, "main", pv(other, otx_key_ref=f"secret:{ID}/otx-key"),
                   env={**SECRETS, f"HNX_SECRET_{UP}_OTX_KEY": "short"})  # fmt: skip
    assert bad.returncode != 0 and not (other / "app" / "docker-compose.yml").exists()


def test_a_changed_setting_file_restarts_the_two_containers_that_read_it(tmp_path):
    with Server() as front:
        env = {**SECRETS, **_docker(tmp_path), f"HNX_SECRET_{UP}_OTX_KEY": OTX_VALUE}
        assert run_role(tmp_path, ROLE, "main", _live(tmp_path, front), env=env).returncode == 0
        assert not [
            c for c in _calls(tmp_path) if " restart " in f" {c} "
        ]  # a first run: no restart
        r = run_role(tmp_path, ROLE, "main", _live(tmp_path, front, uwsgi_processes=6), env=env)
        assert r.returncode == 0, r.stdout + r.stderr
        restarts = [c for c in _calls(tmp_path) if " restart " in f" {c} "]
        assert len(restarts) == 1 and "restart uwsgi nginx" in restarts[0]
        assert "processes = 6" in (tmp_path / "app" / "config" / "intel_owl.ini").read_text()


# ----------------------------------------------------------------------------- health


def _health(tmp_path, front, state=None, health="healthy", token=None, **kw):
    env = {**SECRETS, **_docker(tmp_path, health=health)}
    if state is not None:
        (tmp_path / "state.json").write_text(json.dumps(state))
    if token:
        env[f"HNX_SECRET_{UP}_API_TOKEN"] = token
    return run_role(tmp_path, ROLE, "health", _live(tmp_path, front, **kw), env=env)


def test_health_passes_and_reads_each_requested_analyzer_through_the_api(tmp_path):
    names = ["Abusix", "MalwareBazaar_Get_Observable", "ThreatFox"]
    with Server(known=names) as front:
        r = _health(tmp_path, front)
        assert r.returncode == 0, r.stdout + r.stderr
        assert "/hc" in front.paths and "/api/analyzer" in front.paths
        assert (
            sorted(p.rsplit("/", 1)[-1] for p in front.paths if p.startswith("/api/analyzer/"))
            == names
        )
        assert set(front.tokens) == {TOKEN}
        state_call = next(c for c in _calls(tmp_path) if "manage.py shell" in c)
        assert (
            "HNX_WANT" in state_call and "Abusix" not in state_call
        )  # the lists go by environment


@pytest.mark.parametrize(
    "state, words",
    [
        ({**STATE_OK, "ok": False, "missing": ["MalwareBazaar"]}, ["MalwareBazaar", "400"]),
        ({**STATE_OK, "ok": False, "disabled": ["ThreatFox"]}, ["ThreatFox", "Disabled"]),
        ({**STATE_OK, "ok": False, "uncovered": ["hash"]}, ["hash", "no listed"]),
    ],
)
def test_health_fails_naming_an_unknown_a_disabled_or_an_uncovered_analyzer(tmp_path, state, words):
    """The analyzer-name trap: an unknown name is a 400 for the whole submit, a disabled one is silently
    dropped, a class with no capable analyzer enriches nothing."""
    with Server(known=["Abusix", "ThreatFox", "MalwareBazaar_Get_Observable"]) as front:
        r = _health(tmp_path, front, state=state)
        assert r.returncode != 0
        out = r.stdout + r.stderr
        assert all(w in out for w in words), out


def test_health_fails_when_the_api_does_not_know_a_name_or_refuses_the_token(tmp_path):
    with Server(known=["Abusix", "ThreatFox"]) as front:  # MalwareBazaar_Get_Observable is a 404
        bad = _health(tmp_path, front)
        assert bad.returncode != 0 and "404" in bad.stdout + bad.stderr
    other = tmp_path / "token"
    other.mkdir()
    with Server(known=["Abusix", "ThreatFox", "MalwareBazaar_Get_Observable"]) as front:
        bad = _health(other, front, token="t" * 40)
        assert bad.returncode != 0 and "401" in bad.stdout + bad.stderr


def test_health_fails_when_the_front_is_down_or_the_api_is_open_to_anonymous_callers(tmp_path):
    names = ["Abusix", "MalwareBazaar_Get_Observable", "ThreatFox"]
    with Server(known=names, live=503) as front:
        bad = _health(tmp_path, front)
        assert bad.returncode != 0 and "503" in bad.stdout + bad.stderr
    sub = tmp_path / "open"
    sub.mkdir()
    with Server(known=names, anonymous=200) as front:
        bad = _health(sub, front)
        assert bad.returncode != 0 and "200" in bad.stdout + bad.stderr


def test_health_fails_on_counts_below_the_expected_and_on_an_unhealthy_container(tmp_path):
    names = ["Abusix", "MalwareBazaar_Get_Observable", "ThreatFox"]
    with Server(known=names) as front:
        low = _health(tmp_path, front, expected_min_analyzers=300)
        assert low.returncode != 0 and "analyzer configurations" in low.stdout + low.stderr
        sub = tmp_path / "jobs"
        sub.mkdir()
        low = _health(sub, front, expected_min_jobs=13)
        assert low.returncode != 0 and "12 jobs" in low.stdout + low.stderr
        sub = tmp_path / "unhealthy"
        sub.mkdir()
        bad = _health(sub, front, health="unhealthy")
        assert bad.returncode != 0 and "unhealthy" in bad.stdout + bad.stderr


# ----------------------------------------------------------------------------- export, restore


def _export(tmp_path, env, v):
    r = run_role(tmp_path, ROLE, "export", v, env=env)
    assert r.returncode == 0, r.stdout + r.stderr
    return tmp_path / "data" / "export"


def test_export_writes_an_object_tree_with_a_sha256_listing(tmp_path):
    env = {**SECRETS, **_docker(tmp_path)}
    exp = _export(tmp_path, env, pv(tmp_path))
    dump = exp / "db" / "intel_owl.dump"
    assert dump.read_bytes() == b"PGDMP fake dump"
    rows = [json.loads(line) for line in (exp / "listing.jsonl").read_text().splitlines()]
    assert rows == [
        {
            "key": "db/intel_owl.dump",
            "size": 15,
            "sha256": hashlib.sha256(dump.read_bytes()).hexdigest(),
        }
    ]
    call = next(c for c in _calls(tmp_path) if "pg_dump" in c)
    assert "-Fc" in call and "--no-owner" in call
    assert not list(Path("/tmp").glob("*intel_owl*dump*"))  # nothing staged in /tmp


def _restore_vars(tmp_path, front, exp, **kw):
    dump = exp / "db" / "intel_owl.dump"
    return _live(
        tmp_path, front,
        restore_dump=str(dump),
        restore_sha256=hashlib.sha256(dump.read_bytes()).hexdigest(),
        restore_expected_counts=COUNTS,
        admin_bootstrap=False,
        **kw,
    )  # fmt: skip


def _restore(tmp_path, front, **kw):
    env = {**SECRETS, **_docker(tmp_path)}
    exp = _export(tmp_path, env, pv(tmp_path))
    (tmp_path / "docker.log").unlink()
    v = _restore_vars(tmp_path, front, exp, **kw)
    return run_role(tmp_path, ROLE, "restore", v, env=env), exp


NAMES = ["Abusix", "MalwareBazaar_Get_Observable", "ThreatFox"]


def test_restore_stops_the_application_restores_counts_then_starts_clears_keys_and_proves_health(
    tmp_path,
):
    with Server(known=NAMES) as front:
        r, _ = _restore(tmp_path, front)
        assert r.returncode == 0, r.stdout + r.stderr
        calls = _calls(tmp_path)
        order = [
            next(i for i, c in enumerate(calls) if k in c)
            for k in (
                " stop nginx worker beat daphne uwsgi",
                "pg_restore --list",
                "pg_restore -U",
                "select count(*) from api_app_job",
                " up -d --wait --wait-timeout",
                "HNX-STRIP",
                "HNX_API_TOKEN",
                "HNX-STATE",
            )
        ]  # fmt: skip
        assert order == sorted(order), calls
        restore = next(c for c in calls if "pg_restore -U" in c)
        assert (
            "--clean" in restore
            and "--single-transaction" in restore
            and "--exit-on-error" in restore
        )
        assert not (tmp_path / "data" / "export" / "db" / ".restore.dump").exists()
        assert "HNX-STRIP 3" in r.stdout  # the stored keys were cleared and the run says which


def test_restore_keeps_the_stored_keys_only_when_asked(tmp_path):
    with Server(known=NAMES) as front:
        r, _ = _restore(tmp_path, front, restore_keep_keys=True)
        assert r.returncode == 0, r.stdout + r.stderr
        assert not [c for c in _calls(tmp_path) if "HNX-STRIP" in c]


def test_restore_refuses_a_restored_database_whose_counts_differ_and_leaves_the_app_stopped(
    tmp_path,
):
    with Server(known=NAMES) as front:
        env = {**SECRETS, **_docker(tmp_path)}
        exp = _export(tmp_path, env, pv(tmp_path))
        (tmp_path / "docker.log").unlink()
        (tmp_path / "counts.json").write_text(json.dumps({**COUNTS, "jobs": COUNTS["jobs"] - 1}))
        r = run_role(tmp_path, ROLE, "restore", _restore_vars(tmp_path, front, exp), env=env)
        assert r.returncode != 0
        assert "jobs=11" in r.stdout + r.stderr and "jobs=12" in r.stdout + r.stderr
        calls = _calls(tmp_path)
        assert not [c for c in calls if " --wait-timeout" in c or "manage.py" in c]  # never started
        assert not (
            tmp_path / "data" / "export" / "db" / ".restore.dump"
        ).exists()  # staged copy gone


def test_restore_refuses_a_dump_that_is_not_the_products_database(tmp_path):
    with Server(known=NAMES) as front:
        env = {**SECRETS, **_docker(tmp_path)}
        exp = _export(tmp_path, env, pv(tmp_path))
        (tmp_path / "docker.log").unlink()
        (tmp_path / "toc.txt").write_text("1; 0 1 TABLE DATA public some_other_table x\n")
        r = run_role(tmp_path, ROLE, "restore", _restore_vars(tmp_path, front, exp), env=env)
        assert r.returncode != 0 and "does not hold the product's tables" in r.stdout + r.stderr
        assert not [c for c in _calls(tmp_path) if "pg_restore -U" in c]  # nothing was restored


def _first_restore_refuses_a_tampered_dump_and_writes_nothing(tmp_path):
    env = {**SECRETS, **_docker(tmp_path)}
    v = pv(tmp_path)
    exp = _export(tmp_path, env, v)
    good = hashlib.sha256((exp / "db" / "intel_owl.dump").read_bytes()).hexdigest()
    (exp / "db" / "intel_owl.dump").write_bytes(b"PGDMP tampered")
    (tmp_path / "docker.log").unlink()
    return {
        "role": ROLE,
        "tasks_from": "restore",
        "extra_vars": {**v, **P({"restore_dump": str(exp / "db" / "intel_owl.dump"),
                                 "restore_sha256": good, "restore_expected_counts": COUNTS})},
        "env": env,
    }  # fmt: skip


@first_run(_first_restore_refuses_a_tampered_dump_and_writes_nothing)
def test_restore_refuses_a_tampered_dump_and_writes_nothing(first):
    r, tmp_path = first
    assert r.returncode != 0 and "not an intact dump" in r.stdout + r.stderr
    assert not [c for c in _calls(tmp_path) if "pg_restore" in c or " stop " in f" {c} "]


@pytest.mark.parametrize(
    "over",
    [
        {"restore_dump": ""},
        {"restore_dump": "relative/intel.dump"},
        {"restore_dump": "/var/lib/../etc/intel.dump"},
        {"restore_sha256": "abc"},
        {"restore_expected_counts": {}},
        {"restore_expected_counts": {k: v for k, v in COUNTS.items() if k != "users"}},
        {"restore_expected_counts": {**COUNTS, "analyzer_configs": 0}},  # vacuous
        {"restore_expected_counts": {**COUNTS, "users": 0}},  # vacuous
        {"restore_expected_counts": {**COUNTS, "jobs": "many"}},
        {"restore_expected_counts": {**COUNTS, "extra": 1}},
    ],
)
def test_restore_refuses_a_restore_that_does_not_say_what_it_restores(tmp_path, over):
    env = {**SECRETS, **_docker(tmp_path)}
    exp = _export(tmp_path, env, pv(tmp_path))
    (tmp_path / "docker.log").unlink()
    dump = exp / "db" / "intel_owl.dump"
    named = {
        "restore_dump": str(dump),
        "restore_sha256": hashlib.sha256(dump.read_bytes()).hexdigest(),
        "restore_expected_counts": COUNTS,
    }
    v = pv(tmp_path, **{**named, **over})
    r = run_role(tmp_path, ROLE, "restore", v, env=env)
    assert r.returncode != 0
    assert not [c for c in _calls(tmp_path) if "pg_restore" in c or " stop " in f" {c} "]


def test_restore_refuses_a_link_in_place_of_the_dump(tmp_path):
    env = {**SECRETS, **_docker(tmp_path)}
    exp = _export(tmp_path, env, pv(tmp_path))
    (tmp_path / "docker.log").unlink()
    link = tmp_path / "linked.dump"
    link.symlink_to(exp / "db" / "intel_owl.dump")
    v = pv(tmp_path, restore_dump=str(link),
           restore_sha256=hashlib.sha256(b"PGDMP fake dump").hexdigest(),
           restore_expected_counts=COUNTS)  # fmt: skip
    r = run_role(tmp_path, ROLE, "restore", v, env=env)
    assert r.returncode != 0 and not [c for c in _calls(tmp_path) if "pg_restore" in c]


# ----------------------------------------------------------------------------- upgrade


def _first_upgrade_records_only_a_pinned_target_of_the_same_repository(tmp_path):
    v = pv(tmp_path)
    return {"role": ROLE, "tasks_from": "main", "extra_vars": v, "env": SECRETS, "setup": {"v": v}}


@first_run(_first_upgrade_records_only_a_pinned_target_of_the_same_repository)
def test_upgrade_records_only_a_pinned_target_of_the_same_repository(first):
    first_result, tmp_path = first
    v = first.setup["v"]
    assert first_result.returncode == 0
    app = repo("image") + ":v6.8.0@sha256:" + "c" * 64
    front = repo("nginx_image") + ":v6.8.0@sha256:" + "d" * 64
    good = {"target_image": app, "target_nginx_image": front}
    r = run_role(tmp_path, ROLE, "upgrade", {**v, **P(good)}, env=SECRETS)
    assert r.returncode == 0, r.stdout + r.stderr
    rec = json.loads((tmp_path / "app" / "pending-upgrade.json").read_text())
    assert rec == {"service": "uwsgi", "tag": "v6.8.0", "digest": "sha256:" + "c" * 64}
    for bad in (
        {"target_image": app},  # the front moves with it
        {"target_nginx_image": front},
        {**good, "target_nginx_image": repo("nginx_image") + ":v6.7.1@sha256:" + "d" * 64},
        {**good, "target_image": repo("image") + ":v6.8.0"},
        {**good, "target_image": "docker.io/other/app:v6.8.0@sha256:" + "c" * 64},
        # older than the running release: the database cannot go back
        {"target_image": repo("image") + ":v6.6.0@sha256:" + "c" * 64,
         "target_nginx_image": repo("nginx_image") + ":v6.6.0@sha256:" + "d" * 64},
        {"target_postgres_image": "docker.io/library/postgres:18.1@sha256:" + "d" * 64},
        {"target_redis_image": PINNED, "target_postgres_image": PINNED},
        {**good, "target_redis_image": PINNED},
        {},
    ):  # fmt: skip
        (tmp_path / "app" / "pending-upgrade.json").unlink(missing_ok=True)
        r = run_role(tmp_path, ROLE, "upgrade", {**v, **P(bad)}, env=SECRETS)
        assert r.returncode != 0, bad
        assert not (tmp_path / "app" / "pending-upgrade.json").exists()
    for one in (
        {"target_redis_image": PINNED},
        {"target_postgres_image": "docker.io/library/postgres:17.11@sha256:" + "e" * 64},
    ):
        r = run_role(tmp_path, ROLE, "upgrade", {**v, **P(one)}, env=SECRETS)
        assert r.returncode == 0, (one, r.stdout + r.stderr)


# ----------------------------------------------------------------------------- the snippets


def _load_code(name: str) -> str:
    return yaml.safe_load((Path(ROLE) / "vars" / "main.yml").read_text())[f"{ID}_{name}"]


class _Rows(list):
    def filter(self, *a, **kw):
        names = kw.get("name__in")
        return _Rows(r for r in self if names is None or r.name in names)

    def exclude(self, *a, **kw):
        return _Rows(r for r in self if getattr(r, "value", "") != kw.get("value", object()))

    def count(self):
        return len(self)

    def update(self, **kw):
        for r in self:
            for k, v in kw.items():
                setattr(r, k, v)


def _models(monkeypatch, **modules):
    for dotted, members in modules.items():
        parts = dotted.split(".")
        for i in range(1, len(parts) + 1):
            name = ".".join(parts[:i])
            if name not in sys.modules:
                monkeypatch.setitem(sys.modules, name, types.ModuleType(name))
        for k, v in members.items():
            setattr(sys.modules[dotted], k, v)


def _manager(rows):
    return type("M", (), {"objects": _Rows(rows)})


def _analyzer(name, supported, disabled=False):
    return types.SimpleNamespace(name=name, observable_supported=supported, disabled=disabled)


def _run_state(monkeypatch, capsys, rows, want):
    _models(
        monkeypatch,
        **{
            "api_app.analyzers_manager.models": {"AnalyzerConfig": _manager(rows)},
            "api_app.models": {"Job": _manager([1, 2, 3])},
            "certego_saas.apps.user.models": {"User": _manager([1])},
            "api_app.playbooks_manager.models": {"PlaybookConfig": _manager([1, 2])},
        },
    )
    monkeypatch.setenv("HNX_WANT", json.dumps(want))
    exec(compile(_load_code("state_code"), "state", "exec"), {})
    line = next(x for x in capsys.readouterr().out.splitlines() if x.startswith("HNX-STATE "))
    return json.loads(line.removeprefix("HNX-STATE "))


def test_the_state_snippet_names_unknown_disabled_and_uncovered(monkeypatch, capsys):
    rows = [
        _analyzer("MalwareBazaar_Get_Observable", ["hash"]),
        _analyzer("ThreatFox", ["ip", "hash"], disabled=True),
        _analyzer("Abusix", ["ip"]),
    ]
    ok = _run_state(
        monkeypatch, capsys, rows, {"hash": ["MalwareBazaar_Get_Observable"], "ip": ["Abusix"]}
    )
    assert ok["ok"] is True and ok["counts"] == {
        "analyzer_configs": 3,
        "jobs": 3,
        "playbooks": 2,
        "users": 1,
    }
    # the bare name: not registered, the whole-submit 400
    bad = _run_state(
        monkeypatch, capsys, rows, {"hash": ["MalwareBazaar", "MalwareBazaar_Get_Observable"]}
    )
    assert bad["ok"] is False and bad["missing"] == ["MalwareBazaar"]
    off = _run_state(monkeypatch, capsys, rows, {"ip": ["ThreatFox", "Abusix"]})
    assert off["ok"] is False and off["disabled"] == ["ThreatFox"] and off["missing"] == []
    # a class only a disabled analyzer, or one that does not support it, would run
    none = _run_state(monkeypatch, capsys, rows, {"hash": ["ThreatFox"], "domain": ["Abusix"]})
    assert none["uncovered"] == ["domain", "hash"]
    # a known analyzer that does not support the type is dropped silently, which is not an error
    # while another one covers the class
    mixed = _run_state(
        monkeypatch, capsys, rows, {"ip": ["Abusix", "MalwareBazaar_Get_Observable"]}
    )
    assert mixed["ok"] is True


def test_the_token_snippet_creates_replaces_and_leaves_alone(monkeypatch, capsys):
    tokens: list = []
    user = types.SimpleNamespace(username="svc")

    class Token:
        class objects:
            @staticmethod
            def filter(user=None):
                def delete():
                    tokens.clear()

                return types.SimpleNamespace(
                    first=lambda: next((t for t in tokens if t.user is user), None), delete=delete
                )

            @staticmethod
            def create(user, key):
                tokens.append(types.SimpleNamespace(user=user, key=key))

    class Users:
        @staticmethod
        def filter(username):
            return types.SimpleNamespace(first=lambda: user if username == "svc" else None)

    _models(
        monkeypatch,
        **{
            "django.contrib.auth": {"get_user_model": lambda: type("U", (), {"objects": Users})},
            "rest_framework.authtoken.models": {"Token": Token},
        },
    )

    def run(name, key):
        monkeypatch.setenv("HNX_API_USER", name)
        monkeypatch.setenv("HNX_API_TOKEN", key)
        exec(compile(_load_code("api_seed_code"), "token", "exec"), {})
        return capsys.readouterr().out.strip()

    assert run("nobody", "k" * 40) == "HNX-TOKEN no-user"
    assert run("svc", "k" * 40) == "HNX-TOKEN created"
    assert run("svc", "k" * 40) == "HNX-TOKEN unchanged"
    assert run("svc", "j" * 40) == "HNX-TOKEN replaced"
    assert [t.key for t in tokens] == ["j" * 40]  # one token per account


def test_the_strip_snippet_clears_every_stored_secret_and_names_the_analyzers(monkeypatch, capsys):
    secret = [
        types.SimpleNamespace(
            value="x", analyzer_config_id=1, analyzer_config=types.SimpleNamespace(name="ThreatFox")
        ),
        types.SimpleNamespace(
            value="y", analyzer_config_id=2, analyzer_config=types.SimpleNamespace(name="OTXQuery")
        ),
        types.SimpleNamespace(
            value="", analyzer_config_id=3, analyzer_config=types.SimpleNamespace(name="Abusix")
        ),
    ]
    _models(monkeypatch, **{"api_app.models": {"PluginConfig": _manager(secret)}})
    exec(compile(_load_code("strip_code"), "strip", "exec"), {})
    out = capsys.readouterr().out.strip()
    assert out == "HNX-STRIP 2 OTXQuery,ThreatFox"
    assert [r.value for r in secret] == ["", "", ""]
