# SPDX-License-Identifier: Apache-2.0
"""The feed-reader module's role (modules/<id>/roles/<id>), run on localhost against fakes (CI is
unprivileged): main renders the container through compose_app with no secret in any file and a second
run is ``changed=0``; a reference with no value in the secret store, or a malformed input or credential,
is refused by name before anything is written; with the container "started" (a fake docker) every
account is created through the environment of one command, never an argument; the pinned feed list is
checked on the control host before a byte is copied and subscribed once per list for the accounts that
asked; health passes against a stand-in and fails on an open API, a refused key, a missing sign-in or too
few feeds; export writes a whole copy with a manifest and a sha256 listing and keeps the previous one
when it fails; restore refuses a tampered source and an account that holds anything, imports an intact
one and compares counts; upgrade refuses an unpinned, foreign or older target."""

from __future__ import annotations

import grp
import hashlib
import json
import os
import pwd
import socket
from pathlib import Path

import pytest
import yaml
from rolerun import fake, run_role

from tests.modules.feed_reader_front import ACCOUNTS, Server
from tests.modules.feed_reader_module import MID, ROLE_DIR, P, defaults, env_for, ref

LOOPBACK = socket.gethostbyname("localhost")  # the stand-in listens here; resolved, never a literal

ROOT = Path(__file__).resolve().parents[2]
ROLE = str(ROLE_DIR)
USER = pwd.getpwuid(os.getuid()).pw_name
DEFAULTS = defaults()
VARS = yaml.safe_load((ROLE_DIR / "vars" / "main.yml").read_text())
DEFAULT_IMAGE = DEFAULTS[P + "image"]
REPO = DEFAULT_IMAGE.split("@")[0].rsplit(":", 1)[0]
#: the example registry's edge address (a documentation-range address, never connected to)
GUEST = yaml.safe_load((ROOT / "examples" / "services.yml").read_text())["hosts"]["edge-core"][
    "address"
]
ADMIN_PW = "Admin-fake-" + "x" * 8
NAME1, NAME2 = "reader-one", "reader-two"
ADMIN_ENV = env_for(ref("admin-password"))
SECRETS = {
    ADMIN_ENV: ADMIN_PW,
    "HNX_SECRET_CONSUMER_FEED_NAME": NAME1,
    "HNX_SECRET_CONSUMER_FEED_API": ACCOUNTS[NAME1],
    "HNX_SECRET_CONSUMER_SHADOW_NAME": NAME2,
    "HNX_SECRET_CONSUMER_SHADOW_API": ACCOUNTS[NAME2],
}
USERS = [
    {"name_ref": "secret:consumer/feed-name", "api_password_ref": "secret:consumer/feed-api"},
    {"name_ref": "secret:consumer/shadow-name", "api_password_ref": "secret:consumer/shadow-api"},
]
OPML = """<?xml version="1.0" encoding="UTF-8"?>
<opml version="2.0"><head><title>t</title></head><body>
<outline text="Cat"><outline text="A" type="rss" xmlUrl="https://a.example.internal/feed.xml"/>
<outline text="B" type="rss" xmlUrl="https://b.example.internal/feed.xml"/>
<outline text="A again" type="rss" xmlUrl="https://a.example.internal/feed.xml"/></outline>
<outline text="C" type="rss" xmlURL="https://c.example.internal/feed.xml"/></body></opml>
"""
OPML_FEEDS = 3  # the distinct addresses in OPML


def dv(tmp_path: Path, **kw) -> dict:
    """The role's variables for a test: ``kw`` names the role's own variables without their prefix
    (``hnx_`` and ``ansible_`` ones as they are)."""
    v = {
        "logical_id": "feeds",
        "dir": str(tmp_path / "app"),
        "owner": USER,
        "group": grp.getgrgid(os.getgid()).gr_name,
        "data_root": str(tmp_path / "data"),
        # the unprivileged test's own ids (the role requires 1 or more): it can chown to no other
        "app_uid": os.getuid(),
        "app_gid": os.getgid(),
        "users": USERS,
        "start": False,
        "validate_with_docker": False,
    }
    v.update(kw)
    out = {"ansible_host": GUEST}
    out.update({k if k.startswith(("hnx_", "ansible_")) else P + k: x for k, x in v.items()})
    return out


def compose(tmp_path: Path) -> dict:
    return yaml.safe_load((tmp_path / "app" / "docker-compose.yml").read_text())


def opml_file(tmp_path: Path, text: str = OPML) -> tuple[str, str]:
    p = tmp_path / "feeds.opml"
    p.write_text(text)
    return str(p), hashlib.sha256(text.encode()).hexdigest()


def opml_vars(tmp_path: Path, text: str = OPML, **kw) -> dict:
    src, sha = opml_file(tmp_path, text)
    return {"opml_src": src, "opml_sha256": sha, **kw}


# ----------------------------------------------------------------------------- render


def test_main_renders_one_narrow_container_with_no_secret_in_any_file(tmp_path):
    v = dv(tmp_path)
    r = run_role(tmp_path, ROLE, "main", v, env=SECRETS)
    assert r.returncode == 0, r.stdout + r.stderr
    doc = compose(tmp_path)
    assert sorted(doc["services"]) == ["app"]
    app = doc["services"]["app"]
    assert app["image"] == DEFAULT_IMAGE and "@sha256:" in app["image"]
    assert app["cap_drop"] == ["ALL"] and sorted(app["cap_add"]) == [
        "CHOWN", "DAC_OVERRIDE", "FOWNER", "NET_BIND_SERVICE", "SETGID", "SETUID",
    ]  # fmt: skip
    assert app["security_opt"] == ["no-new-privileges:true"] and "privileged" not in app
    assert app["ports"] == [GUEST + ":8084:80"]
    root = str(tmp_path / "data")
    assert set(app["volumes"]) == {
        f"{root}/data:{VARS[P + 'container_data']}",
        f"{root}/export:/hnx-export",
        f"{root}/import:/hnx-import:ro",
    }
    env = app["environment"]
    assert env["CRON_MIN"] == "7,37" and env["TZ"] == "Etc/UTC"
    install = next(x for x in env.values() if "--api-enabled" in x).split()
    assert "--api-enabled" in install and install[install.index("--db-type") + 1] == "sqlite"
    assert install[install.index("--default-user") + 1] == "admin"
    assert install[install.index("--base-url") + 1] == f"http://{GUEST}:8084"
    # no account name or password in any file the role wrote
    secrets = [ADMIN_PW, NAME1, NAME2, *ACCOUNTS.values()]
    written = [p for p in tmp_path.rglob("*") if p.is_file() and p.name not in ("vars.json",)]
    for p in written:
        if p.parent == tmp_path and p.name.startswith(("play", "vars")):
            continue
        body = p.read_text(errors="ignore")
        assert not [s for s in secrets if s in body], p
    assert not (tmp_path / "app" / "secrets").exists()
    assert oct((tmp_path / "data" / "data").stat().st_mode & 0o777) == "0o750"
    assert oct((tmp_path / "data" / "export").stat().st_mode & 0o777) == "0o700"
    again = run_role(tmp_path, ROLE, "main", v, env=SECRETS)
    assert again.returncode == 0 and "changed=0" in again.stdout, again.stdout


def test_a_base_url_and_the_schedule_are_data(tmp_path):
    v = dv(tmp_path, base_url="https://feeds.example.internal", cron_minutes="5")
    assert run_role(tmp_path, ROLE, "main", v, env=SECRETS).returncode == 0
    env = compose(tmp_path)["services"]["app"]["environment"]
    assert env["CRON_MIN"] == "5"
    assert (
        "--base-url https://feeds.example.internal "
        in next(x for x in env.values() if "--api-enabled" in x) + " "
    )


def test_the_containers_join_the_role_slice_the_module_play_names(tmp_path):
    v = dv(tmp_path, hnx_module_slice=f"hnx-{MID}-server.slice")
    assert run_role(tmp_path, ROLE, "main", v, env=SECRETS).returncode == 0
    assert compose(tmp_path)["services"]["app"]["cgroup_parent"] == f"hnx-{MID}-server.slice"


BAD = [
    ({"logical_id": "Feeds"}, "registry id"),
    ({"image": REPO + ":1.30.4"}, "pinned by tag and digest"),
    ({"image": REPO + ":latest@sha256:" + "a" * 64}, "pinned by tag and digest"),
    ({"bind": "0.0.0.0"}, "not all interfaces"),
    ({"bind": "feeds.example.internal"}, "not all interfaces"),
    ({"port": 0}, "a port"),
    ({"data_root": "/srv"}, "canonical directories"),
    ({"data_root": "/var/lib/../etc/x"}, "canonical directories"),
    ({"cron_minutes": "*/5"}, "cron minutes"),
    ({"cron_minutes": "61"}, "cron minutes"),
    ({"base_url": "ftp://x.example.internal"}, "base URL"),
    ({"admin_user": "bad name"}, "account names"),
    ({"users": "x"}, "additional accounts"),
    ({"users": [{"name_ref": "secret:a/b"}]}, "additional accounts"),
    ({"users": [{"api_password_ref": "secret:a/b"}]}, "additional accounts"),
    ({"users": [{**USERS[0], "extra": 1}]}, "additional accounts"),
    ({"users": [{**USERS[0], "name_ref": "not-a-ref"}]}, "distinct secret"),
    ({"users": [USERS[0], USERS[0]]}, "distinct secret"),
    ({"opml_src": "/srv/feeds.opml"}, "names both its path and its sha256"),
    ({"opml_sha256": "a" * 64}, "names both its path and its sha256"),
    ({"opml_src": "/srv/feeds.opml", "opml_sha256": "xyz"}, "sha256"),
    ({"opml_tolerance": -1}, "tolerance"),
    ({"mem_limit": "lots"}, "memory limit"),
]


@pytest.mark.parametrize(("over", "why"), BAD, ids=[str(i) for i in range(len(BAD))])
def test_main_refuses_bad_inputs_and_writes_nothing(tmp_path, over, why):
    r = run_role(tmp_path, ROLE, "main", dv(tmp_path, **over), env=SECRETS)
    assert r.returncode != 0 and why in r.stdout + r.stderr, r.stdout + r.stderr
    assert not (tmp_path / "app").exists() and not (tmp_path / "data").exists()


@pytest.mark.parametrize(
    "missing",
    [
        ADMIN_ENV,
        "HNX_SECRET_CONSUMER_FEED_NAME",
        "HNX_SECRET_CONSUMER_SHADOW_API",
    ],
)
def test_a_reference_with_no_value_is_named_and_nothing_is_written(tmp_path, missing):
    env = {k: v for k, v in SECRETS.items() if k != missing}
    r = run_role(tmp_path, ROLE, "main", dv(tmp_path), env=env)
    out = r.stdout + r.stderr
    want = {
        ADMIN_ENV: ref("admin-password"),
        "HNX_SECRET_CONSUMER_FEED_NAME": "secret:consumer/feed-name",
        "HNX_SECRET_CONSUMER_SHADOW_API": "secret:consumer/shadow-api",
    }[missing]
    assert r.returncode != 0 and want in out, out
    assert not (tmp_path / "app").exists() and not (tmp_path / "data").exists()
    assert not [s for s in [ADMIN_PW, NAME1, NAME2, *ACCOUNTS.values()] if s in out]


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("HNX_SECRET_CONSUMER_FEED_API", "short"),
        ("HNX_SECRET_CONSUMER_FEED_API", "has space " + "x" * 12),
        (ADMIN_ENV, "sh" * 4),
        ("HNX_SECRET_CONSUMER_FEED_NAME", "bad name"),
        ("HNX_SECRET_CONSUMER_FEED_NAME", "-leading"),
        ("HNX_SECRET_CONSUMER_FEED_NAME", NAME2),  # one name twice
        ("HNX_SECRET_CONSUMER_SHADOW_API", ACCOUNTS[NAME1]),  # one password twice
        ("HNX_SECRET_CONSUMER_FEED_API", ADMIN_PW),  # the administrator's password reused
    ],
)
def test_a_malformed_or_repeated_credential_is_refused(tmp_path, name, value):
    r = run_role(tmp_path, ROLE, "main", dv(tmp_path), env={**SECRETS, name: value})
    out = r.stdout + r.stderr
    assert r.returncode != 0, out
    assert not (tmp_path / "app").exists()
    assert value not in out  # a value is never printed, even one that was refused


def test_readiness_passes_with_every_reference_and_names_a_missing_one(tmp_path):
    ok = run_role(tmp_path, ROLE, "credentials", dv(tmp_path), env=SECRETS)
    assert ok.returncode == 0, ok.stdout + ok.stderr
    env = {k: v for k, v in SECRETS.items() if k != "HNX_SECRET_CONSUMER_FEED_API"}
    bad = run_role(tmp_path, ROLE, "credentials", dv(tmp_path), env=env)
    assert bad.returncode != 0 and "secret:consumer/feed-api" in bad.stdout + bad.stderr


# ----------------------------------------------------------------------------- start, accounts, list

COUNTS = {"categories": 2, "feeds": OPML_FEEDS, "reads": 0, "unreads": 5, "favourites": 0}


def _docker(tmp_path: Path, health: str = "healthy") -> dict:
    """A fake docker.  ``compose ps`` lists the service in ``health``.  ``exec`` answers by the script
    it is asked to run: the account script (the contents of ``user``, default ``created``; it logs
    whether the name and the passwords reached its environment, never their values), the feed list's
    (``opml``, default ``imported 3``; logs the sha256 and floor), an export (writes the two files under
    the export directory and prints the counts of the application and of the copy), an import (prints
    the contents of ``after``) and the counts alone (``counts``).  Every call is logged."""
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    rows = json.dumps({"Service": "app", "State": "running", "Health": health}) + "\n"
    export = str(tmp_path / "data" / "export")
    body = f"""
import json, os, sys
a = sys.argv[1:]
open({str(tmp_path / "docker.log")!r}, "a").write(" ".join(a).replace(chr(10), " ") + "\\n")
def read(name, default):
    p = {str(tmp_path)!r} + "/" + name
    return open(p).read() if os.path.exists(p) else default
env = os.environ
if "ps" in a:
    sys.stdout.write({rows!r})
elif "exec" in a:
    code = a[-1]
    who = env.get("HNX_USER", "")
    counts = read("counts-" + who, read("counts", {json.dumps(COUNTS)!r})).strip()
    if "export-sqlite-for-user" in code:
        base = env["HNX_FILE"].replace("/hnx-export", {export!r})
        os.makedirs(os.path.dirname(base), exist_ok=True)
        open(base + ".sqlite", "w").write("sqlite " + who)
        open(base + ".opml", "w").write("<opml/>")
        copy = read("copy", None)
        c = json.loads(counts)
        sys.stdout.write("HNX-COUNTS " + counts + "\\n")
        sys.stdout.write("HNX-EXPORT " + (copy if copy else json.dumps({{"feeds": c["feeds"], "categories": c["categories"], "entries": 5}})) + "\\n")
    elif "import-sqlite-for-user" in code:
        open({str(tmp_path / "import.log")!r}, "a").write(env["HNX_FILE"] + "\\n")
        if os.path.exists({str(tmp_path / "import.fails")!r}):
            sys.exit(1)
        sys.stdout.write("HNX-COUNTS " + read("after", counts).strip() + "\\n")
    elif "HNX-OPML" in code:
        open({str(tmp_path / "opml.log")!r}, "a").write(who + " " + env.get("HNX_SHA", "") + " " + env.get("HNX_FLOOR", "") + "\\n")
        state = read("opml", "imported 3").strip()
        sys.stdout.write("HNX-OPML " + state + "\\n")
        sys.exit(1 if state.startswith("short") else 0)
    elif "HNX-USER" in code:
        open({str(tmp_path / "user.log")!r}, "a").write(
            who + " pw=" + ("yes" if env.get("HNX_PW") else "no") + " api=" + ("yes" if env.get("HNX_APIPW") else "no") + "\\n")
        sys.stdout.write("noise\\nHNX-USER " + read("user", "created").strip() + "\\n")
    elif "HNX-COUNTS" in code:
        sys.stdout.write("HNX-COUNTS " + counts + "\\n")
sys.exit(0)
"""
    fake(bindir / "docker", body)
    return {"PATH": f"{bindir}:{os.environ['PATH']}"}


def _calls(tmp_path: Path) -> list[str]:
    log = tmp_path / "docker.log"
    return log.read_text().splitlines() if log.exists() else []


def _live(tmp_path, front, **kw):
    return dv(tmp_path, bind=LOOPBACK, port=front.addr[1], start=True,
              ready_timeout=10, **kw)  # fmt: skip


def test_main_starts_waits_for_the_sign_in_page_and_creates_every_account_through_the_environment(
    tmp_path,
):
    with Server() as front:
        env = {**SECRETS, **_docker(tmp_path)}
        r = run_role(tmp_path, ROLE, "main", _live(tmp_path, front), env=env)
        assert r.returncode == 0, r.stdout + r.stderr
        assert "/i/" in front.paths
    calls = _calls(tmp_path)
    assert any("--remove-orphans" in c for c in calls)  # compose_app started it
    seeding = [c for c in calls if "HNX-USER" in c]
    assert len(seeding) == 3  # the administrator, then the two accounts
    assert all("-u www-data" in c and "-e HNX_USER -e HNX_PW -e HNX_APIPW" in c for c in seeding)
    blob = "\n".join(calls)
    assert not [
        s for s in [ADMIN_PW, NAME1, NAME2, *ACCOUNTS.values()] if s in blob
    ]  # never an argument
    assert (tmp_path / "user.log").read_text().splitlines() == [
        "admin pw=yes api=no",
        f"{NAME1} pw=no api=yes",
        f"{NAME2} pw=no api=yes",
    ]


def test_an_unchanged_account_is_no_change(tmp_path):
    with Server() as front:
        (tmp_path / "user").write_text("unchanged")
        env = {**SECRETS, **_docker(tmp_path)}
        v = _live(tmp_path, front)
        assert run_role(tmp_path, ROLE, "main", v, env=env).returncode == 0
        again = run_role(tmp_path, ROLE, "main", v, env=env)
        assert again.returncode == 0 and "changed=0" in again.stdout, again.stdout


def test_a_command_that_does_not_report_the_account_state_fails_the_run(tmp_path):
    with Server() as front:
        env = {**SECRETS, **_docker(tmp_path)}
        fake(tmp_path / "bin" / "docker", "import sys\nsys.exit(0)\n")  # says nothing
        r = run_role(tmp_path, ROLE, "main", _live(tmp_path, front), env=env)
        assert r.returncode != 0


def test_the_administrator_may_have_an_api_password_and_a_web_only_account_has_none(tmp_path):
    with Server() as front:
        extra = {
            env_for(ref("admin-api-password")): "Api-admin-fake-" + "y" * 6,
            "HNX_SECRET_CONSUMER_WEB_PASSWORD": "Web-fake-" + "z" * 10,
        }
        env = {**SECRETS, **extra, **_docker(tmp_path)}
        users = [*USERS[:1], {**USERS[1], "password_ref": "secret:consumer/web-password"}]
        v = _live(tmp_path, front, users=users,
                  admin_api_login_ref=ref("admin-api-password"))  # fmt: skip
        r = run_role(tmp_path, ROLE, "main", v, env=env)
        assert r.returncode == 0, r.stdout + r.stderr
    assert (tmp_path / "user.log").read_text().splitlines() == [
        "admin pw=yes api=yes",
        f"{NAME1} pw=no api=yes",
        f"{NAME2} pw=yes api=yes",
    ]


# ----------------------------------------------------------------------------- the feed list


def test_a_list_that_is_not_the_pinned_one_is_refused_before_anything_is_copied(tmp_path):
    with Server() as front:
        v = _live(tmp_path, front, **opml_vars(tmp_path))
        v[P + "opml_sha256"] = "0" * 64
        r = run_role(tmp_path, ROLE, "main", v, env={**SECRETS, **_docker(tmp_path)})
    assert r.returncode != 0 and "not the pinned feed list" in r.stdout + r.stderr
    assert not (tmp_path / "data").exists() and not _calls(tmp_path)


def test_a_list_that_is_a_link_or_names_no_feed_or_is_too_large_is_refused(tmp_path):
    with Server() as front:
        env = {**SECRETS, **_docker(tmp_path)}
        real, sha = opml_file(tmp_path)
        link = tmp_path / "link.opml"
        link.symlink_to(real)
        r = run_role(
            tmp_path,
            ROLE,
            "main",
            _live(tmp_path, front, opml_src=str(link), opml_sha256=sha),
            env=env,
        )
        assert r.returncode != 0 and "not the pinned feed list" in r.stdout + r.stderr
        empty = opml_vars(tmp_path, "<opml><body/></opml>")
        r = run_role(tmp_path, ROLE, "main", _live(tmp_path, front, **empty), env=env)
        assert r.returncode != 0 and "names no feed" in r.stdout + r.stderr
    assert not (tmp_path / "data").exists()


def test_the_pinned_list_is_copied_and_subscribed_once_for_the_accounts_that_asked(tmp_path):
    with Server() as front:
        env = {**SECRETS, **_docker(tmp_path)}
        users = [USERS[0], {**USERS[1], "opml": False}]
        v = _live(tmp_path, front, users=users, **opml_vars(tmp_path))
        r = run_role(tmp_path, ROLE, "main", v, env=env)
        assert r.returncode == 0, r.stdout + r.stderr
    placed = tmp_path / "data" / "import" / "feeds.opml"
    assert placed.read_text() == OPML and oct(placed.stat().st_mode & 0o777) == "0o640"
    sha = hashlib.sha256(OPML.encode()).hexdigest()
    # three distinct addresses (a repeat and an upper-case attribute count once and once): the floor
    assert (tmp_path / "opml.log").read_text().splitlines() == [f"{NAME1} {sha} {OPML_FEEDS}"]


def test_the_administrator_is_subscribed_when_asked_and_the_floor_takes_the_tolerance(tmp_path):
    with Server() as front:
        v = _live(tmp_path, front, admin_import_opml=True, opml_tolerance=1,
                  **opml_vars(tmp_path))  # fmt: skip
        r = run_role(tmp_path, ROLE, "main", v, env={**SECRETS, **_docker(tmp_path)})
        assert r.returncode == 0, r.stdout + r.stderr
    rows = (tmp_path / "opml.log").read_text().splitlines()
    assert [x.split()[0] for x in rows] == ["admin", NAME1, NAME2]
    assert {x.split()[2] for x in rows} == {str(OPML_FEEDS - 1)}


def test_an_account_that_ends_short_of_the_list_fails_the_run(tmp_path):
    with Server() as front:
        (tmp_path / "opml").write_text("short 0 of 3")
        v = _live(tmp_path, front, **opml_vars(tmp_path))
        r = run_role(tmp_path, ROLE, "main", v, env={**SECRETS, **_docker(tmp_path)})
    assert r.returncode != 0


def test_a_list_already_subscribed_is_no_change(tmp_path):
    with Server() as front:
        (tmp_path / "user").write_text("unchanged")
        (tmp_path / "opml").write_text("unchanged")
        v = _live(tmp_path, front, **opml_vars(tmp_path))
        env = {**SECRETS, **_docker(tmp_path)}
        assert run_role(tmp_path, ROLE, "main", v, env=env).returncode == 0
        again = run_role(tmp_path, ROLE, "main", v, env=env)
        assert again.returncode == 0 and "changed=0" in again.stdout, again.stdout


# ----------------------------------------------------------------------------- health


def _health(tmp_path, front, health="healthy", **kw):
    v = _live(tmp_path, front, **kw)
    return run_role(tmp_path, ROLE, "health", v, env={**SECRETS, **_docker(tmp_path, health)})


def test_health_passes_and_only_reads(tmp_path):
    with Server() as front:
        r = _health(tmp_path, front, **opml_vars(tmp_path))
        paths, bodies = list(front.paths), list(front.bodies)
    assert r.returncode == 0, r.stdout + r.stderr
    assert paths[0] == "/i/"
    assert paths.count("/api/fever.php?api") == 3  # an unknown key, then each account's own
    assert paths.count("/api/greader.php/accounts/ClientLogin") == 2
    # the Fever calls carry a key, never an API password
    fever = [b for b in bodies if "api_key" in b]
    assert all(len(b["api_key"]) == 32 and set(b) == {"api_key"} for b in fever)
    assert not [b for b in fever if b["api_key"] in ACCOUNTS.values()]
    assert not any("HNX-USER" in c or "import" in c for c in _calls(tmp_path))  # nothing changed


def test_health_fails_when_the_api_is_open_to_any_key(tmp_path):
    with Server(open_api=True) as front:
        r = _health(tmp_path, front)
    assert r.returncode != 0 and "accepted a key that belongs to no account" in r.stdout


def test_health_fails_on_an_account_the_api_does_not_know(tmp_path):
    with Server(accounts={NAME1: ACCOUNTS[NAME1]}) as front:
        r = _health(tmp_path, front)
    assert r.returncode != 0 and "refuses account 2's key" in r.stdout


def test_health_fails_on_an_api_password_the_reader_does_not_hold(tmp_path):
    # the Fever lookup is the account's; the Google Reader sign-in compares the password itself
    with Server(accounts={NAME1: ACCOUNTS[NAME1], NAME2: "other-" + "c" * 14}) as front:
        r = _health(tmp_path, front)
    assert r.returncode != 0 and "The Google Reader API signs the account in" in r.stdout


def test_health_fails_when_the_google_reader_sign_in_is_not_served(tmp_path):
    with Server(greader=False) as front:
        r = _health(tmp_path, front)
    assert r.returncode != 0


def test_health_fails_when_the_sign_in_page_does_not_answer(tmp_path):
    with Server(login=500) as front:
        r = _health(tmp_path, front)
    assert r.returncode != 0 and "The sign-in page answers" in r.stdout


def test_health_fails_when_the_container_is_unhealthy(tmp_path):
    with Server() as front:
        r = _health(tmp_path, front, health="unhealthy")
    assert r.returncode != 0 and "unhealthy" in r.stdout + r.stderr


def test_health_fails_when_an_account_holds_fewer_feeds_than_the_list(tmp_path):
    with Server() as front:
        (tmp_path / f"counts-{NAME1}").write_text(json.dumps({**COUNTS, "feeds": 2}))
        r = _health(tmp_path, front, **opml_vars(tmp_path))
    assert r.returncode != 0 and "holds fewer feeds than it is expected to" in r.stdout


def test_health_fails_when_a_reader_that_should_hold_feeds_holds_none(tmp_path):
    with Server() as front:
        (tmp_path / f"counts-{NAME2}").write_text(json.dumps({**COUNTS, "feeds": 0}))
        r = _health(tmp_path, front, expected_min_feeds=1)
    assert r.returncode != 0 and "holds fewer feeds than it is expected to" in r.stdout


def test_health_with_a_tolerance_accepts_one_feed_fewer(tmp_path):
    with Server() as front:
        (tmp_path / f"counts-{NAME1}").write_text(json.dumps({**COUNTS, "feeds": 2}))
        r = _health(tmp_path, front, opml_tolerance=1, **opml_vars(tmp_path))
    assert r.returncode == 0, r.stdout + r.stderr


# ----------------------------------------------------------------------------- export, restore


def _export(tmp_path, v, **env):
    return run_role(tmp_path, ROLE, "export", v, env={**SECRETS, **_docker(tmp_path), **env})


def test_export_writes_every_account_a_manifest_and_a_listing(tmp_path):
    v = dv(tmp_path, start=True)
    r = _export(tmp_path, v)
    assert r.returncode == 0, r.stdout + r.stderr
    latest = tmp_path / "data" / "export" / "latest"
    assert sorted(p.name for p in latest.iterdir()) == [
        "a0.opml", "a0.sqlite", "a1.opml", "a1.sqlite", "a2.opml", "a2.sqlite",
        "listing.jsonl", "manifest.json",
    ]  # fmt: skip
    manifest = json.loads((latest / "manifest.json").read_text())
    assert manifest["format"] == f"{MID}-export-1"
    assert [a["name"] for a in manifest["accounts"]] == ["admin", NAME1, NAME2]
    assert manifest["accounts"][1]["counts"] == COUNTS and manifest["accounts"][1]["file"] == "a1"
    rows = [json.loads(x) for x in (latest / "listing.jsonl").read_text().splitlines()]
    assert sorted(x["key"] for x in rows) == sorted(
        p.name for p in latest.iterdir() if p.name != "listing.jsonl"
    )
    for x in rows:
        data = (latest / x["key"]).read_bytes()
        assert x["size"] == len(data) and x["sha256"] == hashlib.sha256(data).hexdigest()
    assert oct((latest / "manifest.json").stat().st_mode & 0o777) == "0o600"
    assert not (tmp_path / "data" / "export" / ".new").exists()
    assert not (tmp_path / "data" / "export" / ".previous").exists()
    # a second export replaces the first, whole
    again = _export(tmp_path, v)
    assert again.returncode == 0 and (latest / "manifest.json").is_file()
    assert not (tmp_path / "data" / "export" / ".previous").exists()


@pytest.mark.parametrize(
    ("copy", "why"),
    [
        (json.dumps({"feeds": 1, "categories": 2, "entries": 5}), "is not whole"),
        (json.dumps({"feeds": 3, "categories": 1, "entries": 5}), "is not whole"),
    ],
)
def test_an_export_whose_copy_differs_from_the_application_fails_and_keeps_the_previous(
    tmp_path, copy, why
):
    v = dv(tmp_path, start=True)
    assert _export(tmp_path, v).returncode == 0
    latest = tmp_path / "data" / "export" / "latest"
    before = (latest / "manifest.json").read_text()
    (tmp_path / "copy").write_text(copy)
    r = _export(tmp_path, v)
    assert r.returncode != 0 and why in r.stdout + r.stderr
    assert (latest / "manifest.json").read_text() == before  # the previous copy is untouched


def test_an_account_that_should_hold_feeds_and_holds_none_is_not_exported(tmp_path):
    v = dv(tmp_path, start=True, **opml_vars(tmp_path))
    (tmp_path / f"counts-{NAME1}").write_text(json.dumps({**COUNTS, "feeds": 0}))
    (tmp_path / "copy").write_text(json.dumps({"feeds": 0, "categories": 2, "entries": 0}))
    r = _export(tmp_path, v)
    assert r.returncode != 0 and not (tmp_path / "data" / "export" / "latest").exists()


def test_export_refuses_a_build_directory_that_is_not_a_plain_directory(tmp_path):
    v = dv(tmp_path, start=True)
    export = tmp_path / "data" / "export"
    export.mkdir(parents=True)
    (tmp_path / "elsewhere").mkdir()
    (export / ".new").symlink_to(tmp_path / "elsewhere")
    r = _export(tmp_path, v)
    assert r.returncode != 0 and "is not a directory" in r.stdout + r.stderr
    assert (tmp_path / "elsewhere").is_dir()


def _exported(tmp_path) -> Path:
    v = dv(tmp_path / "src", start=True)
    (tmp_path / "src").mkdir(exist_ok=True)
    r = _export(tmp_path / "src", v)
    assert r.returncode == 0, r.stdout + r.stderr
    return tmp_path / "src" / "data" / "export" / "latest"


def _restore(tmp_path, source, **kw):
    v = dv(tmp_path, start=True, restore_source=str(source), **kw)
    return run_role(tmp_path, ROLE, "restore", v, env={**SECRETS, **_docker(tmp_path)})


def _empty(tmp_path):
    (tmp_path / "counts").write_text(json.dumps({**COUNTS, "feeds": 0, "unreads": 0}))
    (tmp_path / "after").write_text(json.dumps(COUNTS))


def test_restore_imports_into_empty_accounts_creates_them_and_compares_counts(tmp_path):
    source = _exported(tmp_path)
    (tmp_path / "dst").mkdir()
    dst = tmp_path / "dst"
    _empty(dst)
    r = _restore(dst, source)
    assert r.returncode == 0, r.stdout + r.stderr
    assert len((dst / "import.log").read_text().splitlines()) == 3
    assert (dst / "user.log").read_text().splitlines()[0].startswith("admin")  # accounts first
    assert not (dst / "data" / "export" / ".restoring").exists()


def test_restore_refuses_an_account_that_already_holds_feeds(tmp_path):
    source = _exported(tmp_path)
    dst = tmp_path / "dst"
    dst.mkdir()
    r = _restore(dst, source)  # the fake reports feeds in every account
    assert r.returncode != 0 and "already holds feeds or entries" in r.stdout + r.stderr
    assert not (dst / "import.log").exists()


def test_restore_that_does_not_reproduce_the_counts_leaves_the_staged_file(tmp_path):
    source = _exported(tmp_path)
    dst = tmp_path / "dst"
    dst.mkdir()
    _empty(dst)
    (dst / "after").write_text(json.dumps({**COUNTS, "feeds": 1}))
    r = _restore(dst, source)
    assert r.returncode != 0 and "counts differ" in r.stdout + r.stderr
    assert list((dst / "data" / "export" / ".restoring").glob("*.sqlite"))


def test_restore_refuses_a_tampered_file_and_writes_nothing(tmp_path):
    source = _exported(tmp_path)
    (source / "a1.sqlite").write_text("tampered")
    dst = tmp_path / "dst"
    dst.mkdir()
    _empty(dst)
    r = _restore(dst, source)
    assert r.returncode != 0 and "not an intact export" in r.stdout + r.stderr
    assert not (dst / "import.log").exists() and not (dst / "user.log").exists()


@pytest.mark.parametrize("kind", ["link", "name", "unlisted-manifest"])
def test_restore_refuses_a_link_an_odd_name_and_a_source_without_its_manifest(tmp_path, kind):
    source = _exported(tmp_path)
    rows = [json.loads(x) for x in (source / "listing.jsonl").read_text().splitlines()]
    if kind == "link":
        (source / "a0.opml").unlink()
        (source / "a0.opml").symlink_to(source / "a1.opml")
    elif kind == "name":
        (source / "evil.sh").write_text("x")
        rows.append({"key": "evil.sh", "size": 1, "sha256": hashlib.sha256(b"x").hexdigest()})
        (source / "listing.jsonl").write_text("\n".join(json.dumps(x) for x in rows) + "\n")
    else:
        rows = [x for x in rows if x["key"] != "manifest.json"]
        (source / "listing.jsonl").write_text("\n".join(json.dumps(x) for x in rows) + "\n")
    dst = tmp_path / "dst"
    dst.mkdir()
    _empty(dst)
    r = _restore(dst, source)
    assert r.returncode != 0 and not (dst / "import.log").exists()


def test_restore_stops_when_the_export_holds_an_account_the_site_no_longer_names(tmp_path):
    source = _exported(tmp_path)
    dst = tmp_path / "dst"
    dst.mkdir()
    _empty(dst)
    r = _restore(dst, source, users=USERS[:1])
    assert r.returncode != 0 and "no longer names" in r.stdout + r.stderr


# ----------------------------------------------------------------------------- backup, upgrade


def test_backup_names_the_data_root(tmp_path):
    r = run_role(tmp_path, ROLE, "backup", dv(tmp_path), env=SECRETS)
    assert r.returncode == 0, r.stdout + r.stderr
    doc = json.loads((tmp_path / "app" / "backup-manifest.json").read_text())
    assert doc == {"app": MID, "paths": [str(tmp_path / "data")]}


def test_upgrade_records_a_newer_pinned_target_and_refuses_the_rest(tmp_path):
    v = dv(tmp_path)
    assert run_role(tmp_path, ROLE, "main", v, env=SECRETS).returncode == 0
    new = REPO + ":1.31.0@sha256:" + "b" * 64
    ok = run_role(tmp_path, ROLE, "upgrade", {**v, P + "target_image": new}, env=SECRETS)
    assert ok.returncode == 0, ok.stdout + ok.stderr
    for bad in (
        REPO + ":1.31.0",  # not pinned
        "docker.io/other/app:1.31.0@sha256:" + "b" * 64,  # another repository
        REPO + ":1.29.9@sha256:" + "b" * 64,  # older
        REPO + ":latest@sha256:" + "b" * 64,  # not a version
    ):
        r = run_role(tmp_path, ROLE, "upgrade", {**v, P + "target_image": bad}, env=SECRETS)
        assert r.returncode != 0, bad


@pytest.mark.static
def test_every_script_run_in_the_container_is_kept_from_the_controllers_variable_expansion():
    """The command module expands ``$NAME`` in its arguments from the task's environment, which would
    put an account's password into the argument list: every task that hands a shell script to the
    container turns that off (the script's ``$NAME`` is for the container's own shell)."""
    seen = 0
    for path in sorted((ROLE_DIR / "tasks").glob("*.yml")):
        for task in _tasks(yaml.safe_load(path.read_text())):
            cmd = task.get("ansible.builtin.command")
            if isinstance(cmd, dict) and "sh" in cmd.get("argv", []):
                seen += 1
                assert cmd.get("expand_argument_vars") is False, (path.name, task["name"])
    assert seen >= 6


def _tasks(doc):
    """Every task of a task file, inside blocks, rescues and always sections too."""
    for task in doc or []:
        yield task
        for key in ("block", "rescue", "always"):
            yield from _tasks(task.get(key))


@pytest.mark.parametrize("bad", ["../../etc/x", "a1/../a2", "/abs", "a1000", "b1", "a1 ", "a9"])
def test_restore_refuses_a_manifest_file_name_that_is_not_a_listed_plain_name(tmp_path, bad):
    source = _exported(tmp_path)
    manifest = json.loads((source / "manifest.json").read_text())
    manifest["accounts"][0]["file"] = bad
    text = json.dumps(manifest)
    (source / "manifest.json").write_text(text)
    rows = [json.loads(x) for x in (source / "listing.jsonl").read_text().splitlines()]
    for x in rows:
        if x["key"] == "manifest.json":
            x["size"], x["sha256"] = len(text), hashlib.sha256(text.encode()).hexdigest()
    (source / "listing.jsonl").write_text("\n".join(json.dumps(x) for x in rows) + "\n")
    dst = tmp_path / "dst"
    dst.mkdir()
    _empty(dst)
    r = _restore(dst, source)
    assert r.returncode != 0 and not (dst / "import.log").exists()


# ------------------------------------------------- a value that begins with "-" is never an option


def _run_cli_script(tmp_path: Path, script: str, env: dict) -> list[list[str]]:
    """Run one of the role's in-container scripts under a fake ``php`` that records its argv words.
    ``list-users`` reports nothing (so the account is created), and the ``-r`` verifier reports a
    difference (so an existing account is updated)."""
    import subprocess

    bindir = tmp_path / "pbin"
    bindir.mkdir()
    log = tmp_path / "php.log"
    fake(
        bindir / "php",
        f"""
import json, sys
a = sys.argv[1:]
if a[:1] == ["-r"]:
    sys.exit(1)
open({str(log)!r}, "a").write(json.dumps(a) + "\\n")
sys.exit(0)
""",
    )
    body = "".join(ln for ln in script.splitlines(True) if not ln.startswith("cd /"))
    r = subprocess.run(
        ["sh", "-c", body],
        env={"PATH": f"{bindir}:{os.environ['PATH']}", **env},
        capture_output=True,
        text=True,
        check=False,
    )
    assert r.returncode == 0, r.stdout + r.stderr
    return [json.loads(x) for x in log.read_text().splitlines()]


@pytest.mark.parametrize("existing", [False, True])
def test_a_password_or_name_that_begins_with_a_dash_is_one_option_word(tmp_path, existing):
    pw, api, name = "-" + "p" * 20, "-" + "a" * 20, "-reader"
    env = {"HNX_USER": name, "HNX_PW": pw, "HNX_APIPW": api, "HNX_LANG": "en"}
    script = VARS[P + "user_script"]
    if existing:  # make list-users name the account, so the update tool runs
        script = script.replace(
            "php cli/list-users.php 2>/dev/null | grep -qxF --", f"echo {name} | grep -qxF --"
        )
    calls = [c for c in _run_cli_script(tmp_path, script, env) if c[0] != "cli/list-users.php"]
    assert len(calls) == 1
    argv = calls[0]
    assert argv[0] == ("cli/update-user.php" if existing else "cli/create-user.php")
    assert f"--user={name}" in argv
    assert f"--password={pw}" in argv and f"--api-password={api}" in argv
    # no value ever stands as its own word, where the tool would take it for an option
    assert not [w for w in argv[1:] if w.startswith("-") and not w.startswith("--")]
    assert not {"--user", "--password", "--api-password", "--language"} & set(argv)
    assert not [w for w in argv if w in {name, pw, api}]


def test_every_cli_invocation_in_the_role_uses_the_single_word_option_form():
    import re

    for key, script in VARS.items():
        if not (key.startswith(P) and key.endswith("_script")):
            continue
        for line in script.splitlines():
            if "cli/" not in line:
                continue
            assert not re.search(r"\s--(user|password|api-password|language|filename)\s", line), (
                key,
                line,
            )
