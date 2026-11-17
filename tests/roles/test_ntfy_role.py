# SPDX-License-Identifier: Apache-2.0
"""Role ``ntfy`` (modules/ntfy/roles/ntfy), run on localhost against fakes (CI is unprivileged):
main renders deny-all ntfy through compose_app with the credentials only in the env_file and a
second run is ``changed=0``; malformed inputs and credentials are refused; health passes against
a deny-all stand-in and fails when anonymous publishing is open or the admin cannot sign in;
export writes an object-tree with a sha256 listing and restore refuses a tampered one."""

from __future__ import annotations

import grp
import http.server
import json
import os
import pwd
import socket
import socketserver
import sqlite3
import subprocess
import sys
import threading
from pathlib import Path

import pytest
import yaml
from rolerun import fake, run_role

from conformance.fakes.ntfy_api import FakeNtfy
from tests.modules.ntfy_front import DenyAllNtfy

ROOT = Path(__file__).resolve().parents[2]
ROLE = str(ROOT / "modules" / "ntfy" / "roles" / "ntfy")
USER = pwd.getpwuid(os.getuid()).pw_name
GUEST = "192.0.2.40"  # no-raw-endpoint: allow a documentation-range guest address
TOKEN = "tk_fakefakefakefakefakefakefake0"
PASSWORD = "admin-password-fake"
HASH = "$2b$10$" + "f" * 53
SECRETS = {
    "HNX_SECRET_NTFY_ADMIN_PASSWORD": PASSWORD,
    "HNX_SECRET_NTFY_ADMIN_PASSWORD_HASH": HASH,
    "HNX_SECRET_NTFY_PUBLISHER_TOKEN": TOKEN,
}

# The container's uid and gid are the test's own (CI runs unprivileged, as a uid of 1000 or more,
# which the role requires), so the role's ownership changes need no privilege.


def ntfy_vars(tmp_path: Path, **kw) -> dict:
    v = {
        "ntfy_logical_id": "notify",
        "ansible_host": GUEST,
        "ntfy_dir": str(tmp_path / "app"),
        "ntfy_data_root": str(tmp_path / "data"),
        "ntfy_owner": USER,
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
    # the data root's group is the container's gid by default, so the container's user (which
    # runs the export) passes through it to db/ and export/
    root = (tmp_path / "data").stat()
    assert root.st_gid == os.getgid() and oct(root.st_mode & 0o777) == "0o750"
    assert TOKEN not in r.stdout and HASH not in r.stdout
    again = run_role(tmp_path, ROLE, "main", v, env=SECRETS)
    assert again.returncode == 0 and "changed=0" in again.stdout, again.stdout


def test_main_puts_the_container_in_the_role_slice_the_module_play_names(tmp_path):
    """The module apply path sets hnx_module_slice on ntfy's play (its role slice, installed by
    the limits play); compose_app makes it the container's cgroup parent without ntfy passing it."""
    v = ntfy_vars(tmp_path, hnx_module_slice="hnx-ntfy-server.slice")
    r = run_role(tmp_path, ROLE, "main", v, env=SECRETS)
    assert r.returncode == 0, r.stdout + r.stderr
    doc = yaml.safe_load((tmp_path / "app" / "docker-compose.yml").read_text())
    assert doc["services"]["ntfy"]["cgroup_parent"] == "hnx-ntfy-server.slice"


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
        ({"ntfy_publisher_topics": ["hnxconf-x*"]}, {}),  # inside the scratch prefix
        ({"ntfy_data_root": "/var/lib/../etc"}, {}),
        ({"ntfy_dir": "relative/dir"}, {}),
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


def _auth_db(root: Path, minted: int = 0, unprovisioned: tuple[str, ...] = ()) -> None:
    """A user database shaped like ntfy's (the columns the drift check reads): the provisioned
    admin and publisher with the publisher's token, ``minted`` tokens nobody provisioned and
    ``unprovisioned`` accounts."""
    (root / "db").mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(root / "db" / "auth.db")
    c.execute("CREATE TABLE user (id TEXT, user TEXT, provisioned INT)")
    c.execute("CREATE TABLE user_token (user_id TEXT, token TEXT, provisioned INT)")
    users = [("u_e", "*", 0), ("u_a", "admin", 1), ("u_p", "publisher", 1)]
    users += [(f"u_{n}", n, 0) for n in unprovisioned]
    c.executemany("INSERT INTO user VALUES (?, ?, ?)", users)
    tokens = [("u_p", TOKEN, 1)] + [("u_p", f"tk_minted{i}", 0) for i in range(minted)]
    c.executemany("INSERT INTO user_token VALUES (?, ?, ?)", tokens)
    c.commit()
    c.close()


def _health(tmp_path, srv, **env):
    if not (tmp_path / "data" / "db" / "auth.db").exists():
        _auth_db(tmp_path / "data")
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


def test_health_fails_when_the_publisher_can_read_any_topic(tmp_path):
    with DenyAllNtfy(token=TOKEN, admin=("admin", PASSWORD)) as srv:
        srv.scratch = ""  # an access list that lets the token read everything
        r = _health(tmp_path, srv)
    assert r.returncode != 0 and "may not read a topic outside the scratch prefix" in r.stdout


@pytest.mark.parametrize("drift", [{"minted": 1}, {"unprovisioned": ("intruder",)}])
def test_health_fails_on_a_token_or_account_the_environment_does_not_provision(tmp_path, drift):
    _auth_db(tmp_path / "data", **drift)
    with DenyAllNtfy(token=TOKEN, admin=("admin", PASSWORD)) as srv:
        r = _health(tmp_path, srv)
    assert r.returncode != 0
    assert "holds only what the environment provisions" in r.stdout
    assert TOKEN not in r.stdout


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
    restored = (tmp_path / "data" / "db" / "cache.db").stat()
    assert restored.st_uid == os.getuid() and oct(restored.st_mode & 0o777) == "0o600"
    assert not list((tmp_path / "data" / "db").glob(".*.restore"))
    # a tampered file, or one the listing does not name, is refused before anything changes
    log.unlink()
    with open(src / "cache.db", "ab") as f:
        f.write(b"x")
    bad = run_role(tmp_path, ROLE, "restore", {**v, "ntfy_restore_source": str(src)}, env=env)
    assert bad.returncode != 0 and "cache.db: not the listed size" in bad.stdout
    assert not log.exists()
    (src / "cache.db").write_bytes((export / "cache.db").read_bytes())
    # a file another user could have written, or a link in place of one, is refused too
    (src / "cache.db").chmod(0o664)
    bad = run_role(tmp_path, ROLE, "restore", {**v, "ntfy_restore_source": str(src)}, env=env)
    assert bad.returncode != 0 and "writable by no one else" in bad.stdout
    (src / "cache.db").chmod(0o600)
    (src / "cache.db").rename(tmp_path / "cache.db.real")
    (src / "cache.db").symlink_to(tmp_path / "cache.db.real")
    bad = run_role(tmp_path, ROLE, "restore", {**v, "ntfy_restore_source": str(src)}, env=env)
    assert bad.returncode != 0 and "cache.db: cannot be opened (missing, or a link)" in bad.stdout
    assert not log.exists()
    (src / "cache.db").unlink()
    (tmp_path / "cache.db.real").rename(src / "cache.db")
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
    other = "docker.io/someone/ntfy:v9.9.9@sha256:" + "a" * 64  # another repository
    assert run_role(tmp_path, ROLE, "upgrade", {**v, "ntfy_target_image": other}).returncode != 0
    target = "docker.io/binwiederhier/ntfy:v9.9.9@sha256:" + "a" * 64
    ok = run_role(tmp_path, ROLE, "upgrade", {**v, "ntfy_target_image": target})
    assert ok.returncode == 0, ok.stdout + ok.stderr
    pending = json.loads((tmp_path / "app" / "pending-upgrade.json").read_text())
    assert pending == {"service": "ntfy", "tag": "v9.9.9", "digest": "sha256:" + "a" * 64}


# -----------------------------------------------------------------------------
# The dead-man watch (LL-571)
#


jinja2 = pytest.importorskip("jinja2")

TEMPLATE = Path(ROLE) / "templates" / "deadman-watch.py.j2"
LOOPBACK = socket.gethostbyname("localhost")
BEAT = {"name": "metrics", "topic": "beat", "max_age_minutes": 15}


class _Quick(http.server.HTTPServer):
    def server_bind(self):
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = self.server_address[:2]


class Notify:
    """A loopback notify service: records every POST, answers ``status``."""

    def __init__(self, status=200):
        self.status, self.posts = status, []
        me = self

        class H(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                n = int(self.headers.get("Content-Length") or 0)
                me.posts.append((self.path, dict(self.headers), self.rfile.read(n).decode()))
                self.send_response(me.status)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *a):
                pass

        self.srv = _Quick((LOOPBACK, 0), H)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def close(self):
        self.srv.shutdown()
        self.srv.server_close()


@pytest.fixture
def notify():
    made = []

    def make(**kw):
        n = Notify(**kw)
        made.append(n)
        return n

    yield make
    for n in made:
        n.close()


def cache(path: Path, rows=(), schema="topic TEXT, time INT, event TEXT") -> Path:
    c = sqlite3.connect(path)
    c.execute(f"CREATE TABLE messages ({schema})")
    for topic, ago_min, event in rows:
        c.execute("INSERT INTO messages VALUES (?, ?, ?)", (topic, NOW - ago_min * 60, event))
    c.commit()
    c.close()
    return path


def build(tmp_path, srv, beats=(BEAT,)):
    token = tmp_path / "auth"
    token.write_text(TOKEN + "\n")
    values = {
        "ntfy_deadman_cache_file": str(tmp_path / "cache.db"),
        "ntfy_deadman_state_dir": str(tmp_path / "state"),
        "ntfy_deadman_beats": list(beats),
        "ntfy_bind": LOOPBACK,
        "ntfy_port": srv.srv.server_port,
        "ntfy_deadman_alert_topic": "alerts",
        "ntfy_deadman_auth_file": str(token),
        "ntfy_logical_id": "notify",
    }
    e = jinja2.Environment(undefined=jinja2.StrictUndefined, keep_trailing_newline=True)
    e.filters["to_json"] = json.dumps
    script = tmp_path / "watch.py"
    script.write_text(e.from_string(TEMPLATE.read_text()).render(**values))
    return script


# the watch reads the clock once: it is run under a fixed one (injected, not the wall clock), so
# "40 minutes ago" is an exact number in the cache and the test never races a minute boundary
NOW = 1_800_000_000
FIXED_CLOCK = (
    "import runpy, sys, time\n"
    f"time.time = lambda: {NOW}\n"
    "sys.argv = sys.argv[1:]\n"
    "runpy.run_path(sys.argv[0], run_name='__main__')\n"
)


def run(script):
    return subprocess.run(
        [sys.executable, "-c", FIXED_CLOCK, str(script)], capture_output=True, text=True
    )


def state(tmp_path):
    return json.loads((tmp_path / "state" / "state.json").read_text())


def test_a_live_beat_pages_nobody(tmp_path, notify):
    cache(tmp_path / "cache.db", [("beat", 3, "message")])
    srv = notify()
    assert run(build(tmp_path, srv)).returncode == 0
    assert srv.posts == [] and state(tmp_path)["state"] == {"metrics": "ok"}


def test_silence_pages_once_at_urgent_priority_and_the_return_pages_once(tmp_path, notify):
    db = cache(tmp_path / "cache.db", [("beat", 40, "message")])
    srv = notify()
    script = build(tmp_path, srv)
    r = run(script)
    assert r.returncode == 0, r.stderr
    ((path, headers, body),) = srv.posts
    assert path == "/alerts" and headers["Priority"] == "5"
    assert headers["Title"] == "DEAD-MAN: metrics silent on notify"
    assert "last heartbeat 40 min ago" in body and "limit 15 min" in body
    assert headers["Authorization"] == "Bearer " + TOKEN
    assert run(script).returncode == 0 and len(srv.posts) == 1  # the same silence: no second page
    c = sqlite3.connect(db)
    c.execute("INSERT INTO messages VALUES ('beat', ?, 'message')", (NOW,))
    c.commit()
    c.close()
    assert run(script).returncode == 0 and len(srv.posts) == 2
    assert srv.posts[1][1]["Title"] == "dead-man: metrics is back on notify"
    assert run(script).returncode == 0 and len(srv.posts) == 2


def test_other_topics_and_keepalive_events_are_not_the_heartbeat(tmp_path, notify):
    cache(tmp_path / "cache.db", [("other", 1, "message"), ("beat", 1, "keepalive")])
    srv = notify()
    assert run(build(tmp_path, srv)).returncode == 0
    assert srv.posts == []  # not yet: counted from arming, which is now
    st = state(tmp_path)
    st["armed"]["metrics"] -= 3600  # armed an hour ago and never heard from
    (tmp_path / "state" / "state.json").write_text(json.dumps(st))
    assert run(build(tmp_path, srv)).returncode == 0
    assert "no heartbeat seen" in srv.posts[0][2]


def test_a_failed_page_is_not_recorded_and_is_retried(tmp_path, notify):
    cache(tmp_path / "cache.db", [("beat", 40, "message")])
    srv = notify(status=503)
    script = build(tmp_path, srv)
    r = run(script)
    assert r.returncode == 2 and "page not sent" in r.stderr and TOKEN not in r.stdout + r.stderr
    assert state(tmp_path)["state"] == {}  # owed
    srv.status = 200
    assert run(script).returncode == 0 and state(tmp_path)["state"] == {"metrics": "stale"}


def test_a_stopped_servers_wal_cache_is_read_without_creating_files(tmp_path, notify):
    """The watch runs as root: opening a WAL-mode cache whose server is not running would create
    a root-owned -wal/-shm the server's own user could not open at its next start."""
    db = cache(tmp_path / "cache.db", [("beat", 3, "message")])
    c = sqlite3.connect(db)
    c.execute("PRAGMA journal_mode=wal")
    c.close()
    srv = notify()
    script = build(tmp_path, srv)
    before = sorted(p.name for p in tmp_path.iterdir())
    assert run(script).returncode == 0 and srv.posts == []
    assert sorted(p.name for p in tmp_path.iterdir() if p.name != "state") == [
        n for n in before if n != "state"
    ]
    assert not (tmp_path / "cache.db-wal").exists() and not (tmp_path / "cache.db-shm").exists()


@pytest.mark.parametrize("what", ["missing", "no table", "wrong columns"])
def test_an_unreadable_cache_is_an_error_not_a_silence(tmp_path, notify, what):
    if what == "no table":
        sqlite3.connect(tmp_path / "cache.db").close()
    elif what == "wrong columns":
        cache(tmp_path / "cache.db", schema="a TEXT, b INT, c TEXT")
    srv = notify()
    r = run(build(tmp_path, srv))
    assert r.returncode == 1 and "nothing judged" in r.stderr
    assert srv.posts == []


# ----------------------------------------------------------------------------- the role


def dvars(tmp_path, **kw):
    v = ntfy_vars(
        tmp_path,
        ntfy_deadman_beats=[BEAT],
        ntfy_unit_dir=str(tmp_path / "units"),
        ntfy_last_run_dir=str(tmp_path / "last-run"),
        ntfy_last_run_group=grp.getgrgid(os.getgid()).gr_name,
        ntfy_last_run_writer=str(tmp_path / "libexec" / "hnx-last-run"),
        ntfy_deadman_script=str(tmp_path / "libexec" / "watch"),
        ntfy_deadman_state_dir=str(tmp_path / "wstate"),
        ntfy_deadman_auth_file=str(tmp_path / "etc" / "auth"),
    )
    v.update(kw)
    return v


FAKE_SYSTEMCTL = r"""
import os, sys
a = sys.argv[1:]
open(LOG, "a").write(" ".join(a) + "\n")
if a[0] == "enable":
    open(STATE + ".enabled", "w").close(); open(STATE + ".active", "w").close()
elif a[0] in ("is-enabled", "is-active"):
    ok = os.path.exists(STATE + (".enabled" if a[0] == "is-enabled" else ".active"))
    print("enabled" if a[0] == "is-enabled" and ok else "active" if ok else "inactive")
    sys.exit(0 if ok else 3)
"""


def test_with_beats_the_script_units_and_owner_only_token_are_installed_and_it_converges(tmp_path):
    systemctl = fake(
        tmp_path / "systemctl",
        FAKE_SYSTEMCTL.replace("LOG", repr(str(tmp_path / "sc.log"))).replace(
            "STATE", repr(str(tmp_path / "sc"))
        ),
    )
    (tmp_path / "units").mkdir()
    v = dvars(tmp_path, ntfy_systemctl_cli=systemctl)
    r = run_role(tmp_path, ROLE, "main", v, env=SECRETS)
    assert r.returncode == 0, r.stdout + r.stderr
    script = tmp_path / "libexec" / "watch"
    assert script.exists() and "BEATS = " in script.read_text() and TOKEN not in script.read_text()
    token = tmp_path / "etc" / "auth"
    assert token.read_text().strip() == TOKEN and oct(token.stat().st_mode & 0o777) == "0o400"
    service = (tmp_path / "units" / "hnx-ntfy-deadman.service").read_text()
    assert "User=" not in service and "--job timer:ntfy/deadman" in service
    assert "ExecStart=/usr/local/libexec/homelabnext/ntfy-deadman-watch\n" in service
    timer = (tmp_path / "units" / "hnx-ntfy-deadman.timer").read_text()
    assert "OnCalendar=*-*-* *:0/5:00 UTC" in timer and "OnBootSec" not in timer
    assert "enable --now hnx-ntfy-deadman.timer" in (tmp_path / "sc.log").read_text()
    again = run_role(tmp_path, ROLE, "main", v, env=SECRETS)
    assert again.returncode == 0, again.stdout + again.stderr
    calls = (tmp_path / "sc.log").read_text().splitlines()
    assert (
        calls.count("enable --now hnx-ntfy-deadman.timer") == 1
    )  # a second run does not re-enable
    assert calls.count("daemon-reload") == 1  # nor reload: the units did not change


def test_without_beats_nothing_of_the_watch_is_installed(tmp_path):
    v = dvars(tmp_path, ntfy_deadman_beats=[])
    r = run_role(tmp_path, ROLE, "main", v, env=SECRETS)
    assert r.returncode == 0, r.stdout + r.stderr
    assert not (tmp_path / "units").exists() and not (tmp_path / "libexec").exists()


BAD = {
    "a limit under twice the interval": [{**BEAT, "max_age_minutes": 9}],
    "a limit over half the cache duration": [{**BEAT, "max_age_minutes": 400}],
    "a bad topic": [{**BEAT, "topic": "has space"}],
    "a bad name": [{**BEAT, "name": "Not A Slug"}],
    "a missing topic": [{"name": "metrics", "max_age_minutes": 15}],
    "a duplicate topic": [BEAT, {**BEAT, "name": "other"}],
    "a duplicate name": [BEAT, {**BEAT, "topic": "other"}],
    "the alert topic itself": [{**BEAT, "topic": "homelabnext-alerts"}],
}


@pytest.mark.parametrize("beats", list(BAD.values()), ids=list(BAD))
def test_a_bad_beat_is_refused_before_anything_is_written(tmp_path, beats):
    r = run_role(tmp_path, ROLE, "main", dvars(tmp_path, ntfy_deadman_beats=beats), env=SECRETS)
    assert r.returncode != 0 and "each dead-man beat needs" in r.stdout + r.stderr
    assert not (tmp_path / "app").exists() and not (tmp_path / "units").exists()


def test_a_topic_the_publisher_may_not_write_is_refused(tmp_path):
    v = dvars(tmp_path, ntfy_publisher_topics=["alerts-*"])
    r = run_role(tmp_path, ROLE, "main", v, env=SECRETS)
    assert r.returncode != 0 and "['beat'] may not be" in r.stdout + r.stderr
    sub = tmp_path / "ok"
    sub.mkdir()
    ok = dvars(sub, ntfy_publisher_topics=["alerts-*", "be*"])
    r = run_role(sub, ROLE, "validate", ok)
    assert r.returncode == 0, r.stdout + r.stderr
