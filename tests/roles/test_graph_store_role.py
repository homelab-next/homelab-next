# SPDX-License-Identifier: Apache-2.0
"""The graph-store module's role (modules/<id>/roles/<role>), run on localhost against fakes (CI is
unprivileged): main renders one unprivileged container through compose_app with no secret in any file and
a second run is ``changed=0``; a reference with no value, or a malformed input or credential, is refused by
name before anything is written; with the container "started" (a fake docker) root's password and every
account are set through the environment of one command, never an argument; health passes against a fake
service and fails on an open API, a refused login or too few nodes; export makes a sealed backup with the
service's own machinery in both modes, refuses one whose counts moved, and prunes by name; restore refuses a
tampered source, a running service and a storage that holds anything, restores an intact one and compares
the count of every form; upgrade refuses an unpinned, foreign or older target."""

from __future__ import annotations

import grp
import json
import os
import pwd
from pathlib import Path

import pytest
import yaml
from rolerun import fake, run_role

from tests.modules.graph_store_module import (
    MID,
    ROLE,
    ROLE_DIR,
    TOOL,
    P,
    defaults,
    env_for,
    ref,
)

ROOT = Path(__file__).resolve().parents[2]
USER = pwd.getpwuid(os.getuid()).pw_name
DEFAULTS = defaults()
VARS = yaml.safe_load((ROLE_DIR / "vars" / "main.yml").read_text())
DEFAULT_IMAGE = DEFAULTS[P + "image"]
REPO = DEFAULT_IMAGE.split("@")[0].rsplit(":", 1)[0]
GUEST = yaml.safe_load((ROOT / "examples" / "services.yml").read_text())["hosts"]["edge-core"][
    "address"
]
ROOT_PW = "Root-fake-" + "x" * 8
PW1, PW2 = "Cti-fake-" + "a" * 9, "Feed-fake-" + "b" * 9
NAME1, NAME2 = "cti-writer", "feed-ingest"
ROOT_ENV = env_for(ref("root-password"))
SECRETS = {
    ROOT_ENV: ROOT_PW,
    "HNX_SECRET_CONSUMER_GRAPH_NAME": NAME1,
    "HNX_SECRET_CONSUMER_GRAPH_PW": PW1,
    "HNX_SECRET_CONSUMER_FEED_NAME": NAME2,
    "HNX_SECRET_CONSUMER_FEED_PW": PW2,
}
USERS = [
    {
        "name_ref": "secret:consumer/graph-name",
        "password_ref": "secret:consumer/graph-pw",
        "roles": ["writer"],
    },
    {
        "name_ref": "secret:consumer/feed-name",
        "password_ref": "secret:consumer/feed-pw",
        "admin": False,
    },
]
ROLES = [{"name": "writer", "rules": ["node", "storm", "!node.del"]}]
COUNTS = {"inet:fqdn": 3, "inet:ipv4": 5, "it:mitre:attack:technique": 2}


def dv(tmp_path: Path, **kw) -> dict:
    """The role's variables for a test: ``kw`` names the role's own variables without their prefix
    (``hnx_`` and ``ansible_`` ones as they are)."""
    v = {
        "logical_id": "graph",
        "dir": str(tmp_path / "app"),
        "owner": USER,
        "group": grp.getgrgid(os.getgid()).gr_name,
        "data_root": str(tmp_path / "data"),
        # the unprivileged test's own ids (the role requires 1 or more): it can chown to no other
        "uid": os.getuid(),
        "gid": os.getgid(),
        "users": USERS,
        "roles": ROLES,
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


def test_main_renders_one_narrow_unprivileged_container_with_no_secret_in_any_file(tmp_path):
    v = dv(tmp_path)
    r = run_role(tmp_path, str(ROLE_DIR), "main", v, env=SECRETS)
    assert r.returncode == 0, r.stdout + r.stderr
    doc = compose(tmp_path)
    assert sorted(doc["services"]) == ["app"]
    app = doc["services"]["app"]
    assert app["image"] == DEFAULT_IMAGE and "@sha256:" in app["image"]
    assert app["user"] == f"{os.getuid()}:{os.getgid()}"
    assert app["cap_drop"] == ["ALL"] and "cap_add" not in app
    assert app["security_opt"] == ["no-new-privileges:true"] and "privileged" not in app
    assert app["ports"] == [GUEST + ":4443:4443"]
    root = str(tmp_path / "data")
    assert set(app["volumes"]) == {f"{root}/storage:/vertex/storage", f"{root}/export:/hnx-export"}
    assert app["environment"] == {
        "SYN_CORTEX_HTTPS": "4443",
        "SYN_CORTEX_BACKUP_DIR": "/hnx-export/backups",
    }
    assert "healthcheck" in app and "synapse.tools.service.healthcheck" in json.dumps(
        app["healthcheck"]
    )
    secrets = [ROOT_PW, NAME1, NAME2, PW1, PW2]
    for p in (q for q in tmp_path.rglob("*") if q.is_file() and q.name != "vars.json"):
        if p.parent == tmp_path and p.name.startswith(("play", "vars")):
            continue
        assert not [s for s in secrets if s in p.read_text(errors="ignore")], p
    for sub, mode in (("storage", "0o700"), ("export", "0o700"), ("export/backups", "0o700")):
        assert oct((tmp_path / "data" / sub).stat().st_mode & 0o777) == mode
    again = run_role(tmp_path, str(ROLE_DIR), "main", v, env=SECRETS)
    assert again.returncode == 0 and "changed=0" in again.stdout, again.stdout


def test_a_telepath_listener_is_data_and_needs_a_name(tmp_path):
    v = dv(tmp_path, telepath_port=27492, telepath_hostname="graph.example.internal")
    assert run_role(tmp_path, str(ROLE_DIR), "main", v, env=SECRETS).returncode == 0
    app = compose(tmp_path)["services"]["app"]
    listen = app["environment"]["SYN_CORTEX_DMON_LISTEN"]
    assert listen.startswith("ssl://") and listen.endswith(":27492?hostname=graph.example.internal")
    assert app["ports"] == [GUEST + ":4443:4443", GUEST + ":27492:27492"]


def test_the_containers_join_the_role_slice_the_module_play_names(tmp_path):
    v = dv(tmp_path, hnx_module_slice=f"hnx-{ROLE}-server.slice")
    assert run_role(tmp_path, str(ROLE_DIR), "main", v, env=SECRETS).returncode == 0
    assert compose(tmp_path)["services"]["app"]["cgroup_parent"] == f"hnx-{ROLE}-server.slice"


BAD = [
    ({"logical_id": "Graph"}, "registry id"),
    ({"image": REPO + ":v2.247.0"}, "pinned by tag and digest"),
    ({"image": REPO + ":latest@sha256:" + "a" * 64}, "pinned by tag and digest"),
    ({"bind": "0.0.0.0"}, "not all interfaces"),
    ({"bind": "graph.example.internal"}, "not all interfaces"),
    ({"https_port": 0}, "a port"),
    ({"telepath_port": 4443}, "other than the HTTPS one"),
    ({"telepath_port": 27492}, "host name"),
    ({"data_root": "/srv"}, "canonical directories"),
    ({"data_root": "/var/lib/../etc/x"}, "canonical directories"),
    ({"root_login_ref": "not-a-ref"}, "root password reference"),
    ({"roles": "x"}, "Validation of arguments failed"),
    ({"roles": [{"name": "w"}]}, "roles that are mappings"),
    ({"roles": [{"name": "w", "rules": ["Not A Rule"]}]}, "roles that are mappings"),
    ({"roles": [{"name": "w", "rules": [], "x": 1}]}, "roles that are mappings"),
    ({"roles": [ROLES[0], ROLES[0]]}, "roles that are mappings"),
    ({"users": "x"}, "Validation of arguments failed"),
    ({"users": [{"name_ref": "secret:a/b"}]}, "accounts that are mappings"),
    ({"users": [{**USERS[0], "extra": 1}]}, "accounts that are mappings"),
    ({"users": [{**USERS[0], "roles": ["nobody"]}]}, "accounts that are mappings"),
    ({"users": [{**USERS[0], "name_ref": "not-a-ref"}]}, "distinct secret"),
    ({"users": [USERS[0], USERS[0]]}, "distinct secret"),
    ({"mem_limit": "lots"}, "memory limit"),
    ({"export_mode": "fast"}, "must be one of: live, offline"),
    ({"export_keep": 0}, "keep of 1 or more"),
]


@pytest.mark.parametrize(("over", "why"), BAD, ids=[str(i) for i in range(len(BAD))])
def test_main_refuses_bad_inputs_and_writes_nothing(tmp_path, over, why):
    r = run_role(tmp_path, str(ROLE_DIR), "main", dv(tmp_path, **over), env=SECRETS)
    assert r.returncode != 0 and why in r.stdout + r.stderr, r.stdout + r.stderr
    assert not (tmp_path / "app").exists() and not (tmp_path / "data").exists()


@pytest.mark.parametrize(
    "missing", [ROOT_ENV, "HNX_SECRET_CONSUMER_GRAPH_NAME", "HNX_SECRET_CONSUMER_FEED_PW"]
)
def test_a_reference_with_no_value_is_named_and_nothing_is_written(tmp_path, missing):
    env = {k: v for k, v in SECRETS.items() if k != missing}
    r = run_role(tmp_path, str(ROLE_DIR), "main", dv(tmp_path), env=env)
    out = r.stdout + r.stderr
    want = {
        ROOT_ENV: ref("root-password"),
        "HNX_SECRET_CONSUMER_GRAPH_NAME": "secret:consumer/graph-name",
        "HNX_SECRET_CONSUMER_FEED_PW": "secret:consumer/feed-pw",
    }[missing]
    assert r.returncode != 0 and want in out, out
    assert not (tmp_path / "app").exists() and not (tmp_path / "data").exists()
    assert not [s for s in [ROOT_PW, NAME1, NAME2, PW1, PW2] if s in out]


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("HNX_SECRET_CONSUMER_GRAPH_PW", "short"),
        ("HNX_SECRET_CONSUMER_GRAPH_PW", "has space " + "x" * 12),
        (ROOT_ENV, "sh" * 4),
        ("HNX_SECRET_CONSUMER_GRAPH_NAME", "bad name"),
        ("HNX_SECRET_CONSUMER_GRAPH_NAME", "root"),  # root is the service's own account
        ("HNX_SECRET_CONSUMER_GRAPH_NAME", NAME2),  # one name twice
        ("HNX_SECRET_CONSUMER_FEED_PW", PW1),  # one password twice
        ("HNX_SECRET_CONSUMER_GRAPH_PW", ROOT_PW),  # root's password reused
    ],
)
def test_a_malformed_or_repeated_credential_is_refused(tmp_path, name, value):
    r = run_role(tmp_path, str(ROLE_DIR), "main", dv(tmp_path), env={**SECRETS, name: value})
    out = r.stdout + r.stderr
    assert r.returncode != 0, out
    assert not (tmp_path / "app").exists()
    if (
        value != "root"
    ):  # the word is in the output anyway; every other value is never printed, even one that was refused
        assert value not in out


def test_readiness_passes_with_every_reference_and_names_a_missing_one(tmp_path):
    ok = run_role(tmp_path, str(ROLE_DIR), "credentials", dv(tmp_path), env=SECRETS)
    assert ok.returncode == 0, ok.stdout + ok.stderr
    env = {k: v for k, v in SECRETS.items() if k != "HNX_SECRET_CONSUMER_GRAPH_PW"}
    bad = run_role(tmp_path, str(ROLE_DIR), "credentials", dv(tmp_path), env=env)
    assert bad.returncode != 0 and "secret:consumer/graph-pw" in bad.stdout + bad.stderr


# ----------------------------------------------------------------------------- a fake docker

SLAB = b"slab-bytes" * 100


def _docker(tmp_path: Path, health: str = "healthy") -> dict:
    """A fake docker.  ``compose ps`` lists the service in ``health``; ``ps -q --status running`` prints an id
    while ``running`` exists.  ``exec`` answers by the script it is asked to run: the probe (prints the
    contents of ``probe``, default ``HNX-PROBE ok``; fails unless that is ok; logs whether the logins
    reached its environment), the accounts' (logs the names of the environment variables only; prints the
    contents of ``auth``, default one creation), and the counts (the first line of ``counts-seq`` when it
    exists, else ``counts``).  The service's own backup (livebackup, or the offline tool in a one-off
    container) makes a service directory under the backups directory.  Every call is logged."""
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    rows = json.dumps({"Service": "app", "State": "running", "Health": health}) + "\n"
    body = f"""
import json, os, sys
a = sys.argv[1:]
open({str(tmp_path / "docker.log")!r}, "a").write(" ".join(a).replace(chr(10), " ") + "\\n")
T = {str(tmp_path)!r}
def read(name, default):
    p = T + "/" + name
    return open(p).read() if os.path.exists(p) else default
def make_backup(path):
    for rel, data in (("cell.guid", b"guid-1"), ("slabs/cell.lmdb/data.mdb", {SLAB!r}), ("layers/l1/data.mdb", b"layer")):
        os.makedirs(os.path.dirname(os.path.join(path, rel)), exist_ok=True)
        open(os.path.join(path, rel), "wb").write(data)
if "ps" in a and "-q" in a:
    sys.stdout.write("abc123\\n" if os.path.exists(T + "/running") else "")
elif "ps" in a:
    sys.stdout.write({rows!r})
elif "exec" in a:
    code = a[-1]
    if "HNX-PROBE" in code:
        logins = os.environ.get("HNX_LOGINS", "[]")
        open(T + "/probe.log", "a").write("logins=" + str(len(json.loads(logins))) + " port=" + os.environ.get("HNX_PORT", "") + "\\n")
        out = read("probe", "HNX-PROBE ok").strip()
        sys.stdout.write(out + "\\n")
        sys.exit(0 if out == "HNX-PROBE ok" else 1)
    elif "HNX-AUTH" in code:
        spec = json.loads(os.environ["HNX_SPEC"])
        open(T + "/auth.log", "a").write("roles=" + str(len(spec["roles"])) + " users=" + str(len(spec["users"])) + " root=" + str(bool(spec["root"]["passwd"])) + "\\n")
        sys.stdout.write(read("auth", "HNX-AUTH user-created 1\\nHNX-AUTH done 1\\n"))
    elif "HNX-COUNTS" in code:
        seq = T + "/counts-seq"
        if os.path.exists(seq):
            lines = open(seq).read().splitlines()
            line, rest = lines[0], lines[1:]
            open(seq, "w").write("\\n".join(rest) + ("\\n" if rest else ""))
            if not rest: os.unlink(seq)
        else:
            line = read("counts", {json.dumps(COUNTS)!r}).strip()
        sys.stdout.write("HNX-COUNTS " + line + "\\n")
    elif "synapse.tools.service.livebackup" in a:
        if os.path.exists(T + "/livebackup.fails"): sys.exit(1)
        make_backup({str(tmp_path / "data" / "export" / "backups")!r} + "/" + a[a.index("--name") + 1])
elif "run" in a:
    make_backup({str(tmp_path / "data" / "export")!r} + a[-1][len("/hnx-export"):])
sys.exit(0)
"""
    fake(bindir / "docker", body)
    return {"PATH": f"{bindir}:{os.environ['PATH']}"}


def _calls(tmp_path: Path) -> list[str]:
    log = tmp_path / "docker.log"
    return log.read_text().splitlines() if log.exists() else []


def _live(tmp_path, **kw):
    return dv(tmp_path, start=True, ready_timeout=10, **kw)


def test_main_starts_waits_for_the_active_service_and_sets_every_account_through_the_environment(
    tmp_path,
):
    env = {**SECRETS, **_docker(tmp_path)}
    r = run_role(tmp_path, str(ROLE_DIR), "main", _live(tmp_path), env=env)
    assert r.returncode == 0, r.stdout + r.stderr
    calls = _calls(tmp_path)
    assert any("--remove-orphans" in c for c in calls)  # compose_app started it
    assert "logins=0 port=4443" in (tmp_path / "probe.log").read_text()
    assert (tmp_path / "auth.log").read_text() == "roles=1 users=2 root=True\n"
    seeding = [c for c in calls if "HNX-AUTH" in c]
    assert len(seeding) == 1 and "-e HNX_SPEC app python -c" in seeding[0]
    for secret in (ROOT_PW, NAME1, NAME2, PW1, PW2):  # in no argument of any command
        assert not [c for c in calls if secret in c]
    assert "changed=" in r.stdout


def test_a_service_that_never_becomes_active_stops_main(tmp_path):
    (tmp_path / "probe").write_text("HNX-PROBE inactive")
    r = run_role(
        tmp_path, str(ROLE_DIR), "main", _live(tmp_path), env={**SECRETS, **_docker(tmp_path)}
    )
    assert r.returncode != 0
    assert not (tmp_path / "auth.log").exists()  # no account is touched on a service that is not up


def test_a_second_run_that_changes_nothing_reports_changed_zero_for_the_accounts(tmp_path):
    (tmp_path / "auth").write_text("HNX-AUTH done 0\n")
    env = {**SECRETS, **_docker(tmp_path)}
    run_role(tmp_path, str(ROLE_DIR), "main", _live(tmp_path), env=env)
    again = run_role(tmp_path, str(ROLE_DIR), "main", _live(tmp_path), env=env)
    assert again.returncode == 0 and "changed=0" in again.stdout, again.stdout


def test_a_script_that_names_no_final_line_is_a_failure(tmp_path):
    (tmp_path / "auth").write_text("HNX-AUTH user-created 1\n")
    r = run_role(
        tmp_path, str(ROLE_DIR), "main", _live(tmp_path), env={**SECRETS, **_docker(tmp_path)}
    )
    assert r.returncode != 0


# ----------------------------------------------------------------------------- health


def test_health_passes_and_signs_every_account_in(tmp_path):
    env = {**SECRETS, **_docker(tmp_path)}
    r = run_role(tmp_path, str(ROLE_DIR), "health", _live(tmp_path, expected_min_nodes=10), env=env)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "logins=3 port=4443" in (tmp_path / "probe.log").read_text()  # root and the two accounts
    for secret in (ROOT_PW, PW1, PW2):
        assert not [c for c in _calls(tmp_path) if secret in c]


@pytest.mark.parametrize(
    "probe", ["HNX-PROBE open 200", "HNX-PROBE login [1]", "HNX-PROBE inactive"]
)
def test_health_fails_on_an_open_api_a_refused_login_or_an_inactive_service(tmp_path, probe):
    (tmp_path / "probe").write_text(probe)
    r = run_role(
        tmp_path, str(ROLE_DIR), "health", _live(tmp_path), env={**SECRETS, **_docker(tmp_path)}
    )
    assert r.returncode != 0


def test_health_fails_when_the_graph_holds_fewer_nodes_than_expected(tmp_path):
    r = run_role(
        tmp_path,
        str(ROLE_DIR),
        "health",
        _live(tmp_path, expected_min_nodes=11),
        env={**SECRETS, **_docker(tmp_path)},
    )
    assert r.returncode != 0 and "fewer nodes" in r.stdout + r.stderr


def test_health_fails_on_an_unhealthy_container(tmp_path):
    r = run_role(
        tmp_path,
        str(ROLE_DIR),
        "health",
        _live(tmp_path),
        env={**SECRETS, **_docker(tmp_path, "unhealthy")},
    )
    assert r.returncode != 0


# ----------------------------------------------------------------------------- export


def _backups(tmp_path: Path) -> list[Path]:
    d = tmp_path / "data" / "export" / "backups"
    return sorted(p for p in d.iterdir() if p.is_dir()) if d.exists() else []


def _tool(*args: str, stdin: str = "") -> object:
    import subprocess
    import sys

    return subprocess.run(
        [sys.executable, "-I", str(TOOL), *args], capture_output=True, text=True, input=stdin
    )


def test_export_live_asks_the_service_for_its_own_backup_counts_before_and_after_and_seals_it(
    tmp_path,
):
    env = {**SECRETS, **_docker(tmp_path)}
    r = run_role(tmp_path, str(ROLE_DIR), "export", _live(tmp_path), env=env)
    assert r.returncode == 0, r.stdout + r.stderr
    (b,) = _backups(tmp_path)
    assert b.name.startswith("hnx-") and (b / "hnx-manifest.json").is_file()
    m = json.loads((b / "hnx-manifest.json").read_text())
    assert m["counts_before"] == m["counts_after"] == COUNTS
    assert m["mode"] == "live" and m["version"] == "v2.247.0" and m["image"] == DEFAULT_IMAGE
    assert _tool("check", str(b)).returncode == 0  # what the export sealed is what restore accepts
    calls = _calls(tmp_path)
    live = [c for c in calls if "synapse.tools.service.livebackup" in c]
    assert len(live) == 1 and f"--name {b.name}" in live[0]
    assert not [c for c in calls if " stop " in c]  # no stop in live mode


def test_export_refuses_a_backup_taken_while_the_graph_was_changing(tmp_path):
    seq = json.dumps(COUNTS) + "\n" + json.dumps({**COUNTS, "inet:ipv4": 6}) + "\n"
    (tmp_path / "counts-seq").write_text(seq)
    r = run_role(
        tmp_path, str(ROLE_DIR), "export", _live(tmp_path), env={**SECRETS, **_docker(tmp_path)}
    )
    assert r.returncode != 0 and "changed while the backup was taken" in r.stdout + r.stderr
    assert (
        _backups(tmp_path) == []
    )  # the unsealed directory was discarded, nothing is left to fill the disk


def test_export_refuses_an_empty_graph(tmp_path):
    (tmp_path / "counts").write_text("{}")
    r = run_role(
        tmp_path, str(ROLE_DIR), "export", _live(tmp_path), env={**SECRETS, **_docker(tmp_path)}
    )
    assert r.returncode != 0


def test_a_failed_backup_leaves_the_previous_sealed_one_alone(tmp_path):
    env = {**SECRETS, **_docker(tmp_path)}
    assert run_role(tmp_path, str(ROLE_DIR), "export", _live(tmp_path), env=env).returncode == 0
    (first,) = _backups(tmp_path)
    (tmp_path / "livebackup.fails").write_text("")
    bad = run_role(tmp_path, str(ROLE_DIR), "export", _live(tmp_path), env=env)
    assert bad.returncode != 0
    assert (
        _backups(tmp_path) == [first] and _tool("check", str(first)).returncode == 0
    )  # and no partial one beside it


def test_export_offline_stops_runs_the_offline_tool_and_starts_the_service_again_even_on_failure(
    tmp_path,
):
    env = {**SECRETS, **_docker(tmp_path)}
    r = run_role(tmp_path, str(ROLE_DIR), "export", _live(tmp_path, export_mode="offline"), env=env)
    assert r.returncode == 0, r.stdout + r.stderr
    (b,) = _backups(tmp_path)
    assert json.loads((b / "hnx-manifest.json").read_text())["mode"] == "offline"
    order = [
        c
        for c in _calls(tmp_path)
        if " stop " in c or "synapse.tools.service.backup" in c or "up -d" in c
    ]
    assert [
        ("stop" if " stop " in c else "backup" if "service.backup" in c else "up") for c in order
    ][-3:] == ["stop", "backup", "up"]
    run = next(c for c in _calls(tmp_path) if "service.backup" in c)
    assert (
        "--no-deps" in run and "/vertex/storage" in run and f"/hnx-export/backups/{b.name}" in run
    )


def test_export_prunes_only_the_oldest_sealed_beyond_the_keep(tmp_path):
    env = {**SECRETS, **_docker(tmp_path)}
    old = tmp_path / "data" / "export" / "backups"
    old.mkdir(parents=True)
    for i in (1, 2):
        d = old / f"hnx-2026110{i}T000000Z"
        (d / "slabs").mkdir(parents=True)
        (d / "cell.guid").write_text("g")
        (d / "slabs" / "data.mdb").write_bytes(b"x")
        assert (
            _tool(
                "seal",
                str(d),
                stdin=json.dumps(
                    {"counts_before": COUNTS, "counts_after": COUNTS, "version": "v2.247.0"}
                ),
            ).returncode
            == 0
        )
    keep_me = old / "operators-notes"
    keep_me.mkdir()
    r = run_role(tmp_path, str(ROLE_DIR), "export", _live(tmp_path, export_keep=2), env=env)
    assert r.returncode == 0, r.stdout + r.stderr
    names = [p.name for p in _backups(tmp_path)]
    assert len(names) == 3 and "hnx-20261101T000000Z" not in names and "operators-notes" in names
    assert "hnx-20261102T000000Z" in names


# ----------------------------------------------------------------------------- restore


def _source(tmp_path: Path, counts=COUNTS) -> Path:
    src = tmp_path / "src" / "backups" / "hnx-20261120T000000Z"
    for rel, data in (
        ("cell.guid", b"guid-1"),
        ("slabs/cell.lmdb/data.mdb", SLAB),
        ("layers/l1/data.mdb", b"layer"),
    ):
        (src / rel).parent.mkdir(parents=True, exist_ok=True)
        (src / rel).write_bytes(data)
    m = {"counts_before": counts, "counts_after": counts, "version": "v2.247.0", "mode": "live"}
    assert _tool("seal", str(src), stdin=json.dumps(m)).returncode == 0
    return src


def _restore(tmp_path: Path, src: Path, **kw):
    v = dv(tmp_path, start=True, ready_timeout=10, restore_source=str(src), **kw)
    return run_role(tmp_path, str(ROLE_DIR), "restore", v, env={**SECRETS, **_docker(tmp_path)})


def test_restore_puts_the_listed_files_in_place_compares_every_forms_count_and_sets_the_accounts(
    tmp_path,
):
    src = _source(tmp_path)
    r = _restore(tmp_path, src)
    assert r.returncode == 0, r.stdout + r.stderr
    storage = tmp_path / "data" / "storage"
    assert sorted(str(p.relative_to(storage)) for p in storage.rglob("*") if p.is_file()) == [
        "cell.guid", "layers/l1/data.mdb", "slabs/cell.lmdb/data.mdb",
    ]  # fmt: skip
    assert (storage / "slabs" / "cell.lmdb" / "data.mdb").read_bytes() == SLAB
    assert not (tmp_path / "data" / "storage.restoring").exists()
    assert (src / "cell.guid").exists()  # the source is untouched
    assert (
        tmp_path / "auth.log"
    ).exists()  # root's password and the accounts were made after the counts matched
    calls = _calls(tmp_path)
    assert [c for c in calls if "--wait-timeout" in c]


def test_restore_refuses_a_tampered_source_and_writes_nothing(tmp_path):
    src = _source(tmp_path)
    (src / "cell.guid").write_bytes(b"tampered")
    r = _restore(tmp_path, src)
    assert r.returncode != 0
    assert (
        not list((tmp_path / "data" / "storage").iterdir())
        and not (tmp_path / "data" / "storage.restoring").exists()
    )


def test_restore_refuses_a_backup_whose_counts_moved_or_are_empty(tmp_path):
    src = _source(tmp_path)
    m = json.loads((src / "hnx-manifest.json").read_text())
    m["counts_after"] = {**COUNTS, "inet:ipv4": 6}
    (src / "hnx-manifest.json").write_text(json.dumps(m))
    assert _restore(tmp_path, src).returncode != 0


def test_restore_refuses_a_running_service(tmp_path):
    src = _source(tmp_path)
    (tmp_path / "running").write_text("")
    r = _restore(tmp_path, src)
    assert r.returncode != 0 and "is running" in r.stdout + r.stderr
    assert not list((tmp_path / "data" / "storage").iterdir())


def test_restore_never_merges_into_or_overwrites_a_graph(tmp_path):
    src = _source(tmp_path)
    storage = tmp_path / "data" / "storage"
    storage.mkdir(parents=True)
    (storage / "cell.guid").write_text("an existing graph")
    r = _restore(tmp_path, src)
    assert r.returncode != 0 and "never merges" in r.stdout + r.stderr
    assert (storage / "cell.guid").read_text() == "an existing graph"


def test_restore_refuses_a_staging_directory_an_earlier_restore_left(tmp_path):
    src = _source(tmp_path)
    (tmp_path / "data" / "storage.restoring").mkdir(parents=True)
    assert _restore(tmp_path, src).returncode != 0


def test_restore_refuses_a_backup_of_a_newer_version_than_the_image(tmp_path):
    src = _source(tmp_path)
    m = json.loads((src / "hnx-manifest.json").read_text())
    m["version"] = "v2.999.0"
    (src / "hnx-manifest.json").write_text(json.dumps(m))
    # the manifest's own hash is part of the listing, so the seal is made again for a newer version
    src2 = tmp_path / "src2" / "backups" / "hnx-20261120T000000Z"
    for rel, data in (("cell.guid", b"guid-1"), ("slabs/cell.lmdb/data.mdb", SLAB)):
        (src2 / rel).parent.mkdir(parents=True, exist_ok=True)
        (src2 / rel).write_bytes(data)
    body = {"counts_before": COUNTS, "counts_after": COUNTS, "version": "v2.999.0"}
    assert _tool("seal", str(src2), stdin=json.dumps(body)).returncode == 0
    r = _restore(tmp_path, src2)
    assert r.returncode != 0 and "newer version" in r.stdout + r.stderr


def test_restore_that_ends_with_different_counts_is_an_error_and_leaves_the_storage(tmp_path):
    src = _source(tmp_path)
    (tmp_path / "counts").write_text(json.dumps({**COUNTS, "inet:fqdn": 2}))
    r = _restore(tmp_path, src)
    assert r.returncode != 0 and "differ from the backup's" in r.stdout + r.stderr
    assert (
        tmp_path / "data" / "storage" / "cell.guid"
    ).exists()  # left for inspection, not removed
    assert not (tmp_path / "auth.log").exists()  # and no account was touched


def test_restore_that_ends_with_an_empty_graph_is_an_error(tmp_path):
    src = _source(tmp_path)
    (tmp_path / "counts").write_text(json.dumps({"inet:fqdn": 0}))
    assert _restore(tmp_path, src).returncode != 0


def test_restore_needs_a_source(tmp_path):
    r = run_role(
        tmp_path,
        str(ROLE_DIR),
        "restore",
        dv(tmp_path, start=True),
        env={**SECRETS, **_docker(tmp_path)},
    )
    assert r.returncode != 0


# ----------------------------------------------------------------------------- backup manifest, upgrade


def test_the_backup_hook_names_the_export_directory_only(tmp_path):
    r = run_role(tmp_path, str(ROLE_DIR), "backup", dv(tmp_path), env=SECRETS)
    assert r.returncode == 0, r.stdout + r.stderr
    doc = json.loads((tmp_path / "app" / "backup-manifest.json").read_text())
    assert doc == {"app": MID, "paths": [str(tmp_path / "data" / "export")]}


def _upgrade(tmp_path, target):
    v = dv(tmp_path)
    if not (tmp_path / "app").exists():
        assert run_role(tmp_path, str(ROLE_DIR), "main", v, env=SECRETS).returncode == 0
    return run_role(
        tmp_path, str(ROLE_DIR), "upgrade", {**v, P + "target_image": target}, env=SECRETS
    )


def test_upgrade_records_a_newer_pinned_target(tmp_path):
    target = REPO + ":v2.248.0@sha256:" + "b" * 64
    r = _upgrade(tmp_path, target)
    assert r.returncode == 0, r.stdout + r.stderr


@pytest.mark.parametrize(
    "target",
    [
        REPO + ":v2.248.0",  # no digest
        "docker.io/other/graphstore:v2.248.0@sha256:" + "b" * 64,  # another repository
        REPO + ":v2.246.9@sha256:" + "b" * 64,  # older
        REPO + ":latest@sha256:" + "b" * 64,
    ],
)
def test_upgrade_refuses_an_unpinned_foreign_or_older_target(tmp_path, target):
    r = _upgrade(tmp_path, target)
    assert r.returncode != 0


def _tasks(doc):
    """Every task of a task file, inside blocks, rescues and always sections too."""
    for task in doc or []:
        yield task
        for key in ("block", "rescue", "always"):
            yield from _tasks(task.get(key))


def test_every_script_run_in_the_container_is_kept_from_the_controllers_variable_expansion():
    """The command module expands ``$NAME`` in its arguments from the task's environment, which would
    put an account's password into the argument list: every task that hands a script to the container
    turns that off."""
    seen = 0
    for path in sorted((ROLE_DIR / "tasks").glob("*.yml")):
        for task in _tasks(yaml.safe_load(path.read_text())):
            cmd = task.get("ansible.builtin.command")
            if (
                isinstance(cmd, dict)
                and "-c" in cmd.get("argv", [])
                and "python" in cmd.get("argv", [])
            ):
                seen += 1
                assert cmd.get("expand_argument_vars") is False, (path.name, task["name"])
    assert seen >= 5
