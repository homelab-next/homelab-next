# SPDX-License-Identifier: Apache-2.0
"""The endpoint-forensics server role (its module's ``roles/<id>_server``), run on localhost against
a stateful stand-in for the container engine (CI is unprivileged):

* main renders one guarded container (the start command never regenerates the configuration), the
  administrator's password only in the 0600 env file, and a second run is ``changed=0``;
* malformed inputs and credentials, and an allow-list that widens the principal, are refused;
* the hunt principal is made once, holds exactly the allow-list's permissions, the server is
  restarted once to read it, and the certificate authority is the same before and after; a restart
  that rotated the authority (the unguarded entrypoint) fails the run (LL-087);
* a recorded authority that differs fails a later run unless the operator accepted it;
* health passes against a well-behaved server and fails on a widened principal, an open ``execve``,
  an open artifact upload, an open GUI and a changed authority;
* export writes a listed tree, restore refuses a tampered one and moves what it replaces aside.
"""

from __future__ import annotations

import grp
import json
import os
import pwd
import shutil
import stat
from pathlib import Path

import pytest
import yaml
from rolerun import fake, first_run, run_role

from homelabnext.modules import loader as ld
from tests.modules.endpoint_forensics_module import (
    MID,
    SERVER,
    SP,
    env_for,
    ref,
    server_defaults,
)
from tests.modules.endpoint_forensics_script import catalog_doc, catalog_names
from tests.roles.endpoint_forensics_docker import body

ROOT = Path(__file__).resolve().parents[2]
USER = pwd.getpwuid(os.getuid()).pw_name
GROUP = grp.getgrgid(os.getgid()).gr_name
GUEST = ld.load_yaml(ROOT / "examples" / "services.yml")["hosts"]["dns-core"]["address"]
HOSTNAME = "frontend.example.internal"
PASSWORD = "admin-password-fake"
SECRETS = {env_for(ref("admin-password")): PASSWORD}
ROLE = str(SERVER)

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


def sv(tmp_path: Path, **kw) -> dict:
    v = {
        f"{SP}logical_id": "endpoint-forensics",
        f"{SP}frontend_hostname": HOSTNAME,
        "ansible_host": GUEST,
        f"{SP}dir": str(tmp_path / "app"),
        f"{SP}data_root": str(tmp_path / "data"),
        f"{SP}owner": USER,
        f"{SP}group": GROUP,
        f"{SP}uid": os.getuid(),
        f"{SP}gid": os.getgid(),
        f"{SP}client_config_group": GROUP,
        f"{SP}results_group": GROUP,
        f"{SP}start": False,
        f"{SP}validate_with_docker": False,
        f"{SP}unit_dir": str(tmp_path / "units"),
        f"{SP}last_run_dir": str(tmp_path / "last-run"),
        f"{SP}last_run_group": GROUP,
        f"{SP}last_run_writer": str(tmp_path / "libexec" / "hnx-last-run"),
        f"{SP}script": str(tmp_path / "libexec" / "cycle"),
        f"{SP}check_script": str(tmp_path / "libexec" / "check"),
        f"{SP}config_dir": str(tmp_path / "etc"),
        f"{SP}config_file": str(tmp_path / "etc" / "config.json"),
        f"{SP}catalog_file": str(tmp_path / "etc" / "catalog.yml"),
    }
    v.update(kw)
    return v


def tools(tmp_path: Path, **env) -> dict:
    """The fake engine and fake systemctl on the PATH and in the role's variables' reach."""
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    fake(bindir / "docker", body())
    sc = fake(
        bindir / "systemctl",
        FAKE_SYSTEMCTL.replace("LOG", repr(str(tmp_path / "sc.log"))).replace(
            "STATE", repr(str(tmp_path / "sc"))
        ),
    )
    (tmp_path / "units").mkdir(exist_ok=True)
    return {
        "PATH": f"{bindir}:{os.environ['PATH']}",
        "FAKE_STATE": str(tmp_path / "engine.json"),
        "FAKE_ETC": str(tmp_path / "data" / "etc"),
        "FAKE_HOST": HOSTNAME,
        "FAKE_SERVICE": MID,
        "FAKE_ARTIFACTS": ",".join(catalog_names()),
        "SYSTEMCTL": sc,
        **env,
    }


def live_vars(tmp_path: Path, env: dict, **kw) -> dict:
    return sv(tmp_path, **{f"{SP}start": True, f"{SP}systemctl_cli": env["SYSTEMCTL"], **kw})


def engine(tmp_path: Path) -> dict:
    return json.loads((tmp_path / "engine.json").read_text())


def run(tmp_path, hook, v, env):
    return run_role(tmp_path, ROLE, hook, v, env={**SECRETS, **env})


def _first_main_renders_the_guarded_server_with_the_credential_only_in_the_env_file(tmp_path):
    env = tools(tmp_path)
    v = sv(tmp_path, **{f"{SP}systemctl_cli": env["SYSTEMCTL"]})
    return {"role": ROLE, "tasks_from": "main", "extra_vars": v, "env": {**SECRETS, **env},
            "setup": {"v": v, "env": env}}  # fmt: skip


@first_run(_first_main_renders_the_guarded_server_with_the_credential_only_in_the_env_file)
def test_main_renders_the_guarded_server_with_the_credential_only_in_the_env_file(first):
    r, tmp_path = first
    v, env = first.setup["v"], first.setup["env"]
    assert r.returncode == 0, r.stdout + r.stderr
    text = (tmp_path / "app" / "docker-compose.yml").read_text()
    svc = yaml.safe_load(text)["services"][MID]
    assert svc["image"] == server_defaults()[f"{SP}image"]
    assert svc["user"] == f"{os.getuid()}:{os.getgid()}"
    assert svc["cap_drop"] == ["ALL"] and svc["security_opt"] == ["no-new-privileges:true"]
    # LL-087: the stock entrypoint (which regenerates the configuration) runs only when there is none
    cmd = svc["command"]
    assert cmd[:2] == ["/bin/sh", "-c"] and "-s /etc/" in cmd[2] and cmd[2].count("entrypoint") == 1
    assert "then exec" in cmd[2] and "else exec /bin/sh /bin/entrypoint" in cmd[2]
    assert svc["ports"] == [f"{GUEST}:8000:8000", f"{GUEST}:8890:8889"]
    assert svc["volumes"] == [
        f"{tmp_path}/data/etc:/etc/{MID}",
        f"{tmp_path}/data/datastore:/datastore",
        f"{tmp_path}/data/custom_artifacts:/custom_artifacts:ro",
    ]
    env_ = svc["environment"]
    assert env_[f"{MID.upper()}_HOSTNAME"] == HOSTNAME
    assert env_[f"{MID.upper()}_NO_INITIALIZE"] == "true"  # no tool is downloaded
    assert PASSWORD not in text
    secrets = tmp_path / "app" / "secrets" / f"{MID}.env"
    assert f"{MID.upper()}_INITIAL_ADMIN_PASSWORD='{PASSWORD}'" in secrets.read_text()
    assert oct(secrets.stat().st_mode & 0o777) == "0o600"
    for sub, mode in (("etc", "0o700"), ("datastore", "0o700"), ("results/hunts", "0o2750"),
                      ("client", "0o750"), ("state", "0o700"), ("custom_artifacts", "0o755")):  # fmt: skip
        assert oct((tmp_path / "data" / sub).stat().st_mode & 0o7777) == mode, sub
    art = tmp_path / "data" / "custom_artifacts"
    assert [p.name for p in art.iterdir()] == [
        p.name for p in (SERVER / "files" / "custom_artifacts").iterdir()
    ]
    assert PASSWORD not in r.stdout
    assert (tmp_path / "libexec" / "cycle").stat().st_mode & stat.S_IXUSR
    cfg = json.loads((tmp_path / "etc" / "config.json").read_text())
    assert cfg["service"] == MID and cfg["principal"] == "hnx-hunt" and cfg["min_clients"] == 1
    assert cfg["results_dir"] == f"{tmp_path}/data/results/hunts"
    timer = (tmp_path / "units" / f"hnx-{MID}-server-cycle.timer").read_text()
    assert "OnCalendar=*-*-* *:0/5:00 UTC" in timer and "OnBootSec" not in timer
    service = (tmp_path / "units" / f"hnx-{MID}-server-cycle.service").read_text()
    assert "--job timer:" in service and f"{MID}_server/cycle" in service
    again = run_role(tmp_path, ROLE, "main", v, env={**SECRETS, **env})
    assert again.returncode == 0 and "changed=0" in again.stdout, again.stdout


def _first_main_puts_the_container_in_the_role_slice_the_module_play_names(tmp_path):
    env = tools(tmp_path)
    v = sv(
        tmp_path,
        hnx_module_slice=f"hnx-{MID}-server.slice",
        **{f"{SP}systemctl_cli": env["SYSTEMCTL"]},
    )
    return {"role": ROLE, "tasks_from": "main", "extra_vars": v, "env": {**SECRETS, **env}}


@first_run(_first_main_puts_the_container_in_the_role_slice_the_module_play_names)
def test_main_puts_the_container_in_the_role_slice_the_module_play_names(first):
    r, tmp_path = first
    assert r.returncode == 0, r.stdout + r.stderr
    doc = yaml.safe_load((tmp_path / "app" / "docker-compose.yml").read_text())
    assert doc["services"][MID]["cgroup_parent"] == f"hnx-{MID}-server.slice"


REPO = server_defaults()[f"{SP}image"].split("@")[0].rsplit(":", 1)[0]
BAD = [
    ({f"{SP}image": REPO + ":latest"}, {}),
    ({"ansible_host": "0.0.0.0"}, {}),
    ({"ansible_host": "frontend.example.internal"}, {}),
    ({f"{SP}frontend_hostname": "https://frontend.example.internal"}, {}),  # a URL, not a name
    ({f"{SP}frontend_hostname": ""}, {}),
    ({f"{SP}frontend_hostname": "a b"}, {}),
    ({f"{SP}frontend_port": 8890}, {}),  # both ports the same
    ({f"{SP}hunt_principal": "admin"}, {}),
    ({f"{SP}uid": 0}, {}),
    ({f"{SP}data_root": "/var/lib/../etc"}, {}),
    ({f"{SP}dir": "relative/dir"}, {}),
    ({f"{SP}schedule": "*-*-* *:0/7:00 UTC"}, {}),
    ({f"{SP}stale_after_minutes": 5}, {}),  # under twice the cycle's interval
    ({f"{SP}min_clients": 0}, {}),
    ({}, {env_for(ref("admin-password")): "short"}),
    ({}, {env_for(ref("admin-password")): "has a space in it 12345"}),
]


def _first_main_refuses_bad_inputs_and_credentials(tmp_path, over, env):
    tool_env = tools(tmp_path)
    v = sv(tmp_path, **{f"{SP}systemctl_cli": tool_env["SYSTEMCTL"]}, **over)
    return {
        "role": ROLE,
        "tasks_from": "main",
        "extra_vars": v,
        "env": {**SECRETS, **tool_env, **env},
    }


@pytest.mark.parametrize("over, env", BAD)
@first_run(_first_main_refuses_bad_inputs_and_credentials)
def test_main_refuses_bad_inputs_and_credentials(first, over, env):
    r, tmp_path = first
    assert r.returncode != 0, r.stdout
    assert not (tmp_path / "app" / "docker-compose.yml").exists()
    assert PASSWORD not in r.stdout


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d["principal"]["permissions"].append("EXECVE"),
        lambda d: d["principal"]["permissions"].append("FILESYSTEM_WRITE"),
        lambda d: d["principal"]["permissions"].append("ARTIFACT_WRITER"),
        lambda d: d["principal"]["permissions"].append("SERVER_ADMIN"),
        lambda d: d["artifacts"][0].update(required_permissions=["EXECVE"]),
        lambda d: d["artifacts"].append(dict(d["artifacts"][0])),
    ],
)
def test_an_allow_list_that_widens_the_principal_is_refused_before_anything_is_rendered(
    tmp_path, mutate
):
    role = tmp_path / "role-copy" / f"{MID}_server"
    shutil.copytree(SERVER, role)
    doc = catalog_doc()
    mutate(doc)
    (role / "files" / "baseline-artifacts.yml").write_text(yaml.safe_dump(doc))
    env = tools(tmp_path)
    v = sv(tmp_path, **{f"{SP}systemctl_cli": env["SYSTEMCTL"]})
    r = run_role(tmp_path, str(role), "main", v, env={**SECRETS, **env})
    assert r.returncode != 0 and "allow-list" in (r.stdout + r.stderr)
    assert not (tmp_path / "app" / "docker-compose.yml").exists()


def _first_live_main_makes_the_collect_only_principal_once_and_keeps_the_authority(tmp_path):
    env = tools(tmp_path)
    v = live_vars(tmp_path, env)
    return {"role": ROLE, "tasks_from": "main", "extra_vars": v, "env": {**SECRETS, **env},
            "setup": {"v": v, "env": env}}  # fmt: skip


@first_run(_first_live_main_makes_the_collect_only_principal_once_and_keeps_the_authority)
def test_live_main_makes_the_collect_only_principal_once_and_keeps_the_authority(first):
    r, tmp_path = first
    v, env = first.setup["v"], first.setup["env"]
    assert r.returncode == 0, r.stdout + r.stderr
    st = engine(tmp_path)
    want = {p.lower(): True for p in catalog_doc()["principal"]["permissions"]}
    assert st["principals"]["hnx-hunt"]["policy"] == want
    for banned in ("execve", "filesystem_write", "artifact_writer", "server_admin"):
        assert banned not in st["principals"]["hnx-hunt"]["policy"]
    assert st["restarts"] == 1  # once, to read the account
    api = tmp_path / "data" / "etc" / "hunt.api.config.yaml"
    assert oct(api.stat().st_mode & 0o777) == "0o600"
    client = tmp_path / "data" / "client" / "client.config.yaml"
    text = client.read_text()
    assert HOSTNAME + ":8000" in text and "BEGIN CERTIFICATE" in text
    assert oct(client.stat().st_mode & 0o777) == "0o640"
    recorded = (tmp_path / "data" / "state" / "ca.sha256").read_text().strip()
    assert len(recorded) == 64
    again = run_role(tmp_path, ROLE, "main", v, env={**SECRETS, **env})
    assert again.returncode == 0 and "changed=0" in again.stdout, again.stdout
    assert engine(tmp_path)["restarts"] == 1  # nothing was granted or restarted again


def _first_live_main_fails_when_the_restart_rotated_the_authority(tmp_path):
    env = tools(tmp_path, FAKE_ROTATE="1")
    v = live_vars(tmp_path, env)
    return {"role": ROLE, "tasks_from": "main", "extra_vars": v, "env": {**SECRETS, **env}}


@first_run(_first_live_main_fails_when_the_restart_rotated_the_authority)
def test_live_main_fails_when_the_restart_rotated_the_authority(first):
    r, _tmp = first
    assert r.returncode != 0
    assert "certificate authority changed" in (r.stdout + r.stderr)
    assert "LL-087" in (r.stdout + r.stderr)


def test_a_changed_authority_fails_a_later_run_unless_the_operator_accepted_it(tmp_path):
    env = tools(tmp_path)
    v = live_vars(tmp_path, env)
    assert run(tmp_path, "main", v, env).returncode == 0
    cfg = tmp_path / "data" / "etc" / "server.config.yaml"
    doc = json.loads(cfg.read_text())
    doc["Client"]["ca_certificate"] = doc["Client"]["ca_certificate"].replace("0001", "0777")
    cfg.write_text(json.dumps(doc))
    r = run(tmp_path, "main", v, env)
    assert r.returncode != 0 and "certificate authority changed" in (r.stdout + r.stderr)
    ok = run(tmp_path, "main", {**v, f"{SP}accept_new_ca": True}, env)
    assert ok.returncode == 0, ok.stdout + ok.stderr
    assert run(tmp_path, "main", v, env).returncode == 0  # the new one is the recorded one now


def test_a_principal_that_held_more_is_cut_back_to_the_allow_list(tmp_path):
    env = tools(tmp_path)
    v = live_vars(tmp_path, env)
    assert run(tmp_path, "main", v, env).returncode == 0
    st = engine(tmp_path)
    st["principals"]["hnx-hunt"]["policy"]["execve"] = True
    (tmp_path / "engine.json").write_text(json.dumps(st))
    r = run(tmp_path, "main", v, env)
    assert r.returncode == 0, r.stdout + r.stderr
    st = engine(tmp_path)
    assert "execve" not in st["principals"]["hnx-hunt"]["policy"] and st["restarts"] == 2


# --- health ---------------------------------------------------------------------------------


@pytest.fixture
def healthy(tmp_path):
    env = tools(tmp_path)
    v = live_vars(tmp_path, env)
    r = run(tmp_path, "main", v, env)
    assert r.returncode == 0, r.stdout + r.stderr
    return tmp_path, v, env


def test_health_passes_against_a_well_behaved_server(healthy):
    tmp_path, v, env = healthy
    r = run(tmp_path, "health", v, env)
    assert r.returncode == 0, r.stdout + r.stderr
    assert PASSWORD not in r.stdout


@pytest.mark.parametrize(
    "what, change, why",
    [
        ("an open execve", {"FAKE_EXEC_OPEN": "1"}, "ran a command"),
        ("an open artifact upload", {"FAKE_UPLOAD_OPEN": "1"}, "defined an artifact"),
        ("a GUI that does not ask for a sign-in", {"FAKE_GUI_STATUS": "200"}, "sign-in"),
    ],
)
def test_health_fails_when_the_server_gives_the_principal_or_the_world_too_much(
    healthy, what, change, why
):
    tmp_path, v, env = healthy
    r = run(tmp_path, "health", v, {**env, **change})
    assert r.returncode != 0, what
    assert why in (r.stdout + r.stderr), what


def test_health_fails_on_a_widened_principal_and_on_a_listed_artifact_that_needs_exec(healthy):
    tmp_path, v, env = healthy
    st = engine(tmp_path)
    st["principals"]["hnx-hunt"]["policy"]["filesystem_write"] = True
    (tmp_path / "engine.json").write_text(json.dumps(st))
    r = run(tmp_path, "health", v, env)
    assert r.returncode != 0 and "permissions are" in (r.stdout + r.stderr)
    st["principals"]["hnx-hunt"]["policy"].pop("filesystem_write")
    st["definitions"] = [
        {"name": n, "required_permissions": ["EXECVE"] if i == 0 else [], "implied_permissions": []}
        for i, n in enumerate(catalog_names())
    ]
    (tmp_path / "engine.json").write_text(json.dumps(st))
    r = run(tmp_path, "health", v, env)
    assert r.returncode != 0 and "EXECVE" in (r.stdout + r.stderr)


def test_health_fails_when_the_authority_is_not_the_recorded_one_and_when_a_file_is_loose(healthy):
    tmp_path, v, env = healthy
    cfg = tmp_path / "data" / "etc" / "server.config.yaml"
    keep = cfg.read_text()
    doc = json.loads(keep)
    doc["Client"]["ca_certificate"] = doc["Client"]["ca_certificate"].replace("0001", "0555")
    cfg.write_text(json.dumps(doc))
    r = run(tmp_path, "health", v, env)
    assert r.returncode != 0 and "certificate authority changed" in (r.stdout + r.stderr)
    cfg.write_text(keep)
    cfg.chmod(0o644)
    r = run(tmp_path, "health", v, env)
    assert r.returncode != 0 and "0600" in (r.stdout + r.stderr)


# --- export, restore ----------------------------------------------------------------------------


def test_export_writes_a_listed_tree_and_restore_refuses_a_tampered_one(healthy):
    tmp_path, v, env = healthy
    (tmp_path / "data" / "datastore" / "clients").mkdir()
    (tmp_path / "data" / "datastore" / "clients" / "C.1.json").write_text("{}")
    assert run(tmp_path, "export", v, env).returncode == 0
    (stamped,) = sorted((tmp_path / "data" / "export").iterdir())
    listing = [json.loads(x) for x in (stamped / "listing.jsonl").read_text().splitlines()]
    keys = {r["key"] for r in listing}
    assert "etc/server.config.yaml" in keys and "etc/hunt.api.config.yaml" in keys
    assert "datastore/clients/C.1.json" in keys
    engine_calls = engine(tmp_path)["calls"]
    assert any(c.endswith("stop") for c in engine_calls)
    assert engine_calls[-1].endswith("up -d")  # started again
    bad = tmp_path / "tampered"
    shutil.copytree(stamped, bad)
    (bad / "etc" / "server.config.yaml").write_text("{}")
    r = run(tmp_path, "restore", {**v, f"{SP}restore_source": str(bad)}, env)
    assert r.returncode != 0 and "differs from the listing" in (r.stdout + r.stderr)
    assert "certificate authority changed" not in (r.stdout + r.stderr)
    assert (tmp_path / "data" / "etc" / "server.config.yaml").read_text() != "{}"  # untouched


def test_restore_moves_the_replaced_trees_aside_and_records_the_restored_authority(healthy):
    tmp_path, v, env = healthy
    assert run(tmp_path, "export", v, env).returncode == 0
    (stamped,) = sorted((tmp_path / "data" / "export").iterdir())
    cfg = tmp_path / "data" / "etc" / "server.config.yaml"
    cfg.write_text(json.dumps({"Client": {"ca_certificate": "other"}}))
    r = run(tmp_path, "restore", {**v, f"{SP}restore_source": str(stamped)}, env)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "BEGIN CERTIFICATE" in cfg.read_text()
    asides = [p.name for p in (tmp_path / "data").iterdir() if ".replaced-" in p.name]
    assert sorted(a.split(".replaced-")[0] for a in asides) == [
        "etc"
    ]  # the empty datastore was not populated
    assert (
        run(tmp_path, "health", v, env).returncode == 0
    )  # the restored authority is the recorded one


# --- readiness, upgrade, hooks --------------------------------------------------------------------


def test_readiness_passes_with_an_engine_and_the_credential_and_fails_without_the_credential(
    tmp_path,
):
    env = tools(tmp_path)
    sc = env["SYSTEMCTL"]
    (tmp_path / "sc.active").touch()
    extra = {"docker_engine_systemctl_cli": sc, "docker_engine_cli": str(tmp_path / "bin" / "info")}
    fake(
        Path(extra["docker_engine_cli"]),
        'import sys\nprint(\'{"ServerVersion": "29.0", "ServerErrors": []}\')\n',
    )
    v = sv(tmp_path, **extra)
    ok = run(tmp_path, "readiness", v, env)
    assert ok.returncode == 0, ok.stdout + ok.stderr
    r = run_role(
        tmp_path,
        ROLE,
        "readiness",
        v,
        env=dict(env) | {env_for(ref("admin-password")): "short"},
    )
    assert r.returncode != 0


@pytest.mark.parametrize(
    "target, ok",
    [
        (REPO + ":9.9.9@sha256:" + "a" * 64, True),
        (REPO + ":latest", False),
        ("registry.example.internal/other/server:9.9.9@sha256:" + "a" * 64, False),
    ],
)
def test_upgrade_accepts_only_a_pinned_bump_of_the_same_repository(tmp_path, target, ok):
    env = tools(tmp_path)
    (tmp_path / "app").mkdir()
    v = sv(tmp_path, **{f"{SP}target_image": target})
    r = run(tmp_path, "upgrade", v, env)
    assert (r.returncode == 0) == ok, r.stdout + r.stderr
