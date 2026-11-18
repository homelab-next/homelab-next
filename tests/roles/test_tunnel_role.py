# SPDX-License-Identifier: Apache-2.0
"""Role ``tunnel`` (modules/tunnel/roles/tunnel), run on localhost against fakes (CI is
unprivileged): main renders the connector of a remotely managed tunnel through compose_app with the
token only in the env_file, no ingress configuration, and a second run is ``changed=0``; an empty,
malformed or unset token and bad inputs are refused before anything is rendered; health passes
against a stand-in readiness endpoint and fails with no ready connection or a published port that
is not the guest's."""

from __future__ import annotations

import base64
import json
import os
import pwd
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest
import yaml
from rolerun import fake, first_run, run_role

ROOT = Path(__file__).resolve().parents[2]
ROLE = str(ROOT / "modules" / "tunnel" / "roles" / "tunnel")
USER = pwd.getpwuid(os.getuid()).pw_name
# the guest's address is one the example registry already carries (no literal of our own)
GUEST = yaml.safe_load((ROOT / "examples" / "services.yml").read_text())["hosts"]["edge-core"][
    "address"
]
JOIN_VALUE = base64.b64encode(
    json.dumps(
        {"a": "acct" * 8, "t": "11111111-2222-3333-4444-555555555555", "s": "c2VjcmV0" * 4}
    ).encode()
).decode()
ENV = "HNX_SECRET_TUNNEL_TOKEN"
# the image the role pins by default (read, not repeated): its repository is the only one allowed
IMAGE = yaml.safe_load((Path(ROLE) / "defaults" / "main.yml").read_text())["tunnel_image"]
REPO = IMAGE.split("@")[0].rsplit(":", 1)[0]
SECRETS = {ENV: JOIN_VALUE}


def tunnel_vars(tmp_path: Path, **kw) -> dict:
    v = {
        "tunnel_logical_id": "tunnel",
        "ansible_host": GUEST,
        "tunnel_dir": str(tmp_path / "app"),
        "tunnel_data_root": str(tmp_path / "data"),
        "tunnel_owner": USER,
        "tunnel_group": pwd.getpwuid(os.getuid()).pw_name,
        "tunnel_uid": os.getuid() if os.getuid() >= 1000 else 65532,
        "tunnel_gid": os.getgid() if os.getgid() >= 1000 else 65532,
        "tunnel_sysctl_file": str(tmp_path / "sysctl.conf"),
        "tunnel_sysctl_apply": False,
        "tunnel_start": False,
        "tunnel_validate_with_docker": False,
    }
    v.update(kw)
    return v


def _first_main_renders_a_remotely_managed_connector_with_the_token_only_in_the_env_file(tmp_path):
    v = tunnel_vars(tmp_path)
    return {"role": ROLE, "tasks_from": "main", "extra_vars": v, "env": SECRETS, "setup": {"v": v}}


@first_run(_first_main_renders_a_remotely_managed_connector_with_the_token_only_in_the_env_file)
def test_main_renders_a_remotely_managed_connector_with_the_token_only_in_the_env_file(first):
    r, tmp_path = first
    v = first.setup["v"]
    assert r.returncode == 0, r.stdout + r.stderr
    compose = (tmp_path / "app" / "docker-compose.yml").read_text()
    svc = yaml.safe_load(compose)["services"]["tunnel"]
    assert svc["image"].startswith(REPO + ":") and "@sha256:" in svc["image"]
    assert svc["cap_drop"] == ["ALL"] and svc["security_opt"] == ["no-new-privileges:true"]
    assert svc["read_only"] is True
    # outbound only: the one published port is the metrics/readiness listener, on the guest
    assert svc["ports"] == [GUEST + ":20241:20241"]
    # remotely managed: no ingress configuration of any kind
    assert svc["command"][:5] == ["tunnel", "--no-autoupdate", "--metrics", ":20241", "run"]
    assert svc["command"][5] == "--token-file" and "--config" not in svc["command"]
    # the token is mounted read-only as a file, never in the environment
    assert svc["volumes"] == [f"{tmp_path}/data/join/token:{svc['command'][6]}:ro"]
    assert "ingress" not in compose.lower()
    assert not list((tmp_path / "app").rglob("config.y*ml"))
    assert not any(k.startswith("TUNNEL_") for k in svc.get("environment", {}))
    assert JOIN_VALUE not in compose and "env_file" not in compose
    token_file = tmp_path / "data" / "join" / "token"
    assert token_file.read_text() == JOIN_VALUE
    assert oct(token_file.stat().st_mode & 0o777) == "0o400"
    assert not (tmp_path / "app" / "secrets" / "tunnel.env").exists()
    assert JOIN_VALUE not in r.stdout
    again = run_role(tmp_path, ROLE, "main", v, env=SECRETS)
    assert again.returncode == 0 and "changed=0" in again.stdout, again.stdout


def _first_main_puts_the_container_in_the_role_slice_the_module_play_names(tmp_path):
    v = tunnel_vars(tmp_path, hnx_module_slice="hnx-tunnel-server.slice")
    return {"role": ROLE, "tasks_from": "main", "extra_vars": v, "env": SECRETS}


@first_run(_first_main_puts_the_container_in_the_role_slice_the_module_play_names)
def test_main_puts_the_container_in_the_role_slice_the_module_play_names(first):
    r, tmp_path = first
    assert r.returncode == 0, r.stdout + r.stderr
    doc = yaml.safe_load((tmp_path / "app" / "docker-compose.yml").read_text())
    assert doc["services"]["tunnel"]["cgroup_parent"] == "hnx-tunnel-server.slice"


def _b64(obj) -> str:
    return base64.b64encode(json.dumps(obj).encode()).decode()


def _first_main_refuses_an_empty_or_malformed_token(tmp_path, env, word):
    return {"role": ROLE, "tasks_from": "main", "extra_vars": tunnel_vars(tmp_path), "env": env}


@pytest.mark.parametrize(
    "env, word",
    [
        ({ENV: ""}, "unset or empty"),
        ({ENV: "   "}, "unset or empty"),
        ({ENV: "not a token with spaces " * 4}, "not base64"),
        ({ENV: "short"}, "not base64"),
        ({ENV: _b64({"a": "x" * 20, "t": "y" * 20})}, "does not decode"),  # no secret key
        ({ENV: _b64(["a", "s", "t"] * 10)}, "does not decode"),
        ({ENV: base64.b64encode(b"plainly not json " * 5).decode()}, "does not decode"),
    ],
)
@first_run(_first_main_refuses_an_empty_or_malformed_token)
def test_main_refuses_an_empty_or_malformed_token(first, env, word):
    r, tmp_path = first
    assert r.returncode != 0, r.stdout
    assert word in r.stdout
    assert not (tmp_path / "app" / "docker-compose.yml").exists()
    assert not (tmp_path / "app" / "secrets").exists()
    assert (JOIN_VALUE not in r.stdout and env[ENV].strip() not in r.stdout) or not env[ENV].strip()


def _first_main_refuses_an_unset_token_naming_the_secret(tmp_path):
    return {"role": ROLE, "tasks_from": "main", "extra_vars": tunnel_vars(tmp_path), "env": {}}


@first_run(_first_main_refuses_an_unset_token_naming_the_secret)
def test_main_refuses_an_unset_token_naming_the_secret(first):
    r, tmp_path = first
    assert r.returncode != 0
    assert "secret:tunnel/token" in r.stdout + r.stderr
    assert not (tmp_path / "app" / "docker-compose.yml").exists()


def _first_main_refuses_bad_inputs(tmp_path, over):
    return {
        "role": ROLE,
        "tasks_from": "main",
        "extra_vars": tunnel_vars(tmp_path, **over),
        "env": SECRETS,
    }


@pytest.mark.parametrize(
    "over",
    [
        {"tunnel_image": REPO + ":latest"},
        {"ansible_host": "0.0.0.0"},
        {"ansible_host": "edge.example.internal"},
        {"tunnel_uid": 0},
        {"tunnel_join_ref": "tunnel/token"},
        {"tunnel_min_connections": 0},
        {"tunnel_udp_buffer_bytes": 212992},
        {"tunnel_dir": "relative/dir"},
        {"tunnel_data_root": "/var/lib/../etc"},
        {"tunnel_mem_limit": "lots"},
    ],
)
@first_run(_first_main_refuses_bad_inputs)
def test_main_refuses_bad_inputs(first, over):
    r, tmp_path = first
    assert r.returncode != 0, r.stdout
    assert not (tmp_path / "app" / "docker-compose.yml").exists()


def _docker(tmp_path: Path, health: str = "healthy", port: str = f"{GUEST}:20241") -> dict:
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    state = json.dumps({"Service": "tunnel", "State": "running", "Health": health})
    fake(
        bindir / "docker",
        "import sys\n"
        f"sys.stdout.write({port + chr(10)!r} if 'port' in sys.argv else {state + chr(10)!r})\n",
    )
    return {"PATH": f"{bindir}:{os.environ['PATH']}"}


class _Ready(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/ready":
            self.send_response(404)
            self.end_headers()
            return
        n = self.server.connections
        body = json.dumps({"status": 200 if n else 503, "readyConnections": n}).encode()
        self.send_response(200 if n else 503)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


class Ready:
    def __init__(self, connections: int):
        self.httpd = HTTPServer(("localhost", 0), _Ready)
        self.httpd.connections = connections

    def __enter__(self):
        threading.Thread(
            target=self.httpd.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True
        ).start()
        return self.httpd.server_address[:2]

    def __exit__(self, *a):
        self.httpd.shutdown()
        self.httpd.server_close()


def _health(tmp_path, connections: int, **kw):
    with Ready(connections) as (host, port):
        v = tunnel_vars(tmp_path, tunnel_bind=host, tunnel_port=port, tunnel_start=True)
        env = {**SECRETS, **_docker(tmp_path, port=f"{host}:{port}"), **kw}
        return run_role(tmp_path, ROLE, "health", v, env=env)


def test_health_passes_with_a_ready_connection(tmp_path):
    r = _health(tmp_path, 4)
    assert r.returncode == 0, r.stdout + r.stderr


def test_health_fails_with_no_ready_connection(tmp_path):
    r = _health(tmp_path, 0)
    assert r.returncode != 0
    assert "reports itself ready" in r.stdout


def test_health_fails_when_the_port_is_published_on_another_address(tmp_path):
    with Ready(2) as (host, port):
        v = tunnel_vars(tmp_path, tunnel_bind=host, tunnel_port=port, tunnel_start=True)
        env = {**SECRETS, **_docker(tmp_path, port=f"{GUEST}:{port}")}
        r = run_role(tmp_path, ROLE, "health", v, env=env)
    assert r.returncode != 0 and "bound to the guest's address only" in r.stdout


def _first_upgrade_refuses_another_repository_and_an_unpinned_target(tmp_path):
    ok = REPO + ":2026.11.0@sha256:" + "a" * 64
    (tmp_path / "app").mkdir()
    return {
        "role": ROLE,
        "tasks_from": "upgrade",
        "extra_vars": tunnel_vars(tmp_path, tunnel_target_image=ok),
        "env": SECRETS,
    }


@first_run(_first_upgrade_refuses_another_repository_and_an_unpinned_target)
def test_upgrade_refuses_another_repository_and_an_unpinned_target(first):
    r, tmp_path = first
    assert r.returncode == 0, r.stdout + r.stderr
    for bad in (REPO + ":2026.11.0", "docker.io/other/x:1@sha256:" + "a" * 64):
        r = run_role(
            tmp_path, ROLE, "upgrade", tunnel_vars(tmp_path, tunnel_target_image=bad), env=SECRETS
        )
        assert r.returncode != 0


@pytest.mark.parametrize(
    "form",
    [
        lambda raw: base64.urlsafe_b64encode(raw).decode(),  # URL-safe, padded
        lambda raw: base64.b64encode(raw).decode().rstrip("="),  # standard, unpadded
        lambda raw: base64.urlsafe_b64encode(raw).decode().rstrip("="),  # URL-safe, unpadded
    ],
)
def test_main_accepts_url_safe_and_unpadded_token_forms(tmp_path, form):
    # a payload whose encoding needs padding and uses + or / in the standard alphabet
    raw = json.dumps({"a": "acct" * 8, "t": "~~~???" * 6, "s": "\xfb\xff" * 8}).encode()
    value = form(raw)
    assert len(value) >= 60
    r = run_role(tmp_path, ROLE, "main", tunnel_vars(tmp_path), env={ENV: value})
    assert r.returncode == 0, r.stdout + r.stderr
    assert (tmp_path / "data" / "join" / "token").read_text() == value


def _sysctl(tmp_path: Path, live: int) -> tuple[dict, Path]:
    bindir = tmp_path / "sbin"
    bindir.mkdir(exist_ok=True)
    log = tmp_path / "sysctl.log"
    fake(
        bindir / "sysctl",
        "import sys\n"
        f"open({str(log)!r}, 'a').write(' '.join(sys.argv[1:]) + chr(10))\n"
        f"sys.stdout.write('{live}' + chr(10)) if '-n' in sys.argv else None\n",
    )
    return {"PATH": f"{bindir}:{os.environ['PATH']}"}, log


def _first_sysctl_only_raises_a_low_ceiling_and_never_lowers_a_higher_one(tmp_path):
    env, log = _sysctl(tmp_path, live=999999999)
    v = tunnel_vars(tmp_path, tunnel_sysctl_apply=True)
    return {
        "role": ROLE,
        "tasks_from": "main",
        "extra_vars": v,
        "env": {**SECRETS, **env},
        "setup": {"env": env, "log": log},
    }


@first_run(_first_sysctl_only_raises_a_low_ceiling_and_never_lowers_a_higher_one)
def test_sysctl_only_raises_a_low_ceiling_and_never_lowers_a_higher_one(first):
    r, tmp_path = first
    env = first.setup["env"]
    log = first.setup["log"]
    assert r.returncode == 0, r.stdout + r.stderr
    assert not (tmp_path / "sysctl.conf").exists()  # above the floor already: nothing written
    assert " -w " not in " " + log.read_text()
    low = tmp_path / "low"
    low.mkdir()
    env, log = _sysctl(low, live=212992)
    r = run_role(
        low, ROLE, "main", tunnel_vars(low, tunnel_sysctl_apply=True), env={**SECRETS, **env}
    )
    assert r.returncode == 0, r.stdout + r.stderr
    assert "rmem_max = 8388608" in (low / "sysctl.conf").read_text()
    assert log.read_text().count("-w") == 2


def test_remove_is_idempotent_and_deletes_the_token_file(tmp_path):
    import subprocess

    app = tmp_path / "app"
    data = tmp_path / "data"
    (data / "join").mkdir(parents=True)
    app.mkdir()
    (app / "docker-compose.yml").write_text("services: {}\n")
    (data / "join" / "token").write_text(JOIN_VALUE)
    bindir = tmp_path / "bin"
    bindir.mkdir()
    log = tmp_path / "docker.log"
    fake(
        bindir / "docker",
        f"import sys\nopen({str(log)!r}, 'a').write(' '.join(sys.argv[1:]) + chr(10))\n",
    )
    inv = tmp_path / "inv.ini"
    inv.write_text("[mod_tunnel_server]\nlocalhost ansible_connection=local\n")
    play = ROOT / "modules" / "tunnel" / "playbooks" / "remove.yml"
    env = dict(
        os.environ,
        PATH=f"{bindir}:{os.environ['PATH']}",
        ANSIBLE_CONFIG=str(ROOT / "ansible" / "ansible.cfg"),
        ANSIBLE_HOME=str(tmp_path / ".ansible"),
        ANSIBLE_NOCOLOR="1",
    )
    cmd = ["ansible-playbook", "-i", str(inv), str(play), "-e", f"tunnel_dir={app}", "-e", f"tunnel_data_root={data}",
           "-e", "ansible_become=false", "-e", f"ansible_python_interpreter={__import__('sys').executable}"]  # fmt: skip
    for _ in range(2):  # the second run finds nothing to stop and must still succeed
        r = subprocess.run(cmd, capture_output=True, text=True, env=env, cwd=tmp_path)
        assert r.returncode == 0, r.stdout + r.stderr
        assert not (data / "join" / "token").exists()
    assert log.read_text().count("down") == 2
    (app / "docker-compose.yml").unlink()
    r = subprocess.run(cmd, capture_output=True, text=True, env=env, cwd=tmp_path)
    assert r.returncode == 0, r.stdout + r.stderr  # a half-removed host: no compose file at all
    assert log.read_text().count("down") == 2


def _logging_docker(tmp_path: Path) -> tuple[dict, Path]:
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    log = tmp_path / "docker.log"
    fake(
        bindir / "docker",
        f"import sys\nopen({str(log)!r}, 'a').write(' '.join(sys.argv[1:]) + chr(10))\n",
    )
    return {"PATH": f"{bindir}:{os.environ['PATH']}"}, log


def test_a_rotated_token_recreates_the_running_connector_and_an_unchanged_one_does_not(tmp_path):
    env, log = _logging_docker(tmp_path)
    v = tunnel_vars(tmp_path, tunnel_start=True)
    first = run_role(tmp_path, ROLE, "main", v, env={**SECRETS, **env})
    assert first.returncode == 0, first.stdout + first.stderr
    assert log.read_text().count("--force-recreate") == 1  # the token file was just written
    again = run_role(tmp_path, ROLE, "main", v, env={**SECRETS, **env})
    assert again.returncode == 0 and "changed=0" in again.stdout, again.stdout
    assert log.read_text().count("--force-recreate") == 1  # same token: left running
    rotated = _b64({"a": "other" * 6, "t": "11111111-2222-3333-4444-555555555555", "s": "n" * 40})
    third = run_role(tmp_path, ROLE, "main", v, env={ENV: rotated, **env})
    assert third.returncode == 0, third.stdout + third.stderr
    assert log.read_text().count("--force-recreate") == 2  # a rotated token is picked up
    assert (tmp_path / "data" / "join" / "token").read_text() == rotated
    assert rotated not in third.stdout


def _first_nothing_is_recreated_when_the_connector_is_deliberately_not_started(tmp_path):
    env, log = _logging_docker(tmp_path)
    return {
        "role": ROLE,
        "tasks_from": "main",
        "extra_vars": tunnel_vars(tmp_path),
        "env": {**SECRETS, **env},
        "setup": {"log": log},
    }


@first_run(_first_nothing_is_recreated_when_the_connector_is_deliberately_not_started)
def test_nothing_is_recreated_when_the_connector_is_deliberately_not_started(first):
    r, _ = first
    log = first.setup["log"]
    assert r.returncode == 0, r.stdout + r.stderr
    assert not log.exists() or "--force-recreate" not in log.read_text()


def _first_health_reports_not_started_by_design_instead_of_failing(tmp_path):
    env, log = _logging_docker(tmp_path)
    return {
        "role": ROLE,
        "tasks_from": "health",
        "extra_vars": tunnel_vars(tmp_path),
        "env": {**SECRETS, **env},
        "setup": {"log": log},
    }


@first_run(_first_health_reports_not_started_by_design_instead_of_failing)
def test_health_reports_not_started_by_design_instead_of_failing(first):
    r, _ = first
    log = first.setup["log"]
    assert r.returncode == 0, r.stdout + r.stderr
    assert "deliberately not running" in r.stdout
    assert not log.exists()  # no container or endpoint was asked


def test_the_sysctl_drop_in_sorts_first():
    defaults = yaml.safe_load((Path(ROLE) / "defaults" / "main.yml").read_text())
    assert Path(defaults["tunnel_sysctl_file"]).name.startswith("00-")
