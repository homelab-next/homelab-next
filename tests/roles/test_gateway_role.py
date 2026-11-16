# SPDX-License-Identifier: Apache-2.0
"""Role ``gateway`` (modules/gateway/roles/gateway), run on localhost against fakes (CI is
unprivileged).

* main renders the gateway's configuration on the controller from the site's gateway spec (the
  real generator and its audit), installs it read-only for the container, delivers every key only
  through the env_file and converges (a second run is ``changed=0``);
* it refuses what must never reach a guest: an unset or short or repeated key (naming the
  ``secret:`` reference, never a value), a cloud host the site did not allow, a refused host, a
  test-only rendering, an image that is not pinned or that names the compromised gateway, an
  address that is not the guest's;
* health passes against a stand-in that behaves like the gateway and fails when the gateway
  answers without a key, serves other role aliases than its config names, has dropped usage
  records or has a usage file past its size bound;
* export writes the usage records as an object tree and restore checks them first.
"""

from __future__ import annotations

import hashlib
import http.server
import ipaddress
import json
import os
import pwd
import socket
import sys
import threading
from pathlib import Path

import pytest
import yaml
from rolerun import fake, run_role

ROOT = Path(__file__).resolve().parents[2]
ROLE = str(ROOT / "modules" / "gateway" / "roles" / "gateway")
FIXTURES = Path(__file__).resolve().parent / "fixtures" / "gateway"
USER = pwd.getpwuid(os.getuid()).pw_name
LOOPBACK = socket.gethostbyname("localhost")  # the loopback address, by name
GUEST = LOOPBACK  # the guest's own address, as the inventory would give it
UNSPECIFIED = str(ipaddress.IPv4Address(0))  # all interfaces: a bind the role refuses
IMAGE = "localhost/hnx-llm-gateway:0.1.0-0123456789ab@sha256:" + "a" * 64
MASTER = "sk-" + "m" * 64
CONTROLLER = "sk-" + "c" * 64
JOBS = "sk-" + "j" * 64
READER = "sk-" + "r" * 64
UPSTREAM = "sk-ant-" + "u" * 40
SECRETS = {
    "HNX_SECRET_GATEWAY_MASTER_KEY": MASTER,
    "HNX_SECRET_GATEWAY_KEY_CONTROLLER": CONTROLLER,
    "HNX_SECRET_GATEWAY_KEY_JOBS": JOBS,
    "HNX_SECRET_GATEWAY_KEY_TELEMETRY_READER": READER,
    "HNX_SECRET_GATEWAY_UPSTREAM_CLOUD": UPSTREAM,
}
ROLES = ["embedder", "fast-classifier", "general"]  # the fixture role table's aliases


def spec_dir(tmp_path: Path, spec: str | None = None) -> Path:
    """A copy of the fixture spec and role table (a test may change either)."""
    d = tmp_path / "site"
    d.mkdir(exist_ok=True)
    (d / "model_roles.json").write_text((FIXTURES / "model_roles.json").read_text())
    (d / "gateway.yml").write_text(
        spec if spec is not None else (FIXTURES / "gateway.yml").read_text()
    )
    return d / "gateway.yml"


def gateway_vars(tmp_path: Path, **kw) -> dict:
    v = {
        "gateway_logical_id": "gateway",
        "ansible_host": GUEST,
        "gateway_hnx_cli": [sys.executable, "-m", "homelabnext.cli"],
        "gateway_image": IMAGE,
        "gateway_cloud_hosts_allowed": ["api.anthropic.com"],
        "gateway_dir": str(tmp_path / "app"),
        "gateway_data_root": str(tmp_path / "data"),
        "gateway_owner": USER,
        "gateway_uid": os.getuid(),
        "gateway_gid": os.getgid(),
        "gateway_start": False,
        "gateway_validate_with_docker": False,
    }
    v.update(kw)
    v["gateway_spec"] = str(kw["gateway_spec"] if "gateway_spec" in kw else spec_dir(tmp_path))
    return v


def main(tmp_path: Path, env: dict | None = None, **kw):
    v = gateway_vars(tmp_path, **kw)
    return run_role(tmp_path, ROLE, "main", v, env={**SECRETS, **(env or {})}), v


def compose(tmp_path: Path) -> dict:
    return yaml.safe_load((tmp_path / "app" / "docker-compose.yml").read_text())


# ----------------------------------------------------------------------------- main


def test_main_renders_the_container_and_keeps_every_key_out_of_the_compose_file(tmp_path):
    r, _ = main(tmp_path)
    assert r.returncode == 0, r.stdout + r.stderr
    text = (tmp_path / "app" / "docker-compose.yml").read_text()
    svc = yaml.safe_load(text)["services"]["gateway"]
    assert svc["image"] == IMAGE
    assert svc["user"] == f"{os.getuid()}:{os.getgid()}"
    assert svc["cap_drop"] == ["ALL"] and svc["security_opt"] == ["no-new-privileges:true"]
    assert svc["read_only"] is True
    assert svc["ports"] == [GUEST + ":4100:4100"]
    assert svc["volumes"] == [
        f"{tmp_path}/data/config:/etc/llm-gateway:ro",
        f"{tmp_path}/data/state:/var/lib/llm-gateway",
    ]
    cmd = svc["command"]
    assert cmd[cmd.index("-config") + 1] == "/etc/llm-gateway/gateway.json"
    assert cmd[cmd.index("-usage") + 1] == "/var/lib/llm-gateway/usage.jsonl"
    assert "-allow-plaintext" in cmd and "-conformance" not in cmd
    # no key and no environment of any kind in the compose file; the keys are in the env_file
    assert "environment" not in svc
    for secret in (MASTER, CONTROLLER, JOBS, READER, UPSTREAM):
        assert secret not in text and secret not in r.stdout
    env = (tmp_path / "app" / "secrets" / "gateway.env").read_text()
    for name, value in SECRETS.items():
        assert f"{name}='{value}'" in env
    assert oct((tmp_path / "app" / "secrets" / "gateway.env").stat().st_mode & 0o777) == "0o600"


def test_main_installs_the_generated_config_read_only_for_the_container(tmp_path):
    r, _ = main(tmp_path)
    assert r.returncode == 0, r.stdout + r.stderr
    config = tmp_path / "data" / "config" / "gateway.json"
    doc = json.loads(config.read_text())
    assert sorted(doc["roles"]) == ROLES and doc["name"] == "test-lab"
    assert "conformance_only" not in doc
    assert oct(config.stat().st_mode & 0o777) == "0o640"
    assert oct((tmp_path / "data" / "state").stat().st_mode & 0o777) == "0o700"
    # the config names environment variables, never a key value
    assert not any(s in config.read_text() for s in (MASTER, CONTROLLER, JOBS, READER, UPSTREAM))


def test_main_is_idempotent(tmp_path):
    r, v = main(tmp_path)
    assert r.returncode == 0, r.stdout + r.stderr
    again = run_role(tmp_path, ROLE, "main", v, env=SECRETS)
    assert again.returncode == 0 and "changed=0" in again.stdout, again.stdout


def test_main_puts_the_container_in_the_role_slice_the_module_play_names(tmp_path):
    r, _ = main(tmp_path, hnx_module_slice="hnx-gateway-server.slice")
    assert r.returncode == 0, r.stdout + r.stderr
    assert compose(tmp_path)["services"]["gateway"]["cgroup_parent"] == "hnx-gateway-server.slice"


def test_main_passes_the_limits_the_site_sets(tmp_path):
    r, _ = main(tmp_path, gateway_max_inflight=64, gateway_max_inflight_per_key=8,
                gateway_upstream_timeout="45s", gateway_reserve_output=2048)  # fmt: skip
    assert r.returncode == 0, r.stdout + r.stderr
    cmd = compose(tmp_path)["services"]["gateway"]["command"]
    for flag, value in (("-max-inflight", "64"), ("-max-inflight-per-key", "8"),
                        ("-upstream-timeout", "45s"), ("-reserve-tokens", "2048")):  # fmt: skip
        assert cmd[cmd.index(flag) + 1] == value


@pytest.mark.parametrize(
    "over",
    [
        {"gateway_image": "localhost/hnx-llm-gateway:latest"},
        {"gateway_image": "localhost/hnx-llm-gateway:0.1.0"},  # no digest
        {"gateway_image": "docker.io/vendor/other-gateway:v1.2.3@sha256:" + "a" * 64},
        {"gateway_image": "localhost/hnx-other:0.1.0-0123456789ab@sha256:" + "a" * 64},
        {"ansible_host": UNSPECIFIED},
        {"ansible_host": "gateway.example.internal"},
        {"gateway_port": 0},
        {"gateway_uid": 0},
        {"gateway_data_root": "/var/lib/../etc"},
        {"gateway_dir": "relative/dir"},
        {"gateway_max_inflight": 0},
        {"gateway_upstream_timeout": "forever"},
        {"gateway_cloud_hosts_allowed": ["https://api.anthropic.com"]},  # a host, not a URL
        {"gateway_usage_max_mb": 0},
        {"gateway_spec": "relative/gateway.yml"},
        {"gateway_hnx_cli": ["/bin/sh", "-c", "true"]},  # a generator that writes nothing
    ],
)
def test_main_refuses_bad_inputs(tmp_path, over):
    r, _ = main(tmp_path, **over)
    assert r.returncode != 0, r.stdout
    assert not (tmp_path / "app" / "docker-compose.yml").exists()
    assert not (tmp_path / "data" / "config" / "gateway.json").exists()
    assert MASTER not in r.stdout


def test_an_image_of_another_repository_is_refused_as_not_the_labs_own_gateway(tmp_path):
    other = "docker.io/vendor/other-gateway:v1.2.3@sha256:" + "a" * 64
    r, _ = main(tmp_path, gateway_image=other)
    assert r.returncode != 0
    assert "not the lab's own gateway" in r.stdout and "gateway_build_repositories" in r.stdout
    # a site that pushes the build to its own registry names that repository, and only that one
    mine = "registry.example.internal/lab/gateway:0.1.0-0123456789ab@sha256:" + "a" * 64
    still, _ = main(tmp_path, gateway_image=mine)
    assert still.returncode != 0
    ok, _ = main(tmp_path, gateway_image=mine,
                 gateway_build_repositories=["registry.example.internal/lab/gateway"])  # fmt: skip
    assert ok.returncode == 0, ok.stdout + ok.stderr
    assert compose(tmp_path)["services"]["gateway"]["image"] == mine


@pytest.mark.parametrize(
    "name",
    [
        "HNX_SECRET_GATEWAY_MASTER_KEY",
        "HNX_SECRET_GATEWAY_KEY_CONTROLLER",
        "HNX_SECRET_GATEWAY_KEY_TELEMETRY_READER",
        "HNX_SECRET_GATEWAY_UPSTREAM_CLOUD",
    ],
)
def test_main_refuses_an_unset_secret_naming_its_reference(tmp_path, name):
    env = {k: v for k, v in SECRETS.items() if k != name}
    v = gateway_vars(tmp_path)
    r = run_role(tmp_path, ROLE, "main", v, env=env)
    assert r.returncode != 0, r.stdout
    assert not (tmp_path / "app" / "docker-compose.yml").exists()
    assert "secret:gateway" in r.stdout  # the reference is named, never a value


@pytest.mark.parametrize(
    "bad",
    [
        {"HNX_SECRET_GATEWAY_KEY_CONTROLLER": "sk-short"},  # under 32 bytes
        {"HNX_SECRET_GATEWAY_KEY_JOBS": CONTROLLER},  # the same key for two callers
        {"HNX_SECRET_GATEWAY_KEY_TELEMETRY_READER": MASTER},  # the reader holds the admin key
        {"HNX_SECRET_GATEWAY_MASTER_KEY": "sk-" + "m" * 40 + "'; rm -rf /; '"},  # a quote
    ],
)
def test_main_refuses_a_key_the_gateway_would_refuse_at_start(tmp_path, bad):
    r, _ = main(tmp_path, env=bad)
    assert r.returncode != 0, r.stdout
    assert not (tmp_path / "app" / "docker-compose.yml").exists()
    for value in bad.values():
        assert value not in r.stdout


def test_main_refuses_a_cloud_host_the_site_did_not_allow(tmp_path):
    r, _ = main(tmp_path, gateway_cloud_hosts_allowed=[])
    assert r.returncode != 0, r.stdout
    assert "is not one this site allows" in r.stdout and "gateway_cloud_hosts_allowed" in r.stdout
    # a different provider's host does not admit this one's deployment
    other, _ = main(tmp_path, gateway_cloud_hosts_allowed=["api.openai.com"])
    assert other.returncode != 0 and "is not one this site allows" in other.stdout
    assert not (tmp_path / "data" / "config" / "gateway.json").exists()


def test_main_refuses_a_backend_host_the_site_listed_as_refused(tmp_path):
    r, _ = main(tmp_path, gateway_refused_hosts=["pool.svc.example.internal"])
    assert r.returncode != 0, r.stdout
    assert "pool.svc.example.internal" in r.stdout and "gateway_refused_hosts" in r.stdout
    assert not (tmp_path / "data" / "config" / "gateway.json").exists()


def test_main_refuses_a_spec_the_generator_refuses(tmp_path):
    bad = (
        (FIXTURES / "gateway.yml")
        .read_text()
        .replace(
            "  svc:cloud: {locality: cloud, provider: anthropic, api_key: secret:gateway/upstream-cloud}",
            "  svc:cloud: {locality: local, host: api.example.com, port: 443}",
        )
    )
    r, _ = main(tmp_path, gateway_spec=spec_dir(tmp_path, bad))
    assert r.returncode != 0, r.stdout
    assert not (tmp_path / "data" / "config" / "gateway.json").exists()


def _fake_cli(tmp_path: Path, mutate: str) -> list[str]:
    """A generator stand-in: the real one into the scratch directory, then ``mutate(doc)``
    on the rendered gateway.json."""
    body = (
        "import json, subprocess, sys\n"
        "if '--check' in sys.argv:\n"
        "    sys.exit(0)  # the audit is the real generator's, proved elsewhere; it would see the edit\n"
        "out = sys.argv[sys.argv.index('render') + 2]\n"
        f"r = subprocess.run([{sys.executable!r}, '-m', 'homelabnext.cli'] + sys.argv[1:])\n"
        "if r.returncode == 0:\n"
        "    p = out + '/gateway/gateway.json'\n"
        "    doc = json.load(open(p))\n"
        f"    {mutate}\n"
        "    json.dump(doc, open(p, 'w'))\n"
        "sys.exit(r.returncode)\n"
    )
    return [fake(tmp_path / "hnx-cli", body)]


def test_main_refuses_a_test_only_rendering(tmp_path):
    cli = _fake_cli(tmp_path, "doc['conformance_only'] = True")
    r, _ = main(tmp_path, gateway_hnx_cli=cli)
    assert r.returncode != 0, r.stdout
    assert "must not be a test-only" in r.stdout
    assert not (tmp_path / "data" / "config" / "gateway.json").exists()


def test_main_names_a_key_whose_secret_the_spec_does_not_reference(tmp_path):
    cli = _fake_cli(
        tmp_path,
        "doc['keys'][0]['key_env'] = 'HNX_SECRET_GATEWAY_KEY_MYSTERY'",
    )
    r, _ = main(
        tmp_path, gateway_hnx_cli=cli, env={"HNX_SECRET_GATEWAY_KEY_MYSTERY": "sk-" + "y" * 64}
    )
    assert r.returncode != 0, r.stdout
    assert "HNX_SECRET_GATEWAY_KEY_MYSTERY" in r.stdout and "gateway_key_refs_extra" in r.stdout
    # naming the reference in the role's settings is what resolves it
    ok, _ = main(tmp_path, gateway_hnx_cli=cli, gateway_key_refs_extra=["secret:gateway/key-mystery"],
                 env={"HNX_SECRET_GATEWAY_KEY_MYSTERY": "sk-" + "y" * 64})  # fmt: skip
    assert ok.returncode == 0, ok.stdout + ok.stderr
    assert "sk-" + "y" * 64 in (tmp_path / "app" / "secrets" / "gateway.env").read_text()


def test_a_changed_key_restarts_the_container_and_an_unchanged_one_does_not(tmp_path):
    log = tmp_path / "docker.log"
    bindir = tmp_path / "bin"
    bindir.mkdir()
    fake(
        bindir / "docker",
        f"import sys\nopen({str(log)!r}, 'a').write(' '.join(sys.argv[1:]) + '\\n')\n",
    )
    env = {"PATH": f"{bindir}:{os.environ['PATH']}"}
    v = gateway_vars(tmp_path, gateway_start=True, gateway_health_timeout=1)
    v["gateway_wait_ready"] = False  # the stand-in docker starts nothing: do not wait for it
    first = run_role(tmp_path, ROLE, "main", v, env={**SECRETS, **env})
    assert first.returncode == 0, first.stdout + first.stderr
    log.unlink()
    again = run_role(tmp_path, ROLE, "main", v, env={**SECRETS, **env})
    assert again.returncode == 0, again.stdout + again.stderr
    assert not any(" restart " in line for line in log.read_text().splitlines())
    log.unlink()
    rotated = {**SECRETS, "HNX_SECRET_GATEWAY_KEY_JOBS": "sk-" + "k" * 64, **env}
    third = run_role(tmp_path, ROLE, "main", v, env=rotated)
    assert third.returncode == 0, third.stdout + third.stderr
    assert any(" restart " in line for line in log.read_text().splitlines()), log.read_text()


# ----------------------------------------------------------------------------- health


class StandIn:
    """A server that answers like the gateway: /healthz open, every other route behind a key,
    /v1/models its role aliases for the admin key."""

    def __init__(self, *, open_models=False, roles=None, dropped=0):
        self.open_models, self.dropped, self.skipped = open_models, dropped, 0
        self.roles = ROLES if roles is None else roles
        outer = self

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, code, doc):
                body = json.dumps(doc).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                if self.path == "/healthz":
                    return self._send(200, {"status": "ok", "usage_records_dropped": outer.dropped,
                                            "usage_lines_skipped": outer.skipped, "replies_overloaded": 0})  # fmt: skip
                if self.path == "/v1/models":
                    auth = self.headers.get("Authorization", "")
                    if auth != f"Bearer {MASTER}" and not outer.open_models:
                        return self._send(401, {"error": {"code": "unauthorized"}})
                    return self._send(200, {"object": "list",
                                            "data": [{"id": r, "object": "model"} for r in outer.roles]})  # fmt: skip
                self._send(404, {})

        self._httpd = http.server.ThreadingHTTPServer((LOOPBACK, 0), H)
        self.url = "http://{}:{}".format(*self._httpd.server_address[:2])

    def __enter__(self):
        threading.Thread(target=self._httpd.serve_forever, daemon=True).start()
        return self

    def __exit__(self, *a):
        self._httpd.shutdown()
        self._httpd.server_close()


def _installed(tmp_path: Path) -> None:
    """The role's own configuration on disk, as main leaves it."""
    (tmp_path / "data" / "config").mkdir(parents=True, exist_ok=True)
    shutil_copy = (FIXTURES / "model_roles.json").read_text()
    roles = json.loads(shutil_copy)["roles"]
    doc = {"admin_key_env": "HNX_SECRET_GATEWAY_MASTER_KEY", "keys": [], "name": "x",
           "roles": {r: {} for r in roles}, "telemetry_reader": None, "version": 1}  # fmt: skip
    (tmp_path / "data" / "config" / "gateway.json").write_text(json.dumps(doc))
    (tmp_path / "data" / "state").mkdir(parents=True, exist_ok=True)


def _docker(tmp_path: Path, health: str = "healthy") -> dict:
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    state = json.dumps({"Service": "gateway", "State": "running", "Health": health})
    fake(bindir / "docker", f"import sys\nsys.stdout.write({state + chr(10)!r})\n")
    return {"PATH": f"{bindir}:{os.environ['PATH']}"}


def _health(tmp_path: Path, srv: StandIn, **kw):
    _installed(tmp_path)
    host, port = srv._httpd.server_address[:2]
    v = gateway_vars(tmp_path, gateway_bind=host, gateway_port=port, **kw)
    return run_role(tmp_path, ROLE, "health", v, env={**SECRETS, **_docker(tmp_path)})


def test_health_passes_against_a_gateway_that_serves_its_roles_behind_the_key(tmp_path):
    with StandIn() as srv:
        r = _health(tmp_path, srv)
    assert r.returncode == 0, r.stdout + r.stderr
    assert MASTER not in r.stdout


def test_health_fails_when_a_call_without_a_key_is_served(tmp_path):
    with StandIn(open_models=True) as srv:
        r = _health(tmp_path, srv)
    assert r.returncode != 0 and "without a key is refused" in r.stdout


def test_health_fails_when_the_served_roles_are_not_the_configured_ones(tmp_path):
    with StandIn(roles=["embedder", "fast-classifier"]) as srv:
        r = _health(tmp_path, srv)
    assert r.returncode != 0 and "exactly the configured role aliases" in r.stdout


def test_health_fails_on_dropped_usage_records(tmp_path):
    with StandIn(dropped=3) as srv:
        r = _health(tmp_path, srv)
    assert r.returncode != 0 and "usage records" in r.stdout


def test_health_fails_when_the_usage_file_is_past_its_bound(tmp_path):
    with StandIn() as srv:
        _installed(tmp_path)
        (tmp_path / "data" / "state" / "usage.jsonl").write_bytes(b"x" * (2 * 1024 * 1024))
        r = _health(tmp_path, srv, gateway_usage_max_mb=1)
    assert r.returncode != 0 and "usage.jsonl" in r.stdout and "export" in r.stdout


def test_health_fails_when_the_container_is_unhealthy(tmp_path):
    with StandIn() as srv:
        _installed(tmp_path)
        host, port = srv._httpd.server_address[:2]
        v = gateway_vars(tmp_path, gateway_bind=host, gateway_port=port)
        r = run_role(tmp_path, ROLE, "health", v, env={**SECRETS, **_docker(tmp_path, "unhealthy")})
    assert r.returncode != 0


# ----------------------------------------------------------------------------- readiness


def test_readiness_names_a_missing_secret_before_anything_is_written(tmp_path):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    fake(bindir / "systemctl", "print('active')\n")
    fake(bindir / "docker", "import json\nprint(json.dumps({'ServerVersion': '27.0'}))\n")
    env = {k: v for k, v in SECRETS.items() if k != "HNX_SECRET_GATEWAY_KEY_JOBS"}
    env["PATH"] = f"{bindir}:{os.environ['PATH']}"
    v = gateway_vars(tmp_path, docker_engine_state_dir=str(tmp_path / "engine"))
    r = run_role(tmp_path, ROLE, "readiness", v, env=env)
    assert r.returncode != 0 and "secret:gateway/key-jobs" in r.stdout
    assert not (tmp_path / "data").exists()


# ----------------------------------------------------------------------------- export and restore


def _usage(tmp_path: Path, lines=3, partial=True) -> bytes:
    state = tmp_path / "data" / "state"
    state.mkdir(parents=True, exist_ok=True)
    rows = "".join(json.dumps({"caller": "controller", "role": "fast-classifier", "n": i}) + "\n"
                   for i in range(lines))  # fmt: skip
    data = rows + ('{"caller": "contr' if partial else "")
    (state / "usage.jsonl").write_text(data)
    return rows.encode()


def test_export_copies_whole_usage_records_and_lists_them(tmp_path):
    complete = _usage(tmp_path)
    v = gateway_vars(tmp_path)
    r = run_role(tmp_path, ROLE, "export", v)
    assert r.returncode == 0, r.stdout + r.stderr
    export = tmp_path / "data" / "export"
    assert (
        export / "usage.jsonl"
    ).read_bytes() == complete  # the half-written last line is left out
    (row,) = [json.loads(x) for x in (export / "listing.jsonl").read_text().splitlines()]
    assert row == {"key": "usage.jsonl", "lines": 3, "size": len(complete),
                   "sha256": hashlib.sha256(complete).hexdigest()}  # fmt: skip


def test_export_refuses_a_missing_or_corrupt_usage_file(tmp_path):
    v = gateway_vars(tmp_path)
    (tmp_path / "data" / "state").mkdir(parents=True)
    r = run_role(tmp_path, ROLE, "export", v)
    assert r.returncode != 0 and "usage.jsonl" in r.stdout
    (tmp_path / "data" / "state" / "usage.jsonl").write_text("not json\n")
    bad = run_role(tmp_path, ROLE, "export", v)
    assert bad.returncode != 0 and "not a JSON record" in bad.stdout


def test_restore_checks_the_export_before_it_stops_the_gateway(tmp_path):
    _usage(tmp_path, partial=False)
    v = gateway_vars(tmp_path)
    assert run_role(tmp_path, ROLE, "export", v).returncode == 0
    src = tmp_path / "src"
    src.mkdir()
    for p in (tmp_path / "data" / "export").iterdir():
        (src / p.name).write_bytes(p.read_bytes())
    log = tmp_path / "docker.log"
    bindir = tmp_path / "bin"
    bindir.mkdir()
    fake(
        bindir / "docker",
        f"import sys\nopen({str(log)!r}, 'a').write(' '.join(sys.argv[1:]) + '\\n')\n",
    )
    env = {"PATH": f"{bindir}:{os.environ['PATH']}"}
    (tmp_path / "data" / "state" / "usage.jsonl").write_text("previous\n")
    ok = run_role(
        tmp_path,
        ROLE,
        "restore",
        {**v, "gateway_restore_source": str(src), "gateway_wait_ready": False},
        env=env,
    )
    assert ok.returncode == 0, ok.stdout + ok.stderr
    calls = log.read_text().splitlines()
    assert calls[0].endswith(" stop") and calls[-1].endswith(" up -d")
    restored = tmp_path / "data" / "state" / "usage.jsonl"
    assert restored.read_bytes() == (src / "usage.jsonl").read_bytes()
    assert oct(restored.stat().st_mode & 0o777) == "0o600"
    # the file that was there is kept beside it, never overwritten
    (kept,) = (tmp_path / "data" / "state").glob("usage.jsonl.before-restore-*")
    assert kept.read_text() == "previous\n"
    # a second restore the same day refuses (before anything stops) and keeps both files
    log.unlink()
    again = run_role(
        tmp_path,
        ROLE,
        "restore",
        {**v, "gateway_restore_source": str(src), "gateway_wait_ready": False},
        env=env,
    )
    assert again.returncode != 0 and "already exists" in again.stdout
    assert not log.exists() and kept.read_text() == "previous\n"
    assert restored.read_bytes() == (src / "usage.jsonl").read_bytes()
    kept.unlink()
    # a tampered file is refused before anything stops
    with open(src / "usage.jsonl", "ab") as f:
        f.write(b'{"x": 1}\n')
    bad = run_role(
        tmp_path,
        ROLE,
        "restore",
        {**v, "gateway_restore_source": str(src), "gateway_wait_ready": False},
        env=env,
    )
    assert bad.returncode != 0 and "not the listed size" in bad.stdout
    assert not log.exists()


# ----------------------------------------------------------------------------- upgrade


def test_upgrade_records_a_pinned_target_of_the_same_repository_only(tmp_path):
    v = gateway_vars(tmp_path)
    assert run_role(tmp_path, ROLE, "main", v, env=SECRETS).returncode == 0
    for target in (
        "localhost/hnx-llm-gateway:0.2.0",  # not pinned by digest
        "localhost/hnx-other:0.2.0-0123456789ab@sha256:" + "b" * 64,  # another repository
        "localhost/hnx-llm-gateway:latest@sha256:" + "b" * 64,
    ):
        assert (
            run_role(tmp_path, ROLE, "upgrade", {**v, "gateway_target_image": target}).returncode
            != 0
        )
    target = "localhost/hnx-llm-gateway:0.2.0-0123456789ab@sha256:" + "b" * 64
    ok = run_role(tmp_path, ROLE, "upgrade", {**v, "gateway_target_image": target})
    assert ok.returncode == 0, ok.stdout + ok.stderr
    pending = json.loads((tmp_path / "app" / "pending-upgrade.json").read_text())
    assert pending == {
        "service": "gateway",
        "tag": "0.2.0-0123456789ab",
        "digest": "sha256:" + "b" * 64,
    }


# ----------------------------------------------------------------------------- the image


def test_a_missing_image_is_loaded_from_the_archive_and_a_still_missing_one_refused(tmp_path):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    log = tmp_path / "docker.log"
    # `docker image inspect` fails until `docker load` ran, then succeeds
    fake(
        bindir / "docker",
        (
            "import os, sys\n"
            f"log, flag = {str(log)!r}, {str(tmp_path / 'loaded')!r}\n"
            "open(log, 'a').write(' '.join(sys.argv[1:]) + '\\n')\n"
            "if sys.argv[1:3] == ['image', 'inspect']:\n"
            "    sys.exit(0 if os.path.exists(flag) else 1)\n"
            "if sys.argv[1] == 'load':\n"
            "    open(flag, 'w').close()\n"
        ),
    )
    archive = tmp_path / "gateway.tar"
    archive.write_bytes(b"not a real archive")
    env = {**SECRETS, "PATH": f"{bindir}:{os.environ['PATH']}"}
    v = gateway_vars(tmp_path, gateway_image_archive=str(archive))
    r = run_role(tmp_path, ROLE, "main", v, env=env)
    assert r.returncode == 0, r.stdout + r.stderr
    assert any(line.startswith("load -i ") for line in log.read_text().splitlines())
    (tmp_path / "loaded").unlink()
    missing = run_role(
        tmp_path, ROLE, "main", {**v, "gateway_image_archive": str(tmp_path / "nope.tar")}, env=env
    )
    assert missing.returncode != 0 and "not a regular file" in missing.stdout


# ----------------------------------------------------------------------------- streaming


VARS = yaml.safe_load((ROOT / "modules/gateway/roles/gateway/vars/main.yml").read_text())
BIG = 192 * 1024 * 1024  # a usage file this big; the scripts run under an address-space limit below
LIMIT = 160 * 1024 * 1024  # smaller than the file: a script that reads it whole cannot finish


def _limited():
    import resource

    resource.setrlimit(resource.RLIMIT_AS, (LIMIT, LIMIT))


def _big_usage(path: Path) -> int:
    row = json.dumps({"caller": "controller", "role": "fast-classifier", "pad": "x" * 400}) + "\n"
    chunk = row.encode() * 2048
    n = 0
    with open(path, "wb") as f:
        while f.tell() < BIG:
            f.write(chunk)
            n += 2048
    return n


def _script(name: str, *args: str):
    import subprocess

    return subprocess.run(
        [sys.executable, "-I", "-c", VARS[name], *args],
        capture_output=True,
        text=True,
        preexec_fn=_limited,
    )


def test_export_and_restore_stream_a_usage_file_larger_than_the_memory_they_may_use(tmp_path):
    state, export = tmp_path / "state", tmp_path / "export"
    state.mkdir()
    export.mkdir()
    lines = _big_usage(state / "usage.jsonl")
    assert (state / "usage.jsonl").stat().st_size > LIMIT
    r = _script("gateway_export_script", str(state), str(export))
    assert r.returncode == 0, r.stderr[-500:]
    row = json.loads(r.stdout)
    assert row["lines"] == lines and row["size"] == (state / "usage.jsonl").stat().st_size
    h = hashlib.sha256()
    with open(export / "usage.jsonl", "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    assert h.hexdigest() == row["sha256"]
    uid, gid = str(os.getuid()), str(os.getgid())
    new = tmp_path / "newstate"
    new.mkdir()
    chk = _script("gateway_restore_script", "check", str(export), uid, str(new))
    assert chk.returncode == 0, chk.stderr[-500:]
    ap = _script("gateway_restore_script", "apply", str(export), str(new), uid, gid)
    assert ap.returncode == 0, ap.stderr[-500:]
    assert (new / "usage.jsonl").stat().st_size == row["size"]


def test_a_line_over_the_bound_is_refused_not_buffered(tmp_path):
    state, export = tmp_path / "state", tmp_path / "export"
    state.mkdir()
    export.mkdir()
    (state / "usage.jsonl").write_bytes(b'{"x": "' + b"y" * (2 * 1024 * 1024) + b'"}\n')
    r = _script("gateway_export_script", str(state), str(export))
    assert r.returncode != 0 and "over 1 MiB" in r.stderr
    assert not (export / "usage.jsonl").exists()


def test_health_warns_but_does_not_fail_on_skipped_usage_lines(tmp_path):
    with StandIn() as srv:
        srv.skipped = 2
        r = _health(tmp_path, srv)
    assert r.returncode == 0, r.stdout
    assert "WARNING gateway" in r.stdout and "2" in r.stdout


def test_the_module_target_has_no_embeddings_feature_until_a_backend_exists():
    target = yaml.safe_load((ROOT / "modules/gateway/conformance/target.yml").read_text())
    cap = target["capabilities"]["inference"]
    assert "embeddings" not in cap["features"] and "embed_model" not in cap["config"]
    manifest = yaml.safe_load((ROOT / "modules/gateway/module.yml").read_text())
    assert "embeddings" not in manifest["provides"]["slots"]["inference"]["features"]


def test_a_restore_source_that_is_not_a_canonical_absolute_path_is_refused(tmp_path):
    v = {**gateway_vars(tmp_path), "gateway_restore_source": "relative/../src"}
    r = run_role(tmp_path, ROLE, "restore", v)
    assert r.returncode != 0
