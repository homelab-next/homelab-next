# SPDX-License-Identifier: Apache-2.0
"""Render the shipped roles through Ansible's template engine (strict undefined vars),
validate compose output with `docker compose config` when docker exists."""

import http.server
import json
import os
import shutil
import subprocess
import threading
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
ANSIBLE = ROOT / "ansible"
GOLDEN = Path(__file__).parent / "golden"
pytestmark = pytest.mark.skipif(
    shutil.which("ansible-playbook") is None, reason="ansible-playbook not installed"
)

DIGEST = "sha256:" + "ab" * 32
ZERO = "sha256:" + "0" * 64


def docker_compose_ok():
    if shutil.which("docker") is None:
        return False
    return subprocess.run(["docker", "compose", "version"], capture_output=True).returncode == 0


def run_role(tmp_path, role, tasks_from, extra_vars, tags=None):
    play = [
        {
            "hosts": "localhost",
            "connection": "local",
            "gather_facts": False,
            "tasks": [{"ansible.builtin.include_role": {"name": role, "tasks_from": tasks_from}}],
        }
    ]
    pb = tmp_path / "play.yml"
    pb.write_text(yaml.safe_dump(play))
    ev = tmp_path / "vars.json"
    ev.write_text(
        json.dumps(
            {"hnx_registry_file": str(ANSIBLE / "inventory/example/registry.yml"), **extra_vars}
        )
    )
    env = dict(
        os.environ,
        ANSIBLE_CONFIG=str(ANSIBLE / "ansible.cfg"),
        ANSIBLE_ERROR_ON_UNDEFINED_VARS="True",
        ANSIBLE_LOCALHOST_WARNING="False",
        ANSIBLE_HOME=str(tmp_path / ".ansible"),
    )
    cmd = ["ansible-playbook", "-i", "localhost,", "-e", f"@{ev}", str(pb)]
    return subprocess.run(cmd, capture_output=True, text=True, env=env, cwd=tmp_path)


def svc_vars(tmp_path, **kw):
    d = {
        "example_service_logical_id": "example-service",
        "example_service_data_dir": str(tmp_path / "data"),
        "example_service_config_dir": str(tmp_path / "etc"),
        "example_service_export_dir": str(tmp_path / "export"),
        "example_service_dependencies": ["query-core", "lake-catalog"],
    }
    d.update(kw)
    return d


def test_example_service_main_renders_with_registry_lookup(tmp_path):
    r = run_role(tmp_path, "example_service", "main", svc_vars(tmp_path))
    assert r.returncode == 0, r.stdout + r.stderr
    cfg = yaml.safe_load((tmp_path / "etc" / "config.yml").read_text())
    assert cfg["dependencies"] == [
        {"id": "query-core", "url": "https://query-01.example.internal:8443"},
        {"id": "lake-catalog", "url": "http://lake-01.example.internal:8181"},
    ]
    assert (
        (tmp_path / "etc" / "example-service.service")
        .read_text()
        .startswith("# Managed by Ansible")
    )


def test_example_service_unknown_dependency_fails(tmp_path):
    r = run_role(
        tmp_path,
        "example_service",
        "main",
        svc_vars(tmp_path, example_service_dependencies=["nope"]),
    )
    assert r.returncode != 0
    assert "unknown service id 'nope'" in r.stdout + r.stderr


def test_example_service_missing_required_input_fails(tmp_path):
    v = svc_vars(tmp_path)
    del v["example_service_logical_id"]
    r = run_role(tmp_path, "example_service", "main", v)
    assert r.returncode != 0
    assert "example_service_logical_id" in r.stdout + r.stderr


def test_example_service_wrong_type_rejected_by_argument_specs(tmp_path):
    r = run_role(
        tmp_path,
        "example_service",
        "main",
        svc_vars(tmp_path, example_service_listen_port="not-a-port"),
    )
    assert r.returncode != 0


def test_example_service_hooks_backup_upgrade_export_restore(tmp_path):
    v = svc_vars(tmp_path)
    assert run_role(tmp_path, "example_service", "main", v).returncode == 0
    (tmp_path / "data" / "f.txt").write_text("payload")
    r = run_role(tmp_path, "example_service", "backup", v)
    assert r.returncode == 0, r.stdout + r.stderr
    manifest = json.loads((tmp_path / "etc" / "backup-manifest.json").read_text())
    assert str(tmp_path / "data") in manifest["paths"]
    r = run_role(tmp_path, "example_service", "export", v)
    assert r.returncode == 0, r.stdout + r.stderr
    assert (tmp_path / "export" / "example-service.tar.gz").stat().st_size > 0
    src = tmp_path / "src"
    src.mkdir()
    (src / "g.txt").write_text("restored")
    r = run_role(
        tmp_path, "example_service", "restore", {**v, "example_service_restore_source": str(src)}
    )
    assert r.returncode == 0, r.stdout + r.stderr
    assert (tmp_path / "data" / "g.txt").read_text() == "restored"
    ok = run_role(
        tmp_path, "example_service", "upgrade", {**v, "example_service_target_version": "1.5.0"}
    )
    assert ok.returncode == 0, ok.stdout + ok.stderr
    bad = run_role(
        tmp_path, "example_service", "upgrade", {**v, "example_service_target_version": "1.0.0"}
    )
    assert bad.returncode != 0


def test_example_service_health_hook_against_fake_server(tmp_path):
    class H(http.server.BaseHTTPRequestHandler):
        code = 200

        def do_GET(self):
            self.send_response(self.code)
            self.end_headers()

        def log_message(self, *a):
            pass

    srv = http.server.HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        v = svc_vars(tmp_path, example_service_listen_port=srv.server_address[1])
        assert run_role(tmp_path, "example_service", "health", v).returncode == 0
        H.code = 503
        assert run_role(tmp_path, "example_service", "health", v).returncode != 0
    finally:
        srv.shutdown()


# ------------------------------------------------------------------ compose_app
def spec(**svc_over):
    web = {
        "image": "registry.example.internal/demo/web",
        "tag": "1.2.3",
        "digest": DIGEST,
        "ports": ["8080:80"],
        "environment": {"MODE": "demo", "COUNT": 3},
        "volumes": ["./data/web:/var/lib/web", "/srv/shared:/shared:ro"],
        "depends_on": ["db"],
        "healthcheck": {"test": ["CMD", "wget", "-q", "--spider", "http://localhost:80/"]},
    }
    web.update(svc_over)
    db = {
        "image": "docker.io/library/postgres",
        "tag": "16.4",
        "digest": DIGEST,
        "environment": {"POSTGRES_PASSWORD_FILE": "/run/secrets/db"},
        "healthcheck": {"test": ["CMD-SHELL", "pg_isready"], "interval": "10s", "retries": 5},
    }
    return {"services": {"web": web, "db": db}}


def app_vars(tmp_path, s=None, **kw):
    d = {
        "compose_app_name": "demo-app",
        "compose_app_spec": s or spec(),
        "compose_app_dir": str(tmp_path / "app"),
        "compose_app_data_dir": str(tmp_path / "app" / "data"),
        "compose_app_export_dir": str(tmp_path / "export"),
        "compose_app_start": False,
        "compose_app_validate_with_docker": docker_compose_ok(),
    }
    d.update(kw)
    return d


def test_compose_app_renders_golden_byte_identical(tmp_path):
    r = run_role(tmp_path, "compose_app", "main", app_vars(tmp_path))
    assert r.returncode == 0, r.stdout + r.stderr
    out = (tmp_path / "app" / "docker-compose.yml").read_bytes()
    assert out == (GOLDEN / "compose_app.docker-compose.yml").read_bytes()


def test_compose_app_output_passes_docker_compose_config(tmp_path):
    if not docker_compose_ok():
        pytest.skip("docker compose not available")
    r = run_role(tmp_path, "compose_app", "main", app_vars(tmp_path))
    assert r.returncode == 0, r.stdout + r.stderr
    c = subprocess.run(
        [
            "docker",
            "compose",
            "-f",
            str(tmp_path / "app" / "docker-compose.yml"),
            "config",
            "--format",
            "json",
        ],
        capture_output=True,
        text=True,
    )
    assert c.returncode == 0, c.stderr
    cfg = json.loads(c.stdout)
    assert set(cfg["services"]) == {"web", "db"}
    for s in cfg["services"].values():
        assert s["healthcheck"]["test"]
        assert "@sha256:" in s["image"]
        assert s["restart"] == "unless-stopped"
    assert cfg["services"]["web"]["depends_on"]["db"]["condition"] == "service_healthy"


def test_compose_app_optional_fields_render_valid_yaml(tmp_path):
    s = spec(command=["serve", "--port", "80"], user=1000, env_file=["app.env"])
    r = run_role(
        tmp_path,
        "compose_app",
        "main",
        app_vars(tmp_path, s, compose_app_validate_with_docker=False),
    )
    assert r.returncode == 0, r.stdout + r.stderr
    doc = yaml.safe_load((tmp_path / "app" / "docker-compose.yml").read_text())
    assert doc["services"]["web"]["command"] == ["serve", "--port", "80"]
    assert doc["services"]["web"]["user"] == "1000"
    assert doc["services"]["web"]["env_file"] == ["app.env"]


REJECTED = {
    "no healthcheck": lambda s: s["services"]["web"].pop("healthcheck"),
    "latest tag": lambda s: s["services"]["web"].update(tag="latest"),
    "no digest": lambda s: s["services"]["web"].pop("digest"),
    "malformed digest": lambda s: s["services"]["web"].update(digest="sha256:abc"),
    "tag inside image": lambda s: s["services"]["web"].update(image="demo/web:1.2.3"),
    "digest inside image": lambda s: s["services"]["web"].update(image="demo/web@" + DIGEST),
    "placeholder digest": lambda s: s["services"]["web"].update(digest=ZERO),
    "depends_on unknown": lambda s: s["services"]["web"].update(depends_on=["ghost"]),
    "empty services": lambda s: s.update(services={}),
}


@pytest.mark.parametrize("case", sorted(REJECTED))
def test_compose_app_rejects_spec_violation(tmp_path, case):
    s = spec()
    REJECTED[case](s)
    r = run_role(
        tmp_path,
        "compose_app",
        "main",
        app_vars(tmp_path, s, compose_app_validate_with_docker=False),
    )
    assert r.returncode != 0, case
    assert not (tmp_path / "app" / "docker-compose.yml").exists()


def test_compose_app_placeholder_digest_allowed_only_when_flagged(tmp_path):
    s = spec(digest=ZERO)
    r = run_role(
        tmp_path,
        "compose_app",
        "main",
        app_vars(
            tmp_path,
            s,
            compose_app_validate_with_docker=False,
            compose_app_allow_placeholder_digest=True,
        ),
    )
    assert r.returncode == 0, r.stdout + r.stderr


def test_compose_app_backup_manifest_lists_bind_sources(tmp_path):
    v = app_vars(tmp_path)
    assert run_role(tmp_path, "compose_app", "main", v).returncode == 0
    r = run_role(tmp_path, "compose_app", "backup", v)
    assert r.returncode == 0, r.stdout + r.stderr
    m = json.loads((tmp_path / "app" / "backup-manifest.json").read_text())
    assert m["paths"] == sorted({str(tmp_path / "app" / "data"), "/srv/shared"})


def test_compose_app_export_and_restore(tmp_path):
    v = app_vars(tmp_path)
    assert run_role(tmp_path, "compose_app", "main", v).returncode == 0
    (tmp_path / "app" / "data" / "x").write_text("1")
    assert run_role(tmp_path, "compose_app", "export", v).returncode == 0
    assert (tmp_path / "export" / "demo-app.tar.gz").exists()
    src = tmp_path / "src"
    src.mkdir()
    (src / "y").write_text("2")
    assert (
        run_role(
            tmp_path, "compose_app", "restore", {**v, "compose_app_restore_source": str(src)}
        ).returncode
        == 0
    )
    assert (tmp_path / "app" / "data" / "y").read_text() == "2"


def test_compose_app_upgrade_hook_validates_pin(tmp_path):
    v = app_vars(tmp_path)
    assert run_role(tmp_path, "compose_app", "main", v).returncode == 0
    up = {
        **v,
        "compose_app_upgrade_service": "web",
        "compose_app_upgrade_tag": "1.3.0",
        "compose_app_upgrade_digest": DIGEST,
    }
    assert run_role(tmp_path, "compose_app", "upgrade", up).returncode == 0
    assert json.loads((tmp_path / "app" / "pending-upgrade.json").read_text())["tag"] == "1.3.0"
    for bad in (
        {"compose_app_upgrade_tag": "latest"},
        {"compose_app_upgrade_digest": ZERO},
        {"compose_app_upgrade_service": "ghost"},
    ):
        assert run_role(tmp_path, "compose_app", "upgrade", {**up, **bad}).returncode != 0


def test_strict_undefined_catches_a_missing_variable(tmp_path):
    play = [
        {
            "hosts": "localhost",
            "connection": "local",
            "gather_facts": False,
            "tasks": [
                {
                    "ansible.builtin.copy": {
                        "dest": str(tmp_path / "o"),
                        "content": "{{ definitely_undefined_var }}",
                    }
                }
            ],
        }
    ]
    pb = tmp_path / "p.yml"
    pb.write_text(yaml.safe_dump(play))
    env = dict(
        os.environ,
        ANSIBLE_CONFIG=str(ANSIBLE / "ansible.cfg"),
        ANSIBLE_ERROR_ON_UNDEFINED_VARS="True",
        ANSIBLE_HOME=str(tmp_path / ".a"),
    )
    r = subprocess.run(
        ["ansible-playbook", "-i", "localhost,", str(pb)], capture_output=True, text=True, env=env
    )
    assert r.returncode != 0 and "undefined" in (r.stdout + r.stderr).lower()


def test_syntax_check_every_role_hook(tmp_path):
    env = dict(
        os.environ, ANSIBLE_CONFIG=str(ANSIBLE / "ansible.cfg"), ANSIBLE_HOME=str(tmp_path / ".a")
    )
    for role in ("example_service", "compose_app"):
        for hook in ("main", "health", "readiness", "backup", "restore", "upgrade", "export"):
            play = [
                {
                    "hosts": "localhost",
                    "tasks": [{"ansible.builtin.include_role": {"name": role, "tasks_from": hook}}],
                }
            ]
            pb = tmp_path / f"{role}-{hook}.yml"
            pb.write_text(yaml.safe_dump(play))
            r = subprocess.run(
                ["ansible-playbook", "--syntax-check", "-i", "localhost,", str(pb)],
                capture_output=True,
                text=True,
                env=env,
            )
            assert r.returncode == 0, (role, hook, r.stderr)
