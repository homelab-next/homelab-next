# SPDX-License-Identifier: Apache-2.0
"""Render the shipped roles through Ansible's template engine (strict undefined vars),
validate compose output with `docker compose config` when docker exists."""

import grp
import http.server
import ipaddress
import json
import os
import pwd
import shutil
import stat
import subprocess
import threading
from pathlib import Path

import pytest
import yaml
from rolerun import first_run

from tests.suite_policy import require_tool

ROOT = Path(__file__).resolve().parents[2]
ANSIBLE = ROOT / "ansible"
GOLDEN = Path(__file__).parent / "golden"
pytestmark = pytest.mark.requires_tool("ansible-playbook")

DIGEST = "sha256:" + "ab" * 32
ZERO = "sha256:" + "0" * 64
LOOPBACK = "127.0.0.1"  # no-raw-endpoint: allow published ports bind loopback in the fixture spec
OWNER = pwd.getpwuid(os.getuid()).pw_name
GROUP = grp.getgrgid(os.getgid()).gr_name


NETMASK = ".".join(["255", "255", "255", "0"])  # a /24


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


def _first(tmp_path):
    return {
        "runner": run_role,
        "role": "example_service",
        "tasks_from": "main",
        "extra_vars": svc_vars(tmp_path),
    }


@first_run(_first)
def test_example_service_main_renders_with_registry_lookup(first):
    r, tmp_path = first
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


def unit_directives(path):
    out = {}
    for line in path.read_text().splitlines():
        if "=" in line and not line.startswith("#"):
            k, _, v = line.partition("=")
            out.setdefault(k, []).append(v)
    return out


def _first(tmp_path):
    return {
        "runner": run_role,
        "role": "example_service",
        "tasks_from": "main",
        "extra_vars": svc_vars(tmp_path),
    }


@first_run(_first)
def test_example_service_unit_runs_unprivileged_and_sandboxed(first):
    r, tmp_path = first
    assert r.returncode == 0, r.stdout + r.stderr
    d = unit_directives(tmp_path / "etc" / "example-service.service")
    assert d["User"] == ["example-service"] and d["Group"] == ["example-service"]
    for key, want in {
        "NoNewPrivileges": "yes",
        "ProtectSystem": "strict",
        "ProtectHome": "yes",
        "PrivateTmp": "yes",
        "PrivateDevices": "yes",
        "CapabilityBoundingSet": "",
        "AmbientCapabilities": "",
        "RestrictSUIDSGID": "yes",
        "ReadWritePaths": str(tmp_path / "data"),
    }.items():
        assert d.get(key) == [want], key


@pytest.mark.parametrize(
    "over",
    [
        {"example_service_data_dir": "/var/lib/x\nExecStartPre=/bin/sh -c id"},
        {"example_service_data_dir": "/var/lib/x y"},
        {"example_service_config_dir": "/etc/%h"},
        {"example_service_logical_id": "x\nUser=root"},
        {"example_service_user": "root"},
        {"example_service_user": "a\nUser=root"},
        {"example_service_listen_port": 80},
    ],
)
@first_run(lambda tmp, over: {"runner": run_role, "role": "example_service", "tasks_from": "main",
                               "extra_vars": svc_vars(tmp, **over)})  # fmt: skip
def test_example_service_refuses_values_that_would_rewrite_the_unit(first, over):
    r, tmp_path = first
    assert r.returncode != 0, over
    assert not (tmp_path / "etc" / "example-service.service").exists()


def _first(tmp_path):
    return {
        "runner": run_role,
        "role": "example_service",
        "tasks_from": "main",
        "extra_vars": svc_vars(tmp_path, example_service_version="1.0: x"),
    }


@first_run(_first)
def test_example_service_config_values_are_quoted(first):
    r, tmp_path = first
    assert r.returncode == 0, r.stdout + r.stderr
    cfg = yaml.safe_load((tmp_path / "etc" / "config.yml").read_text())
    assert cfg["version"] == "1.0: x" and cfg["service_id"] == "example-service"


def _first(tmp_path):
    return {
        "runner": run_role,
        "role": "example_service",
        "tasks_from": "main",
        "extra_vars": svc_vars(tmp_path, example_service_dependencies=["nope"]),
    }


@first_run(_first)
def test_example_service_unknown_dependency_fails(first):
    r, _ = first
    assert r.returncode != 0
    assert "unknown service id 'nope'" in r.stdout + r.stderr


def _first(tmp_path):
    v = svc_vars(tmp_path)
    del v["example_service_logical_id"]
    return {"role": "example_service", "tasks_from": "main", "extra_vars": v}


@first_run(_first)
def test_example_service_missing_required_input_fails(first):
    r, _ = first
    assert r.returncode != 0
    assert "example_service_logical_id" in r.stdout + r.stderr


def _first(tmp_path):
    return {
        "runner": run_role,
        "role": "example_service",
        "tasks_from": "main",
        "extra_vars": svc_vars(tmp_path, example_service_listen_port="not-a-port"),
    }


@first_run(_first)
def test_example_service_wrong_type_rejected_by_argument_specs(first):
    r, _ = first
    assert r.returncode != 0


def _first(tmp_path):
    v = svc_vars(tmp_path)
    return {
        "runner": run_role,
        "role": "example_service",
        "tasks_from": "main",
        "extra_vars": v,
        "setup": {"v": v},
    }


@first_run(_first)
def test_example_service_hooks_backup_upgrade_export_restore(first):
    r, tmp_path = first
    v = first.setup["v"]
    assert r.returncode == 0, r.stdout + r.stderr
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
        "ports": [f"{LOOPBACK}:8080:80"],
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
        "compose_app_owner": OWNER,
        "compose_app_group": GROUP,
        "compose_app_start": False,
        "compose_app_validate_with_docker": docker_compose_ok(),
        # spec() mounts /srv/shared, outside the app's own directories: listed with its reason
        "compose_app_bind_extra": [{"path": "/srv/shared", "reason": "fictional shared media"}],
    }
    d.update(kw)
    return d


def _first(tmp_path):
    return {
        "runner": run_role,
        "role": "compose_app",
        "tasks_from": "main",
        "extra_vars": app_vars(tmp_path),
    }


@first_run(_first)
def test_compose_app_renders_golden_byte_identical(first):
    r, tmp_path = first
    assert r.returncode == 0, r.stdout + r.stderr
    out = (tmp_path / "app" / "docker-compose.yml").read_bytes()
    assert out == (GOLDEN / "compose_app.docker-compose.yml").read_bytes()


def _first(tmp_path):
    require_tool("docker", docker_compose_ok)
    return {
        "runner": run_role,
        "role": "compose_app",
        "tasks_from": "main",
        "extra_vars": app_vars(tmp_path),
    }


@first_run(_first)
def test_compose_app_output_passes_docker_compose_config(first):
    r, tmp_path = first
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


def net(a, b, c, d, prefix=24):
    """A CIDR built from its octets, so no address literal sits in a test."""
    return f"{ipaddress.IPv4Address((a << 24) | (b << 16) | (c << 8) | d)}/{prefix}"


PINNED = net(10, 231, 77, 0)


def _pinned(tmp_path):
    return {
        "runner": run_role,
        "role": "compose_app",
        "tasks_from": "main",
        "extra_vars": app_vars(
            tmp_path,
            compose_app_validate_with_docker=False,
            compose_app_network_subnet=PINNED,
        ),
    }


@first_run(_pinned)
def test_compose_app_pins_the_default_network_when_asked(first):
    r, tmp_path = first
    assert r.returncode == 0, r.stdout + r.stderr
    doc = yaml.safe_load((tmp_path / "app" / "docker-compose.yml").read_text())
    assert doc["networks"] == {"default": {"ipam": {"config": [{"subnet": PINNED}]}}}


def test_compose_app_renders_no_network_block_by_default(tmp_path):
    r = run_role(
        tmp_path, "compose_app", "main", app_vars(tmp_path, compose_app_validate_with_docker=False)
    )
    assert r.returncode == 0, r.stdout + r.stderr
    assert "networks" not in yaml.safe_load((tmp_path / "app" / "docker-compose.yml").read_text())


@pytest.mark.parametrize(
    "subnet",
    [net(10, 0, 0, 0, 16), net(10, 255, 255, 240, 28), net(172, 16, 0, 0, 16),
     net(172, 31, 4, 0, 24), net(192, 168, 0, 0, 16), net(192, 168, 9, 0, 29)],
)  # fmt: skip
def test_compose_app_accepts_private_network_addresses(tmp_path, subnet):
    r = run_role(
        tmp_path,
        "compose_app",
        "network_subnet",
        {"compose_app_network_subnet": subnet, "compose_app_subnet_pattern": SUBNET_PATTERN},
    )
    assert r.returncode == 0, r.stdout + r.stderr


SUBNET_PATTERN = yaml.safe_load((ROOT / "ansible/roles/compose_app/vars/main.yml").read_text())[
    "compose_app_subnet_pattern"
]
BAD_SUBNETS = {
    "no prefix": net(10, 231, 77, 0).split("/")[0],
    "prefix too short": net(10, 0, 0, 0, 8),
    "prefix too long": net(10, 231, 77, 0, 30),
    "not an address": "a/24",
    "octet out of range": "300.1.1.1/24",
    "smuggled line": net(10, 231, 77, 0) + "\nx: y",
    "unspecified": net(0, 0, 0, 0, 16),
    "loopback": net(127, 0, 0, 0, 16),
    "link-local": net(169, 254, 0, 0, 16),
    "multicast": net(224, 0, 0, 0, 16),
    "public": net(8, 8, 0, 0, 16),
    "public, near private": net(172, 32, 0, 0, 16),
    "public, near private 2": net(172, 15, 0, 0, 16),
    "public, near 192.168": net(192, 169, 0, 0, 16),
    "host bits set": net(10, 0, 0, 5),
    "host bits set in a /16": net(192, 168, 1, 0, 16),
}


@pytest.mark.parametrize("bad", list(BAD_SUBNETS.values()), ids=list(BAD_SUBNETS))
def test_compose_app_refuses_a_network_subnet_that_is_not_a_private_network_address(tmp_path, bad):
    r = run_role(
        tmp_path,
        "compose_app",
        "main",
        app_vars(tmp_path, compose_app_validate_with_docker=False, compose_app_network_subnet=bad),
    )
    assert r.returncode != 0 and "compose_app_network_subnet must be" in r.stdout + r.stderr
    assert not (tmp_path / "app" / "docker-compose.yml").exists()


GUEST_FACTS = {
    "network": str(ipaddress.IPv4Address((192 << 24) | (168 << 16) | (50 << 8))),
    "netmask": NETMASK,
    "address": str(ipaddress.IPv4Address((192 << 24) | (168 << 16) | (50 << 8) | 7)),
}


@pytest.mark.parametrize(
    "subnet, host",
    [
        pytest.param(net(192, 168, 0, 0, 16), None, id="a /16 over the guest's own network"),
        pytest.param(net(192, 168, 50, 0, 24), None, id="the guest's own network"),
        pytest.param(net(192, 168, 50, 0, 28), None, id="inside the guest's own network"),
        pytest.param(
            net(10, 0, 0, 0, 16),
            net(10, 0, 4, 9).split("/")[0],
            id="a range holding the guest's address",
        ),
    ],
)
def test_compose_app_refuses_a_network_overlapping_the_guest(tmp_path, subnet, host):
    extra = {"compose_app_network_subnet": subnet, "compose_app_subnet_pattern": SUBNET_PATTERN}
    extra["ansible_default_ipv4"] = GUEST_FACTS
    if host:
        extra["ansible_host"] = host
    r = run_role(tmp_path, "compose_app", "network_subnet", extra)
    assert r.returncode != 0 and "compose_app_network_subnet must not" in r.stdout + r.stderr


def test_compose_app_accepts_a_network_beside_the_guest(tmp_path):
    extra = {
        "compose_app_network_subnet": net(192, 168, 51, 0),
        "compose_app_subnet_pattern": SUBNET_PATTERN,
        "ansible_default_ipv4": GUEST_FACTS,
        "ansible_host": GUEST_FACTS["address"],
    }
    r = run_role(tmp_path, "compose_app", "network_subnet", extra)
    assert r.returncode == 0, r.stdout + r.stderr


def _first(tmp_path):
    s = spec(command=["serve", "--port", "80"], user=1000, env_file=["app.env"])
    return {
        "runner": run_role,
        "role": "compose_app",
        "tasks_from": "main",
        "extra_vars": app_vars(tmp_path, s, compose_app_validate_with_docker=False),
    }


@first_run(_first)
def test_compose_app_optional_fields_render_valid_yaml(first):
    r, tmp_path = first
    assert r.returncode == 0, r.stdout + r.stderr
    doc = yaml.safe_load((tmp_path / "app" / "docker-compose.yml").read_text())
    assert doc["services"]["web"]["command"] == ["serve", "--port", "80"]
    assert doc["services"]["web"]["user"] == "1000"
    assert doc["services"]["web"]["env_file"] == ["app.env"]


def _gpu(tmp_path):
    s = spec(devices=["/dev/dri/renderD128", "nvidia.com/gpu=0"], group_add=[992, "44"])
    return {
        "runner": run_role,
        "role": "compose_app",
        "tasks_from": "main",
        "extra_vars": app_vars(tmp_path, s, compose_app_validate_with_docker=False),
    }


@first_run(_gpu)
def test_compose_app_renders_a_gpu_render_node_and_groups_by_number(first):
    r, tmp_path = first
    assert r.returncode == 0, r.stdout + r.stderr
    doc = yaml.safe_load((tmp_path / "app" / "docker-compose.yml").read_text())
    web = doc["services"]["web"]
    assert web["devices"] == ["/dev/dri/renderD128", "nvidia.com/gpu=0"]
    assert web["group_add"] == ["992", "44"]
    assert web["cap_drop"] == ["ALL"] and "privileged" not in web
    assert "devices" not in doc["services"]["db"] and "group_add" not in doc["services"]["db"]


def _tmpfs(tmp_path):
    s = spec(
        read_only=True,
        tmpfs=[
            {"target": "/tmp", "size_bytes": 268435456, "mode": "1777"},
            {"target": "/scratch", "size_bytes": "8589934592"},
        ],
    )
    return {
        "runner": run_role,
        "role": "compose_app",
        "tasks_from": "main",
        "extra_vars": app_vars(tmp_path, s),
    }


@first_run(_tmpfs)
def test_compose_app_renders_tmpfs_mounts_in_the_long_syntax(first):
    r, tmp_path = first
    assert r.returncode == 0, r.stdout + r.stderr
    path = tmp_path / "app" / "docker-compose.yml"
    web = yaml.safe_load(path.read_text())["services"]["web"]
    # the short-syntax volumes are untouched and the tmpfs mounts follow them
    assert web["volumes"][:2] == ["./data/web:/var/lib/web", "/srv/shared:/shared:ro"]
    assert web["volumes"][2:] == [
        # a leading 0 makes the mode octal: compose reads the number, 1777 would be decimal
        {"type": "tmpfs", "target": "/tmp", "tmpfs": {"size": 268435456, "mode": 0o1777}},
        {"type": "tmpfs", "target": "/scratch", "tmpfs": {"size": 8589934592}},
    ]
    assert web["read_only"] is True
    assert "tmpfs" not in yaml.safe_load(path.read_text())["services"]["db"]
    if docker_compose_ok():
        c = subprocess.run(
            ["docker", "compose", "-f", str(path), "config", "--format", "json"],
            capture_output=True,
            text=True,
        )
        assert c.returncode == 0, c.stderr
        mounts = {
            v["target"]: v
            for v in json.loads(c.stdout)["services"]["web"]["volumes"]
            if v["type"] == "tmpfs"
        }
        assert mounts["/tmp"]["tmpfs"]["mode"] == 0o1777
        assert int(mounts["/scratch"]["tmpfs"]["size"]) == 8589934592


@pytest.mark.parametrize(
    "mount",
    [
        {"target": "/dev/shm", "size_bytes": 4096},  # allowed exactly
        {"target": "/devx", "size_bytes": 4096},  # a prefix of a denied root is not under it
        {"target": "/etcetera", "size_bytes": 4096},
        {"target": "/usr2", "size_bytes": 4096},
        {"target": "/runner", "size_bytes": 4096},
        {"target": "/tmpx", "size_bytes": 4096},  # beside /tmp, not inside it
        {"target": "/m", "size_bytes": 4096, "mode": "1777"},
        {"target": "/m", "size_bytes": 4096, "mode": "0700"},
        {"target": "/m", "size_bytes": 4096, "mode": "0755"},
        {"target": "/m", "size_bytes": 4096, "mode": "755"},
        {"target": "/m", "size_bytes": 4096, "mode": "001"},
    ],
)
def test_compose_app_accepts_a_safe_tmpfs_mount(tmp_path, mount):
    s = spec(tmpfs=[{"target": "/tmp", "size_bytes": 4096}, mount])
    r = run_role(
        tmp_path,
        "compose_app",
        "main",
        app_vars(tmp_path, s, compose_app_validate_with_docker=False),
    )
    assert r.returncode == 0, r.stdout + r.stderr
    web = yaml.safe_load((tmp_path / "app" / "docker-compose.yml").read_text())["services"]["web"]
    got = [v for v in web["volumes"] if isinstance(v, dict) and v["target"] == mount["target"]][0]
    if "mode" in mount:
        assert got["tmpfs"]["mode"] == int(mount["mode"], 8)  # the leading 0 makes it octal


def _only_tmpfs(tmp_path):
    s = spec(tmpfs=[{"target": "/scratch", "size_bytes": 4096}])
    s["services"]["web"].pop("volumes")
    return {
        "runner": run_role,
        "role": "compose_app",
        "tasks_from": "main",
        "extra_vars": app_vars(tmp_path, s),
    }


@first_run(_only_tmpfs)
def test_compose_app_renders_a_volumes_block_for_a_tmpfs_alone(first):
    r, tmp_path = first
    assert r.returncode == 0, r.stdout + r.stderr
    web = yaml.safe_load((tmp_path / "app" / "docker-compose.yml").read_text())["services"]["web"]
    assert web["volumes"] == [{"type": "tmpfs", "target": "/scratch", "tmpfs": {"size": 4096}}]


_DENIED_ROOTS = [
    "/proc", "/sys", "/dev", "/etc", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32",
    "/usr", "/run", "/var/run", "/boot",
]  # fmt: skip
DENIED_TARGETS = [
    "/",
    *_DENIED_ROOTS,
    *(r + "/sub" for r in _DENIED_ROOTS),
    "/dev/shm/sub",
    "/dev/pts",
]

TMPFS_REJECTED = {
    "not a list": {"tmpfs": {"target": "/x", "size_bytes": 4096}},
    "a string": {"tmpfs": "/x"},
    "an entry that is a string": {"tmpfs": ["/x"]},
    "no target": {"tmpfs": [{"size_bytes": 4096}]},
    "no size": {"tmpfs": [{"target": "/x"}]},
    "an unknown key": {"tmpfs": [{"target": "/x", "size_bytes": 4096, "uid": 0}]},
    "a relative target": {"tmpfs": [{"target": "x", "size_bytes": 4096}]},
    "the root": {"tmpfs": [{"target": "/", "size_bytes": 4096}]},
    "a dot-dot target": {"tmpfs": [{"target": "/a/../b", "size_bytes": 4096}]},
    "a trailing slash": {"tmpfs": [{"target": "/x/", "size_bytes": 4096}]},
    "a target that adds a key": {
        "tmpfs": [{"target": "/x\n    privileged: true", "size_bytes": 4096}]
    },
    "an options suffix": {"tmpfs": [{"target": "/x:ro", "size_bytes": 4096}]},
    "zero bytes": {"tmpfs": [{"target": "/x", "size_bytes": 0}]},
    "a negative size": {"tmpfs": [{"target": "/x", "size_bytes": -1}]},
    "below a page": {"tmpfs": [{"target": "/x", "size_bytes": 4095}]},
    "above 1 TiB": {"tmpfs": [{"target": "/x", "size_bytes": 1099511627777}]},
    "a size with a unit": {"tmpfs": [{"target": "/x", "size_bytes": "8g"}]},
    "a size that is a bool": {"tmpfs": [{"target": "/x", "size_bytes": True}]},
    "a size that is a float": {"tmpfs": [{"target": "/x", "size_bytes": 4096.5}]},
    "a size that adds a key": {
        "tmpfs": [{"target": "/x", "size_bytes": "4096\n    privileged: true"}]
    },
    "a // target": {"tmpfs": [{"target": "//x", "size_bytes": 4096}]},
    "a /./ target": {"tmpfs": [{"target": "/./x", "size_bytes": 4096}]},
    "a setuid mode": {"tmpfs": [{"target": "/x", "size_bytes": 4096, "mode": "4755"}]},
    "a setgid mode": {"tmpfs": [{"target": "/x", "size_bytes": 4096, "mode": "2755"}]},
    "setuid and setgid": {"tmpfs": [{"target": "/x", "size_bytes": 4096, "mode": "6777"}]},
    "mode 000": {"tmpfs": [{"target": "/x", "size_bytes": 4096, "mode": "000"}]},
    "mode 0000": {"tmpfs": [{"target": "/x", "size_bytes": 4096, "mode": "0000"}]},
    "mode 1000 (sticky only)": {"tmpfs": [{"target": "/x", "size_bytes": 4096, "mode": "1000"}]},
    "a two-digit mode": {"tmpfs": [{"target": "/x", "size_bytes": 4096, "mode": "77"}]},
    "an 0o mode": {"tmpfs": [{"target": "/x", "size_bytes": 4096, "mode": "0o755"}]},
    **{
        f"the denied path {t}": {"tmpfs": [{"target": t, "size_bytes": 4096}]}
        for t in DENIED_TARGETS
    },
    "a decimal-looking mode (a bare number)": {
        "tmpfs": [{"target": "/x", "size_bytes": 4096, "mode": 1777}]
    },
    "a non-octal mode": {"tmpfs": [{"target": "/x", "size_bytes": 4096, "mode": "1778"}]},
    "a mode of five digits": {"tmpfs": [{"target": "/x", "size_bytes": 4096, "mode": "01777"}]},
    "the same target twice": {
        "tmpfs": [{"target": "/x", "size_bytes": 4096}, {"target": "/x", "size_bytes": 4096}]
    },
    "a target inside another tmpfs": {
        "tmpfs": [{"target": "/x", "size_bytes": 4096}, {"target": "/x/y", "size_bytes": 4096}]
    },
    "a target on a volume": {"tmpfs": [{"target": "/shared", "size_bytes": 4096}]},
    "a target inside a volume": {"tmpfs": [{"target": "/shared/cache", "size_bytes": 4096}]},
    "a target above a volume": {"tmpfs": [{"target": "/var/lib", "size_bytes": 4096}]},
    "a target on an anonymous volume": {
        "volumes": ["/var/lib/anon"],
        "tmpfs": [{"target": "/var/lib/anon", "size_bytes": 4096}],
    },
}


@pytest.mark.parametrize("case", sorted(TMPFS_REJECTED))
def test_compose_app_refuses_a_bad_tmpfs_mount(tmp_path, case):
    r = run_role(
        tmp_path,
        "compose_app",
        "main",
        app_vars(tmp_path, spec(**TMPFS_REJECTED[case]), compose_app_validate_with_docker=False),
    )
    assert r.returncode != 0, r.stdout
    assert "refused tmpfs mount" in r.stdout + r.stderr, r.stdout  # this rule, not another
    assert not (tmp_path / "app" / "docker-compose.yml").exists()


REJECTED = {
    "device /dev/mem": lambda s: s["services"]["web"].update(devices=["/dev/mem"]),
    "device a disk": lambda s: s["services"]["web"].update(devices=["/dev/sda"]),
    "device all of dri": lambda s: s["services"]["web"].update(devices=["/dev/dri"]),
    "device the card node": lambda s: s["services"]["web"].update(devices=["/dev/dri/card0"]),
    "device with a container path and mode": lambda s: s["services"]["web"].update(
        devices=["/dev/dri/renderD128:/dev/x:rwm"]
    ),
    "device a newline": lambda s: s["services"]["web"].update(
        devices=["/dev/dri/renderD128\n    privileged: true"]
    ),
    "device not a list": lambda s: s["services"]["web"].update(devices="/dev/dri/renderD128"),
    "device twice": lambda s: s["services"]["web"].update(
        devices=["/dev/dri/renderD128", "/dev/dri/renderD128"]
    ),
    "cdi any vendor": lambda s: s["services"]["web"].update(devices=["vendor.com/disk=all"]),
    "device a mapping": lambda s: s["services"]["web"].update(
        devices={"/dev/dri/renderD128": "/dev/mem"}
    ),
    "group_add a mapping": lambda s: s["services"]["web"].update(group_add={"44": 0}),
    "group_add over 2^32-1": lambda s: s["services"]["web"].update(group_add=[9999999999]),
    "group_add root": lambda s: s["services"]["web"].update(group_add=[0]),
    "group_add a name": lambda s: s["services"]["web"].update(group_add=["render"]),
    "group_add not a list": lambda s: s["services"]["web"].update(group_add="44"),
    "no healthcheck": lambda s: s["services"]["web"].pop("healthcheck"),
    "latest tag": lambda s: s["services"]["web"].update(tag="latest"),
    "no digest": lambda s: s["services"]["web"].pop("digest"),
    "malformed digest": lambda s: s["services"]["web"].update(digest="sha256:abc"),
    "tag inside image": lambda s: s["services"]["web"].update(image="demo/web:1.2.3"),
    "digest inside image": lambda s: s["services"]["web"].update(image="demo/web@" + DIGEST),
    "placeholder digest": lambda s: s["services"]["web"].update(digest=ZERO),
    "depends_on unknown": lambda s: s["services"]["web"].update(depends_on=["ghost"]),
    "empty services": lambda s: s.update(services={}),
    # YAML injection through a scalar: each of these used to render an extra key
    "tag injects a key": lambda s: s["services"]["web"].update(tag="1.0\n    privileged: true"),
    "tag with trailing newline": lambda s: s["services"]["web"].update(tag="1.0\n"),
    "image injects a key": lambda s: s["services"]["web"].update(
        image="demo/web\n    privileged: true\n    x"
    ),
    "service name injects a key": lambda s: s["services"].update(
        {"x:\n    privileged: true\n  y": s["services"].pop("db")}
    ),
    "interval injects a key": lambda s: s["services"]["web"]["healthcheck"].update(
        interval="5s\n    privileged: true"
    ),
    "restart injects a key": lambda s: s["services"]["web"].update(
        restart="always\n    privileged: true"
    ),
    "tag too long": lambda s: s["services"]["web"].update(tag="1" * 129),
    "tag not a string": lambda s: s["services"]["web"].update(tag=16.4),
    "unknown key": lambda s: s["services"]["web"].update(network_mode="host"),
    # exposure and privilege
    "port without host address": lambda s: s["services"]["web"].update(ports=["8080:80"]),
    "bare container port": lambda s: s["services"]["web"].update(ports=["80"]),
    "port as a number": lambda s: s["services"]["web"].update(ports=[80]),
    "secret in environment": lambda s: s["services"]["db"]["environment"].update(
        POSTGRES_PASSWORD="hunter2"
    ),
    "docker socket": lambda s: s["services"]["web"].update(
        volumes=["/var/run/docker.sock:/var/run/docker.sock"]
    ),
    "docker socket via /run": lambda s: s["services"]["web"].update(volumes=["/run:/host-run"]),
    "host root": lambda s: s["services"]["web"].update(volumes=["/:/host:ro"]),
    "host root as /.": lambda s: s["services"]["web"].update(volumes=["/.:/host"]),
    "host root as //": lambda s: s["services"]["web"].update(volumes=["//:/host"]),
    "host root as /./": lambda s: s["services"]["web"].update(volumes=["/./:/host"]),
    "docker state with a doubled slash": lambda s: s["services"]["web"].update(
        volumes=["/var//lib/docker:/d"]
    ),
    "docker state with a trailing slash": lambda s: s["services"]["web"].update(
        volumes=["/var/lib/docker/:/d"]
    ),
    "docker state through ..": lambda s: s["services"]["web"].update(
        volumes=["/var/lib/app/../docker:/d"]
    ),
    "host root through a relative ..": lambda s: s["services"]["web"].update(
        volumes=["../../../../../..:/host"]
    ),
    "containerd socket": lambda s: s["services"]["web"].update(
        volumes=["/run/containerd/containerd.sock:/c.sock"]
    ),
    "containerd state": lambda s: s["services"]["web"].update(volumes=["/var/lib/containerd:/c"]),
    "podman socket": lambda s: s["services"]["web"].update(
        volumes=["/run/podman/podman.sock:/p.sock"]
    ),
    "rootless podman socket": lambda s: s["services"]["web"].update(
        volumes=["/run/user/1000/podman/podman.sock:/p.sock"]
    ),
    "rootless runtime directory": lambda s: s["services"]["web"].update(
        volumes=["/run/user/1000:/u"]
    ),
    "cri-o socket": lambda s: s["services"]["web"].update(
        volumes=["/var/run/crio/crio.sock:/c.sock"]
    ),
    "podman storage": lambda s: s["services"]["web"].update(
        volumes=["/var/lib/containers/storage:/s"]
    ),
    "all of /var": lambda s: s["services"]["web"].update(volumes=["/var:/v"]),
    # compose interpolation in a source: the text hides host root and the docker socket
    "interpolated host root": lambda s: s["services"]["web"].update(volumes=["${X:-/}:/host"]),
    "interpolated docker socket": lambda s: s["services"]["web"].update(
        volumes=["${X:-/var/run/docker}.sock:/s.sock"]
    ),
    "home through $HOME": lambda s: s["services"]["web"].update(volumes=["$HOME:/home"]),
    "home through ~": lambda s: s["services"]["web"].update(volumes=["~:/home"]),
    "privileged": lambda s: s["services"]["web"].update(privileged=True),
    "cap_add SYS_ADMIN": lambda s: s["services"]["web"].update(cap_add=["SYS_ADMIN"]),
    "cap_add CAP_ALL": lambda s: s["services"]["web"].update(cap_add=["CAP_ALL"]),
    "user root": lambda s: s["services"]["web"].update(user="root"),
    "user 0:0": lambda s: s["services"]["web"].update(user="0:0"),
    "user 00": lambda s: s["services"]["web"].update(user="00"),
    "user 000:0": lambda s: s["services"]["web"].update(user="000:0"),
    "user root:root": lambda s: s["services"]["web"].update(user="root:root"),
    "user as the integer 0": lambda s: s["services"]["web"].update(user=0),
    "group 0": lambda s: s["services"]["web"].update(user="1000:0"),
    "group 000": lambda s: s["services"]["web"].update(user="1000:000"),
    "group root": lambda s: s["services"]["web"].update(user="1000:root"),
    "bad mem_limit": lambda s: s["services"]["web"].update(mem_limit="lots"),
}


def _rejected(tmp, case):
    s = spec()
    REJECTED[case](s)
    v = app_vars(tmp, s, compose_app_validate_with_docker=False)
    return {"runner": run_role, "role": "compose_app", "tasks_from": "main", "extra_vars": v}


@pytest.mark.parametrize("case", sorted(REJECTED))
@first_run(_rejected)
def test_compose_app_rejects_spec_violation(first, case):
    r, tmp_path = first
    assert r.returncode != 0, case
    assert not (tmp_path / "app" / "docker-compose.yml").exists()


def _one_volume(tmp, vol):
    v = app_vars(tmp, spec(volumes=[vol]), compose_app_validate_with_docker=False)
    return {"runner": run_role, "role": "compose_app", "tasks_from": "main", "extra_vars": v}


@pytest.mark.parametrize("vol", ["${X:-/}:/host", "~:/home"])
@first_run(_one_volume)
def test_compose_app_names_the_interpolation_rule_when_it_refuses(first, vol):
    r, _ = first
    assert r.returncode != 0, vol
    assert "has a refused bind source" in r.stdout + r.stderr


def _first(tmp_path):
    s = spec(
        environment={"MODE": "${HOME}", "COUNT": "$X"},
        command=["sh", "-c", "echo $PATH ${Y:-/}"],
    )
    s["services"]["web"]["healthcheck"]["test"] = ["CMD-SHELL", 'test -n "$HOSTNAME"']
    return {
        "runner": run_role,
        "role": "compose_app",
        "tasks_from": "main",
        "extra_vars": app_vars(tmp_path, s, compose_app_validate_with_docker=False),
    }


@first_run(_first)
def test_compose_app_writes_every_dollar_so_compose_reads_it_literally(first):
    """compose interpolates `$` in every value from the environment of whoever runs `compose up`;
    the template writes `$$`, so the container gets exactly the text of the spec."""
    r, tmp_path = first
    assert r.returncode == 0, r.stdout + r.stderr
    web = services_of(tmp_path)["web"]
    assert web["environment"] == {"COUNT": "$$X", "MODE": "$${HOME}"}
    assert web["command"] == ["sh", "-c", "echo $$PATH $${Y:-/}"]
    if not docker_compose_ok():
        return
    c = subprocess.run(
        ["docker", "compose", "-f", str(tmp_path / "app" / "docker-compose.yml"), "config",
         "--format", "json"],
        capture_output=True, text=True,
        # HOME is a value an interpolation would show; DOCKER_CONFIG keeps the docker CLI's own
        # config and plugins where they were (a HOME it cannot read hides the compose plugin)
        env={**os.environ, "HOME": str(tmp_path / "home"), "X": "/", "Y": "/",
             "DOCKER_CONFIG": os.environ.get("DOCKER_CONFIG", os.path.expanduser("~/.docker"))},
    )  # fmt: skip
    assert c.returncode == 0, c.stderr
    # compose prints a literal `$` re-escaped as `$$`; an interpolated value would be the HOME or /
    got = json.loads(c.stdout)["services"]["web"]
    assert got["environment"] == {"COUNT": "$$X", "MODE": "$${HOME}"}
    assert got["command"] == ["sh", "-c", "echo $$PATH $${Y:-/}"]
    assert got["healthcheck"]["test"] == ["CMD-SHELL", 'test -n "$$HOSTNAME"']


def _first(tmp_path):
    data = tmp_path / "app" / "data"
    vols = [
        "./secrets:/run/app-secrets:ro",
        "./secretsx:/x",
        "/var/lib/cache",
        "./data/web:/var/lib/web",
        f"{data}/.config/app:/config:ro",
        f"{data}:/state",
        "/srv/shared:/shared:ro",
        "/run/systemd/journal:/run/systemd/journal:ro",
        "named-volume:/cache",
    ]
    extra = [
        {"path": "/srv/shared", "reason": "fictional shared media"},
        {"path": "/run/systemd/journal", "reason": "the journal socket, read-only"},
        {"path": str(tmp_path / "app" / "secrets"), "reason": "fictional: reads its own env files"},
    ]
    return {
        "runner": run_role,
        "role": "compose_app",
        "tasks_from": "main",
        "extra_vars": app_vars(
            tmp_path,
            spec(volumes=vols),
            compose_app_validate_with_docker=False,
            compose_app_bind_extra=extra,
        ),
        "setup": {"vols": vols},
    }


@first_run(_first)
def test_compose_app_accepts_ordinary_bind_sources(first):
    """Relative sources, named and anonymous volumes, paths under the bind roots and listed paths
    (hidden directories and the listed secrets directory included) pass the allow-list, the
    canonical-source and the runtime rules."""
    r, tmp_path = first
    vols = first.setup["vols"]
    assert r.returncode == 0, r.stdout + r.stderr
    assert services_of(tmp_path)["web"]["volumes"] == vols


OUTSIDE_THE_ROOTS = [
    "/etc:/host-etc",
    "/proc:/host-proc",
    "/dev:/host-dev",
    "/boot:/b",
    "/root:/r",
    "/run/systemd:/s",
    "/var/run/dbus/system_bus_socket:/d.sock",
    "/run/buildkit/buildkitd.sock:/b.sock",
    "/var/lib/rancher:/k3s",
    "/var/log/app:/logs",
    "/srv/other:/o",
]


@pytest.mark.parametrize("vol", OUTSIDE_THE_ROOTS)
@first_run(_one_volume)
def test_compose_app_refuses_a_host_path_outside_the_bind_roots(first, vol):
    r, tmp_path = first
    assert r.returncode != 0, vol
    assert "a host path outside the allowed roots" in r.stdout + r.stderr
    assert not (tmp_path / "app" / "docker-compose.yml").exists()


def refused_sources(r):
    out = r.stdout + r.stderr
    assert r.returncode != 0, out
    return out.split("outside the allowed roots (", 1)[1].split(")", 1)[0].split()


def _first(tmp_path):
    other = str(tmp_path / "other-app" / "secrets" / "db.env")
    ok = ["app.env", "./conf/web.env", f"{tmp_path / 'app' / 'data'}/web.env"]
    s = spec(env_file=[*ok, "/etc/shadow", other])
    return {
        "runner": run_role,
        "role": "compose_app",
        "tasks_from": "main",
        "extra_vars": app_vars(tmp_path, s, compose_app_validate_with_docker=False),
        "setup": {"other": other},
    }


@first_run(_first)
def test_compose_app_env_file_paths_follow_the_bind_source_rule(first):
    """compose reads an env_file on the deploy host and hands it to the container: it used to be
    any string, so /etc/shadow or another application's secrets were accepted."""
    r, tmp_path = first
    other = first.setup["other"]
    assert refused_sources(r) == ["env_file=/etc/shadow", f"env_file={other}"]
    assert not (tmp_path / "app" / "docker-compose.yml").exists()


def _first(tmp_path):
    d = tmp_path / "app"
    vols = [".:/src:ro", "./secrets:/s", f"{d}/secrets:/s2", f"{d}:/app", "./secrets/db.env:/e"]
    s = spec(volumes=vols, env_file=["secrets/db.env", "./secrets/db.env"])
    return {
        "runner": run_role,
        "role": "compose_app",
        "tasks_from": "main",
        "extra_vars": app_vars(tmp_path, s, compose_app_validate_with_docker=False),
        "setup": {"d": d},
    }


@first_run(_first)
def test_compose_app_refuses_the_app_directory_and_its_secrets_unless_listed(first):
    """`.` and secrets/ hold every service's 0600 env file: any service could mount them all."""
    r, _ = first
    d = first.setup["d"]
    want = [".", "./secrets", f"{d}/secrets", str(d), "./secrets/db.env"]
    assert refused_sources(r) == [*want, "env_file=secrets/db.env", "env_file=./secrets/db.env"]


def _first(tmp_path):
    # a sibling whose name only starts like the data root is outside it
    vol = f"{tmp_path / 'app'}-other:/x"
    return {
        "runner": run_role,
        "role": "compose_app",
        "tasks_from": "main",
        "extra_vars": app_vars(
            tmp_path, spec(volumes=[vol]), compose_app_validate_with_docker=False
        ),
    }


@first_run(_first)
def test_compose_app_bind_root_is_a_directory_boundary(first):
    r, _ = first
    assert r.returncode != 0
    assert "outside the allowed roots" in r.stdout + r.stderr


@pytest.mark.parametrize(
    "over",
    [
        {"compose_app_bind_roots": ["/var"]},
        {"compose_app_bind_roots": ["/"]},
        {"compose_app_bind_roots": ["/etc"]},
        {"compose_app_bind_roots": ["relative/dir"]},
        {"compose_app_bind_roots": ["/var/lib/docker"]},
        {"compose_app_bind_extra": [{"path": "/srv/shared"}]},
        {"compose_app_bind_extra": [{"path": "/srv/shared", "reason": "x"}]},
        {"compose_app_bind_extra": [{"path": "/etc", "reason": "fictional, far too wide"}]},
    ],
    ids=["var", "root", "etc", "relative", "docker", "no reason", "short reason", "etc listed"],
)
@first_run(lambda tmp, over: {"runner": run_role, "role": "compose_app", "tasks_from": "main",
                               "extra_vars": app_vars(tmp, compose_app_validate_with_docker=False,
                                                      **over)})  # fmt: skip
def test_compose_app_refuses_a_bind_root_or_listing_that_is_too_wide(first, over):
    r, _ = first
    assert r.returncode != 0, over
    assert "compose_app_bind_roots must be" in r.stdout + r.stderr


def services_of(tmp_path):
    return yaml.safe_load((tmp_path / "app" / "docker-compose.yml").read_text())["services"]


def _first(tmp_path):
    # hnx_module_slice is what the module apply path sets on a module play
    v = app_vars(tmp_path, hnx_module_slice="hnx-web_app-server.slice")
    return {"runner": run_role, "role": "compose_app", "tasks_from": "main", "extra_vars": v}


@first_run(_first)
def test_compose_app_puts_every_container_under_the_module_role_slice(first):
    r, tmp_path = first
    assert r.returncode == 0, r.stdout + r.stderr
    for name, svc in services_of(tmp_path).items():
        assert svc["cgroup_parent"] == "hnx-web_app-server.slice", name
    if not docker_compose_ok():
        return
    c = subprocess.run(
        ["docker", "compose", "-f", str(tmp_path / "app" / "docker-compose.yml"), "config",
         "--format", "json"],
        capture_output=True, text=True,
    )  # fmt: skip
    assert c.returncode == 0, c.stderr
    for svc in json.loads(c.stdout)["services"].values():
        assert svc["cgroup_parent"] == "hnx-web_app-server.slice"


#: never a slice outside the module slices: system.slice and the root slice escape the role's
#: limits, a path is a cgroupfs location, and a value may not add YAML of its own
BAD_PARENTS = [
    "system.slice",
    "-.slice",
    "hnx.slice",
    "hnx-web_app.slice",
    "/hnx.slice/hnx-web_app.slice",
    "hnx-web_app-server",
    "hnx-Web-server.slice",
    "hnx-web_app-server.slice\n    privileged: true",
    "hnx-a-b-c.slice",
]


def _bad_parent(tmp, parent):
    v = app_vars(tmp, compose_app_validate_with_docker=False, compose_app_cgroup_parent=parent)
    return {"runner": run_role, "role": "compose_app", "tasks_from": "main", "extra_vars": v}


def _other_slice(tmp):
    v = app_vars(
        tmp,
        compose_app_validate_with_docker=False,
        hnx_module_slice="hnx-web_app-server.slice",
        compose_app_cgroup_parent="hnx-other-server.slice",
    )
    return {"runner": run_role, "role": "compose_app", "tasks_from": "main", "extra_vars": v}


@first_run(_other_slice)
def test_compose_app_in_a_module_play_takes_only_its_own_role_slice(first):
    r, tmp_path = first
    assert r.returncode != 0
    assert "never another module's" in r.stdout + r.stderr
    assert not (tmp_path / "app" / "docker-compose.yml").exists()


@pytest.mark.parametrize("parent", BAD_PARENTS)
@first_run(_bad_parent)
def test_compose_app_refuses_a_cgroup_parent_that_is_no_module_role_slice(first, parent):
    r, tmp_path = first
    assert r.returncode != 0, parent
    assert "must be empty or a module role slice" in r.stdout + r.stderr
    assert not (tmp_path / "app" / "docker-compose.yml").exists()


def _first(tmp_path):
    s = spec(cap_add=["NET_BIND_SERVICE"], read_only=True, mem_limit="256m", user="1000:1000")
    return {
        "runner": run_role,
        "role": "compose_app",
        "tasks_from": "main",
        "extra_vars": app_vars(tmp_path, s),
    }


@first_run(_first)
def test_compose_app_hardening_defaults(first):
    r, tmp_path = first
    assert r.returncode == 0, r.stdout + r.stderr
    svcs = services_of(tmp_path)
    for svc in svcs.values():
        assert svc["security_opt"] == ["no-new-privileges:true"]
        assert svc["cap_drop"] == ["ALL"]
        assert "privileged" not in svc
    web = svcs["web"]
    assert web["cap_add"] == ["NET_BIND_SERVICE"]
    assert web["read_only"] is True and web["mem_limit"] == "256m" and web["user"] == "1000:1000"


@pytest.mark.parametrize(
    "over, flag",
    [
        ({"privileged": True}, "compose_app_allow_privileged"),
        ({"cap_add": ["SYS_ADMIN"]}, "compose_app_allow_privileged"),
        (
            {"volumes": ["/var/run/docker.sock:/var/run/docker.sock"]},
            "compose_app_allow_docker_socket",
        ),
        ({"user": "root"}, "compose_app_allow_root"),
    ],
)
@first_run(lambda tmp, over, flag: {"runner": run_role, "role": "compose_app", "tasks_from": "main",
                                     "extra_vars": app_vars(tmp, spec(**over), **{flag: True})})  # fmt: skip
def test_compose_app_escape_hatches_need_their_explicit_flag(first, over, flag):
    r, tmp_path = first
    assert r.returncode == 0, r.stdout + r.stderr
    web = services_of(tmp_path)["web"]
    for k, v in over.items():
        assert web[k] == v


def _first(tmp_path):
    refused = ["/", "/var", "/var/lib/docker", "/run/user/1000", "/root/docker.sock"]
    vols = ["/var/run/docker.sock:/var/run/docker.sock"] + [
        f"{v}:/m{i}" for i, v in enumerate(refused)
    ]
    v = app_vars(
        tmp_path, spec(volumes=vols), compose_app_validate_with_docker=False,
        compose_app_allow_docker_socket=True,
    )  # fmt: skip
    return {
        "runner": run_role,
        "role": "compose_app",
        "tasks_from": "main",
        "extra_vars": v,
        "setup": {"refused": refused},
    }


@first_run(_first)
def test_compose_app_docker_socket_flag_unlocks_only_the_socket(first):
    """The flag used to pass every source the runtime pattern matched: host root, /var, /run,
    any path holding docker.sock. Only the socket itself passes now."""
    r, _ = first
    refused = first.setup["refused"]
    assert r.returncode != 0
    out = r.stdout + r.stderr
    listed = out.split("outside the allowed roots (", 1)[1].split(")", 1)[0].split()
    assert listed == refused


def _root_group(tmp, user, ok):
    v = app_vars(
        tmp, spec(user=user), compose_app_validate_with_docker=False,
        compose_app_allow_root_group=True,
    )  # fmt: skip
    return {"runner": run_role, "role": "compose_app", "tasks_from": "main", "extra_vars": v}


@pytest.mark.parametrize(
    ("user", "ok"), [("1000:0", True), ("1000:root", True), ("0:0", False), ("00", False)]
)
@first_run(_root_group)
def test_compose_app_root_group_alone_has_its_own_flag(first, user, ok):
    r, _ = first
    assert (r.returncode == 0) is ok, user


def _first(tmp_path):
    return {
        "runner": run_role,
        "role": "compose_app",
        "tasks_from": "main",
        "extra_vars": app_vars(tmp_path, compose_app_security_opt=[]),
    }


@first_run(_first)
def test_compose_app_dropping_no_new_privileges_needs_the_flag(first):
    r, _ = first
    assert r.returncode != 0


def _first(tmp_path):
    secret = "fake-s3cr3t-$HOME-value"  # a $ must reach the container literally
    v = app_vars(tmp_path, compose_app_secret_env={"db": {"POSTGRES_PASSWORD": secret}})
    return {
        "runner": run_role,
        "role": "compose_app",
        "tasks_from": "main",
        "extra_vars": v,
        "setup": {"secret": secret},
    }


@first_run(_first)
def test_compose_app_secrets_go_to_a_0600_env_file_not_compose_yml(first):
    r, tmp_path = first
    secret = first.setup["secret"]
    assert r.returncode == 0, r.stdout + r.stderr
    assert secret not in r.stdout + r.stderr
    compose_yml = (tmp_path / "app" / "docker-compose.yml").read_text()
    assert secret not in compose_yml
    env = tmp_path / "app" / "secrets" / "db.env"
    assert env.read_text() == f"POSTGRES_PASSWORD='{secret}'\n"
    assert stat.S_IMODE(env.stat().st_mode) == 0o600
    assert stat.S_IMODE(env.parent.stat().st_mode) == 0o700
    assert services_of(tmp_path)["db"]["env_file"] == [str(env)]
    assert "env_file" not in services_of(tmp_path)["web"]


@pytest.mark.parametrize(
    "secret_env",
    [
        {"db": {"POSTGRES_PASSWORD": "fake-never-echoed-it's"}},  # a quote would end the literal
        {"db": {"POSTGRES_PASSWORD": "fake-never-echoed\nINJECTED=1"}},  # a line break adds a var
        {"db": {"BAD-NAME": "fake-never-echoed-1"}},
        {"ghost": {"TOKEN": "fake-never-echoed-2"}},  # not a service in the spec
        {"db": {"POSTGRES_PASSWORD_FILE": "fake-never-echoed-3"}},  # already in environment
    ],
)
@first_run(lambda tmp, secret_env: {"runner": run_role, "role": "compose_app", "tasks_from": "main",
                                     "extra_vars": app_vars(tmp, compose_app_secret_env=secret_env)})  # fmt: skip
def test_compose_app_rejects_bad_secret_env_without_echoing_it(first, secret_env):
    r, tmp_path = first
    assert r.returncode != 0
    for vals in secret_env.values():
        for val in vals.values():
            assert val not in r.stdout + r.stderr
    assert not (tmp_path / "app" / "docker-compose.yml").exists()


def _first(tmp_path):
    s = spec(digest=ZERO)
    return {
        "runner": run_role,
        "role": "compose_app",
        "tasks_from": "main",
        "extra_vars": app_vars(
            tmp_path,
            s,
            compose_app_validate_with_docker=False,
            compose_app_allow_placeholder_digest=True,
        ),
    }


@first_run(_first)
def test_compose_app_placeholder_digest_allowed_only_when_flagged(first):
    r, _ = first
    assert r.returncode == 0, r.stdout + r.stderr


def _first(tmp_path):
    # an anonymous volume (a container path alone) has no host source: accepted, as on main
    # before the bind allow-list, and not a path to back up
    s = spec()
    s["services"]["db"]["volumes"] = ["/var/lib/postgresql/data"]
    v = app_vars(tmp_path, s)
    return {
        "runner": run_role,
        "role": "compose_app",
        "tasks_from": "main",
        "extra_vars": v,
        "setup": {"v": v},
    }


@first_run(_first)
def test_compose_app_backup_manifest_lists_bind_sources(first):
    r, tmp_path = first
    v = first.setup["v"]
    assert r.returncode == 0, r.stdout + r.stderr
    r = run_role(tmp_path, "compose_app", "backup", v)
    assert r.returncode == 0, r.stdout + r.stderr
    m = json.loads((tmp_path / "app" / "backup-manifest.json").read_text())
    assert m["paths"] == sorted({str(tmp_path / "app" / "data"), "/srv/shared"})


def _first(tmp_path):
    v = app_vars(tmp_path)
    return {
        "runner": run_role,
        "role": "compose_app",
        "tasks_from": "main",
        "extra_vars": v,
        "setup": {"v": v},
    }


@first_run(_first)
def test_compose_app_export_and_restore(first):
    r, tmp_path = first
    v = first.setup["v"]
    assert r.returncode == 0, r.stdout + r.stderr
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


def _first(tmp_path):
    v = app_vars(tmp_path)
    return {
        "runner": run_role,
        "role": "compose_app",
        "tasks_from": "main",
        "extra_vars": v,
        "setup": {"v": v},
    }


@first_run(_first)
def test_compose_app_upgrade_hook_validates_pin(first):
    r, tmp_path = first
    v = first.setup["v"]
    assert r.returncode == 0, r.stdout + r.stderr
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
        {"compose_app_upgrade_tag": "1.0\n    privileged: true"},
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
