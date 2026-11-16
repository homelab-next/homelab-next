# SPDX-License-Identifier: Apache-2.0
"""compose_app's shared network namespace (a sidecar with no network of its own: a VPN client's
kill-switch), the tunnel device and the narrow NET_ADMIN flag: each is refused unless the spec says
exactly what the rule allows, and rendered when it does."""

from __future__ import annotations

import grp
import os
import pwd
from pathlib import Path

import pytest
import yaml
from rolerun import run_role

HOST = yaml.safe_load(
    (Path(__file__).resolve().parents[2] / "examples" / "services.yml").read_text()
)["hosts"]["dns-core"]["address"]
DIGEST = "sha256:" + "a" * 64
OWNER = pwd.getpwuid(os.getuid()).pw_name
GROUP = grp.getgrgid(os.getgid()).gr_name
HC = {"test": ["CMD", "true"]}


def svc(**over):
    s = {
        "image": "registry.example.internal/demo/x",
        "tag": "1.0",
        "digest": DIGEST,
        "healthcheck": HC,
    }
    s.update(over)
    return s


def spec(**client):
    return {
        "services": {
            "vpn": svc(
                cap_add=["NET_ADMIN"], devices=["/dev/net/tun"], ports=[f"{HOST}:8080:8080"]
            ),
            "client": svc(network_mode="service:vpn", depends_on=["vpn"], **client),
        }
    }


def run(tmp_path: Path, s: dict, **flags):
    v = {
        "compose_app_name": "demo-app",
        "compose_app_spec": s,
        "compose_app_dir": str(tmp_path / "app"),
        "compose_app_data_dir": str(tmp_path / "app" / "data"),
        "compose_app_export_dir": str(tmp_path / "export"),
        "compose_app_owner": OWNER,
        "compose_app_group": GROUP,
        "compose_app_start": False,
        "compose_app_validate_with_docker": False,
        "compose_app_allow_net_admin": True,
    }
    v.update(flags)
    return run_role(tmp_path, "compose_app", "main", v)


def test_a_sidecar_shares_the_vpn_clients_namespace_and_the_tunnel_device_renders(tmp_path):
    r = run(tmp_path, spec())
    assert r.returncode == 0, r.stdout + r.stderr
    doc = yaml.safe_load((tmp_path / "app" / "docker-compose.yml").read_text())["services"]
    assert doc["client"]["network_mode"] == "service:vpn" and "ports" not in doc["client"]
    assert doc["vpn"]["devices"] == ["/dev/net/tun"] and doc["vpn"]["cap_add"] == ["NET_ADMIN"]
    assert doc["vpn"]["cap_drop"] == ["ALL"]


def test_net_admin_needs_its_own_flag_and_unlocks_nothing_else(tmp_path):
    r = run(tmp_path, spec(), compose_app_allow_net_admin=False)
    assert r.returncode != 0 and not (tmp_path / "app" / "docker-compose.yml").exists()
    s = spec()
    s["services"]["vpn"]["cap_add"] = ["NET_ADMIN", "SYS_ADMIN"]  # the flag opens one capability
    assert run(tmp_path, s).returncode != 0
    s2 = spec()
    s2["services"]["vpn"]["privileged"] = True
    assert run(tmp_path, s2).returncode != 0


@pytest.mark.parametrize(
    "client",
    [
        {"network_mode": "host"},
        {"network_mode": "bridge"},
        {"network_mode": "container:abc"},
        {"network_mode": "service:missing"},
        {"network_mode": "service:client"},  # itself
        {"ports": [f"{HOST}:9:9"]},  # a sidecar publishes nothing: the namespace owner does
        {"depends_on": []},  # no start order: it could start before the tunnel is up
    ],
)
def test_a_shared_namespace_is_refused_unless_it_is_exactly_service_of_this_spec(tmp_path, client):
    s = spec()
    s["services"]["client"].update(client)
    r = run(tmp_path, s)
    assert r.returncode != 0, client
    assert not (tmp_path / "app" / "docker-compose.yml").exists()


def test_a_namespace_owner_may_not_itself_share_another(tmp_path):
    s = spec()
    s["services"]["vpn"]["network_mode"] = "service:client"
    s["services"]["vpn"]["depends_on"] = ["client"]
    s["services"]["vpn"].pop("ports")
    assert run(tmp_path, s).returncode != 0


@pytest.mark.parametrize("device", ["/dev/mem", "/dev/net/tun2", "/dev/net/", "/dev/kmsg"])
def test_only_the_tunnel_device_joins_the_gpu_devices(tmp_path, device):
    s = spec()
    s["services"]["vpn"]["devices"] = [device]
    assert run(tmp_path, s).returncode != 0


def test_init_renders_and_must_be_boolean(tmp_path):
    s = spec()
    s["services"]["vpn"]["init"] = True
    assert run(tmp_path, s).returncode == 0
    assert (
        yaml.safe_load((tmp_path / "app" / "docker-compose.yml").read_text())["services"]["vpn"][
            "init"
        ]
        is True
    )
    s["services"]["vpn"]["init"] = "yes"
    assert run(tmp_path, s).returncode != 0
