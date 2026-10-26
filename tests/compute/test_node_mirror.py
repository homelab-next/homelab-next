# SPDX-License-Identifier: Apache-2.0
"""The hypervisor-side mirror (``_nodes.yml`` ``mirror``, target ``node-mirror``): loading,
rendering, and the generated script run against a fake sysfs with ``tc`` and ``ip`` stubbed."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from homelabnext.compute import ComputeError, load_fleet, load_nodes, render
from homelabnext.compute.zones import MappingZones, ZoneInfo

FLEET = Path(__file__).resolve().parent / "fleet"
STUB = MappingZones(
    [
        ZoneInfo("mgmt", "192.0.2.0/24", "192.0.2.1", None, 10),
        ZoneInfo(
            "data", "198.51.100.0/25", "198.51.100.1", ("198.51.100.100", "198.51.100.126"), 20
        ),
        ZoneInfo("compute", "198.51.100.128/25", "198.51.100.129", None, 30),
        ZoneInfo("edge", "203.0.113.0/24", "203.0.113.1", None, 40),
    ]
)

MIRROR = {"to": "enp65s0f1", "bridges": ["vmbr0", "vmbr1"]}


def nodes_file(tmp_path: Path, nodes: dict) -> Path:
    p = tmp_path / "_nodes.yml"
    p.write_text(yaml.safe_dump({"nodes": nodes}), encoding="utf-8")
    return p


def fleet_with(tmp_path: Path, nodes: dict):
    return load_fleet(FLEET, STUB, nodes_path=nodes_file(tmp_path, nodes))


def test_a_mirror_loads(tmp_path):
    got = load_nodes(nodes_file(tmp_path, {"hv-a": {"mirror": MIRROR}}))
    assert got["hv-a"]["mirror"] == MIRROR


@pytest.mark.parametrize(
    ("mirror", "needle"),
    [
        ({"to": "enp65s0f1"}, "both required"),
        ({**MIRROR, "vlan": 10}, "both required"),
        ({**MIRROR, "to": "eth0; reboot"}, "is not an interface name"),
        ({**MIRROR, "to": "a" * 16}, "is not an interface name"),
        ({**MIRROR, "to": "$(id)"}, "is not an interface name"),
        ({**MIRROR, "bridges": []}, "non-empty list"),
        ({**MIRROR, "bridges": "vmbr0"}, "non-empty list"),
        ({**MIRROR, "bridges": ["vmbr0", "vmbr0"]}, "listed twice"),
        ({**MIRROR, "bridges": ["../x"]}, "is not an interface name"),
        ({**MIRROR, "to": "vmbr0"}, "is one of the bridges"),
    ],
)
def test_a_bad_mirror_is_refused(tmp_path, mirror, needle):
    with pytest.raises(ComputeError, match=needle):
        load_nodes(nodes_file(tmp_path, {"hv-a": {"mirror": mirror}}))


def test_no_mirror_renders_only_a_readme(tmp_path):
    out = render(fleet_with(tmp_path, {"hv-a": {}}), "node-mirror")
    assert list(out) == ["mirror/README.md"]
    assert "No node declares a mirror" in out["mirror/README.md"]


def test_a_mirroring_node_gets_a_script_and_its_units(tmp_path):
    out = render(fleet_with(tmp_path, {"hv-a": {"mirror": MIRROR}, "hv-b": {}}), "node-mirror")
    assert sorted(out) == [
        "mirror/README.md",
        "mirror/hv-a/hnx-mirror.service",
        "mirror/hv-a/hnx-mirror.sh",
        "mirror/hv-a/hnx-mirror.timer",
    ]
    sh = out["mirror/hv-a/hnx-mirror.sh"]
    assert 'TO="enp65s0f1"' in sh and 'BRIDGES="vmbr0 vmbr1"' in sh
    assert "ExecStart=/usr/local/sbin/hnx-mirror.sh" in out["mirror/hv-a/hnx-mirror.service"]
    assert "OnCalendar=*:*:0/15" in out["mirror/hv-a/hnx-mirror.timer"]
    assert "| `hv-a` | `vmbr0`, `vmbr1` | `enp65s0f1` |" in out["mirror/README.md"]


def test_a_mirroring_node_name_must_be_a_path_safe_node_name(tmp_path):
    with pytest.raises(ComputeError, match="must be one a guest can name"):
        render(fleet_with(tmp_path, {"../etc": {"mirror": MIRROR}}), "node-mirror")


@pytest.mark.skipif(not shutil.which("shellcheck"), reason="shellcheck not installed")
def test_the_script_passes_shellcheck(tmp_path):
    out = render(fleet_with(tmp_path, {"hv-a": {"mirror": MIRROR}}), "node-mirror")
    script = tmp_path / "hnx-mirror.sh"
    script.write_text(out["mirror/hv-a/hnx-mirror.sh"], encoding="utf-8")
    subprocess.run(["shellcheck", "-s", "sh", str(script)], check=True)


# ------------------------------------------------------- the script against a fake host
@pytest.fixture
def host(tmp_path):
    """A fake /sys/class/net (two bridges, guest and host ports, the capture NIC), ``tc`` and
    ``ip`` stubs that log their arguments, and the rendered script."""
    sys = tmp_path / "sys"
    ports = {
        "vmbr0": ["eno1", "fwpr110p0", "tap120i0", "veth131i0", "fwln110i0", "bond0"],
        "vmbr1": ["tap121i1"],
    }
    for br, members in ports.items():
        (sys / br / "brif").mkdir(parents=True)
        for m in members:
            (sys / br / "brif" / m).touch()
    (sys / "enp65s0f1").mkdir()
    bin_ = tmp_path / "bin"
    bin_.mkdir()
    log = tmp_path / "calls.log"
    for tool in ("tc", "ip"):
        stub = bin_ / tool
        stub.write_text(f'#!/bin/sh\necho "{tool} $*" >> "{log}"\n', encoding="utf-8")
        stub.chmod(0o755)
    out = render(fleet_with(tmp_path, {"hv-a": {"mirror": MIRROR}}), "node-mirror")
    script = tmp_path / "hnx-mirror.sh"
    script.write_text(out["mirror/hv-a/hnx-mirror.sh"], encoding="utf-8")

    def run(*args):
        env = {**os.environ, "PATH": f"{bin_}:{os.environ['PATH']}", "HNX_MIRROR_SYSFS": str(sys)}
        r = subprocess.run(["sh", str(script), *args], env=env, capture_output=True, text=True)
        calls = log.read_text(encoding="utf-8").splitlines() if log.exists() else []
        return r, calls

    return sys, run


def test_the_script_mirrors_every_guest_port_and_no_host_port(host):
    _, run = host
    r, calls = run()
    assert r.returncode == 0, r.stderr
    assert calls[0] == "ip link set dev enp65s0f1 up"
    mirrored = [c.split()[4] for c in calls if c.startswith("tc filter replace")]
    assert mirrored == ["fwpr110p0", "tap120i0", "veth131i0", "tap121i1"]
    assert (
        "tc filter replace dev tap120i0 ingress pref 49152 handle 1 matchall"
        " action mirred egress mirror dev enp65s0f1"
    ) in calls


def test_the_script_is_a_no_op_shape_on_rerun(host):
    _, run = host
    _, first = run()
    _, both = run()
    assert both == first + first  # replace, never add: the same calls each run


def test_remove_takes_the_filters_off_and_touches_nothing_else(host):
    _, run = host
    r, calls = run("--remove")
    assert r.returncode == 0, r.stderr
    assert calls == [
        f"tc filter del dev {p} ingress pref 49152"
        for p in ("fwpr110p0", "tap120i0", "veth131i0", "tap121i1")
    ]


@pytest.mark.parametrize(
    ("break_it", "needle"),
    [
        (lambda s: shutil.rmtree(s / "enp65s0f1"), "capture NIC enp65s0f1 does not exist"),
        (lambda s: (s / "enp65s0f1" / "master").touch(), "is a port of a bridge"),
        (lambda s: shutil.rmtree(s / "vmbr1"), "vmbr1 is not a bridge"),
    ],
)
def test_the_script_refuses_a_host_that_does_not_match(host, break_it, needle):
    sys, run = host
    break_it(sys)
    r, _ = run()
    assert r.returncode == 1 and needle in r.stderr


def test_the_script_refuses_an_unknown_argument(host):
    _, run = host
    r, calls = run("--yes")
    assert r.returncode == 2 and calls == []
