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
        ({**MIRROR, "to": "lo"}, "loopback"),
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
# ``tc`` keeps one filter per port the way the kernel's matchall does: a second ``add`` fails
# (EEXIST), ``show`` prints the mirred action as iproute2 does, ``del`` removes it.  ``ip`` prints
# an address for a NIC listed in ``addr/``.  Every call is logged.
TC_STUB = r"""#!/bin/sh
echo "tc $*" >> "$LOG"
case "$1 $2" in
  "qdisc add") exit 0 ;;
  "filter add")
    f="$STATE/$4"
    if [ -e "$FAIL/$4" ]; then echo "Cannot find device $4" >&2; exit 1; fi
    if [ -e "$f" ]; then echo "RTNETLINK answers: File exists" >&2; exit 2; fi
    for a; do to="$a"; done
    echo "action order 1: mirred (Egress Mirror to device $to) pipe" > "$f"
    ;;
  "filter show") [ -e "$STATE/$4" ] && cat "$STATE/$4"; exit 0 ;;
  "filter del") rm -f "$STATE/$4" ;;
esac
"""
IP_STUB = r"""#!/bin/sh
echo "ip $*" >> "$LOG"
if [ "$1" = -4 ]; then
  [ -e "$ADDR/$6" ] && cat "$ADDR/$6"
fi
exit 0
"""


@pytest.fixture
def host(tmp_path):
    """A fake /sys/class/net (two bridges, guest and host ports, the capture NIC) and
    /proc/sys/net/ipv6/conf, the ``tc`` and ``ip`` stubs, and the rendered script pointed at
    them."""
    sys = tmp_path / "sys"
    ports = {
        "vmbr0": ["eno1", "fwpr110p0", "tap120i0", "veth131i0", "fwln110i0", "tap5foo", "tap7xi0"],
        "vmbr1": ["tap121i1"],
    }
    for br, members in ports.items():
        (sys / br / "brif").mkdir(parents=True)
        for m in members:
            (sys / br / "brif" / m).touch()
    (sys / "enp65s0f1").mkdir()
    ipv6 = tmp_path / "ipv6"
    (ipv6 / "enp65s0f1").mkdir(parents=True)
    (ipv6 / "enp65s0f1" / "disable_ipv6").write_text("0\n")
    bin_ = tmp_path / "bin"
    bin_.mkdir()
    for name, text in (("tc", TC_STUB), ("ip", IP_STUB)):
        (bin_ / name).write_text(text, encoding="utf-8")
        (bin_ / name).chmod(0o755)
    dirs = {k: tmp_path / k for k in ("state", "fail", "addr")}
    for d in dirs.values():
        d.mkdir()
    log = tmp_path / "calls.log"
    out = render(fleet_with(tmp_path, {"hv-a": {"mirror": MIRROR}}), "node-mirror")
    text = out["mirror/hv-a/hnx-mirror.sh"]
    text = text.replace("SYS=/sys/class/net", f"SYS={sys}")
    text = text.replace("IPV6=/proc/sys/net/ipv6/conf", f"IPV6={ipv6}")
    script = tmp_path / "hnx-mirror.sh"
    script.write_text(text, encoding="utf-8")
    env = {
        **os.environ,
        "PATH": f"{bin_}:{os.environ['PATH']}",
        "LOG": str(log),
        "STATE": str(dirs["state"]),
        "FAIL": str(dirs["fail"]),
        "ADDR": str(dirs["addr"]),
    }

    def run(*args):
        log.unlink(missing_ok=True)
        r = subprocess.run(["sh", str(script), *args], env=env, capture_output=True, text=True)
        calls = log.read_text(encoding="utf-8").splitlines() if log.exists() else []
        return r, calls

    return sys, ipv6, dirs, run


GUEST_PORTS = ["fwpr110p0", "tap120i0", "veth131i0", "tap121i1"]


def added(calls):
    return [c.split()[4] for c in calls if c.startswith("tc filter add")]


def test_the_script_mirrors_every_guest_port_and_nothing_else(host):
    _, ipv6, dirs, run = host
    r, calls = run()
    assert r.returncode == 0, r.stderr
    assert added(calls) == GUEST_PORTS  # not eno1, fwln110i0, tap5foo or tap7xi0
    assert "ip link set dev enp65s0f1 arp off multicast off up" in calls
    assert (ipv6 / "enp65s0f1" / "disable_ipv6").read_text().strip() == "1"
    assert (dirs["state"] / "tap120i0").read_text() == (
        "action order 1: mirred (Egress Mirror to device enp65s0f1) pipe\n"
    )


def test_a_rerun_keeps_the_filters_instead_of_failing_on_them(host):
    """A matchall filter cannot be replaced: the kernel answers EEXIST.  The second run must see
    the filters in place and leave them, and still mirror a guest that started in between."""
    sys, _, _, run = host
    run()
    (sys / "vmbr0" / "brif" / "tap140i0").touch()
    r, calls = run()
    assert r.returncode == 0, r.stderr
    assert added(calls) == ["tap140i0"]
    assert not [c for c in calls if c.startswith("tc filter del")]


def test_a_filter_to_another_nic_is_replaced(host):
    _, _, dirs, run = host
    run()
    (dirs["state"] / "tap120i0").write_text(
        "action order 1: mirred (Egress Mirror to device old0) pipe\n"
    )
    r, calls = run()
    assert r.returncode == 0, r.stderr
    assert "tc filter del dev tap120i0 ingress pref 49152" in calls
    assert added(calls) == ["tap120i0"]


def test_a_port_that_fails_is_reported_and_the_rest_are_still_mirrored(host):
    _, _, dirs, run = host
    (dirs["fail"] / "tap120i0").touch()
    r, _ = run()
    assert r.returncode == 1 and "could not mirror tap120i0" in r.stderr
    assert sorted(p.name for p in dirs["state"].iterdir()) == sorted(
        set(GUEST_PORTS) - {"tap120i0"}
    )


def test_remove_takes_the_filters_off_and_touches_nothing_else(host):
    _, _, dirs, run = host
    run()
    r, calls = run("--remove")
    assert r.returncode == 0, r.stderr
    assert calls == [f"tc filter del dev {p} ingress pref 49152" for p in GUEST_PORTS]
    assert not list(dirs["state"].iterdir())


@pytest.mark.parametrize(
    ("break_it", "needle"),
    [
        (lambda s, d: shutil.rmtree(s / "enp65s0f1"), "capture NIC enp65s0f1 does not exist"),
        (lambda s, d: (s / "enp65s0f1" / "master").touch(), "is a port of a bridge or bond"),
        (
            lambda s, d: (d["addr"] / "enp65s0f1").write_text("2: enp65s0f1 inet 192.0.2.9/24\n"),
            "has an IPv4 address",
        ),
        (lambda s, d: shutil.rmtree(s / "vmbr1"), "vmbr1 is not a Linux bridge"),
    ],
)
def test_the_script_refuses_a_host_that_does_not_match(host, break_it, needle):
    sys, _, dirs, run = host
    break_it(sys, dirs)
    r, calls = run()
    assert r.returncode == 1 and needle in r.stderr
    assert not added(calls)


def test_the_script_refuses_an_unknown_argument(host):
    *_, run = host
    r, calls = run("--yes")
    assert r.returncode == 2 and calls == []


def test_the_service_is_confined_to_network_administration(tmp_path):
    unit = render(fleet_with(tmp_path, {"hv-a": {"mirror": MIRROR}}), "node-mirror")[
        "mirror/hv-a/hnx-mirror.service"
    ]
    for line in (
        "CapabilityBoundingSet=CAP_NET_ADMIN",
        "NoNewPrivileges=yes",
        "ProtectSystem=strict",
    ):
        assert line in unit.splitlines()
