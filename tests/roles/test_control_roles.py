# SPDX-License-Identifier: Apache-2.0
"""The roles bound to the remaining baseline controls (ADR-0016 decision 7).

Each per-guest role installs distribution packages in ``main``, so the part that matters, its
configuration and the check that keeps a bad one from going live, is its own tasks file and runs
here end to end on localhost against fake daemon commands; the package install is proven by the
``--syntax-check`` of the example lab's playbook (``tests/compute/test_products.py``).  Every
refusal is shown failing on a bad input and passing on a good one."""

from __future__ import annotations

import json
import shutil

import pytest
from rolerun import calls, fake, logging_fake, run_role

pytestmark = pytest.mark.skipif(
    shutil.which("ansible-playbook") is None, reason="ansible-playbook not installed"
)

# A fake checker that fails when the staged file contains the word "bogus" (a stand-in for a
# directive the real daemon rejects) and logs the file it was given.
CHECKER = r"""
import os, sys
args = sys.argv[1:]
path = [a for a in args if os.path.isfile(a)][-1]
open(LOG, "a").write(NAME + " " + " ".join(a if a != path else "<staged>" for a in args) + "\n")
sys.exit(1 if "bogus" in open(path).read() else 0)
"""


def checker(tmp_path, name):
    body = CHECKER.replace("LOG", repr(str(tmp_path / "calls.log"))).replace("NAME", repr(name))
    return fake(tmp_path / name, body)


# ---------------------------------------------------------------- chrony
def chrony_vars(tmp_path, **kw):
    d = {
        "chrony_server_ids": ["time"],
        "chrony_config_file": str(tmp_path / "chrony.conf"),
        "chrony_daemon_cli": checker(tmp_path, "chronyd"),
        "chrony_systemctl_cli": logging_fake(tmp_path, "systemctl"),
        "chrony_state_dir": str(tmp_path / "state"),
    }
    d.update(kw)
    return d


def test_chrony_writes_the_registry_sources_checks_then_restarts_once(tmp_path):
    v = chrony_vars(tmp_path)
    r = run_role(tmp_path, "chrony", "config", v)
    assert r.returncode == 0, r.stdout + r.stderr
    conf = (tmp_path / "chrony.conf").read_text()
    assert "server time-01.example.internal iburst\n" in conf and "pool " not in conf
    assert "makestep 1.0 3\n" in conf
    assert calls(tmp_path) == ["chronyd -p -f <staged>", "systemctl restart chrony"]
    again = run_role(tmp_path, "chrony", "config", v)
    assert again.returncode == 0 and len(calls(tmp_path)) == 2  # unchanged: no restart


def test_chrony_never_installs_a_configuration_chronyd_rejects(tmp_path):
    v = chrony_vars(tmp_path)
    assert run_role(tmp_path, "chrony", "config", v).returncode == 0
    good = (tmp_path / "chrony.conf").read_text()
    r = run_role(tmp_path, "chrony", "config", {**v, "chrony_pools": ["bogus.example.internal"]})
    assert r.returncode != 0
    assert (tmp_path / "chrony.conf").read_text() == good
    assert calls(tmp_path)[-1] == "chronyd -p -f <staged>"  # checked, never restarted


def test_chrony_keeps_a_failed_restart_owed(tmp_path):
    v = chrony_vars(tmp_path)
    (tmp_path / "systemctl.fails").touch()
    assert run_role(tmp_path, "chrony", "config", v).returncode != 0
    (tmp_path / "systemctl.fails").unlink()
    assert run_role(tmp_path, "chrony", "config", v).returncode == 0
    assert calls(tmp_path)[-1] == "systemctl restart chrony"
    assert not (tmp_path / "state" / "restart-pending").exists()


@pytest.mark.parametrize(
    "over",
    [
        {"chrony_server_ids": []},
        {"chrony_server_ids": ["Time"]},
        {"chrony_pools": ["pool.example.internal\nallow all"]},
        {"chrony_max_offset": 0},
    ],
)
def test_chrony_refuses_bad_inputs(tmp_path, over):
    r = run_role(tmp_path, "chrony", "config", chrony_vars(tmp_path, **over))
    assert r.returncode != 0 and "chrony: time sources are registry" in r.stdout
    assert not (tmp_path / "chrony.conf").exists()


@pytest.mark.parametrize(
    ("line", "ok"),
    [
        ("C0000201,time-01,3,1792500000.1,-0.000012,0.0,0.0,1.0,0.0,0.1,0.01,0.01,64.0,Normal", True),
        ("C0000201,time-01,3,1792500000.1,1.5,0.0,0.0,1.0,0.0,0.1,0.01,0.01,64.0,Normal", False),
        ("00000000,,0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,1.0,1.0,0.0,Not synchronised", False),
    ],
)  # fmt: skip
def test_chrony_health_reads_the_tracking_line(tmp_path, line, ok):
    cli = fake(tmp_path / "chronyc", f"print({line!r})\n")
    r = run_role(tmp_path, "chrony", "health", chrony_vars(tmp_path, chrony_cli=cli))
    assert (r.returncode == 0) is ok, r.stdout


# ---------------------------------------------------------------- unattended_upgrades
def uu_vars(tmp_path, **kw):
    d = {
        "unattended_upgrades_reboot_time": "03:30",
        "unattended_upgrades_distribution": "Debian",
        "unattended_upgrades_config_file": str(tmp_path / "52hnx"),
        "unattended_upgrades_stamp_file": str(tmp_path / "stamp"),
        "unattended_upgrades_state_dir": str(tmp_path / "state"),
    }
    d.update(kw)
    return d


@pytest.mark.skipif(shutil.which("apt-config") is None, reason="apt-config not installed")
def test_unattended_upgrades_allows_only_the_security_origin(tmp_path):
    """The real apt-config reads the file: #clear drops whatever the package's own file listed,
    so the effective origins are exactly the security origin (and the opt-in extras)."""
    package_file = tmp_path / "50unattended-upgrades"
    package_file.write_text(
        'Unattended-Upgrade::Origins-Pattern { "origin=Debian,codename=${distro_codename},label=Debian"; };\n'
    )
    v = uu_vars(tmp_path, unattended_upgrades_extra_origins=["origin=Lab,label=Lab mirror"])
    r = run_role(tmp_path, "unattended_upgrades", "config", v)
    assert r.returncode == 0, r.stdout + r.stderr
    import subprocess

    dump = subprocess.run(
        ["apt-config", "-c", str(package_file), "-c", str(tmp_path / "52hnx"), "dump",
         "Unattended-Upgrade"], capture_output=True, text=True, check=True,
    ).stdout  # fmt: skip
    origins = [
        x for x in dump.splitlines() if x.startswith("Unattended-Upgrade::Origins-Pattern:: ")
    ]
    assert origins == [
        'Unattended-Upgrade::Origins-Pattern:: "origin=Debian,codename=${distro_codename}-security,label=Debian-Security";',
        'Unattended-Upgrade::Origins-Pattern:: "origin=Lab,label=Lab mirror";',
    ]
    assert 'Unattended-Upgrade::Automatic-Reboot-Time "03:30";' in dump
    never = run_role(
        tmp_path, "unattended_upgrades", "config", {**v, "unattended_upgrades_reboot_time": "never"}
    )
    assert never.returncode == 0
    assert 'Automatic-Reboot "false"' in (tmp_path / "52hnx").read_text()


def test_unattended_upgrades_never_installs_a_file_apt_cannot_parse(tmp_path):
    v = uu_vars(tmp_path, unattended_upgrades_apt_config_cli=checker(tmp_path, "apt-config"))
    assert run_role(tmp_path, "unattended_upgrades", "config", v).returncode == 0
    good = (tmp_path / "52hnx").read_text()
    bad = run_role(
        tmp_path, "unattended_upgrades", "config", {**v, "unattended_upgrades_blocklist": ["bogus"]}
    )
    assert bad.returncode != 0 and (tmp_path / "52hnx").read_text() == good


@pytest.mark.parametrize(
    "over",
    [
        {"unattended_upgrades_reboot_time": "3:30"},
        {"unattended_upgrades_reboot_time": "25:00"},
        {"unattended_upgrades_distribution": "Fedora"},
        {
            "unattended_upgrades_extra_origins": [
                'origin=Lab"; APT::Periodic::Unattended-Upgrade "0'
            ]
        },
        {"unattended_upgrades_blocklist": ["linux-};"]},
        {"unattended_upgrades_mail": "root\n"},
    ],
)
def test_unattended_upgrades_refuses_bad_inputs(tmp_path, over):
    r = run_role(tmp_path, "unattended_upgrades", "config", uu_vars(tmp_path, **over))
    assert r.returncode != 0 and "unattended_upgrades: a reboot window" in r.stdout
    assert not (tmp_path / "52hnx").exists()


def test_unattended_upgrades_health_reads_the_stamp(tmp_path):
    import os

    v = uu_vars(tmp_path)
    assert run_role(tmp_path, "unattended_upgrades", "health", v).returncode != 0  # never ran
    (tmp_path / "stamp").touch()
    assert run_role(tmp_path, "unattended_upgrades", "health", v).returncode == 0
    os.utime(tmp_path / "stamp", (86400, 86400))  # 1970: long stale
    r = run_role(tmp_path, "unattended_upgrades", "health", v)
    assert r.returncode != 0 and "no unattended run" in r.stdout


# ---------------------------------------------------------------- os_hardening
ALL_ITEMS = ["sysctl", "filesystems", "services", "file_modes", "core_dumps"]


def osh_vars(tmp_path, **kw):
    secret = tmp_path / "shadow"
    secret.write_text("x\n")
    secret.chmod(0o644)
    d = {
        "os_hardening_items": ALL_ITEMS,
        "os_hardening_sysctl": {"kernel.dmesg_restrict": 1, "fs.suid_dumpable": 0},
        "os_hardening_file_modes": [
            {"path": str(secret), "mode": "0640"},
            {"path": str(tmp_path / "absent"), "mode": "0600"},
        ],
        "os_hardening_sysctl_file": str(tmp_path / "60-hardening.conf"),
        "os_hardening_modprobe_file": str(tmp_path / "modprobe.conf"),
        "os_hardening_limits_file": str(tmp_path / "limits.conf"),
        "os_hardening_sysctl_cli": logging_fake(tmp_path, "sysctl"),
    }
    d.update(kw)
    return d


def test_os_hardening_writes_and_applies_each_item_once(tmp_path):
    v = osh_vars(tmp_path)
    r = run_role(tmp_path, "os_hardening", "config", v)
    assert r.returncode == 0, r.stdout + r.stderr
    assert (tmp_path / "60-hardening.conf").read_text().splitlines()[1:] == [
        "fs.suid_dumpable = 0",
        "kernel.dmesg_restrict = 1",
    ]
    modprobe = (tmp_path / "modprobe.conf").read_text()
    assert "install cramfs /bin/false\nblacklist cramfs\n" in modprobe
    assert "squashfs" not in modprobe and "vfat" not in modprobe
    assert "*    hard    core    0" in (tmp_path / "limits.conf").read_text()
    assert oct((tmp_path / "shadow").stat().st_mode & 0o777) == "0o640"
    assert not (tmp_path / "absent").exists()  # a missing file is never created
    assert calls(tmp_path) == [f"sysctl -p {tmp_path / '60-hardening.conf'}"]
    assert run_role(tmp_path, "os_hardening", "config", v).returncode == 0
    assert len(calls(tmp_path)) == 1  # unchanged: not applied again


def test_os_hardening_leaves_out_what_is_not_chosen(tmp_path):
    v = osh_vars(tmp_path, os_hardening_items=["core_dumps"])
    assert run_role(tmp_path, "os_hardening", "config", v).returncode == 0
    assert sorted(p.name for p in tmp_path.glob("*.conf")) == ["limits.conf"]
    assert oct((tmp_path / "shadow").stat().st_mode & 0o777) == "0o644" and calls(tmp_path) == []


@pytest.mark.parametrize(
    "over",
    [
        {"os_hardening_items": ["sysctl", "selinux"]},
        {"os_hardening_sysctl": {"kernel.dmesg_restrict\nkernel.x": 1}},
        {"os_hardening_sysctl": {"kernel.dmesg_restrict": "1\nkernel.x = 0"}},
        {"os_hardening_filesystems": ["cramfs /bin/true"]},
        {"os_hardening_file_modes": [{"path": "etc/shadow", "mode": "0640"}]},
        {"os_hardening_file_modes": [{"path": "/etc/shadow", "mode": "640"}]},
    ],
)
def test_os_hardening_refuses_bad_inputs(tmp_path, over):
    r = run_role(tmp_path, "os_hardening", "config", osh_vars(tmp_path, **over))
    assert r.returncode != 0 and "os_hardening: items among" in r.stdout
    assert not list(tmp_path.glob("*.conf"))


@pytest.mark.parametrize(("live", "ok"), [("0\n1\n", True), ("1\n1\n", False)])
def test_os_hardening_health_compares_the_live_settings(tmp_path, live, ok):
    v = osh_vars(
        tmp_path,
        os_hardening_sysctl_cli=fake(tmp_path / "sysctl-live", f"print({live!r}, end='')\n"),
    )
    (tmp_path / "shadow").chmod(0o640)
    r = run_role(tmp_path, "os_hardening", "health", v)
    assert (r.returncode == 0) is ok, r.stdout
    (tmp_path / "shadow").chmod(0o644)
    r = run_role(tmp_path, "os_hardening", "health", {**v, "os_hardening_items": ["file_modes"]})
    assert r.returncode != 0 and "has mode 0644, not 0640" in r.stdout
