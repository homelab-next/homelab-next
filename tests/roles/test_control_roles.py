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


# ---------------------------------------------------------------- ssh_hardening
# A fake sshd: -t parses the file and its Includes (failing on "bogus"); -T prints the effective
# settings, first value wins, keys lower-case, as sshd does.
SSHD = r"""
import glob, sys
args = sys.argv[1:]
conf = args[args.index("-f") + 1]
open(LOG, "a").write("sshd " + args[0] + "\n")
seen = {}
def read(path):
    for line in open(path).read().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, _, value = line.partition(" ")
        if key == "bogus":
            sys.exit(255)
        if key.lower() == "include":
            for p in sorted(glob.glob(value)):
                read(p)
        else:
            seen.setdefault(key.lower(), value)
read(conf)
if "-T" in args:
    for k, v in seen.items():
        print(k, v)
"""


def ssh_setup(tmp_path, groups="ansible hnx-ssh", **kw):
    home = tmp_path / "home"
    (home / ".ssh").mkdir(parents=True)
    (home / ".ssh" / "authorized_keys").write_text("ssh-ed25519 AAAAfake ansible\n")
    d = tmp_path / "sshd_config.d"
    d.mkdir()
    main = tmp_path / "sshd_config"
    main.write_text(f"Include {d}/*.conf\nPasswordAuthentication yes\nPermitRootLogin yes\n")
    v = {
        "ssh_hardening_keep_user": "ansible",
        "ssh_hardening_manage_membership": False,
        "ssh_hardening_dropin": str(d / "00-homelabnext-hardening.conf"),
        "ssh_hardening_main_config": str(main),
        "ssh_hardening_state_dir": str(tmp_path / "state"),
        "ssh_hardening_sshd_cli": fake(
            tmp_path / "sshd", SSHD.replace("LOG", repr(str(tmp_path / "calls.log")))
        ),
        "ssh_hardening_id_cli": fake(tmp_path / "id", f"print({groups!r})\n"),
        "ssh_hardening_getent_cli": fake(
            tmp_path / "getent", f"print('ansible:x:1000:1000::{home}:/bin/sh')\n"
        ),
        "ssh_hardening_systemctl_cli": logging_fake(tmp_path, "systemctl"),
        "hnx_controls": [],
    }
    v.update(kw)
    return v


def test_ssh_hardening_tests_the_drop_in_then_installs_and_reloads(tmp_path):
    v = ssh_setup(tmp_path)
    r = run_role(tmp_path, "ssh_hardening", "config", v)
    assert r.returncode == 0, r.stdout + r.stderr
    text = (tmp_path / "sshd_config.d" / "00-homelabnext-hardening.conf").read_text()
    assert "PasswordAuthentication no\n" in text and "AllowGroups hnx-ssh\n" in text
    assert "AuthorizedKeysCommand" not in text
    assert calls(tmp_path) == ["sshd -t", "sshd -T", "systemctl reload ssh"]
    assert sorted(p.name for p in (tmp_path / "state").iterdir()) == []  # nothing staged or owed
    assert run_role(tmp_path, "ssh_hardening", "config", v).returncode == 0
    assert len(calls(tmp_path)) == 3  # unchanged: not tested or reloaded again
    health = run_role(tmp_path, "ssh_hardening", "health", v)
    assert health.returncode == 0, health.stdout


def test_ssh_hardening_takes_directory_keys_with_central_auth(tmp_path):
    v = ssh_setup(tmp_path, hnx_controls=["ssh-hardening", "central-auth"])
    assert run_role(tmp_path, "ssh_hardening", "config", v).returncode == 0
    text = (tmp_path / "sshd_config.d" / "00-homelabnext-hardening.conf").read_text()
    assert (
        "AuthorizedKeysCommand /usr/bin/sss_ssh_authorizedkeys\nAuthorizedKeysCommandUser nobody\n"
        in text
    )


def test_ssh_hardening_never_locks_out_the_ansible_account(tmp_path):
    """An AllowGroups the kept account is not in, or an account with no key, is refused before
    anything goes live: sshd keeps its old configuration and is not reloaded."""
    v = ssh_setup(tmp_path, groups="ansible users")
    r = run_role(
        tmp_path, "ssh_hardening", "config", {**v, "ssh_hardening_allow_groups": ["wheel"]}
    )
    assert r.returncode != 0 and "it would lock out" in r.stdout
    assert not (tmp_path / "sshd_config.d" / "00-homelabnext-hardening.conf").exists()
    assert "systemctl reload ssh" not in calls(tmp_path)


def test_ssh_hardening_refuses_key_only_ssh_for_an_account_without_a_key(tmp_path):
    v = ssh_setup(tmp_path)
    (tmp_path / "home" / ".ssh" / "authorized_keys").write_text("")
    r = run_role(tmp_path, "ssh_hardening", "config", v)
    assert r.returncode != 0 and "key-only SSH would lock it out" in r.stdout
    assert calls(tmp_path) == []  # refused before sshd was even asked


def test_ssh_hardening_refuses_a_drop_in_sshd_rejects_or_that_another_file_overrides(tmp_path):
    v = ssh_setup(tmp_path)
    (tmp_path / "sshd_config").write_text("bogus yes\n" + (tmp_path / "sshd_config").read_text())
    assert run_role(tmp_path, "ssh_hardening", "config", v).returncode != 0
    assert not (tmp_path / "sshd_config.d" / "00-homelabnext-hardening.conf").exists()
    # health reads the live effective configuration: an earlier drop-in that re-enables
    # passwords is caught
    (tmp_path / "sshd_config").write_text(f"Include {tmp_path}/sshd_config.d/*.conf\n")
    assert run_role(tmp_path, "ssh_hardening", "config", v).returncode == 0
    (tmp_path / "sshd_config.d" / "00-aaa-local.conf").write_text("PasswordAuthentication yes\n")
    r = run_role(tmp_path, "ssh_hardening", "health", v)
    assert r.returncode != 0 and "not key-only" in r.stdout


@pytest.mark.parametrize(
    "over",
    [
        {"ssh_hardening_keep_user": "root"},
        {"ssh_hardening_keep_user": "ansible\nPermitRootLogin yes"},
        {"ssh_hardening_allow_groups": []},
        {"ssh_hardening_allow_groups": ["hnx-ssh root"]},
        {"ssh_hardening_authorized_keys_command": "sss_ssh_authorizedkeys"},
    ],
)
def test_ssh_hardening_refuses_bad_inputs(tmp_path, over):
    r = run_role(tmp_path, "ssh_hardening", "config", ssh_setup(tmp_path, **over))
    assert r.returncode != 0 and "ssh_hardening: the kept account" in r.stdout


# ---------------------------------------------------------------- nftables_host
# nft -c goes to the real nft when it is installed (it checks without touching the kernel's
# ruleset); everything else is logged, so a test never loads a ruleset on the test machine.
NFT = r"""
import os, shutil, subprocess, sys
args = sys.argv[1:]
if args[:1] == ["-c"]:
    real = shutil.which("nft", path="/usr/sbin:/sbin:/usr/bin")
    if real:
        sys.exit(subprocess.run([real, *args]).returncode)
    sys.exit(1 if "bogus" in open(args[-1]).read() else 0)
open(LOG, "a").write("nft " + " ".join(args) + "\n")
sys.exit(1 if os.path.exists(FAIL) else 0)
"""

FIREWALL = {
    "policy_out": "REJECT",
    "inbound_allow": [
        {"name": "query-api", "proto": "tcp", "ports": "8443:8444", "source": "198.51.100.128/25"},
        {"name": "ping", "proto": "icmp", "source": "192.0.2.0/24"},
        {"name": "https-public", "proto": "tcp", "ports": "443", "source": "any"},
    ],
    "outbound_allow": [{"name": "dns", "proto": "udp", "ports": "53", "dest": "192.0.2.0/26"}],
}


def nft_vars(tmp_path, **kw):
    body = NFT.replace("LOG", repr(str(tmp_path / "calls.log"))).replace(
        "FAIL", repr(str(tmp_path / "nft.fails"))
    )
    d = {
        "nftables_host_ssh_sources": ["192.0.2.0/26"],
        "nftables_host_firewall": FIREWALL,
        "nftables_host_require_egress": True,
        "nftables_host_config_file": str(tmp_path / "nftables.conf"),
        "nftables_host_state_dir": str(tmp_path / "state"),
        "nftables_host_nft_cli": fake(tmp_path / "nft", body),
    }
    d.update(kw)
    return d


def test_nftables_host_renders_the_models_rules_checks_and_loads_once(tmp_path):
    v = nft_vars(tmp_path)
    r = run_role(tmp_path, "nftables_host", "config", v)
    assert r.returncode == 0, r.stdout + r.stderr
    text = (tmp_path / "nftables.conf").read_text()
    assert "type filter hook input priority filter; policy drop;" in text
    assert 'ip saddr 192.0.2.0/26 tcp dport 22 accept comment "homelabnext-management-ssh"' in text
    assert 'ip saddr 198.51.100.128/25 tcp dport 8443-8444 accept comment "query-api"' in text
    assert 'ip saddr 192.0.2.0/24 ip protocol icmp accept comment "ping"' in text
    assert '\t\ttcp dport 443 accept comment "https-public"' in text
    assert 'policy drop;\n\t\tct state established,related accept\n\t\toif "lo" accept' in text
    assert 'ip daddr 192.0.2.0/26 udp dport 53 accept comment "dns"' in text
    assert text.rstrip().endswith("reject with icmpx type admin-prohibited\n\t}\n}")
    assert "flush ruleset" not in text  # other tables (a container engine's) are left alone
    assert calls(tmp_path) == [f"nft -f {tmp_path / 'nftables.conf'}"]
    assert run_role(tmp_path, "nftables_host", "config", v).returncode == 0
    assert len(calls(tmp_path)) == 1


def test_nftables_host_accept_egress_has_no_output_rules(tmp_path):
    fw = {"policy_out": "ACCEPT", "inbound_allow": [], "outbound_allow": []}
    v = nft_vars(tmp_path, nftables_host_firewall=fw, nftables_host_require_egress=False,
                 nftables_host_ssh_sources=["any"])  # fmt: skip
    assert run_role(tmp_path, "nftables_host", "config", v).returncode == 0
    text = (tmp_path / "nftables.conf").read_text()
    assert "policy accept;\n\t}" in text and "\t\ttcp dport 22 accept" in text


def test_nftables_host_retries_a_failed_load(tmp_path):
    v = nft_vars(tmp_path)
    (tmp_path / "nft.fails").touch()
    assert run_role(tmp_path, "nftables_host", "config", v).returncode != 0
    (tmp_path / "nft.fails").unlink()
    assert run_role(tmp_path, "nftables_host", "config", v).returncode == 0
    assert calls(tmp_path) == [f"nft -f {tmp_path / 'nftables.conf'}"] * 2
    assert not (tmp_path / "state" / "load-pending").exists()


@pytest.mark.parametrize(
    "over",
    [
        {"nftables_host_firewall": {**FIREWALL, "policy_out": "ACCEPT"}},  # egress required
        {"nftables_host_firewall": {**FIREWALL, "policy_out": "accept"}},
        {"nftables_host_ssh_sources": []},
        {"nftables_host_ssh_sources": ["192.0.2.0/26 accept"]},
        {
            "nftables_host_firewall": {
                **FIREWALL,
                "inbound_allow": [{"name": "x", "proto": "tcp", "source": "any"}],
            }
        },
        {
            "nftables_host_firewall": {
                **FIREWALL,
                "inbound_allow": [{"name": 'x"; accept', "proto": "icmp", "source": "any"}],
            }
        },
        {
            "nftables_host_firewall": {
                **FIREWALL,
                "inbound_allow": [{"name": "x", "proto": "icmp", "source": "zone:mgmt"}],
            }
        },
        {
            "nftables_host_firewall": {
                **FIREWALL,
                "outbound_allow": [{"name": "x", "proto": "udp", "ports": "53"}],
            }
        },
    ],
)
def test_nftables_host_refuses_bad_inputs(tmp_path, over):
    r = run_role(tmp_path, "nftables_host", "config", nft_vars(tmp_path, **over))
    assert r.returncode != 0 and "nftables_host: policy_out ACCEPT, DROP or REJECT" in r.stdout
    assert not (tmp_path / "nftables.conf").exists() and calls(tmp_path) == []


@pytest.mark.parametrize(
    ("policies", "egress", "ok"),
    [({"input": "drop", "output": "drop"}, True, True), ({"input": "drop", "output": "accept"}, False, True),
     ({"input": "drop", "output": "accept"}, True, False), ({"input": "accept", "output": "drop"}, False, False)],
)  # fmt: skip
def test_nftables_host_health_reads_the_hook_policies(tmp_path, policies, egress, ok):
    doc = {"nftables": [{"metainfo": {}}, {"table": {"family": "inet", "name": "homelabnext"}}]
           + [{"chain": {"family": "inet", "table": "homelabnext", "name": h, "type": "filter",
                         "hook": h, "prio": 0, "policy": p}} for h, p in policies.items()]}  # fmt: skip
    cli = fake(tmp_path / "nft-json", f"print({json.dumps(doc)!r})\n")
    v = nft_vars(tmp_path, nftables_host_nft_cli=cli, nftables_host_require_egress=egress)
    assert (run_role(tmp_path, "nftables_host", "health", v).returncode == 0) is ok


@pytest.mark.skipif(
    shutil.which("nft", path="/usr/sbin:/sbin:/usr/bin") is None, reason="nft not installed"
)
def test_nftables_host_never_installs_a_ruleset_nft_rejects(tmp_path):
    v = nft_vars(tmp_path)
    assert run_role(tmp_path, "nftables_host", "config", v).returncode == 0
    good = (tmp_path / "nftables.conf").read_text()
    port = {"name": "x", "proto": "tcp", "ports": "70000", "source": "any"}  # the shape passes
    r = run_role(tmp_path, "nftables_host", "config",
                 {**v, "nftables_host_firewall": {**FIREWALL, "inbound_allow": [port]}})  # fmt: skip
    assert r.returncode != 0 and (tmp_path / "nftables.conf").read_text() == good
    assert len(calls(tmp_path)) == 1  # never loaded


# ---------------------------------------------------------------- sssd_ldap
BIND = "bind-pass-fake"
SSSD_ENV = {"HNX_SECRET_IDP_LDAP_BIND_PASSWORD": BIND}


def sssd_vars(tmp_path, local=True, nsswitch="passwd: files systemd sss\n", **kw):
    (tmp_path / "nsswitch.conf").write_text(nsswitch)
    getent = f"import sys\nsys.exit(0 if {local!r} else 2)\n"
    d = {
        "sssd_ldap_ldap_id": "idp-ldap",
        "sssd_ldap_bind_dn": "cn=ldapservice,ou=users,dc=ldap,dc=goauthentik,dc=io",
        "sssd_ldap_break_glass_user": "breakglass",
        "sssd_ldap_config_file": str(tmp_path / "sssd.conf"),
        "sssd_ldap_nsswitch_file": str(tmp_path / "nsswitch.conf"),
        "sssd_ldap_state_dir": str(tmp_path / "state"),
        "sssd_ldap_sssctl_cli": checker(tmp_path, "sssctl"),
        "sssd_ldap_getent_cli": fake(tmp_path / "getent", getent),
        "sssd_ldap_systemctl_cli": logging_fake(tmp_path, "systemctl"),
    }
    d.update(kw)
    return d


def test_sssd_ldap_writes_a_checked_0600_config_over_ldaps_and_restarts(tmp_path):
    v = sssd_vars(tmp_path)
    r = run_role(tmp_path, "sssd_ldap", "config", v, SSSD_ENV)
    assert r.returncode == 0, r.stdout + r.stderr
    conf = tmp_path / "sssd.conf"
    text = conf.read_text()
    assert oct(conf.stat().st_mode & 0o777) == "0o600"
    assert "ldap_uri = ldaps://idp-01.example.internal:636\n" in text
    assert "ldap_tls_reqcert = demand\n" in text and "simple_allow_groups = hnx-admins\n" in text
    assert "filter_users = root, breakglass\n" in text
    assert f"ldap_default_authtok = {BIND}\n" in text
    assert BIND not in r.stdout + r.stderr
    assert calls(tmp_path) == ["sssctl config-check -c <staged>", "systemctl restart sssd"]
    assert run_role(tmp_path, "sssd_ldap", "config", v, SSSD_ENV).returncode == 0
    assert len(calls(tmp_path)) == 2  # unchanged: neither checked nor restarted again


@pytest.mark.parametrize(
    ("kw", "why"),
    [({"local": False}, "is not in /etc/passwd"),
     ({"nsswitch": "passwd: sss files\n"}, "does not resolve files first (sss files)")],
)  # fmt: skip
def test_sssd_ldap_never_takes_away_the_break_glass_account(tmp_path, kw, why):
    r = run_role(tmp_path, "sssd_ldap", "config", sssd_vars(tmp_path, **kw), SSSD_ENV)
    assert r.returncode != 0 and why in r.stdout
    assert not (tmp_path / "sssd.conf").exists() and calls(tmp_path) == []


def test_sssd_ldap_never_installs_a_config_sssctl_rejects(tmp_path):
    v = sssd_vars(tmp_path)
    assert run_role(tmp_path, "sssd_ldap", "config", v, SSSD_ENV).returncode == 0
    good = (tmp_path / "sssd.conf").read_text()
    r = run_role(
        tmp_path, "sssd_ldap", "config", {**v, "sssd_ldap_allow_groups": ["bogus"]}, SSSD_ENV
    )
    assert r.returncode != 0 and (tmp_path / "sssd.conf").read_text() == good
    assert BIND not in r.stdout + r.stderr


@pytest.mark.parametrize(
    ("over", "env"),
    [
        ({"sssd_ldap_ldap_id": "siem"}, SSSD_ENV),  # tcp, not ldaps
        ({"sssd_ldap_bind_dn": "cn=svc\nldap_tls_reqcert = never"}, SSSD_ENV),
        ({"sssd_ldap_break_glass_user": "root"}, SSSD_ENV),
        ({"sssd_ldap_allow_groups": []}, SSSD_ENV),
        ({"sssd_ldap_bind_ref": "bind-pass-fake"}, SSSD_ENV),
    ],
)
def test_sssd_ldap_refuses_bad_inputs(tmp_path, over, env):
    r = run_role(tmp_path, "sssd_ldap", "config", sssd_vars(tmp_path, **over), env)
    assert r.returncode != 0 and "sssd_ldap: the outpost is a registry logical id" in r.stdout
    assert not (tmp_path / "sssd.conf").exists()


def test_sssd_ldap_refuses_a_bind_credential_with_a_line_break(tmp_path):
    env = {"HNX_SECRET_IDP_LDAP_BIND_PASSWORD": "bind-pass-fake\nldap_tls_reqcert = never"}
    r = run_role(tmp_path, "sssd_ldap", "config", sssd_vars(tmp_path), env)
    assert (
        r.returncode != 0 and "holds a line break" in r.stdout and "bind-pass-fake" not in r.stdout
    )
    assert not (tmp_path / "sssd.conf").exists()


@pytest.mark.parametrize(
    ("status", "ok"), [("Online status: Online\n", True), ("Online status: Offline\n", False)]
)
def test_sssd_ldap_health(tmp_path, status, ok):
    v = sssd_vars(
        tmp_path, sssd_ldap_sssctl_cli=fake(tmp_path / "sssctl-status", f"print({status!r})\n")
    )
    assert (run_role(tmp_path, "sssd_ldap", "health", v).returncode == 0) is ok


# ---------------------------------------------------------------- rsyslog_forward
def rsyslog_vars(tmp_path, **kw):
    d = {
        "rsyslog_forward_collector_id": "log-collector",
        "rsyslog_forward_dropin": str(tmp_path / "60-forward.conf"),
        "rsyslog_forward_state_dir": str(tmp_path / "state"),
        "rsyslog_forward_rsyslogd_cli": checker(tmp_path, "rsyslogd"),
        "rsyslog_forward_systemctl_cli": logging_fake(tmp_path, "systemctl"),
    }
    d.update(kw)
    return d


def test_rsyslog_forward_sends_everything_over_tls_to_the_registry_receiver(tmp_path):
    v = rsyslog_vars(tmp_path)
    r = run_role(tmp_path, "rsyslog_forward", "config", v)
    assert r.returncode == 0, r.stdout + r.stderr
    text = (tmp_path / "60-forward.conf").read_text()
    assert (
        '*.* action(type="omfwd"\n    target="logs-01.example.internal" port="6514" protocol="tcp"'
        in text
    )
    assert 'StreamDriver="gtls" StreamDriverMode="1" StreamDriverAuthMode="x509/name"' in text
    assert 'StreamDriverPermittedPeers="logs-01.example.internal"' in text
    assert 'queue.saveOnShutdown="on"' in text and 'action.resumeRetryCount="-1"' in text
    assert calls(tmp_path) == ["rsyslogd -N1 -f <staged>", "systemctl restart rsyslog"]
    plain = run_role(tmp_path, "rsyslog_forward", "config", {**v, "rsyslog_forward_tls": False})
    assert (
        plain.returncode == 0 and "StreamDriver" not in (tmp_path / "60-forward.conf").read_text()
    )


def test_rsyslog_forward_never_installs_a_rule_rsyslogd_rejects(tmp_path):
    v = rsyslog_vars(tmp_path)
    assert run_role(tmp_path, "rsyslog_forward", "config", v).returncode == 0
    good = (tmp_path / "60-forward.conf").read_text()
    r = run_role(
        tmp_path, "rsyslog_forward", "config", {**v, "rsyslog_forward_permitted_peer": "bogus"}
    )
    assert r.returncode != 0 and (tmp_path / "60-forward.conf").read_text() == good
    assert calls(tmp_path)[-1] == "rsyslogd -N1 -f <staged>"


@pytest.mark.parametrize(
    "over",
    [
        {"rsyslog_forward_collector_id": "Logs"},
        {"rsyslog_forward_permitted_peer": 'logs" StreamDriverMode="0'},
        {"rsyslog_forward_selector": "*.* /dev/null\n*.*"},
        {"rsyslog_forward_queue_max_disk": "1 g"},
    ],
)
def test_rsyslog_forward_refuses_bad_inputs(tmp_path, over):
    r = run_role(tmp_path, "rsyslog_forward", "config", rsyslog_vars(tmp_path, **over))
    assert r.returncode != 0 and "rsyslog_forward: the receiver is a registry" in r.stdout
    assert not (tmp_path / "60-forward.conf").exists()


# ---------------------------------------------------------------- disk_encryption_check
LSBLK = {
    "blockdevices": [
        {"name": "vda2", "type": "part", "mountpoints": ["/"], "children": [{"name": "vda", "type": "disk"}]},
        {"name": "data-crypt", "type": "crypt", "mountpoints": ["/srv"],
         "children": [{"name": "vdb1", "type": "part", "children": [{"name": "vdb", "type": "disk"}]}]},
        {"name": "vg-lake", "type": "lvm", "mountpoints": ["/var/lib/lake"],
         "children": [{"name": "pv-crypt", "type": "crypt", "children": [{"name": "vdc", "type": "disk"}]}]},
        {"name": "vdd", "type": "disk", "mountpoints": ["/var/lib/docker", None]},
        {"name": "vde", "type": "disk", "mountpoints": ["/mnt/zfs-encrypted"]},
        {"name": "vdf", "type": "disk", "mountpoints": [None]},
    ]
}  # fmt: skip


def disk_vars(tmp_path, doc=LSBLK, **kw):
    d = {
        "disk_encryption_check_accepted": {
            "/mnt/zfs-encrypted": "encrypted on the hypervisor's pool"
        },
        "disk_encryption_check_lsblk_cli": fake(
            tmp_path / "lsblk", f"print({json.dumps(doc)!r})\n"
        ),
        "disk_encryption_check_state_dir": str(tmp_path / "state"),
    }
    d.update(kw)
    return d


def test_disk_encryption_check_reports_the_volumes_without_a_crypt_layer(tmp_path):
    """Directly on a crypt mapping, or on LVM over one, counts; a bare disk does not; the system
    mounts, unmounted devices and accepted mounts are not data volumes to report."""
    r = run_role(tmp_path, "disk_encryption_check", "main", disk_vars(tmp_path))
    assert r.returncode == 0, r.stdout + r.stderr  # main reports, never fails or changes a disk
    report = json.loads((tmp_path / "state" / "report.json").read_text())
    assert report["unencrypted"] == [{"mountpoint": "/var/lib/docker", "device": "vdd"}]
    assert "/var/lib/docker has no encrypted" in r.stdout
    health = run_role(tmp_path, "disk_encryption_check", "health", disk_vars(tmp_path))
    assert health.returncode != 0 and "no encrypted mapping under /var/lib/docker" in health.stdout
    ok = disk_vars(tmp_path, disk_encryption_check_accepted={
        "/mnt/zfs-encrypted": "encrypted on the hypervisor's pool",
        "/var/lib/docker": "rebuildable cache, nothing at rest worth keeping"})  # fmt: skip
    assert run_role(tmp_path, "disk_encryption_check", "health", ok).returncode == 0


def test_disk_encryption_check_needs_a_reason_for_each_accepted_volume(tmp_path):
    r = run_role(tmp_path, "disk_encryption_check", "health",
                 disk_vars(tmp_path, disk_encryption_check_accepted={"/var/lib/docker": " "}))  # fmt: skip
    assert r.returncode != 0 and "non-empty reason" in r.stdout


@pytest.mark.skipif(shutil.which("lsblk") is None, reason="lsblk not installed")
def test_disk_encryption_check_reads_the_real_lsblk(tmp_path):
    v = disk_vars(tmp_path)
    del v["disk_encryption_check_lsblk_cli"]
    r = run_role(tmp_path, "disk_encryption_check", "main", v)
    assert r.returncode == 0, r.stdout + r.stderr
    assert isinstance(
        json.loads((tmp_path / "state" / "report.json").read_text())["unencrypted"], list
    )


# ---------------------------------------------------------------- config_leak_scan
PEM = "-----BEGIN OPENSSH " + "PRIVATE KEY-----\nfake\n-----END OPENSSH " + "PRIVATE KEY-----\n"


def leak_tree(tmp_path):
    etc = tmp_path / "etc"
    (etc / "app").mkdir(parents=True)
    (etc / "ssh").mkdir()
    (etc / "app" / "settings.conf").write_text("listen = 8080\nlog_level = info\n")
    (etc / "ssh" / "ssh_host_ed25519_key").write_text(PEM)
    (etc / "blob.bin").write_bytes(b"\x00\x01binary")
    return etc


def leak_vars(etc, tmp_path, **kw):
    d = {
        "config_leak_scan_paths": [str(etc)],
        "config_leak_scan_accepted": [f"{etc}/ssh/ssh_host_*_key"],
        "config_leak_scan_python": __import__("sys").executable,
        "config_leak_scan_state_dir": str(tmp_path / "state"),
    }
    d.update(kw)
    return d


def test_config_leak_scan_uses_the_repositorys_scanner_and_never_shows_the_value(tmp_path):
    etc = leak_tree(tmp_path)
    v = leak_vars(etc, tmp_path)
    clean = run_role(tmp_path, "config_leak_scan", "health", v)
    assert clean.returncode == 0, clean.stdout + clean.stderr  # host key accepted, binary skipped
    (etc / "app" / "settings.conf").write_text("listen = 8080\n" + PEM)
    r = run_role(tmp_path, "config_leak_scan", "main", v)
    assert r.returncode == 0, r.stdout + r.stderr
    report = json.loads((tmp_path / "state" / "report.json").read_text())
    assert report["hits"] == [
        {"path": f"{etc}/app/settings.conf", "line": 2, "pattern": "private-key-block"}
    ]
    health = run_role(tmp_path, "config_leak_scan", "health", v)
    assert (
        health.returncode != 0 and f"{etc}/app/settings.conf:2:private-key-block" in health.stdout
    )
    assert "fake" not in health.stdout + r.stdout  # the matched text never leaves the guest
    assert "TASK [config_leak_scan : Remove the scanner]" in health.stdout


def test_config_leak_scan_refuses_a_relative_path(tmp_path):
    r = run_role(tmp_path, "config_leak_scan", "health", leak_vars("etc", tmp_path))
    assert r.returncode != 0 and "at least one absolute path" in r.stdout


# ---------------------------------------------------------------- restore_drill
DRILL = r"""
import json, os, sys
gid, name = sys.argv[1:3]
open(LOG, "a").write("drill " + gid + "\n")
if os.path.exists(os.path.join(DIR, name + ".fails")):
    sys.exit(3)
print(json.dumps({"snapshot": "vm/" + name + "/2026-10-20T02:30:00Z",
                  "verified": not os.path.exists(os.path.join(DIR, name + ".corrupt"))}))
"""
NOW = "2026-10-21T12:00:00Z"
DRILL_GUESTS = [
    {"id": "guest:bus-core", "name": "bus-core", "fqdn": "bus-core.example.internal", "ip": "192.0.2.80", "zone": "data"},
    {"id": "guest:lake-core", "name": "lake-core", "fqdn": "lake-core.example.internal", "ip": "192.0.2.90", "zone": "data"},
    {"id": "guest:edge-core", "name": "edge-core", "fqdn": "edge-core.example.internal", "ip": "203.0.113.10", "zone": "edge"},
]  # fmt: skip


def drill_vars(tmp_path, records=None, **kw):
    state = tmp_path / "drills.json"
    if records is not None:
        state.write_text(json.dumps({"guests": records}))
    body = DRILL.replace("LOG", repr(str(tmp_path / "calls.log"))).replace(
        "DIR", repr(str(tmp_path))
    )
    d = {
        "restore_drill_guests": DRILL_GUESTS,
        "restore_drill_cli": fake(tmp_path / "drill", body),
        "restore_drill_now": NOW,
        "restore_drill_state_file": str(state),
    }
    d.update(kw)
    return d


def test_restore_drill_drills_only_the_due_guests_and_records_the_verified_restore(tmp_path):
    records = {
        "guest:bus-core": {
            "last_verified": "2026-10-01T02:00:00Z",
            "snapshot": "vm/bus-core/old",
        },  # 20 days: not due
        "guest:lake-core": {
            "last_verified": "2026-08-01T02:00:00Z",
            "snapshot": "vm/lake-core/old",
        },  # 81 days: due
    }  # edge-core: never drilled
    r = run_role(tmp_path, "restore_drill", "main", drill_vars(tmp_path, records))
    assert r.returncode == 0, r.stdout + r.stderr
    assert calls(tmp_path) == ["drill guest:lake-core", "drill guest:edge-core"]  # in guest order
    doc = json.loads((tmp_path / "drills.json").read_text())["guests"]
    assert doc["guest:bus-core"] == records["guest:bus-core"]
    assert doc["guest:lake-core"] == {
        "last_verified": NOW,
        "snapshot": "vm/lake-core/2026-10-20T02:30:00Z",
    }
    assert run_role(tmp_path, "restore_drill", "health", drill_vars(tmp_path)).returncode == 0


def test_restore_drill_records_a_failed_or_unverified_drill_and_fails_after_trying_all(tmp_path):
    (tmp_path / "edge-core.fails").touch()
    (tmp_path / "lake-core.corrupt").touch()
    r = run_role(tmp_path, "restore_drill", "main", drill_vars(tmp_path, {}))
    assert r.returncode != 0
    assert "the drill of guest:lake-core, guest:edge-core failed or did not verify" in r.stdout
    doc = json.loads((tmp_path / "drills.json").read_text())["guests"]
    assert doc["guest:bus-core"]["last_verified"] == NOW
    assert doc["guest:edge-core"] == {"last_failure": NOW, "failure": "exit 3"}
    assert doc["guest:lake-core"] == {"last_failure": NOW, "failure": "not verified"}


@pytest.mark.parametrize(
    ("now", "ok"), [("2026-12-29T12:00:00Z", True), ("2027-01-21T12:00:00Z", False)]
)  # 2026-10-01 + 90 days = 2026-12-30
def test_restore_drill_health_marks_a_drill_older_than_90_days_stale(tmp_path, now, ok):
    records = {
        g["id"]: {"last_verified": "2026-10-01T02:00:00Z", "snapshot": "s"} for g in DRILL_GUESTS
    }
    r = run_role(
        tmp_path, "restore_drill", "health", drill_vars(tmp_path, records, restore_drill_now=now)
    )
    assert (r.returncode == 0) is ok, r.stdout
    if not ok:
        assert (
            "no verified restore drill within 90 days for guest:bus-core, guest:edge-core"
            in r.stdout
        )


def test_restore_drill_health_fails_for_a_guest_never_drilled(tmp_path):
    r = run_role(tmp_path, "restore_drill", "health", drill_vars(tmp_path, {}))
    assert r.returncode != 0 and "guest:bus-core, guest:edge-core, guest:lake-core" in r.stdout


def test_restore_drill_backup_export_and_restore_keep_the_records(tmp_path):
    records = {"guest:bus-core": {"last_verified": "2026-10-01T02:00:00Z", "snapshot": "s"}}
    v = drill_vars(tmp_path, records)
    assert run_role(tmp_path, "restore_drill", "backup", v).returncode == 0
    assert json.loads((tmp_path / "backup-manifest.json").read_text())["paths"] == [
        str(tmp_path / "drills.json")
    ]
    out = tmp_path / "export"
    assert (
        run_role(
            tmp_path, "restore_drill", "export", {**v, "restore_drill_export_dir": str(out)}
        ).returncode
        == 0
    )
    (tmp_path / "drills.json").unlink()
    back = run_role(
        tmp_path,
        "restore_drill",
        "restore",
        {**v, "restore_drill_restore_source": str(out / "drills.json")},
    )
    assert (
        back.returncode == 0
        and json.loads((tmp_path / "drills.json").read_text())["guests"] == records
    )


@pytest.mark.parametrize(
    "over",
    [
        {"restore_drill_guests": []},
        {"restore_drill_guests": [{**DRILL_GUESTS[0], "id": "bus-core"}]},
        {"restore_drill_guests": [{**DRILL_GUESTS[0], "name": "bus core; rm"}]},
        {"restore_drill_max_age_days": 10},
        {"restore_drill_now": "yesterday"},
    ],
)
def test_restore_drill_refuses_bad_inputs(tmp_path, over):
    r = run_role(tmp_path, "restore_drill", "main", drill_vars(tmp_path, **over))
    assert (
        r.returncode != 0
        and "restore_drill: at least one guest" in r.stdout
        and calls(tmp_path) == []
    )


# ---------------------------------------------------------------- etckeeper
def git(*args, cwd):
    import subprocess

    return subprocess.run(
        ["git", *args], cwd=cwd, check=True, capture_output=True, text=True
    ).stdout


ETCKEEPER = r"""
import os, subprocess, sys
args = sys.argv[1:]
d = args[args.index("-d") + 1]
open(LOG, "a").write("etckeeper " + args[0] + "\n")
g = ["git", "-C", d, "-c", "user.name=etckeeper", "-c", "user.email=etckeeper@example.invalid"]
if args[0] == "unclean":
    sys.exit(0 if subprocess.run(["git", "-C", d, "status", "--porcelain"], capture_output=True, text=True).stdout else 1)
if args[0] == "commit":  # as etckeeper does with PUSH_REMOTE: commit, then push
    subprocess.run(g + ["add", "-A"], check=True)
    subprocess.run(g + ["commit", "-qm", args[-1]], check=True)
    subprocess.run(g + ["push", "-q", "origin", "HEAD"], check=True)
"""


@pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")
def test_etckeeper_points_origin_at_the_git_service_commits_and_health_sees_the_push(tmp_path):
    etc = tmp_path / "etc"
    etc.mkdir()
    git("init", "-q", "-b", "master", cwd=etc)
    (etc / "etckeeper").mkdir()
    conf = etc / "etckeeper" / "etckeeper.conf"
    conf.write_text('VCS="git"\nPUSH_REMOTE=""\n')
    v = {
        "etckeeper_remote_id": "config-git",
        "etckeeper_remote_path": "etc/bus-core.git",
        "etckeeper_dir": str(etc),
        "etckeeper_conf_file": str(conf),
        "etckeeper_cli": fake(
            tmp_path / "etckeeper", ETCKEEPER.replace("LOG", repr(str(tmp_path / "calls.log")))
        ),
    }
    # the push goes to a local bare repository standing in for the git service
    remote = tmp_path / "remote.git"
    git("init", "-q", "--bare", str(remote), cwd=tmp_path)
    git(
        "config",
        f"url.{remote}.insteadOf",
        "ssh://git-01.example.internal:22/etc/bus-core.git",
        cwd=etc,
    )
    r = run_role(tmp_path, "etckeeper", "config", v)
    assert r.returncode == 0, r.stdout + r.stderr
    assert (
        git("config", "--get", "remote.origin.url", cwd=etc).strip()
        == "ssh://git-01.example.internal:22/etc/bus-core.git"
    )
    assert 'PUSH_REMOTE="origin"\n' in conf.read_text()
    assert calls(tmp_path) == ["etckeeper unclean", "etckeeper commit"]
    again = run_role(tmp_path, "etckeeper", "config", v)
    assert again.returncode == 0 and "changed=0" in again.stdout
    assert git("log", "--format=%s", cwd=remote).strip() == "homelabnext: configuration run"
    assert run_role(tmp_path, "etckeeper", "health", v).returncode == 0
    (etc / "hosts").write_text("changed\n")
    r = run_role(tmp_path, "etckeeper", "health", v)
    assert r.returncode != 0 and "has uncommitted changes" in r.stdout


def test_etckeeper_refuses_a_git_service_not_reached_over_ssh(tmp_path):
    v = {"etckeeper_remote_id": "log-collector", "etckeeper_dir": str(tmp_path)}
    r = run_role(tmp_path, "etckeeper", "config", v)
    assert r.returncode != 0 and "etckeeper: the git service is a registry logical id" in r.stdout
