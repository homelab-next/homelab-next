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
