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
from pathlib import Path

import pytest
from rolerun import calls, fake, last_run_vars, logging_fake, run_cases, run_role

ROOT = Path(__file__).resolve().parents[2]

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
text = open(path).read()
text += "".join(open(t).read() for t in text.split() if t.startswith(BASE) and os.path.isfile(t))  # includes (the test's own files only)
sys.exit(1 if "bogus" in text else 0)
"""


def checker(tmp_path, name):
    body = (
        CHECKER.replace("LOG", repr(str(tmp_path / "calls.log")))
        .replace("NAME", repr(name))
        .replace("BASE", repr(str(tmp_path)))
    )
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


def test_chrony_refuses_bad_inputs(tmp_path):
    results = run_cases(
        tmp_path,
        "chrony",
        "config",
        chrony_vars(tmp_path),
        [
            {"chrony_server_ids": []},
            {"chrony_server_ids": ["Time"]},
            {"chrony_pools": ["pool.example.internal\nallow all"]},
            {"chrony_max_offset": 0},
        ],
    )
    assert all(f and "chrony: time sources are registry" in m for f, m in results), results
    assert not (tmp_path / "chrony.conf").exists()


CHRONY_TRACKING = [
    ("C0000201,time-01,3,1792500000.1,-0.000012,0.0,0.0,1.0,0.0,0.1,0.01,0.01,64.0,Normal", True),
    ("C0000201,time-01,3,1792500000.1,1.5,0.0,0.0,1.0,0.0,0.1,0.01,0.01,64.0,Normal", False),
    ("00000000,,0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,1.0,1.0,0.0,Not synchronised", False),
]  # fmt: skip


def test_chrony_health_reads_the_tracking_line(tmp_path):
    cases = [{"chrony_cli": fake(tmp_path / f"chronyc-{i}", f"print({line!r})\n")}
             for i, (line, _) in enumerate(CHRONY_TRACKING)]  # fmt: skip
    results = run_cases(tmp_path, "chrony", "health", chrony_vars(tmp_path), cases)
    assert [not f for f, _ in results] == [ok for _, ok in CHRONY_TRACKING], results


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


def test_unattended_upgrades_refuses_bad_inputs(tmp_path):
    results = run_cases(
        tmp_path,
        "unattended_upgrades",
        "config",
        uu_vars(tmp_path),
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
    assert all(f and "unattended_upgrades: a reboot window" in m for f, m in results), results
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


def test_os_hardening_refuses_bad_inputs(tmp_path):
    results = run_cases(
        tmp_path,
        "os_hardening",
        "config",
        osh_vars(tmp_path),
        [
            {"os_hardening_items": ["sysctl", "selinux"]},
            {"os_hardening_sysctl": {"kernel.dmesg_restrict\nkernel.x": 1}},
            {"os_hardening_sysctl": {"kernel.dmesg_restrict": "1\nkernel.x = 0"}},
            {"os_hardening_filesystems": ["cramfs /bin/true"]},
            {"os_hardening_file_modes": [{"path": "etc/shadow", "mode": "0640"}]},
            {"os_hardening_file_modes": [{"path": "/etc/shadow", "mode": "640"}]},
        ],
    )
    assert all(f and "os_hardening: items among" in m for f, m in results), results
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


def test_ssh_hardening_refuses_bad_inputs(tmp_path):
    results = run_cases(
        tmp_path,
        "ssh_hardening",
        "config",
        ssh_setup(tmp_path),
        [
            {"ssh_hardening_keep_user": "root"},
            {"ssh_hardening_keep_user": "ansible\nPermitRootLogin yes"},
            {"ssh_hardening_allow_groups": []},
            {"ssh_hardening_allow_groups": ["hnx-ssh root"]},
            {"ssh_hardening_authorized_keys_command": "sss_ssh_authorizedkeys"},
        ],
    )
    assert all(f and "ssh_hardening: the kept account" in m for f, m in results), results


# ---------------------------------------------------------------- nftables_host


def _real_nft_check() -> str | None:
    """The real nft, when it can check a ruleset unprivileged (in a user and network namespace,
    as tests/network does); None where it cannot (not installed, or no unprivileged namespaces)."""
    import subprocess
    import tempfile

    nft = shutil.which("nft", path="/usr/sbin:/sbin:/usr/bin")
    if not (nft and shutil.which("unshare")):
        return None
    with tempfile.NamedTemporaryFile("w", suffix=".nft") as probe:
        probe.write("table inet probe {\n}\n")
        probe.flush()
        r = subprocess.run(["unshare", "-rn", nft, "-c", "-f", probe.name], capture_output=True)
    return nft if r.returncode == 0 else None


REAL_NFT = _real_nft_check()

# nft -c goes to the real nft when it can check unprivileged (it never touches the kernel's
# ruleset), else to a stand-in that refuses the word "bogus"; everything else is logged, so a
# test never loads a ruleset on the test machine.
NFT = r"""
import os, subprocess, sys
args = sys.argv[1:]
if args[:1] == ["-c"]:
    if REAL_NFT_PATH:
        sys.exit(subprocess.run(["unshare", "-rn", REAL_NFT_PATH, *args]).returncode)
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
    body = (
        NFT.replace("LOG", repr(str(tmp_path / "calls.log")))
        .replace("FAIL", repr(str(tmp_path / "nft.fails")))
        .replace("REAL_NFT_PATH", repr(REAL_NFT))
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
    assert (
        '"homelabnext-refused-destination"\n\t\tct state established,related accept\n\t\toif "lo" accept'
        in text
    )
    assert 'ip daddr 192.0.2.0/26 udp dport 53 accept comment "dns"' in text
    assert text.rstrip().endswith(
        'log prefix "hnx-egress-drop: " level warn\n'
        "\t\treject with icmpx type admin-prohibited\n\t}\n}"
    )
    assert "flush ruleset" not in text  # other tables (a container engine's) are left alone
    assert calls(tmp_path) == [f"nft -f {tmp_path / 'nftables.conf'}"]
    assert run_role(tmp_path, "nftables_host", "config", v).returncode == 0
    assert len(calls(tmp_path)) == 1


def test_nftables_host_renders_a_physical_model_runtime_default_deny(tmp_path):
    """gpu-1 (kind host, cap:inference; tests/compute/physical) end to end: the inventory the
    compute model renders for it is what the role is fed, and the ruleset that passes nft's own
    check drops every outbound packet its lab allows do not name."""
    import importlib.util

    import yaml

    from homelabnext.compute import load_fleet, render

    spec = importlib.util.spec_from_file_location(
        "compute_test_firewall", ROOT / "tests" / "compute" / "test_firewall.py"
    )
    tf = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tf)
    fleet = load_fleet(tf.physical_fleet(tmp_path / "src"), tf.STUB)
    hv = yaml.safe_load(render(fleet, "inventory")["host_vars/gpu-1.example.internal.yml"])
    egress = "egress-filter" in hv["hnx_controls"]
    v = nft_vars(tmp_path, nftables_host_firewall=hv["hnx_firewall"],
                 nftables_host_require_egress=egress)  # fmt: skip
    r = run_role(tmp_path, "nftables_host", "config", v)
    assert egress and r.returncode == 0, r.stdout + r.stderr
    text = (tmp_path / "nftables.conf").read_text()
    out = text.split("chain output {", 1)[1]
    assert "type filter hook output priority filter; policy drop;" in out
    assert 'ip daddr 198.51.100.0/25 tcp dport 443 accept comment "model-store"' in out
    assert out.rstrip().endswith('log prefix "hnx-egress-drop: " level warn\n\t}\n}')
    assert 'ip saddr 198.51.100.0/25 tcp dport 8000 accept comment "inference-api"' in text
    assert calls(tmp_path) == [f"nft -f {tmp_path / 'nftables.conf'}"]


def test_nftables_host_accept_egress_refuses_only_the_metadata_services(tmp_path):
    fw = {"policy_out": "ACCEPT", "inbound_allow": [], "outbound_allow": []}
    v = nft_vars(tmp_path, nftables_host_firewall=fw, nftables_host_require_egress=False,
                 nftables_host_ssh_sources=["any"])  # fmt: skip
    assert run_role(tmp_path, "nftables_host", "config", v).returncode == 0
    text = (tmp_path / "nftables.conf").read_text()
    out = text.split("chain output {", 1)[1]
    assert "policy accept;" in out and "\t\ttcp dport 22 accept" in text
    assert out.rstrip().endswith('"homelabnext-refused-destination"\n\t}\n}')
    assert "accept" not in out.split("policy accept;", 1)[1] and "hnx-egress-drop" not in out


def test_nftables_host_refuses_cloud_metadata_before_any_allow(tmp_path):
    """No outbound_allow (here the whole link-local range) and no policy reopens the metadata
    services: their drop is the output chain's first verdict, ahead of established flows."""
    for policy in ("ACCEPT", "DROP"):
        fw = {
            "policy_out": policy,
            "inbound_allow": [],
            "outbound_allow": []
            if policy == "ACCEPT"
            else [{"name": "link-local", "proto": "tcp", "ports": "80", "dest": "169.254.0.0/16"}],
        }
        v = nft_vars(tmp_path, nftables_host_firewall=fw, nftables_host_require_egress=False)
        assert run_role(tmp_path, "nftables_host", "config", v).returncode == 0
        out = (tmp_path / "nftables.conf").read_text().split("chain output {", 1)[1]
        lines = [
            ln.strip() for ln in out.splitlines() if ln.strip() and not ln.strip().startswith("#")
        ]
        verdicts = [
            ln
            for ln in lines[1:]
            if ln.endswith(("accept", "drop")) or '" accept' in ln or "drop comment" in ln
        ]
        assert (
            verdicts[0]
            == (
                "ip daddr { 169.254.169.254, 169.254.170.2, 192.0.0.192, 100.100.100.200 } "  # scrub-allow: cloud metadata, refused
                'drop comment "homelabnext-refused-destination"'
            )
        )
        assert (
            verdicts[1]
            == 'ip6 daddr { fd00:ec2::254 } drop comment "homelabnext-refused-destination"'  # scrub-allow: cloud metadata, refused
        )
        assert lines[1].endswith('log prefix "hnx-egress-refused: " level warn')
        assert ("hnx-egress-drop: " in out) is (policy == "DROP")
        # forwarded (container bridge) traffic: the same refusal, ahead of a container engine's
        # forward chains (priority filter is 0), and nothing else
        text = (tmp_path / "nftables.conf").read_text()
        fwd = text.split("chain forward {", 1)[1].split("chain output {", 1)[0]
        assert "type filter hook forward priority filter - 10; policy accept;" in fwd
        assert fwd.count('drop comment "homelabnext-refused-destination"') == 2
        assert "accept comment" not in fwd and "hnx-egress-drop" not in fwd


def test_nftables_host_retries_a_failed_load(tmp_path):
    v = nft_vars(tmp_path)
    (tmp_path / "nft.fails").touch()
    assert run_role(tmp_path, "nftables_host", "config", v).returncode != 0
    (tmp_path / "nft.fails").unlink()
    assert run_role(tmp_path, "nftables_host", "config", v).returncode == 0
    assert calls(tmp_path) == [f"nft -f {tmp_path / 'nftables.conf'}"] * 2
    assert not (tmp_path / "state" / "load-pending").exists()


def test_nftables_host_refuses_bad_inputs(tmp_path):
    results = run_cases(
        tmp_path,
        "nftables_host",
        "config",
        nft_vars(tmp_path),
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
    want = "nftables_host: policy_out ACCEPT, DROP or REJECT"
    assert all(f and want in m for f, m in results), results
    assert not (tmp_path / "nftables.conf").exists() and calls(tmp_path) == []


NFT_POLICIES = [
    ({"input": "drop", "output": "drop"}, True, True), ({"input": "drop", "output": "accept"}, False, True),
    ({"input": "drop", "output": "accept"}, True, False), ({"input": "accept", "output": "drop"}, False, False),
]  # fmt: skip


def test_nftables_host_health_reads_the_hook_policies(tmp_path):
    cases = []
    for i, (policies, egress, _) in enumerate(NFT_POLICIES):
        doc = {"nftables": [{"metainfo": {}}, {"table": {"family": "inet", "name": "homelabnext"}}]
               + [{"chain": {"family": "inet", "table": "homelabnext", "name": h, "type": "filter",
                             "hook": h, "prio": 0, "policy": p}} for h, p in policies.items()]}  # fmt: skip
        cli = fake(tmp_path / f"nft-json-{i}", f"print({json.dumps(doc)!r})\n")
        cases.append({"nftables_host_nft_cli": cli, "nftables_host_require_egress": egress})
    results = run_cases(tmp_path, "nftables_host", "health", nft_vars(tmp_path), cases)
    assert [not f for f, _ in results] == [ok for _, _, ok in NFT_POLICIES], results


@pytest.mark.skipif(
    REAL_NFT is None, reason="nft with an unprivileged network namespace is not available"
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


def test_sssd_ldap_refuses_bad_inputs(tmp_path):
    cases = [
        over
        for over, _ in [
            ({"sssd_ldap_ldap_id": "siem"}, SSSD_ENV),  # tcp, not ldaps
            ({"sssd_ldap_bind_dn": "cn=svc\nldap_tls_reqcert = never"}, SSSD_ENV),
            ({"sssd_ldap_break_glass_user": "root"}, SSSD_ENV),
            ({"sssd_ldap_allow_groups": []}, SSSD_ENV),
            ({"sssd_ldap_bind_ref": "bind-pass-fake"}, SSSD_ENV),
        ]
    ]
    results = run_cases(tmp_path, "sssd_ldap", "config", sssd_vars(tmp_path), cases, SSSD_ENV)
    want = "sssd_ldap: the outpost is a registry logical id"
    assert all(f and want in m for f, m in results), results
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


def test_rsyslog_forward_refuses_bad_inputs(tmp_path):
    results = run_cases(
        tmp_path,
        "rsyslog_forward",
        "config",
        rsyslog_vars(tmp_path),
        [
            {"rsyslog_forward_collector_id": "Logs"},
            {"rsyslog_forward_permitted_peer": 'logs" StreamDriverMode="0'},
            {"rsyslog_forward_selector": "*.* /dev/null\n*.*"},
            {"rsyslog_forward_queue_max_disk": "1 g"},
        ],
    )
    assert all(f and "rsyslog_forward: the receiver is a registry" in m for f, m in results), (
        results
    )
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


def test_restore_drill_refuses_bad_inputs(tmp_path):
    results = run_cases(
        tmp_path,
        "restore_drill",
        "main",
        drill_vars(tmp_path),
        [
            {"restore_drill_guests": []},
            {"restore_drill_guests": [{**DRILL_GUESTS[0], "id": "bus-core"}]},
            {"restore_drill_guests": [{**DRILL_GUESTS[0], "name": "bus core; rm"}]},
            {"restore_drill_max_age_days": 10},
            {"restore_drill_now": "yesterday"},
        ],
    )
    assert all(f and "restore_drill: at least one guest" in m for f, m in results), results
    assert calls(tmp_path) == []


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


# ---------------------------------------------------------------- the scheduled scanners
# Each scanner role writes a scan script and an OnCalendar timer; the tests render both, run the
# script itself against a fake scanner, and point the health hook at what the run left behind.
def scanner_vars(tmp_path, role, **kw):
    d = {
        f"{role}_unit_dir": str(tmp_path / "units"),
        f"{role}_script": str(tmp_path / "bin" / "scan"),
        f"{role}_state_dir": str(tmp_path / "state"),
        f"{role}_systemctl_cli": logging_fake(tmp_path, "systemctl"),
        **last_run_vars(tmp_path, role),
    }
    (tmp_path / "units").mkdir(exist_ok=True)
    d.update(kw)
    return d


def run_scan(tmp_path):
    import subprocess

    subprocess.run(["sh", str(tmp_path / "bin" / "scan")], check=True, capture_output=True)


def test_scanner_units_are_oncalendar_timers_enabled_once(tmp_path):
    v = scanner_vars(
        tmp_path,
        "lynis",
        lynis_min_hardening_index=60,
        lynis_dpkg_verify=False,
    )
    r = run_role(tmp_path, "lynis", "config", v)
    assert r.returncode == 0, r.stdout + r.stderr
    timer = (tmp_path / "units" / "hnx-lynis.timer").read_text()
    assert "OnCalendar=*-*-* 04:10:00 UTC\nPersistent=true\n" in timer
    assert "OnBootSec" not in timer and "OnUnitActiveSec" not in timer  # docs/role-interface.md 8
    # the unit names the script's catalogued install path (docs/scripts.md, installs_to)
    service = (tmp_path / "units" / "hnx-lynis.service").read_text()
    assert "ExecStart=/usr/local/libexec/homelabnext/lynis-scan\n" in service
    assert calls(tmp_path) == ["systemctl daemon-reload", "systemctl enable --now hnx-lynis.timer"]
    assert run_role(tmp_path, "lynis", "config", v).returncode == 0 and len(calls(tmp_path)) == 2
    bad = run_role(tmp_path, "lynis", "config", {**v, "lynis_schedule": "daily\nExecStart=/bin/sh"})
    assert bad.returncode != 0 and "lynis: an OnCalendar schedule ending in UTC" in bad.stdout


LYNIS = r"""
import sys
args = sys.argv[1:]
report = args[args.index("--report-file") + 1]
open(report, "w").write(REPORT)
"""


@pytest.mark.parametrize(
    ("report", "ok", "why"),
    [
        ("hardening_index=72\nsuggestion[]=SSH-7408|tune|\n", True, ""),
        ("hardening_index=55\n", False, "hardening index 55 (at least 60)"),
        (
            "hardening_index=80\nwarning[]=KRNL-5830|Reboot of system is most likely needed|\n",
            False,
            "1\nwarning(s)",
        ),
    ],
)
def test_lynis_run_and_health(tmp_path, report, ok, why):
    cli = fake(tmp_path / "lynis-cli", LYNIS.replace("REPORT", repr(report)))
    v = scanner_vars(
        tmp_path, "lynis", lynis_min_hardening_index=60, lynis_dpkg_verify=False, lynis_cli=cli
    )
    assert run_role(tmp_path, "lynis", "health", v).returncode != 0  # never ran
    assert run_role(tmp_path, "lynis", "config", v).returncode == 0
    run_scan(tmp_path)
    r = run_role(tmp_path, "lynis", "health", v)
    assert (r.returncode == 0) is ok, r.stdout
    assert why.split("\n")[0] in r.stdout


def test_lynis_files_the_run_through_the_broker_when_a_socket_is_set(tmp_path):
    cli = fake(
        tmp_path / "lynis-cli",
        LYNIS.replace("REPORT", repr("hardening_index=70\nwarning[]=X-1|w|\n")),
    )
    filed, argv = tmp_path / "filed.json", tmp_path / "argv"
    hnx = fake(
        tmp_path / "hnx",
        "import shutil, sys\n"
        f"shutil.copy(sys.argv[sys.argv.index('--params-file') + 1], {str(filed)!r})\n"
        f"open({str(argv)!r}, 'w').write(' '.join(sys.argv[1:5]))\n",
    )
    v = scanner_vars(tmp_path, "lynis", lynis_min_hardening_index=60, lynis_dpkg_verify=False, lynis_cli=cli,
                     lynis_hnx_cli=hnx, lynis_broker_socket="/run/hnx-broker/broker.sock")  # fmt: skip
    assert run_role(tmp_path, "lynis", "config", v).returncode == 0
    run_scan(tmp_path)
    assert (tmp_path / "argv").read_text() == "broker call finding.write --socket"
    filed = json.loads((tmp_path / "filed.json").read_text())
    assert filed["name"].startswith("lynis-") and "Hardening index: 70" in filed["content"]
    assert "- X-1|w|" in filed["content"]


# ---------------------------------------------------------------- aide
AIDE_PATHS = [{"path": "/etc/ssh", "rule": "p+i+n+u+g+s+m+c+sha256"}]


def test_aide_checks_the_drop_in_in_a_test_config_before_it_goes_live(tmp_path):
    main = tmp_path / "aide.conf"
    main.write_text("database_in=file:/var/lib/aide/aide.db\n")
    v = scanner_vars(tmp_path, "aide", aide_paths=AIDE_PATHS, aide_config_file=str(main),
                     aide_dropin=str(tmp_path / "90_homelabnext"), aide_cli=checker(tmp_path, "aide"))  # fmt: skip
    r = run_role(tmp_path, "aide", "config", v)
    assert r.returncode == 0, r.stdout + r.stderr
    assert (tmp_path / "90_homelabnext").read_text().splitlines()[1:] == [
        "/etc/ssh p+i+n+u+g+s+m+c+sha256"
    ]
    assert calls(tmp_path)[0] == "aide --config-check --config <staged>"
    bad = run_role(
        tmp_path, "aide", "config", {**v, "aide_paths": [{"path": "/bogus", "rule": "p"}]}
    )
    assert bad.returncode != 0
    assert "/bogus" not in (tmp_path / "90_homelabnext").read_text()
    assert sorted(p.name for p in (tmp_path / "state").iterdir()) == []  # nothing staged is left


def test_aide_refuses_bad_paths(tmp_path):
    cases = [
        {"aide_paths": paths}
        for paths in [
            [{"path": "/etc/ssh\n/ R", "rule": "p"}],
            [{"path": "/etc", "rule": "p+i\n!/"}],
            [{"path": "etc"}],
        ]
    ]
    v = scanner_vars(tmp_path, "aide", aide_paths=[])
    results = run_cases(tmp_path, "aide", "config", v, cases)
    assert all(f and "aide: an OnCalendar schedule ending in UTC" in m for f, m in results), results


@pytest.mark.parametrize(("rc", "ok"), [(0, True), (4, False)])
def test_aide_health_follows_the_checks_exit_status(tmp_path, rc, ok):
    cli = fake(
        tmp_path / "aide-cli",
        f"import sys\nprint('changed: /etc/ssh/sshd_config')\nsys.exit({rc} if '--check' in sys.argv else 0)\n",
    )
    v = scanner_vars(tmp_path, "aide", aide_paths=AIDE_PATHS, aide_cli=cli,
                     aide_dropin=str(tmp_path / "90_homelabnext"), aide_config_file=str(tmp_path / "aide.conf"))  # fmt: skip
    (tmp_path / "aide.conf").write_text("")
    assert run_role(tmp_path, "aide", "config", v).returncode == 0
    run_scan(tmp_path)
    r = run_role(tmp_path, "aide", "health", v)
    assert (r.returncode == 0) is ok and (ok or "the last check exited 4" in r.stdout)


# ---------------------------------------------------------------- rkhunter
def rk_vars(tmp_path, **kw):
    (tmp_path / "default").write_text('CRON_DAILY_RUN="true"\nAPT_AUTOGEN="false"\n')
    return scanner_vars(tmp_path, "rkhunter", rkhunter_whitelist={"ALLOWHIDDENDIR": ["/etc/.git"]},
                        rkhunter_local_config=str(tmp_path / "rkhunter-local.conf"),
                        rkhunter_default_file=str(tmp_path / "default"), **kw)  # fmt: skip


def test_rkhunter_writes_its_settings_refreshes_after_apt_and_puts_back_a_rejected_file(tmp_path):
    # the fake config check rejects a local file that holds "bogus"
    local = str(tmp_path / "rkhunter-local.conf")
    check = fake(
        tmp_path / "rkhunter-cli",
        f"import sys\nsys.exit(1 if 'bogus' in open({local!r}).read() else 0)\n",
    )
    v = rk_vars(tmp_path, rkhunter_cli=check)
    r = run_role(tmp_path, "rkhunter", "config", v)
    assert r.returncode == 0, r.stdout + r.stderr
    local = (tmp_path / "rkhunter-local.conf").read_text()
    assert (
        "PKGMGR=DPKG\n" in local
        and 'WEB_CMD=""\n' in local
        and "ALLOWHIDDENDIR=/etc/.git\n" in local
    )
    assert (tmp_path / "default").read_text() == 'CRON_DAILY_RUN="false"\nAPT_AUTOGEN="true"\n'
    bad = run_role(tmp_path, "rkhunter", "config", {**v, "rkhunter_settings": {"PKGMGR": "bogus"}})
    assert bad.returncode != 0 and "the previous one is back" in bad.stdout
    assert (tmp_path / "rkhunter-local.conf").read_text() == local
    assert sorted(p.name for p in tmp_path.glob("rkhunter-local.conf*")) == ["rkhunter-local.conf"]


def test_rkhunter_refuses_bad_inputs(tmp_path):
    results = run_cases(
        tmp_path,
        "rkhunter",
        "config",
        rk_vars(tmp_path),
        [
            {"rkhunter_whitelist": {"ALLOWHIDDENDIR": ["relative"]}},
            {"rkhunter_whitelist": {"PKGMGR": ["/x"]}},
            {"rkhunter_settings": {"PKGMGR": "DPKG\nWEB_CMD=curl"}},
        ],
    )
    assert all(f and "rkhunter: an OnCalendar schedule" in m for f, m in results), results


@pytest.mark.parametrize(("rc", "ok"), [(0, True), (1, False)])
def test_rkhunter_health_follows_the_checks_exit_status(tmp_path, rc, ok):
    cli = fake(
        tmp_path / "rkhunter-cli", f"import sys\nsys.exit({rc} if '--check' in sys.argv else 0)\n"
    )
    v = rk_vars(tmp_path, rkhunter_cli=cli)
    assert run_role(tmp_path, "rkhunter", "config", v).returncode == 0
    run_scan(tmp_path)
    assert (run_role(tmp_path, "rkhunter", "health", v).returncode == 0) is ok


# ---------------------------------------------------------------- clamav
@pytest.mark.parametrize(
    ("rc", "fresh", "ok"), [(0, True, True), (1, True, False), (0, False, False)]
)
def test_clamav_scans_the_paths_that_exist_and_health_wants_fresh_signatures(
    tmp_path, rc, fresh, ok
):
    import os

    share = tmp_path / "share"
    share.mkdir()
    db = tmp_path / "clamdb"
    db.mkdir()
    (db / "daily.cld").write_text("")
    if not fresh:
        os.utime(db / "daily.cld", (86400, 86400))
    out = str(tmp_path / "argv")
    cli = fake(
        tmp_path / "clamscan",
        f"import sys\nopen({out!r}, 'w').write(' '.join(sys.argv[1:]))\nsys.exit({rc})\n",
    )
    v = scanner_vars(tmp_path, "clamav", clamav_paths=[str(share), str(tmp_path / "absent")], clamav_cli=cli,
                     clamav_exclude_dirs=["^/srv/cache"], clamav_database_dir=str(db),
                     clamav_freshclam_config=str(tmp_path / "freshclam.conf"))  # fmt: skip
    assert run_role(tmp_path, "clamav", "config", v).returncode == 0
    run_scan(tmp_path)
    argv = (tmp_path / "argv").read_text()
    assert argv.startswith("--recursive --infected --no-summary --exclude-dir=^/srv/cache --log=")
    assert argv.endswith(f" {share}")  # the absent path is left out
    assert (run_role(tmp_path, "clamav", "health", v).returncode == 0) is ok


def test_clamav_uses_a_private_mirror_when_set(tmp_path):
    conf = tmp_path / "freshclam.conf"
    conf.write_text("DatabaseMirror database.clamav.net\n")
    v = scanner_vars(tmp_path, "clamav", clamav_paths=["/srv"], clamav_freshclam_config=str(conf),
                     clamav_private_mirror="clamav-mirror.example.internal")  # fmt: skip
    assert run_role(tmp_path, "clamav", "config", v).returncode == 0
    assert "PrivateMirror clamav-mirror.example.internal\n" in conf.read_text()
    bad = run_role(
        tmp_path, "clamav", "config", {**v, "clamav_private_mirror": "x\nDatabaseMirror y"}
    )
    assert bad.returncode != 0 and "clamav: an OnCalendar schedule" in bad.stdout


# ---------------------------------------------------------------- trivy
TRIVY = r"""
import json, sys
args = sys.argv[1:]
open(LOG, "a").write(" ".join(args) + "\n")
out = args[args.index("--output") + 1]
if args[0] == "rootfs" and "cyclonedx" in args:
    json.dump({"bomFormat": "CycloneDX"}, open(out, "w"))
else:
    json.dump({"Results": [{"Target": "debian", "Vulnerabilities": VULNS}, {"Target": "x"}]}, open(out, "w"))
"""


@pytest.mark.parametrize(
    ("vulns", "ok"), [([], True), ([{"VulnerabilityID": "CVE-2026-0001-FAKE"}], False)]
)
def test_trivy_scans_the_root_filesystem_and_writes_an_sbom(tmp_path, vulns, ok):
    cli = fake(
        tmp_path / "trivy-cli",
        TRIVY.replace("LOG", repr(str(tmp_path / "trivy.log"))).replace("VULNS", repr(vulns)),
    )
    v = scanner_vars(tmp_path, "trivy", trivy_severity="HIGH", trivy_cli=cli, trivy_skip_db_update=True,
                     trivy_scan_containers=False)  # fmt: skip
    r = run_role(tmp_path, "trivy", "config", v)
    assert r.returncode == 0, r.stdout + r.stderr
    run_scan(tmp_path)
    runs = (tmp_path / "trivy.log").read_text().splitlines()
    assert runs[0].startswith(
        "rootfs --quiet --severity HIGH,CRITICAL --skip-db-update --scanners vuln --format json"
    )
    assert runs[0].endswith(
        " --skip-dirs /proc,/sys,/dev,/run,/var/lib/docker,/var/lib/containers /"
    )
    assert "--format cyclonedx" in runs[1] and (tmp_path / "state" / "sbom.cdx.json").exists()
    h = run_role(tmp_path, "trivy", "health", v)
    assert (h.returncode == 0) is ok, h.stdout
    if not ok:
        assert "1 finding(s) (at most 0):" in h.stdout and "CVE-2026-0001-FAKE" in h.stdout


def test_trivy_refuses_bad_inputs(tmp_path):
    v = scanner_vars(tmp_path, "trivy", trivy_severity="HIGH")
    results = run_cases(
        tmp_path,
        "trivy",
        "config",
        v,
        [
            {"trivy_severity": "high"},
            {"trivy_version": "0.60"},
            {"trivy_db_repository": "mirror db"},
            {"trivy_repository": "http://mirror.example.internal/deb"},
            {"trivy_key_fingerprints": []},
        ],
    )
    assert all(f and "trivy: an OnCalendar schedule" in m for f, m in results), results


# ---------------------------------------------------------------- auditd
def auditd_vars(tmp_path, **kw):
    (tmp_path / "auditd.conf").write_text(
        "max_log_file = 8\nnum_logs = 5\nmax_log_file_action = ROTATE\n"
    )
    d = {
        "auditd_rule_groups": ["identity", "privilege", "sshd", "modules", "time"],
        "auditd_rules_file": str(tmp_path / "50-homelabnext.rules"),
        "auditd_conf_file": str(tmp_path / "auditd.conf"),
        "auditd_augenrules_cli": logging_fake(tmp_path, "augenrules", "No change\n"),
        "auditd_systemctl_cli": logging_fake(tmp_path, "systemctl"),
    }
    d.update(kw)
    return d


def test_auditd_writes_the_keyed_rules_loads_them_and_rotates_the_log(tmp_path):
    v = auditd_vars(tmp_path)
    r = run_role(tmp_path, "auditd", "config", v)
    assert r.returncode == 0, r.stdout + r.stderr
    rules = (tmp_path / "50-homelabnext.rules").read_text()
    for key in ("identity", "privilege", "sshd", "modules", "time"):
        assert f"-k hnx-{key}\n" in rules
    assert "-w /usr/bin/sudo -p x -k hnx-privilege" in rules
    assert "-S init_module,finit_module,delete_module -k hnx-modules" in rules
    conf = (tmp_path / "auditd.conf").read_text()
    assert "max_log_file = 50\n" in conf and "num_logs = 5\n" in conf
    assert calls(tmp_path) == [
        "augenrules --check",
        "augenrules --load",
        "systemctl kill --signal=SIGHUP auditd",
    ]
    assert run_role(tmp_path, "auditd", "config", v).returncode == 0
    assert calls(tmp_path)[3:] == ["augenrules --check"]  # unchanged: nothing loaded or signalled
    only = run_role(tmp_path, "auditd", "config", {**v, "auditd_rule_groups": ["time"]})
    assert (
        only.returncode == 0
        and "hnx-identity" not in (tmp_path / "50-homelabnext.rules").read_text()
    )


def test_auditd_reloads_rules_augenrules_says_are_stale(tmp_path):
    v = auditd_vars(tmp_path)
    assert run_role(tmp_path, "auditd", "config", v).returncode == 0
    stale = logging_fake(
        tmp_path, "augenrules", "/usr/sbin/augenrules: Rules have changed and should be updated\n"
    )
    assert (
        run_role(tmp_path, "auditd", "config", {**v, "auditd_augenrules_cli": stale}).returncode
        == 0
    )
    assert calls(tmp_path)[-1] == "augenrules --load"


AUDIT_STATES = [
    ("-w /etc/passwd -p wa -k hnx-identity\n-a always,exit -S adjtimex -F key=hnx-time\n", "enabled 1\n", True),
    ("-w /etc/passwd -p wa -k hnx-identity\n", "enabled 1\n", False),
    ("-w /etc/passwd -p wa -k hnx-identity\n-a always,exit -F key=hnx-time\n", "enabled 0\n", False),
]  # fmt: skip


def test_auditd_health(tmp_path):
    cases = [
        {"auditd_auditctl_cli": fake(tmp_path / f"auditctl-{i}",
                                     f"import sys\nprint({status!r} if sys.argv[1] == '-s' else {loaded!r}, end='')\n")}
        for i, (loaded, status, _) in enumerate(AUDIT_STATES)
    ]  # fmt: skip
    v = auditd_vars(tmp_path, auditd_rule_groups=["identity", "time"])
    results = run_cases(tmp_path, "auditd", "health", v, cases)
    assert [not f for f, _ in results] == [ok for _, _, ok in AUDIT_STATES], results


def test_auditd_refuses_bad_inputs(tmp_path):
    results = run_cases(
        tmp_path,
        "auditd",
        "config",
        auditd_vars(tmp_path),
        [{"auditd_rule_groups": []}, {"auditd_rule_groups": ["network"]}, {"auditd_num_logs": 0}],
    )
    assert all(f and "auditd: rule groups among" in m for f, m in results), results


# ---------------------------------------------------------------- needrestart
NEEDRESTART = r"""
import sys
open(LOG, "a").write("needrestart " + " ".join(sys.argv[1:]) + "\n")
sys.stdout.write(open(OUT).read())
"""
BATCH = (
    "NEEDRESTART-VER: 3.6\nNEEDRESTART-KCUR: 6.1.0-25-amd64\nNEEDRESTART-KEXP: 6.1.0-25-amd64\n"
    "NEEDRESTART-KSTA: 1\n"
)


def nr_setup(tmp_path, **kw):
    log = str(tmp_path / "calls.log")
    out = tmp_path / "nr.out"
    out.write_text(BATCH)
    mail = fake(
        tmp_path / "sendmail",
        f"import sys\nopen({str(tmp_path / 'mail.log')!r}, 'a').write(sys.stdin.read() + '\\0')\n",
    )
    d = {
        "needrestart_notify": "mail",
        "needrestart_cli": fake(
            tmp_path / "needrestart",
            NEEDRESTART.replace("LOG", repr(log)).replace("OUT", repr(str(out))),
        ),
        "needrestart_sendmail_cli": mail,
        "needrestart_perl_cli": checker(tmp_path, "perl"),
        "needrestart_systemctl_cli": logging_fake(tmp_path, "systemctl"),
        "needrestart_dropin": str(tmp_path / "50-homelabnext.conf"),
        "needrestart_aliases_file": str(tmp_path / "aliases"),
        "needrestart_unit_dir": str(tmp_path / "units"),
        "needrestart_state_dir": str(tmp_path / "state"),
        "needrestart_script": str(tmp_path / "bin" / "needrestart-check"),
        **last_run_vars(tmp_path, "needrestart"),
    }
    (tmp_path / "units").mkdir(exist_ok=True)
    d.update(kw)
    return d, out


def nr_check(tmp_path):
    import subprocess
    import sys

    return subprocess.run(
        [sys.executable, str(tmp_path / "bin" / "needrestart-check")],
        capture_output=True,
        text=True,
    )


def mails(tmp_path):
    p = tmp_path / "mail.log"
    return [m for m in p.read_text().split("\0") if m] if p.exists() else []


def test_needrestart_is_list_only_and_alerts_only_when_the_set_changes(tmp_path):
    import os

    v, out = nr_setup(tmp_path)
    r = run_role(tmp_path, "needrestart", "config", v)
    assert r.returncode == 0, r.stdout + r.stderr
    conf = (tmp_path / "50-homelabnext.conf").read_text()
    assert "$nrconf{restart} = 'l';" in conf and "$nrconf{kernelhints} = 1;" in conf
    assert "perl -c <staged>" in calls(tmp_path)
    timer = (tmp_path / "units" / "hnx-needrestart.timer").read_text()
    assert "OnCalendar=*-*-* 07:40:00 UTC\n" in timer and "OnBootSec" not in timer
    service = (tmp_path / "units" / "hnx-needrestart.service").read_text()
    assert "After=apt-daily-upgrade.service" in service
    assert "ExecStart=/usr/local/libexec/homelabnext/needrestart-check\n" in service
    assert nr_check(tmp_path).returncode == 0 and mails(tmp_path) == []  # nothing needs a restart
    state = tmp_path / "state" / "state.json"
    assert oct(state.stat().st_mode & 0o777) == "0o600"
    out.write_text(BATCH + "NEEDRESTART-SVC: ssh.service\nNEEDRESTART-SVC: cron.service\n")
    assert nr_check(tmp_path).returncode == 0
    (first,) = mails(tmp_path)
    assert first.startswith("To: root\nSubject: ") and "restart-required: 2 service(s)" in first
    assert "- cron.service\n- ssh.service" in first and "nothing was restarted" in first
    assert nr_check(tmp_path).returncode == 0 and len(mails(tmp_path)) == 1  # unchanged: silent
    out.write_text(BATCH)
    assert nr_check(tmp_path).returncode == 0
    assert "nothing needs a restart now" in mails(tmp_path)[-1] and len(mails(tmp_path)) == 2
    assert nr_check(tmp_path).returncode == 0 and len(mails(tmp_path)) == 2
    # it only ever ran `needrestart -b` (batch, list only) and restarted nothing itself
    nr_calls = [c for c in calls(tmp_path) if c.startswith("needrestart")]
    assert nr_calls and set(nr_calls) == {"needrestart -b"}
    assert not [c for c in calls(tmp_path) if "restart" in c.split()[1:2]]
    assert run_role(tmp_path, "needrestart", "health", v).returncode == 0
    os.utime(state, (86400, 86400))
    assert run_role(tmp_path, "needrestart", "health", v).returncode != 0


def test_needrestart_leaves_a_pending_kernel_to_patching_unless_asked(tmp_path):
    v, out = nr_setup(tmp_path)
    assert run_role(tmp_path, "needrestart", "config", v).returncode == 0
    out.write_text(BATCH.replace("KSTA: 1", "KSTA: 3").replace("KEXP: 6.1.0-25", "KEXP: 6.1.0-26"))
    assert (
        nr_check(tmp_path).returncode == 0 and mails(tmp_path) == []
    )  # unattended-upgrades mails reboots
    doc = json.loads((tmp_path / "state" / "state.json").read_text())
    assert doc["kernel"]["reboot_pending"] is True and doc["kernel"]["expected"] == "6.1.0-26-amd64"
    assert (
        run_role(
            tmp_path, "needrestart", "config", {**v, "needrestart_alert_kernel": True}
        ).returncode
        == 0
    )
    assert nr_check(tmp_path).returncode == 0
    assert "reboot into kernel 6.1.0-26-amd64" in mails(tmp_path)[0]


@pytest.mark.parametrize(
    ("aliases", "mode"),
    [("root: ops@example.org\n", "mail"), ("postmaster: root\n", "none"), (None, "none")],
)
def test_needrestart_auto_mails_only_where_root_mail_is_forwarded(tmp_path, aliases, mode):
    v, out = nr_setup(tmp_path, needrestart_notify="auto")
    if aliases is not None:
        (tmp_path / "aliases").write_text(aliases)
    assert run_role(tmp_path, "needrestart", "config", v).returncode == 0
    assert f'MODE = "{mode}"' in (tmp_path / "bin" / "needrestart-check").read_text()
    out.write_text(BATCH + "NEEDRESTART-SVC: ssh.service\n")
    assert nr_check(tmp_path).returncode == 0
    assert len(mails(tmp_path)) == (1 if mode == "mail" else 0)


def test_needrestart_posts_to_the_notify_endpoint_and_retries_a_failed_alert(tmp_path):
    import http.server
    import threading

    got = []

    class H(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            body = self.rfile.read(int(self.headers["Content-Length"])).decode()
            got.append((self.path, dict(self.headers), body))
            self.send_response(200)
            self.end_headers()

        def log_message(self, *a):
            pass

    srv = http.server.HTTPServer(("127.0.0.1", 0), H)  # no-raw-endpoint: allow test server
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    reg = tmp_path / "registry.yml"
    reg.write_text(
        f"services:\n  notify:\n    host: 127.0.0.1\n    port: {srv.server_port}\n    scheme: http\n"
    )
    v, out = nr_setup(
        tmp_path,
        needrestart_notify="notify",
        needrestart_notify_priority=4,
        hnx_registry_file=str(reg),
    )
    try:
        assert run_role(tmp_path, "needrestart", "config", v).returncode == 0
        out.write_text(BATCH + "NEEDRESTART-SVC: ssh.service\n")
        srv.shutdown()
        srv.server_close()
        failed = nr_check(tmp_path)
        assert failed.returncode == 2 and "alert not sent" in failed.stderr  # owed, not lost
        srv2 = http.server.HTTPServer(
            ("127.0.0.1", srv.server_port), H
        )  # no-raw-endpoint: allow test server
        threading.Thread(target=srv2.serve_forever, daemon=True).start()
        assert nr_check(tmp_path).returncode == 0
        assert nr_check(tmp_path).returncode == 0  # unchanged now: silent
        srv2.shutdown()
        srv2.server_close()
    finally:
        srv.server_close()
    (path, headers, body) = got[0]
    assert len(got) == 1 and path == "/homelabnext-restarts"
    assert headers["Priority"] == "4" and headers["Tags"] == "homelabnext,restart-required"
    assert "restart-required: 1 service(s)" in headers["Title"] and "- ssh.service" in body
    assert "Authorization" not in headers


def test_needrestart_refuses_bad_inputs_and_a_token_over_plain_http(tmp_path):
    v, _ = nr_setup(tmp_path)
    cases = [{"needrestart_notify": "slack"}, {"needrestart_notify_topic": "a/b"}, {"needrestart_notify_priority": 9},
             {"needrestart_notify_auth_ref": "tk_fake"}, {"needrestart_schedule": "daily"}]  # fmt: skip
    results = run_cases(tmp_path, "needrestart", "config", v, cases)
    # an unknown channel is refused by the argument spec's choices, the rest by validate.yml
    assert results[0][0] and "needrestart_notify must be one of" in results[0][1]
    want = "needrestart: notify is auto, none, notify or mail"
    assert all(f and want in m for f, m in results[1:]), results
    reg = tmp_path / "registry.yml"
    reg.write_text(
        "services:\n  notify:\n    host: ntfy-01.example.internal\n    port: 80\n    scheme: http\n"
    )
    plain = {
        **v,
        "needrestart_notify": "notify",
        "needrestart_notify_auth_ref": "secret:notify/token-fake",
        "hnx_registry_file": str(reg),
    }
    r = run_role(
        tmp_path, "needrestart", "config", plain, {"HNX_SECRET_NOTIFY_TOKEN_FAKE": "tk-fake"}
    )
    assert r.returncode != 0 and "a token would go over plain http" in r.stdout


# ---------------------------------------------------------------- lynis: package integrity sweep
DPKG = r"""
import os, sys
args = sys.argv[1:]
if args == ["--verify"]:
    sys.stdout.write(open(OUT).read())
elif args[0] == "-S":
    pkg = {"/usr/bin/sudo": "sudo", "/usr/lib/libfoo.so.1": "libfoo1", "/opt/vendor/agent": "vendor-agent"}
    if args[1] in pkg:
        print(f"{pkg[args[1]]}: {args[1]}")
    else:
        sys.exit(1)
"""
VERIFY_DIRTY = (
    "??5??????   /usr/bin/sudo\n"  # digest mismatch: a finding
    "missing     /usr/lib/libfoo.so.1\n"  # missing: a finding
    "??5?????? c /etc/ssh/sshd_config\n"  # conffile: left out by default
    "??5??????   /opt/vendor/agent\n"  # accepted by package
)


def sweep_setup(tmp_path, verify_out, **kw):
    cfg = tmp_path / "dpkg.cfg.d"
    cfg.mkdir(exist_ok=True)
    (cfg / "excludes").write_text(
        "path-exclude=/usr/share/doc/*\npath-include=/usr/share/doc/*/copyright\n"
    )
    out = tmp_path / "verify.out"
    out.write_text(verify_out)
    mail = fake(
        tmp_path / "sendmail",
        f"import sys\nopen({str(tmp_path / 'mail.log')!r}, 'a').write(sys.stdin.read() + '\\0')\n",
    )
    v = scanner_vars(
        tmp_path, "lynis", lynis_min_hardening_index=60,
        lynis_cli=fake(tmp_path / "lynis-cli", LYNIS.replace("REPORT", repr("hardening_index=70\n"))),
        lynis_dpkg_cli=fake(tmp_path / "dpkg", DPKG.replace("OUT", repr(str(out)))),
        lynis_verify_script=str(tmp_path / "bin" / "verify"), lynis_notify="mail", lynis_sendmail_cli=mail,
        lynis_dpkg_verify_allow=[{"package": "vendor-agent", "reason": "the vendor patches its own binary in place"}],
        lynis_dpkg_cfg_files=[str(tmp_path / "dpkg.cfg.d")],
        **kw,
    )  # fmt: skip
    return v, out


def run_sweep(tmp_path):
    import subprocess
    import sys

    return subprocess.run(
        [sys.executable, str(tmp_path / "bin" / "verify")], capture_output=True, text=True
    )


def test_dpkg_verify_flags_digest_mismatches_and_missing_files_but_not_conffiles(tmp_path):
    v, out = sweep_setup(tmp_path, VERIFY_DIRTY)
    assert run_role(tmp_path, "lynis", "config", v).returncode == 0
    assert (
        "ExecStart=/usr/local/libexec/homelabnext/lynis-dpkg-verify"
        in (tmp_path / "units" / "hnx-lynis.service").read_text()
    )
    run_scan(tmp_path)
    assert run_sweep(tmp_path).returncode == 0
    result = tmp_path / "state" / "dpkg-verify.json"
    assert oct(result.stat().st_mode & 0o777) == "0o600"
    doc = json.loads(result.read_text())
    assert doc["findings"] == [
        {"path": "/usr/bin/sudo", "problem": "digest", "package": "sudo"},
        {"path": "/usr/lib/libfoo.so.1", "problem": "missing", "package": "libfoo1"},
    ]
    assert doc["accepted"][0]["path"] == "/opt/vendor/agent" and doc["conffiles_skipped"] == 1
    (mail,) = [m for m in (tmp_path / "mail.log").read_text().split("\0") if m]
    assert (
        "package integrity: 2 file(s) differ" in mail and "- digest: /usr/bin/sudo (sudo)" in mail
    )
    r = run_role(tmp_path, "lynis", "health", v)
    assert r.returncode != 0 and "package integrity: 2 finding(s)" in r.stdout
    assert run_sweep(tmp_path).returncode == 0  # unchanged: no second alert
    assert len([m for m in (tmp_path / "mail.log").read_text().split("\0") if m]) == 1
    out.write_text("")  # clean again: one more alert, then health passes with the count
    assert run_sweep(tmp_path).returncode == 0
    mails = [m for m in (tmp_path / "mail.log").read_text().split("\0") if m]
    assert len(mails) == 2 and "clean again" in mails[1]
    ok = run_role(tmp_path, "lynis", "health", v, verbose=True)
    assert (
        ok.returncode == 0
        and "package integrity: 0 findings, 0 accepted, 0 conffile(s) skipped" in ok.stdout
    )


def test_dpkg_verify_reports_conffiles_when_asked(tmp_path):
    v, _ = sweep_setup(tmp_path, VERIFY_DIRTY, lynis_dpkg_verify_include_conffiles=True)
    assert run_role(tmp_path, "lynis", "config", v).returncode == 0
    assert run_sweep(tmp_path).returncode == 0
    doc = json.loads((tmp_path / "state" / "dpkg-verify.json").read_text())
    assert (
        "/etc/ssh/sshd_config" in [f["path"] for f in doc["findings"]]
        and doc["conffiles_skipped"] == 0
    )


def test_dpkg_verify_clean_host_and_bad_allow_entries(tmp_path):
    clean = ".M.......   /usr/bin/env\nmissing     /usr/share/doc/x/README.gz\n"
    v, _ = sweep_setup(tmp_path, clean)  # a mode difference; a doc file dpkg never unpacked
    assert run_role(tmp_path, "lynis", "config", v).returncode == 0
    assert run_sweep(tmp_path).returncode == 0
    assert json.loads((tmp_path / "state" / "dpkg-verify.json").read_text())["findings"] == []
    assert not (tmp_path / "mail.log").exists()  # nothing changed from the empty set: silent
    cases = [{"lynis_dpkg_verify_allow": [{"path": "/usr/bin/*"}]},
             {"lynis_dpkg_verify_allow": [{"reason": "no target"}]},
             {"lynis_notify": "pager"}]  # fmt: skip
    results = run_cases(tmp_path, "lynis", "config", v, cases)
    assert all(f for f, _ in results), results


def test_dpkg_verify_still_reports_a_missing_file_dpkg_was_told_to_keep(tmp_path):
    v, _ = sweep_setup(tmp_path, "missing     /usr/share/doc/sudo/copyright\n")  # path-include
    assert run_role(tmp_path, "lynis", "config", v).returncode == 0
    assert run_sweep(tmp_path).returncode == 0
    doc = json.loads((tmp_path / "state" / "dpkg-verify.json").read_text())
    assert [f["path"] for f in doc["findings"]] == ["/usr/share/doc/sudo/copyright"]
