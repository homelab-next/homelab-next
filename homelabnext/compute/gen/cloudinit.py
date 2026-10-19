# SPDX-License-Identifier: Apache-2.0
"""cloud-init NoCloud seed files per VM: user-data, meta-data and network-config (v2).

Key names resolve through ``Fleet.keys``; an unresolved name renders as ``<ssh-key:NAME>`` so a
dry render is still reviewable and can never carry key material by accident.

Sudo is per guest (``cloudinit.sudo``) and off unless asked for: ``none`` writes no sudo rule,
``password`` writes ``ALL=(ALL) ALL`` (usable once a password is set out of band, since the
account is created locked), and ``nopasswd`` is the explicit opt-in for an automation account.
"""

from __future__ import annotations

from homelabnext.compute.model import Fleet, Guest

from ._text import HEADER, q

#: ``cloudinit.sudo`` -> sudoers rule (``None`` = no rule)
SUDO_RULES = {"none": None, "password": "ALL=(ALL) ALL", "nopasswd": "ALL=(ALL) NOPASSWD:ALL"}


def user_data(fleet: Fleet, g: Guest) -> str:
    ci = g.cloudinit
    L = ["#cloud-config", f"# {HEADER}"]
    L += [f"hostname: {q(g.name)}", f"fqdn: {q(fleet.fqdn(g))}", "manage_etc_hosts: true"]
    L += [f"timezone: {q(ci.get('timezone', 'UTC'))}"]
    L += ["users:", f"  - name: {q(ci['user'])}"]
    rule = SUDO_RULES[ci.get("sudo", "none")]
    if rule:
        L.append(f"    sudo: {q(rule)}")
    L += ["    lock_passwd: true", "    shell: /bin/bash"]
    keys = ci.get("ssh_authorized_keys", [])
    if keys:
        L.append("    ssh_authorized_keys:")
        for k in keys:
            L.append(f"      - {q(fleet.keys.get(k, f'<ssh-key:{k}>'))}")
    pk = ci.get("packages", [])
    if pk:
        L += ["package_update: true", "packages:"] + [f"  - {q(p)}" for p in sorted(pk)]
    L += ["ssh_pwauth: false"]
    return "\n".join(L) + "\n"


def meta_data(fleet: Fleet, g: Guest) -> str:
    return f"# {HEADER}\ninstance-id: {q(f'{g.name}-{g.vmid}')}\nlocal-hostname: {q(g.name)}\n"


def network_config(fleet: Fleet, g: Guest) -> str:
    return (
        f'# {HEADER}\nversion: 2\nethernets:\n  primary:\n    match:\n      name: "e*"\n'
        f"    addresses:\n      - {q(g.ip + '/' + str(fleet.prefix_len(g)))}\n"
        f"    routes:\n      - to: default\n        via: {q(fleet.gateway(g))}\n"
    )


def render(fleet: Fleet) -> dict[str, str]:
    out: dict[str, str] = {}
    for g in fleet.iac():
        if g.kind != "vm" or not g.cloudinit:
            continue  # containers take cloud-init-like settings from the provider's own block
        out[f"{g.name}/user-data"] = user_data(fleet, g)
        out[f"{g.name}/meta-data"] = meta_data(fleet, g)
        out[f"{g.name}/network-config"] = network_config(fleet, g)
    return out
