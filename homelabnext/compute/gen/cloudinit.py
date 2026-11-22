# SPDX-License-Identifier: Apache-2.0
"""cloud-init NoCloud seed files per VM: user-data, meta-data and network-config (v2).

Key names resolve through ``Fleet.keys``; an unresolved name renders as ``<ssh-key:NAME>`` so a
stdout render is still reviewable and can never carry key material by accident.  The placeholder
is a review aid only: ``hnx guests render --out`` refuses it, since a seed carrying it boots a VM
nobody can log in to.

Sudo is per guest (``cloudinit.sudo``) and off unless asked for: ``none`` writes no sudo rule,
``password`` writes ``ALL=(ALL) ALL`` (usable once a password is set out of band, since the
account is created locked), and ``nopasswd`` is the explicit opt-in for an automation account.
"""

from __future__ import annotations

from homelabnext.compute.model import Fleet, Guest

from ._text import HEADER, q, qlist

#: one hypervisor node applies this output: ``hnx guests render --node`` may narrow it to one
PER_NODE = True

#: ``cloudinit.sudo`` -> sudoers rule (``None`` = no rule)
SUDO_RULES = {"none": None, "password": "ALL=(ALL) ALL", "nopasswd": "ALL=(ALL) NOPASSWD:ALL"}


def _runcmd(ci: dict) -> list[str]:
    """Every ``runcmd`` entry of a VM's user-data (``ci``: its ``cloudinit``), in order, as
    flow-style YAML lists.  The one place that adds one: :func:`user_data` writes them under a
    single ``runcmd:`` key, since a second key would silently replace the first."""
    cmds: list[str] = []
    if "qemu-guest-agent" in ci.get("packages", []):
        # Debian's unit is static and bound to the virtio port's device, which appeared at boot,
        # before cloud-init installed the package: nothing starts it until the next boot, and a
        # hypervisor that waits for the agent (the terraform-proxmox target's agent block) stalls.
        cmds.append("[systemctl, start, qemu-guest-agent]")
    return cmds


def virtiofs_mounts(g: Guest) -> list[tuple[str, str, str]]:
    """``(tag, mount_path, options)`` per directory a VM shares by virtiofs: the tag is the PVE
    directory mapping id, the options carry ``ro`` when ``read_only``."""
    return [
        (d["mapping"], d["mount_path"], "defaults,nofail" + (",ro" if d.get("read_only") else ""))
        for d in g.shared_dirs
        if d.get("mapping")
    ]


def fstab_virtiofs(g: Guest) -> str:
    """``fstab-virtiofs``: the same mounts as fstab lines, rendered for every VM with shares: the
    way an already-provisioned guest gets its mounts (cloud-init's mounts module runs once per
    instance), and the only way for one with no cloud-init seed."""
    L = [f"# {HEADER}"]
    L += [f"{t} {p} virtiofs {o} 0 0" for t, p, o in virtiofs_mounts(g)]
    return "\n".join(L) + "\n"


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
    mounts = virtiofs_mounts(g)
    if mounts:
        L += ["mounts:"] + [f"  - {qlist([t, p, 'virtiofs', o, '0', '0'])}" for t, p, o in mounts]
    runcmd = _runcmd(ci)
    if runcmd:
        L += ["runcmd:"] + [f"  - {c}" for c in runcmd]
    L += ["ssh_pwauth: false"]
    return "\n".join(L) + "\n"


def instance_id(g: Guest) -> str:
    """The cloud-init instance-id: the guest file's ``cloudinit.instance_id`` (what a running VM
    already has), else ``<name>-<vmid>`` for a guest not yet booted.  It must never change for a
    guest that exists: a new id is a new instance, so cloud-init re-runs and regenerates the SSH
    host keys (LL-570)."""
    return g.cloudinit.get("instance_id") or f"{g.name}-{g.vmid}"


def meta_data(fleet: Fleet, g: Guest) -> str:
    return f"# {HEADER}\ninstance-id: {q(instance_id(g))}\nlocal-hostname: {q(g.name)}\n"


def network_config(fleet: Fleet, g: Guest) -> str:
    return (
        f'# {HEADER}\nversion: 2\nethernets:\n  primary:\n    match:\n      name: "e*"\n'
        f"    addresses:\n      - {q(g.ip + '/' + str(fleet.prefix_len(g)))}\n"
        f"    routes:\n      - to: default\n        via: {q(fleet.gateway(g))}\n"
    )


def render(fleet: Fleet) -> dict[str, str]:
    out: dict[str, str] = {}
    for g in fleet.iac():
        if g.kind == "vm" and virtiofs_mounts(g):
            out[f"{g.name}/fstab-virtiofs"] = fstab_virtiofs(g)
        if g.kind != "vm" or not g.cloudinit:
            continue  # containers take cloud-init-like settings from the provider's own block
        out[f"{g.name}/user-data"] = user_data(fleet, g)
        out[f"{g.name}/meta-data"] = meta_data(fleet, g)
        out[f"{g.name}/network-config"] = network_config(fleet, g)
    return out
