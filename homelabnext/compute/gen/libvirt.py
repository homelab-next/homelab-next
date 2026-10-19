# SPDX-License-Identifier: Apache-2.0
"""``virt-install`` commands for the same guests: the model is not tied to one hypervisor.

One shell script per VM.  Directories come from environment variables the operator sets, never
from literals: ``HNX_IMAGE_DIR`` (base images), ``HNX_POOL_<POOL>`` (one per logical pool) and
``HNX_CLOUDINIT_DIR`` (the ``cloudinit`` target's output).  Containers and hosts have no libvirt
rendering and are listed in ``SKIPPED.txt``.

Network isolation is never left to a comment.  ``vlan_tag_mode: per_vlan_bridge`` attaches the
guest to ``<bridge>v<vlan>``, exactly as the Proxmox target does.  Two things ``virt-install``
cannot express are refused, for the whole render, with every offending guest listed:

* a zone VLAN with ``vlan_tag_mode: in_bridge`` (a plain Linux bridge port cannot be tagged from
  the guest definition), and
* an enabled NIC firewall: the ``firewall-rules`` output is Proxmox-format and libvirt would not
  enforce it, so the guest needs ``network.firewall: disabled`` with an exemption that names the
  host-level filter which does.

Every argument that expands a variable is double-quoted (word splitting, SC2086).
"""

from __future__ import annotations

from homelabnext.compute.model import ComputeError, Fleet, Guest
from homelabnext.generators.safe import checked

from ._text import HEADER

OS_VARIANTS = {"linux-6": "linux2022", "debian-12": "debian12", "ubuntu-24.04": "ubuntu24.04"}


def _pool_var(pool: str) -> str:
    return "HNX_POOL_" + pool.upper().replace("-", "_")


def refusals(fleet: Fleet, g: Guest) -> list[str]:
    """Why ``g`` cannot be rendered for libvirt without losing isolation (empty = it can)."""
    out = []
    z = fleet.zone(g)
    mode = g.network.get("vlan_tag_mode", "in_bridge")
    if z.vlan_id is not None and mode == "in_bridge":
        out.append(
            f"{g.id}: zone {g.zone} is VLAN {z.vlan_id} but virt-install cannot tag a bridge port; "
            "set network.vlan_tag_mode: per_vlan_bridge (bridge <name>v<vlan>)"
        )
    if g.nic_firewall:
        out.append(
            f"{g.id}: the NIC firewall is enabled but libvirt does not enforce the firewall-rules "
            "output; set network.firewall: disabled with a firewall_exemption naming the host "
            "filter (nftables, nwfilter) that does"
        )
    return out


def script(fleet: Fleet, g: Guest) -> str:
    z = fleet.zone(g)
    br = g.network.get("bridge", "default")
    bridge = "${HNX_DEFAULT_BRIDGE:?set HNX_DEFAULT_BRIDGE}" if br == "default" else br
    if g.network.get("vlan_tag_mode", "in_bridge") == "per_vlan_bridge":
        bridge += f"v{z.vlan_id}"
    pools = sorted({d["pool"] for d in g.disks})
    L = [
        "#!/bin/sh",
        f"# {HEADER}",
        f"# {g.id} on {g.node}; zone {g.zone}, address {g.ip}",
        "set -eu",
    ]
    for p in pools:
        L.append(f': "${{{_pool_var(p)}:?set {_pool_var(p)}}}"')
    L += [': "${HNX_IMAGE_DIR:?set HNX_IMAGE_DIR}"', 'CI="${HNX_CLOUDINIT_DIR:-./cloudinit}"', ""]
    args = [
        f"--name {g.name}",
        f"--vcpus {g.cpu['cores']}",
        f"--cpu {'host-passthrough' if g.cpu.get('type', 'host') == 'host' else g.cpu['type']}",
        f"--memory {g.memory['size_mb']}",
        f"--os-variant {OS_VARIANTS.get(g.image['os_type'], 'generic')}",
        "--import",
    ]
    for i, d in enumerate(g.disks):
        clone_root = i == 0 and g.image.get("kind") == "template-clone"
        fmt = "qcow2" if clone_root else d.get("format", "raw")  # backing files need qcow2
        path = f"${{{_pool_var(d['pool'])}}}/{g.name}-{d['name']}.{fmt}"
        spec = f"path={path},size={d['size_gb']},format={fmt},bus=virtio"
        if d.get("discard", True):
            spec += ",discard=unmap"
        if clone_root:
            spec += f",backing_store=${{HNX_IMAGE_DIR}}/{g.image['logical']}.qcow2"
        args.append(f'--disk "{spec}"')
    args.append(f'--network "bridge={bridge},model=virtio"')
    if g.cloudinit:
        args.append(
            f'--cloud-init "user-data=$CI/{g.name}/user-data,meta-data=$CI/{g.name}/meta-data"'
        )
    if g.gpu and g.gpu.get("resource_mapping"):
        args.append(
            f'--hostdev "${{HNX_HOSTDEV_{g.gpu["resource_mapping"].upper().replace("-", "_")}}}"'
        )
    for sd in g.shared_dirs:
        ro = ",readonly=on" if sd.get("read_only") else ""
        args.append(
            f'--filesystem "source={sd["host_path"]},target={sd["mount_path"]},driver.type=virtiofs{ro}"'
        )
    args += ["--graphics none", "--noautoconsole"]
    for a in args:
        checked(a, f"{g.id} virt-install argument", "shell" if '"' not in a else None)
    L.append("virt-install \\")
    L += [f"  {a} \\" for a in args[:-1]] + [f"  {args[-1]}"]
    if g.lifecycle.get("on_boot", True):
        L.append(f"virsh autostart {g.name}")
    return "\n".join(L) + "\n"


def render(fleet: Fleet) -> dict[str, str]:
    out: dict[str, str] = {}
    skipped: list[str] = []
    refused = [r for g in fleet.sorted() if g.is_iac and g.kind == "vm" for r in refusals(fleet, g)]
    if refused:
        raise ComputeError("libvirt target refuses guests it cannot isolate", refused)
    for g in fleet.sorted():
        if g.is_iac and g.kind == "vm":
            out[f"{g.name}.sh"] = script(fleet, g)
        else:
            why = "not terraform-provisioned" if g.provisioning != "terraform" else f"kind {g.kind}"
            skipped.append(f"{g.id}: {why}")
    out["SKIPPED.txt"] = "".join(f"{s}\n" for s in skipped)
    return out
