# SPDX-License-Identifier: Apache-2.0
"""``virt-install`` commands for the same guests: the model is not tied to one hypervisor.

One shell script per VM.  Directories come from environment variables the operator sets, never
from literals: ``HNX_IMAGE_DIR`` (base images), ``HNX_POOL_<POOL>`` (one per logical pool) and
``HNX_CLOUDINIT_DIR`` (the ``cloudinit`` target's output).  Containers and hosts have no libvirt
rendering and are listed in ``SKIPPED.txt``.
"""

from __future__ import annotations

from homelabnext.compute.model import Fleet, Guest

from ._text import HEADER

OS_VARIANTS = {"linux-6": "linux2022", "debian-12": "debian12", "ubuntu-24.04": "ubuntu24.04"}


def _pool_var(pool: str) -> str:
    return "HNX_POOL_" + pool.upper().replace("-", "_")


def script(fleet: Fleet, g: Guest) -> str:
    z = fleet.zone(g)
    br = g.network.get("bridge", "default")
    bridge = "${HNX_DEFAULT_BRIDGE:?set HNX_DEFAULT_BRIDGE}" if br == "default" else br
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
        args.append(f"--disk {spec}")
    net = f"--network bridge={bridge},model=virtio"
    args.append(net)
    if g.cloudinit:
        args.append(
            f'--cloud-init user-data="$CI/{g.name}/user-data",meta-data="$CI/{g.name}/meta-data"'
        )
    if g.gpu and g.gpu.get("resource_mapping"):
        args.append(
            f"--hostdev ${{HNX_HOSTDEV_{g.gpu['resource_mapping'].upper().replace('-', '_')}}}"
        )
    for sd in g.shared_dirs:
        ro = ",readonly=on" if sd.get("read_only") else ""
        args.append(
            f"--filesystem source={sd['host_path']},target={sd['mount_path']},driver.type=virtiofs{ro}"
        )
    args += ["--graphics none", "--noautoconsole"]
    L.append("virt-install \\")
    L += [f"  {a} \\" for a in args[:-1]] + [f"  {args[-1]}"]
    if z.vlan_id is not None and g.network.get("vlan_tag_mode", "in_bridge") == "in_bridge":
        L.append(f"# vlan {z.vlan_id}: tag it on the bridge port or a libvirt portgroup")
    if g.lifecycle.get("on_boot", True):
        L.append(f"virsh autostart {g.name}")
    return "\n".join(L) + "\n"


def render(fleet: Fleet) -> dict[str, str]:
    out: dict[str, str] = {}
    skipped: list[str] = []
    for g in fleet.sorted():
        if g.is_iac and g.kind == "vm":
            out[f"{g.name}.sh"] = script(fleet, g)
        else:
            why = "not terraform-provisioned" if g.provisioning != "terraform" else f"kind {g.kind}"
            skipped.append(f"{g.id}: {why}")
    out["SKIPPED.txt"] = "".join(f"{s}\n" for s in skipped)
    return out
