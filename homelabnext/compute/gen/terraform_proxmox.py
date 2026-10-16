# SPDX-License-Identifier: Apache-2.0
"""Terraform HCL for a Proxmox-style provider (bpg/proxmox resource shapes), as text only.

Only guests with ``provisioning: terraform`` are rendered.  Guests created by hand are listed,
with their root steps, in ``MANUAL.md``.  Environment specifics (storage pools, template ids, SSH
keys, the default bridge, the API endpoint) are provider variables, never literals.
"""

from __future__ import annotations

from homelabnext.compute.model import Fleet, Guest

from ._text import HEADER, hcl_align, q, qlist, tf_ident

PROVIDERS = f"""# {HEADER}
terraform {{
  required_providers {{
    proxmox = {{
      source  = "bpg/proxmox"
      version = ">= 0.60.0"
    }}
  }}
}}

provider "proxmox" {{
  endpoint  = var.proxmox_endpoint
  api_token = var.proxmox_api_token
}}
"""

VARIABLES = f"""# {HEADER}
variable "proxmox_endpoint" {{
  type        = string
  description = "API endpoint of the hypervisor cluster (supplied by the environment)."
}}

variable "proxmox_api_token" {{
  type      = string
  sensitive = true
}}

variable "default_bridge" {{
  type        = string
  description = "Bridge used by guests whose network.bridge is 'default'."
}}

variable "pools" {{
  type        = map(string)
  description = "Logical storage pool id -> datastore id."
}}

variable "vm_templates" {{
  type        = map(number)
  description = "Logical image name -> template vm id."
}}

variable "ct_templates" {{
  type        = map(string)
  description = "Logical image name -> container template file id."
}}

variable "ssh_keys" {{
  type        = map(string)
  sensitive   = true
  description = "Key name -> public key line."
}}
"""


def _bridge(fleet: Fleet, g: Guest) -> tuple[str, str | None]:
    """Return (bridge expression, vlan_id literal or None)."""
    z = fleet.zone(g)
    br = g.network.get("bridge", "default")
    base = "var.default_bridge" if br == "default" else q(br)
    if g.network.get("vlan_tag_mode", "in_bridge") == "per_vlan_bridge":
        suffix = f"v{z.vlan_id}"
        expr = f'"${{var.default_bridge}}{suffix}"' if br == "default" else q(f"{br}{suffix}")
        return expr, None
    return base, (str(z.vlan_id) if z.vlan_id is not None else None)


def _fw(g: Guest) -> str | None:
    return {"enabled": "true", "disabled": "false"}.get(g.network.get("firewall", "inherit"))


def _vm(fleet: Fleet, g: Guest) -> str:
    bridge, vlan = _bridge(fleet, g)
    mem = g.memory
    L = [f"# {HEADER}", f'resource "proxmox_virtual_environment_vm" "{tf_ident(g.name)}" {{']
    L += [f"  name      = {q(g.name)}", f"  node_name = {q(g.node)}", f"  vm_id     = {g.vmid}"]
    if g.tags:
        L.append(f"  tags      = {qlist(sorted(g.tags))}")
    L.append(f"  on_boot   = {q(g.lifecycle.get('on_boot', True))}")
    if g.gpu:
        L += ['  bios    = "ovmf"', '  machine = "q35"']
    img = g.image
    if img.get("kind") == "template-clone":
        L += ["", "  clone {", f"    vm_id = var.vm_templates[{q(img['logical'])}]", "  }"]
    L += ["", "  agent {", "    enabled = true", "  }"]
    L += [
        "",
        "  cpu {",
        f"    cores = {g.cpu['cores']}",
        f"    type  = {q(g.cpu.get('type', 'host'))}",
        "  }",
    ]
    L += ["", "  memory {", f"    dedicated = {mem['size_mb']}"]
    if mem.get("balloon_min_mb") is not None:
        L.append(f"    floating  = {mem['balloon_min_mb']}")
    L.append("  }")
    for i, d in enumerate(g.disks):
        L += [
            "",
            "  disk {",
            f"    datastore_id = var.pools[{q(d['pool'])}]",
            f'    interface    = "scsi{i}"',
            f"    size         = {d['size_gb']}",
            f"    file_format  = {q(d.get('format', 'raw'))}",
            f"    discard      = {q('on' if d.get('discard', True) else 'ignore')}",
            "  }",
        ]
    L += ["", "  network_device {", f"    bridge = {bridge}"]
    if vlan:
        L.append(f"    vlan_id  = {vlan}")
    if _fw(g):
        L.append(f"    firewall = {_fw(g)}")
    L.append("  }")
    if img.get("os_type"):
        L += ["", "  operating_system {", f"    type = {q(_pve_ostype(img['os_type']))}", "  }"]
    if g.gpu:
        mapping = g.gpu.get("resource_mapping")
        L += ["", "  hostpci {", '    device = "hostpci0"']
        L.append(
            f"    mapping = {q(mapping)}"
            if mapping
            else "    # resource_mapping unset: set one before apply"
        )
        L += ["    pcie   = true", "  }"]
    ci = g.cloudinit
    if ci:
        L += ["", "  initialization {"]
        if ci.get("storage_pool"):
            L.append(f"    datastore_id = var.pools[{q(ci['storage_pool'])}]")
        L += [
            "    ip_config {",
            "      ipv4 {",
            f"        address = {q(g.ip + '/' + str(fleet.prefix_len(g)))}",
            f"        gateway = {q(fleet.gateway(g))}",
            "      }",
            "    }",
            "    user_account {",
            f"      username = {q(ci['user'])}",
        ]
        keys = ci.get("ssh_authorized_keys", [])
        if keys:
            L.append("      keys     = [" + ", ".join(f"var.ssh_keys[{q(k)}]" for k in keys) + "]")
        L += ["    }", "  }"]
    ign = g.lifecycle.get("ignore_changes", [])
    if ign:
        L += ["", "  lifecycle {", "    ignore_changes = [" + ", ".join(ign) + "]", "  }"]
    L.append("}")
    return hcl_align("\n".join(L)) + "\n"


def _pve_ostype(os_type: str) -> str:
    """Map a logical os_type onto the hypervisor's own ``ostype`` vocabulary."""
    if os_type.startswith("linux-6") or os_type in ("debian-12", "ubuntu-24.04"):
        return "l26"
    if os_type.startswith("win"):
        return "win11"
    return os_type


def _ct(fleet: Fleet, g: Guest) -> str:
    bridge, vlan = _bridge(fleet, g)
    mem = g.memory
    L = [f"# {HEADER}", f'resource "proxmox_virtual_environment_container" "{tf_ident(g.name)}" {{']
    L += [f"  node_name    = {q(g.node)}", f"  vm_id        = {g.vmid}"]
    if g.tags:
        L.append(f"  tags         = {qlist(sorted(g.tags))}")
    L += [
        f"  start_on_boot = {q(g.lifecycle.get('on_boot', True))}",
        "  unprivileged  = true",
        "",
        "  operating_system {",
        f"    template_file_id = var.ct_templates[{q(g.image['logical'])}]",
        f"    type             = {q(g.image['os_type'])}",
        "  }",
        "",
        "  cpu {",
        f"    cores = {g.cpu['cores']}",
        "  }",
        "",
        "  memory {",
        f"    dedicated = {mem['size_mb']}",
        "  }",
    ]
    root = g.disks[0]
    L += [
        "",
        "  disk {",
        f"    datastore_id = var.pools[{q(root['pool'])}]",
        f"    size         = {root['size_gb']}",
        "  }",
    ]
    for d in g.shared_dirs:
        L += [
            "",
            "  mount_point {",
            f"    volume    = {q(d['host_path'])}",
            f"    path      = {q(d['mount_path'])}",
            f"    read_only = {q(d.get('read_only', False))}",
            "  }",
        ]
    L += ["", "  network_interface {", '    name   = "eth0"', f"    bridge = {bridge}"]
    if vlan:
        L.append(f"    vlan_id  = {vlan}")
    if _fw(g):
        L.append(f"    firewall = {_fw(g)}")
    L.append("  }")
    ci = g.cloudinit
    L += [
        "",
        "  initialization {",
        f"    hostname = {q(g.name)}",
        "    ip_config {",
        "      ipv4 {",
        f"        address = {q(g.ip + '/' + str(fleet.prefix_len(g)))}",
        f"        gateway = {q(fleet.gateway(g))}",
        "      }",
        "    }",
    ]
    if ci.get("ssh_authorized_keys"):
        L += [
            "    user_account {",
            "      keys = ["
            + ", ".join(f"var.ssh_keys[{q(k)}]" for k in ci["ssh_authorized_keys"])
            + "]",
            "    }",
        ]
    L.append("  }")
    ign = g.lifecycle.get("ignore_changes", [])
    if ign:
        L += ["", "  lifecycle {", "    ignore_changes = [" + ", ".join(ign) + "]", "  }"]
    L.append("}")
    return hcl_align("\n".join(L)) + "\n"


def manual_steps(fleet: Fleet) -> str:
    L = [f"<!-- {HEADER} -->", "# Guests created by hand", ""]
    guests = fleet.manual()
    if not guests:
        L.append("None.")
    for g in guests:
        L += [f"## {g.id}", "", f"Node `{g.node}`, vmid `{g.vmid}`, address `{g.ip}`.", ""]
        for i, step in enumerate(g.lifecycle.get("requires_root_steps", []), 1):
            L.append(f"{i}. {step.replace('<vmid>', str(g.vmid))}")
        L.append("")
    return "\n".join(L).rstrip("\n") + "\n"


def render(fleet: Fleet) -> dict[str, str]:
    out = {"providers.tf": PROVIDERS, "variables.tf": VARIABLES, "MANUAL.md": manual_steps(fleet)}
    for g in fleet.iac():
        if g.kind == "vm":
            out[f"vm-{g.name}.tf"] = _vm(fleet, g)
        else:
            out[f"ct-{g.name}.tf"] = _ct(fleet, g)
    return out
