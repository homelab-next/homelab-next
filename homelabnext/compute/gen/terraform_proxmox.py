# SPDX-License-Identifier: Apache-2.0
"""Terraform HCL for a Proxmox-style provider (bpg/proxmox resource shapes), as text only.

Only guests with ``provisioning: terraform`` are rendered.  Guests created by hand are listed,
with their root steps, in ``MANUAL.md``.  Environment specifics (storage pools, template ids, SSH
keys, the default bridge, the API endpoint) are provider variables, never literals.
"""

from __future__ import annotations

import hashlib

from homelabnext.compute.model import Fleet, Guest

from . import cloudinit
from ._text import HEADER, hcl_align, hq, hqlist, tf_ident

PROVIDERS = f"""# {HEADER}
terraform {{
  # 1.10: the API token is an ephemeral variable, so it never lands in a saved plan or in state
  required_version = "~> 1.10"
  required_providers {{
    proxmox = {{
      source  = "bpg/proxmox"
      version = "~> 0.60"
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
  type        = string
  sensitive   = true
  ephemeral   = true
  description = "API token (TF_VAR_proxmox_api_token): ephemeral, so never in a saved plan or state."
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

USER_DATA_FILE = "USER_DATA.md"


def _user_data_variable(names: list[str]) -> str:
    """The ``cloudinit_user_data`` variable: with a validation block naming every VM that needs
    an entry, so a missing one fails before the plan, listed by name."""
    L = [
        "",
        'variable "cloudinit_user_data" {',
        "  type        = map(string)",
        "  default     = {}",
        '  description = "Guest name -> snippet file id (datastore:snippets/file) holding the '
        "cloudinit target's user-data; needed by every VM whose cloudinit sets sudo or packages "
        f'({USER_DATA_FILE})."',
    ]
    if names:
        L += [
            "",
            "  validation {",
            f"    condition     = length(setsubtract({hqlist(names)}, "
            "keys(var.cloudinit_user_data))) == 0",
            '    error_message = "cloudinit_user_data needs a snippet file id for each of '
            f'{", ".join(names)} ({USER_DATA_FILE})."',
            "  }",
        ]
    return "\n".join([*L, "}", ""])


def user_data_guests(fleet: Fleet) -> list[tuple[Guest, str | None]]:
    """``(guest, sha256 of its user-data)`` for every VM this target renders with a
    ``user_data_file_id``, by name.  The digest is of the ``cloudinit`` target's
    ``<name>/user-data`` with the same keys file; None while a key name is unresolved (that render
    holds a placeholder, not the snippet to upload)."""
    out = []
    for g in fleet.iac():
        if g.kind == "vm" and needs_user_data(g):
            text = cloudinit.user_data(fleet, g)
            digest = None if "<ssh-key:" in text else hashlib.sha256(text.encode()).hexdigest()
            out.append((g, digest))
    return sorted(out, key=lambda t: t[0].name)


def user_data_steps(fleet: Fleet) -> str:
    """``USER_DATA.md``: the snippets this render's ``cloudinit_user_data`` must name."""
    L = [f"<!-- {HEADER} -->", "# Cloud-init user-data snippets", ""]
    rows = user_data_guests(fleet)
    if not rows:
        return "\n".join([*L, "None: no VM here needs one.", ""])
    width = max(len(hq(g.name)) for g, _ in rows)
    L += [
        "The provider's `user_account` block cannot carry a sudo rule or packages, so each VM",
        "below boots from the `cloudinit` target's `<name>/user-data`, uploaded as a snippet (a",
        "datastore with the `snippets` content type) and named in `terraform.tfvars`:",
        "",
        "```hcl",
        "cloudinit_user_data = {",
        *[
            f'  {hq(g.name):<{width}} = "<datastore>:snippets/{g.name}-user-data.yaml"'
            for g, _ in rows
        ],
        "}",
        "```",
        "",
        "Its SSH keys come from that render's `--keys`, not from `var.ssh_keys`.  Compare each",
        "uploaded snippet with the digest below (`sha256sum` on the node) before `terraform apply`;",
        "re-upload it whenever the cloudinit render changes, since a changed snippet replaces no",
        "VM by itself.",
        "",
        "| guest | node | vmid | sha256 of `<name>/user-data` |",
        "|---|---|---|---|",
    ]
    for g, digest in rows:
        shown = f"`{digest}`" if digest else "unresolved key names: render with `--keys`"
        L.append(f"| `{g.name}` | `{g.node}` | {g.vmid} | {shown} |")
    return "\n".join([*L, ""])


def _bridge(fleet: Fleet, g: Guest) -> tuple[str, str | None]:
    """Return (bridge expression, vlan_id literal or None)."""
    z = fleet.zone(g)
    br = g.network.get("bridge", "default")
    base = "var.default_bridge" if br == "default" else hq(br)
    if g.network.get("vlan_tag_mode", "in_bridge") == "per_vlan_bridge":
        suffix = f"v{z.vlan_id}"
        expr = f'"${{var.default_bridge}}{suffix}"' if br == "default" else hq(f"{br}{suffix}")
        return expr, None
    return base, (str(z.vlan_id) if z.vlan_id is not None else None)


def _fw(g: Guest) -> str:
    """Always rendered, never omitted: an absent flag is how a NIC silently ends up unfiltered
    (or, behind a node firewall, unable to receive routed replies)."""
    return "true" if g.nic_firewall else "false"


def _vm(fleet: Fleet, g: Guest) -> str:
    bridge, vlan = _bridge(fleet, g)
    mem = g.memory
    L = [f"# {HEADER}", f'resource "proxmox_virtual_environment_vm" "{tf_ident(g.name)}" {{']
    L += [f"  name      = {hq(g.name)}", f"  node_name = {hq(g.node)}", f"  vm_id     = {g.vmid}"]
    if g.tags:
        L.append(f"  tags      = {hqlist(sorted(g.tags))}")
    L.append(f"  on_boot   = {hq(g.lifecycle.get('on_boot', True))}")
    if g.gpu:
        L += ['  bios    = "ovmf"', '  machine = "q35"']
    img = g.image
    if img.get("kind") == "template-clone":
        L += ["", "  clone {", f"    vm_id = var.vm_templates[{hq(img['logical'])}]", "  }"]
    L += ["", "  agent {", "    enabled = true", "  }"]
    L += [
        "",
        "  cpu {",
        f"    cores = {g.cpu['cores']}",
        f"    type  = {hq(g.cpu.get('type', 'host'))}",
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
            f"    datastore_id = var.pools[{hq(d['pool'])}]",
            f'    interface    = "scsi{i}"',
            f"    size         = {d['size_gb']}",
            f"    file_format  = {hq(d.get('format', 'raw'))}",
            f"    discard      = {hq('on' if d.get('discard', True) else 'ignore')}",
            "  }",
        ]
    L += ["", "  network_device {", f"    bridge = {bridge}"]
    if vlan:
        L.append(f"    vlan_id  = {vlan}")
    L.append(f"    firewall = {_fw(g)}")
    L.append("  }")
    if img.get("os_type"):
        L += ["", "  operating_system {", f"    type = {hq(_pve_ostype(img['os_type']))}", "  }"]
    if g.gpu:
        mapping = g.gpu.get("resource_mapping")
        L += ["", "  hostpci {", '    device = "hostpci0"']
        L.append(
            f"    mapping = {hq(mapping)}"
            if mapping
            else "    # resource_mapping unset: set one before apply"
        )
        L += ["    pcie   = true", "  }"]
    ci = g.cloudinit
    if ci:
        L += ["", "  initialization {"]
        if ci.get("storage_pool"):
            L.append(f"    datastore_id = var.pools[{hq(ci['storage_pool'])}]")
        L += [
            "    ip_config {",
            "      ipv4 {",
            f"        address = {hq(g.ip + '/' + str(fleet.prefix_len(g)))}",
            f"        gateway = {hq(fleet.gateway(g))}",
            "      }",
            "    }",
        ]
        if needs_user_data(g):
            # The user_account block cannot carry a sudo rule or packages: the cloudinit target's
            # user-data, uploaded as a snippet, replaces it (it creates the user, keys included).
            # An index, not a lookup: a missing snippet fails the plan instead of silently booting
            # a guest without its sudo rule or packages (qemu-guest-agent among them).
            L.append(f"    user_data_file_id = var.cloudinit_user_data[{hq(g.name)}]")
        else:
            L += ["    user_account {", f"      username = {hq(ci['user'])}"]
            keys = ci.get("ssh_authorized_keys", [])
            if keys:
                L.append(
                    "      keys     = [" + ", ".join(f"var.ssh_keys[{hq(k)}]" for k in keys) + "]"
                )
            L.append("    }")
        L.append("  }")
    ign = g.lifecycle.get("ignore_changes", [])
    if ign:
        L += ["", "  lifecycle {", "    ignore_changes = [" + ", ".join(ign) + "]", "  }"]
    L.append("}")
    return hcl_align("\n".join(L)) + "\n"


def needs_user_data(g: Guest) -> bool:
    """Whether the VM's cloud-init asks for what the provider's ``user_account`` block cannot
    express (a sudo rule, packages), so its user-data must come from the ``cloudinit`` target."""
    ci = g.cloudinit
    return bool(ci) and (ci.get("sudo", "none") != "none" or bool(ci.get("packages")))


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
    L += [f"  node_name    = {hq(g.node)}", f"  vm_id        = {g.vmid}"]
    if g.tags:
        L.append(f"  tags         = {hqlist(sorted(g.tags))}")
    L += [
        f"  start_on_boot = {hq(g.lifecycle.get('on_boot', True))}",
        "  unprivileged  = true",
        "",
        "  operating_system {",
        f"    template_file_id = var.ct_templates[{hq(g.image['logical'])}]",
        f"    type             = {hq(g.image['os_type'])}",
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
        f"    datastore_id = var.pools[{hq(root['pool'])}]",
        f"    size         = {root['size_gb']}",
        "  }",
    ]
    for d in g.shared_dirs:
        L += [
            "",
            "  mount_point {",
            f"    volume    = {hq(d['host_path'])}",
            f"    path      = {hq(d['mount_path'])}",
            f"    read_only = {hq(d.get('read_only', False))}",
            "  }",
        ]
    L += ["", "  network_interface {", '    name   = "eth0"', f"    bridge = {bridge}"]
    if vlan:
        L.append(f"    vlan_id  = {vlan}")
    L.append(f"    firewall = {_fw(g)}")
    L.append("  }")
    ci = g.cloudinit
    L += [
        "",
        "  initialization {",
        f"    hostname = {hq(g.name)}",
        "    ip_config {",
        "      ipv4 {",
        f"        address = {hq(g.ip + '/' + str(fleet.prefix_len(g)))}",
        f"        gateway = {hq(fleet.gateway(g))}",
        "      }",
        "    }",
    ]
    if ci.get("ssh_authorized_keys"):
        L += [
            "    user_account {",
            "      keys = ["
            + ", ".join(f"var.ssh_keys[{hq(k)}]" for k in ci["ssh_authorized_keys"])
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
    names = [g.name for g, _ in user_data_guests(fleet)]
    out = {
        "providers.tf": PROVIDERS,
        "variables.tf": VARIABLES + _user_data_variable(names),
        "MANUAL.md": manual_steps(fleet),
        USER_DATA_FILE: user_data_steps(fleet),
    }
    for g in fleet.iac():
        if g.kind == "vm":
            out[f"vm-{g.name}.tf"] = _vm(fleet, g)
        else:
            out[f"ct-{g.name}.tf"] = _ct(fleet, g)
    return out
