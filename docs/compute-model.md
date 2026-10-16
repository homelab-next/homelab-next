<!-- SPDX-License-Identifier: Apache-2.0 -->
# Compute (guest) model

One file per VM, container or physical host describes it in vendor-neutral values. Generators
render everything else from those files: infrastructure-as-code, hypervisor commands, cloud-init
seeds, an Ansible inventory, registry hosts and backup jobs. Nothing here needs hardware: the
whole chain is tested with golden files from a synthetic fleet.

* Contract: `schemas/platform/guest.schema.json` (version 1.0, frozen).
* Code: `homelabnext/compute/`. CLI: `hnx guests`.
* Example fleet and goldens: `tests/compute/fleet/`, `tests/compute/golden/`.

## A guest file

```yaml
id: guest:lake-core            # the slug is the hostname and the file name (lake-core.yml)
kind: vm                       # vm | lxc | host
provisioning: terraform        # terraform | manual | host-only
placement: {node: hv-a, vmid: 40, vmid_scheme: octet}
resources:
  cpu: {cores: 4, type: host}
  memory: {size_mb: 16384}
  disks: [{name: rootfs, size_gb: 20, pool: fast}, {name: data, size_gb: 200, pool: bulk}]
image: {logical: debian-12-cloudinit, kind: template-clone, os_type: linux-6}
cloudinit: {user: ansible, ssh_authorized_keys: [operator], packages: [qemu-guest-agent]}
network: {zone: data, ip: 198.51.100.40, gateway: inherit, firewall: enabled}
capability: cap:lake-query
capability_groups: [cap_lake, cap_query]
backup: {policy: daily, retain: {daily: 7}, export_hook: lake-export}
lifecycle: {on_boot: true, ignore_changes: [clone]}
owners: {primary: data-team}
```

Rules worth knowing:

* Values only. Zones, storage pools, images and SSH keys are referenced by **name**; the
  environment supplies what the names mean (provider variables, a site model, a key file).
* `firewall` is `inherit | enabled | disabled`, not `on | off`: YAML 1.1 reads a bare `on` as a
  boolean.
* `provisioning: manual` guests (for example a container that needs host-level steps) must list
  `lifecycle.requires_root_steps`. They are left out of Terraform, libvirt and cloud-init output
  and printed in `MANUAL.md`, but still appear in the inventory, registry hosts and backup jobs.
* `kind: host` is a physical machine: inventoried, never provisioned (`provisioning: host-only`).

## Validation

Schema first, then `homelabnext.compute.validate`:

| Rule | Why |
|---|---|
| `network.zone` exists in the site model | no guest on an undeclared network |
| `ip` inside the zone subnet, outside the DHCP pool, not network/broadcast/gateway | no collisions with leases |
| `vmid_scheme: octet` means `vmid` equals the last octet of `ip` | the id is predictable from the address |
| ids, `(node, vmid)` and ips are unique | |
| `gpu` requires `kind: vm` | passthrough is a VM feature |
| `provisioning: manual` requires `requires_root_steps` | the hand work is written down |
| `capability` is one of the fourteen in `docs/interfaces.md` | |
| `capability_groups` are known inventory groups (`docs/role-interface.md` section 5, or `cap_<capability>`) | playbooks target groups |
| `backup.policy` is defined (or `none`) | |

The model does not import a site package. It reads zones through a small protocol:

```python
class ZoneLookup(Protocol):
    def zone(self, zone_id: str) -> ZoneInfo | None: ...  # id, subnet, gateway, dhcp_range, vlan_id
```

`open_site(path)` uses `homelabnext.network.site.load_site` when it is installed and otherwise
reads the `zones:` list of a `site.yml`. Tests use a stub.

## Rendering

`hnx guests render DIR --site SITE --target T [--out OUT] [--keys KEYS] [--policies FILE]`

| Target | Output |
|---|---|
| `terraform-proxmox` | `vm-*.tf`, `ct-*.tf`, `providers.tf`, `variables.tf`, `MANUAL.md` (bpg/proxmox resource shapes; text only) |
| `libvirt` | one `virt-install` script per VM plus `SKIPPED.txt` |
| `cloudinit` | `<name>/user-data`, `meta-data`, `network-config` per VM |
| `inventory` | `hosts.yml` with `cap_*` and `tag_*` groups, `host_vars/<fqdn>.yml` |
| `registry-hosts` | a `zones:`/`hosts:` fragment for `services.yml` |
| `backup-jobs` | members, retention and export hooks per policy |

Output is a pure function of the files: no clock, no randomness, no environment. SSH keys are
rendered from a name-to-public-key file, or as `<ssh-key:NAME>` placeholders; storage pool ids,
template ids, the default bridge and the API endpoint stay Terraform variables.

### One entry wires everything

`registry-hosts` produces the `zones:` and `hosts:` sections of a service registry.
`homelabnext.compute.gen.registry_hosts.merge_into_registry(doc, fragment)` overlays them on a
registry document (a conflicting entry is an error), and the existing registry generators (DNS,
proxy, monitoring, firewall matrix) then see the guests.

### Plan (swap kit)

`hnx guests plan DIR --site SITE --target T --against PREVIOUS_RENDER [--exit-code]` renders
fresh and prints a unified diff against a directory holding the previous render, with a
`N to add, N to change, N to remove` summary. With `--exit-code` it exits 2 when something would
change. Swapping the hypervisor stack is: render a second target from the same files and compare.

## SERVER (not implemented)

Applying the output (`terraform apply`, `virt-install`, `virsh autostart`) needs a hypervisor.
The generators only produce text; the plan command is the review step.
