<!-- SPDX-License-Identifier: Apache-2.0 -->
# Compute (guest) model

One file per VM, container or physical host describes it in vendor-neutral values. Generators
render everything else from those files: infrastructure-as-code, hypervisor commands, cloud-init
seeds, an Ansible inventory, registry hosts and backup jobs. Nothing here needs hardware: the
whole chain is tested with golden files from a synthetic fleet.

* Contract: `schemas/platform/guest.schema.json` (version 1.3, additive over 1.0, 1.1 and 1.2; frozen copies in `schemas/_frozen/`).
* Baseline set: `schemas/platform/baseline_set.schema.json` (`_baselines.yml` beside the guest files; [Baselines and defense layers](#baselines-and-defense-layers), ADR-0016).
* Code: `homelabnext/compute/`. CLI: `hnx guests`.
* Example fleet and goldens: `tests/compute/fleet/`, `tests/compute/golden/`.

## A guest file

```yaml
id: guest:lake-core            # the slug is the hostname and the file name (lake-core.yml)
kind: vm                       # vm | lxc | host
provisioning: terraform        # terraform | manual | host-only
placement: {node: hv-a, vmid: 140, vmid_scheme: freeform}
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
baseline: {names: [server, sensitive]}   # 1.3: defense baselines from _baselines.yml
```

Rules worth knowing:

* Values only. Zones, storage pools, images and SSH keys are referenced by **name**; the
  environment supplies what the names mean (provider variables, a site model, a key file).
* `firewall` is `inherit | enabled | disabled`, not `on | off`: YAML 1.1 reads a bare `on` as a
  boolean. **Firewall is on by default**: an absent value and `inherit` both mean enabled, and the
  Terraform renderer always writes the flag (`firewall = true|false`) on every NIC. See
  [Firewall on by default](#firewall-on-by-default).
* `scope: in | out` (1.1) marks a guest the writer tools must not file work about
  (`docs/scope.md`).
* `provisioning: manual` guests (for example a container that needs host-level steps) must list
  `lifecycle.requires_root_steps`. They are left out of Terraform, libvirt and cloud-init output
  and printed in `MANUAL.md`, but still appear in the inventory, registry hosts and backup jobs.
* `kind: host` is a physical machine: inventoried, never provisioned (`provisioning: host-only`).

## Validation

Control characters first (any key or value holding one, a newline included, is refused: every
target writes line-oriented text, and Python's `re` lets a schema pattern's `$` match before a
trailing newline), then the schema, then `homelabnext.compute.validate`:

| Rule | Why |
|---|---|
| `network.zone` exists in the site model | no guest on an undeclared network |
| `ip` inside the zone subnet, outside the DHCP pool, not network/broadcast/gateway | no collisions with leases |
| `vmid_scheme: freeform` is the default; `octet` pins `vmid` to the last octet of `ip` for a readable id | pick whichever reads better for your layout |
| ids, `(node, vmid)` and ips are unique | |
| `gpu` requires `kind: vm` | passthrough is a VM feature |
| `provisioning: manual` requires `requires_root_steps` | the hand work is written down |
| `capability` is one of the fifteen in `docs/interfaces.md` | |
| `capability_groups` are known inventory groups (`docs/role-interface.md` section 5, or `cap_<capability>`) | playbooks target groups |
| `backup.policy` is defined (or `none`) | |
| a NIC with `firewall: disabled` on a node that enforces a firewall needs `network.firewall_exemption.reason` | see below |
| `firewall_rules`: unique names, ports for tcp/udp (none for icmp), valid port ranges, existing `zone:` sources and destinations, valid CIDRs; only on vm/lxc with the flag on | rules that cannot be rendered are errors, not skips |
| `firewall_rules.outbound_allow` needs `policy_out: DROP` or `REJECT` | an allow list under an accept-all policy is dead text |
| with a baseline set, every guest (vm, lxc and host) has `baseline.names` or `baseline.exemption.reason`; names, `extends`, `add` and `remove` resolve; no `extends` cycle; no baseline resolves to nothing | see [Baselines and defense layers](#baselines-and-defense-layers) |

The model does not import a site package. It reads zones through a small protocol:

```python
class ZoneLookup(Protocol):
    def zone(self, zone_id: str) -> ZoneInfo | None: ...  # id, subnet, gateway, dhcp_range, vlan_id
```

`open_site(path)` reads the site document with `homelabnext.network.load_site` (the same loader as
`hnx site`) and takes its `zones:` list and `site.domain`. It does not validate the site; run
`hnx site validate` for that. `load_zones_file` is the loader-free reader kept for tools that only
have a zones file. Tests can also pass a stub.

## Rendering

`hnx guests render DIR --site SITE --target T [--out OUT] [--keys KEYS] [--policies FILE] [--baselines FILE]`

| Target | Output |
|---|---|
| `terraform-proxmox` | `vm-*.tf`, `ct-*.tf`, `providers.tf`, `variables.tf`, `MANUAL.md` (bpg/proxmox resource shapes; text only) |
| `libvirt` | one `virt-install` script per VM plus `SKIPPED.txt`; refuses guests it cannot isolate (below) |
| `cloudinit` | `<name>/user-data`, `meta-data`, `network-config` per VM |
| `inventory` | `hosts.yml` with `cap_*` and `tag_*` groups (and, with a baseline set, `baseline_<name>` and `control_<id>`), `host_vars/<fqdn>.yml` (with `hnx_baselines`, `hnx_controls`) |
| `registry-hosts` | a `zones:`/`hosts:` fragment for `services.yml` |
| `backup-jobs` | members, retention and export hooks per policy |
| `baseline-playbook` | `baseline.yml`: one play per bound control, applying its `role` to `control_<id>`; unbound controls as commented blocks |
| `firewall-rules` | `firewall/<vmid>.fw` per guest (inbound drop, the outbound policy, the guest's allow rules), `firewall/verify-datacenter.sh` and `firewall/EXEMPTIONS.md` |

Output is a pure function of the files: no clock, no randomness, no environment.  The `terraform-proxmox` target was validated against the real `bpg/proxmox` provider **version 0.116.1** (`terraform init && terraform validate` plus a one-guest live `plan` / `apply` / `destroy` cycle on a scoped scratch pool).  A trimmed snapshot of the provider's resource schemas is committed at `tests/compute/fixtures/bpg_proxmox_schema.json` and used by `tests/compute/test_terraform_proxmox_schema.py` as a CI-safe shape check.  Note that the real provider enforces `vm_id >= 100`, so the example fleet uses vmids in the `110-230` range; the `octet` scheme is still available but requires IPs whose last octet is `>= 100`. SSH keys are
rendered from a name-to-public-key file, or as `<ssh-key:NAME>` placeholders; storage pool ids,
template ids, the default bridge and the API endpoint stay Terraform variables.

The provider constraint is `~> 0.60` (any 0.x from 0.60; a 1.0 with breaking changes is not picked
up silently). Commit the `.terraform.lock.hcl` that `terraform init` writes next to the rendered
files so every apply uses the same provider build and checksums, and keep state in an encrypted
remote backend with locking (for example an S3-compatible bucket with server-side encryption, or
OpenTofu's client-side state encryption): state holds the API token's effects, guest addresses and
anything a provider marks sensitive, in plain JSON. The renderer does not emit a backend block,
because the backend and its credentials belong to the environment, not to the guest files.

### cloud-init and sudo

`cloudinit.sudo` (1.2) decides the sudo rule of the cloud-init user, per guest:

| Value | Rule | Use |
|---|---|---|
| `none` (default) | no rule | the account can log in with its key; escalation goes through something else |
| `password` | `ALL=(ALL) ALL` | interactive admin; the account is created locked (`lock_passwd: true`), so sudo works only after a password is set out of band |
| `nopasswd` | `ALL=(ALL) NOPASSWD:ALL` | an automation account (Ansible `become`) that has no password to type |

The trade-off: `nopasswd` makes the SSH key the only secret between a remote login and root. That
is usually what an automation account needs, so it is allowed, but it is an explicit line in the
guest file rather than a blanket default for every account. A restricted rule (named commands
only) belongs in the configuration-management role that knows the commands.

The `terraform-proxmox` target configures the user through the provider's `user_account` block,
which does not set sudo: the image's default-user policy applies there (many cloud images grant
passwordless sudo to it). To apply `cloudinit.sudo` on that path, upload the `cloudinit` target's
`user-data` as a snippet and point the VM's `initialization.user_data_file_id` at it.

### libvirt

`virt-install` cannot express two things the model promises, so the target refuses them, listing
every offending guest, instead of rendering a script that silently drops them:

* a zone VLAN with `vlan_tag_mode: in_bridge`: a plain bridge port cannot be tagged from the guest
  definition. Use `vlan_tag_mode: per_vlan_bridge`; the guest then attaches to `<bridge>v<vlan>`,
  the same name the Proxmox target uses.
* an enabled NIC firewall: the `firewall-rules` output is Proxmox-format and libvirt does not
  enforce it. Set `network.firewall: disabled` with a `firewall_exemption` whose reason names the
  host-level filter (nftables, nwfilter) that does.

Every argument that expands a variable is double-quoted.

### Firewall on by default

Every guest NIC defaults to `firewall: enabled`. The guest file can carry the rules:

```yaml
network:
  zone: data
  ip: 198.51.100.40
  firewall: enabled              # the default; spelled out here for clarity
firewall_rules:
  inbound_allow:
    - {name: query-api, proto: tcp, ports: "8443", source: "zone:compute"}   # zone id -> its subnet
    - {name: ssh-admin, proto: tcp, ports: "22",   source: "192.0.2.0/24"}   # or a CIDR
    - {name: ping,      proto: icmp,               source: any}
```

`hnx guests render ... --target firewall-rules` writes one Proxmox-style file per guest, named
`<vmid>.fw` because that is the name the hypervisor reads from `/etc/pve/firewall/` (a file named
after the guest is ignored): `policy_in: DROP`, the outbound policy, then exactly the allow rules
above in file order. A guest with no rules gets the policies and nothing else; silence is never an
implicit allow.

Egress is `policy_out: ACCEPT` unless the guest asks for default-deny (1.2):

```yaml
firewall_rules:
  policy_out: DROP               # or REJECT; ACCEPT is the default
  inbound_allow: [...]
  outbound_allow:
    - {name: dns,       proto: udp, ports: "53",  dest: "zone:mgmt"}
    - {name: https-out, proto: tcp, ports: "443", dest: any}
```

Default-deny egress stops a compromised guest from reaching anything it was not meant to, at the
cost of listing what it needs (resolvers, package mirrors, time, the services it calls). Start with
the accept default and switch a guest to `DROP` once its outbound needs are known.

Guest rules only take effect while the datacenter firewall is on (`enable: 1` under `[OPTIONS]` in
`cluster.fw`). That file also holds the operator's own cluster rules, so it is not generated;
`firewall/verify-datacenter.sh`, run on a cluster node after installing the files, exits non-zero
if the switch is off or any rendered `<vmid>.fw` is missing or differs.

**Exemptions.** A NIC may run with the flag off only with a recorded reason:

```yaml
network:
  firewall: disabled
  firewall_exemption: {reason: "Peers connect from changing addresses; the service authenticates itself.", review_by: "2027-03-31"}
```

Validation rejects `disabled` without `firewall_exemption` when the guest's node enforces a
firewall, rejects an exemption on an enabled NIC (a stale exception), and rejects rules on a
disabled NIC. Which nodes enforce a firewall is data: `_nodes.yml` next to the guest files
(`nodes: {hv-a: {firewall: enabled|disabled}}`, or `--nodes FILE`); a node that is not listed is
assumed to enforce one, the safe default. Exemptions are listed with their reasons in
`firewall/EXEMPTIONS.md`.

**The incident class this prevents.** Hypervisor-level firewalls filter per virtual NIC, and the
per-NIC flag decides whether a guest's traffic goes through that filtering path. With the
node-level firewall switched on, a guest whose NIC does not carry the flag is not "simply
unfiltered": traffic it receives that was routed (it arrived from another network segment rather
than from the guest's own bridge) can be treated as unsolicited, because connection tracking never
saw the outbound half of the exchange. The visible symptom is one-directional: the guest can open
connections out and a probe from a neighbour on the same segment works, yet TCP replies that come
back across a router are silently dropped, and nothing in the guest's own logs says why. Leaving
the flag off was never a decision; it was an omission that only showed up after someone turned the
node firewall on. The model therefore (1) defaults the flag on, (2) always renders it explicitly
so a diff shows any change, and (3) turns "off" into a reviewed exception with a reason and a
review date.

### Baselines and defense layers

A guest names the defense baselines it gets; the controls in them are generic and the products
that implement them are chosen later, in one place. The set lives in `_baselines.yml` beside the
guest files (`--baselines FILE` elsewhere; contract `baseline_set.schema.json`, ADR-0016):

```yaml
controls:                 # the catalogue: product-neutral defense controls
  siem-agent:
    layer: detection      # identity | host | network | detection | data | recovery
    description: The endpoint agent of the SIEM runs and reports.
    role: null            # the Ansible role that implements it; null = no product chosen yet
    verify: the SIEM lists the guest's agent as active with a recent heartbeat
baselines:
  base:   {description: "...", controls: [time-sync, patching, ssh-hardening, host-firewall, log-forward, siem-agent]}
  server: {description: "...", extends: [base], controls: [central-auth, vuln-scan, backup-verify, config-backup]}
```

| Layer | Holds controls that decide |
|---|---|
| `identity` | who can get in (SSH hardening, directory accounts and MFA, the remote-access path) |
| `host` | the state of the operating system (time, patches, hardening profile) |
| `network` | what traffic may flow (host firewall, egress filtering) |
| `detection` | whether attacks and weaknesses are seen (log forwarding, SIEM agent, network sensor, vulnerability scan) |
| `data` | how stored data is protected (encryption at rest, secrets fetched from the store) |
| `recovery` | whether the guest can come back (restore drills, configuration kept for a rebuild) |

The layers are a closed set: a control sits in exactly one, so a coverage matrix shows at a glance
which rings of defense a guest has. Each control carries a `verify` line, the observable that
proves it is in place, so a reviewer (or a later check) knows what "done" means without knowing
the product.

**A guest declares its baselines**, and when created it is given one:

```yaml
baseline:
  names: [server, exposed]       # one or more; controls are unioned through extends
  add: [network-sensor]          # optional: extra controls for this guest only
  remove:                        # optional: controls it does not get, each with a reason
    - {control: backup-verify, reason: "Rebuilt from configuration, never restored.", review_by: "2027-03-31"}
# or, instead of names:
#  exemption: {reason: "Appliance firmware; no agent can run on it.", review_by: "2027-03-31"}
```

Resolution is deterministic: for each named baseline in order, depth-first through `extends`
(parents first, in listed order), then the baseline's own controls in listed order, skipping what
was already seen; then `add`; `remove` drops its controls.

**When a set exists, every guest needs a baseline or an exemption** (vm, lxc and physical hosts
alike): `hnx guests validate` fails otherwise, exactly like a disabled firewall flag without a
reason. Without a set nothing is required, so trees written before 1.3 stay valid; a guest that
names a baseline with no set to resolve it against is an error. The set itself is checked too:
unknown controls or `extends` targets, `extends` cycles, and a baseline that resolves to no
controls (an empty baseline is an exemption without a reason) are refused.

**Binding a product.** A control's `role` is the only place a product is named. The `inventory`
target puts each guest in `baseline_<name>` (every baseline it resolves to) and `control_<id>`
(every control it needs) groups, with `hnx_baselines` and `hnx_controls` host variables. The
`baseline-playbook` target writes one play per control whose `role` is set, against its
`control_<id>` group and tagged `control_<id>` and `layer_<layer>`; a control with `role: null`
is a commented "NOT BOUND to a product yet" block naming the guests that wait for it, and a
control no guest needs is listed as such. Choosing a SIEM agent is then a one-line change to the
set, and every guest that needs `siem-agent` gets it.

**Coverage.** `hnx guests baselines DIR --site SITE` prints a guest x layer matrix (controls per
layer; `MISSING` for a guest without a baseline or exemption, `exempt` with the reasons listed),
`--json` the full report (per-guest controls by layer, each control's role, verify and the guests
that need it, the needed-but-unbound controls). `--check` exits 1 when there is no baseline set or
any guest has neither a baseline nor an exemption; `--require-bound` also exits 1 while a control
some guest needs has no role. The report loads the fleet with every rule except "has a baseline",
so it can list the gaps instead of refusing to run. `hnx status serve --guests DIR --guests-site
SITE` serves the same matrix as the hub's Baselines page.

There is no guest scaffold command (`hnx new` makes roles, capabilities, detections and schemas):
a guest is created by writing its file, and the `baseline` key is what validation requires of it.

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
