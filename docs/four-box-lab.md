---
summary: 'A worked four-machine lab (hypervisor, physical sensor, detonation box, secondary DNS) that validates and renders end to end, and how to make it yours.'
summary_of: outline:sha256:ff35a4dc756d201a
---
<!-- SPDX-License-Identifier: Apache-2.0 -->
# A four-box lab, end to end

`examples/four-box-lab/` is a fictional lab of four machines, the shape of a typical first real build.
It is complete enough to validate and render every target, so a new site can start from it
instead of from empty files. `tests/integration/test_four_box_lab.py` keeps it working.

| Machine | Role | Modelled as |
|---|---|---|
| `main-1` | one large hypervisor: every guest but the detonation box | `kind: host`, and a node in `guests/_nodes.yml` with `capacity`, `pools` and a `mirror` |
| `sensor-1` | network sensor (IDS) and DFIR server | `kind: host` in `services`: a management NIC, and two capture NICs with no address |
| `detonation-1` | anything that might be malicious | `kind: host`, alone in the one-way `sandbox` zone |
| `dns-2` | secondary DNS on a single-board computer | `kind: host` in `mgmt`, service `dns-secondary` |

## How it is cabled

```
                    internet
                       |
                   anchor-gw (router)
                       | port 1: trunk, every zone
     +-----------------+-------------------------------------+
     |                         core-sw                       |
     | 2: trunk (mgmt untagged; services, data, edge tagged) | ---- main-1
     | 3: access services                                    | ---- sensor-1 (management NIC)
     | 4: mirror of port 1                                   | ---- sensor-1 (capture NIC A)
     | 5: access sandbox                                     | ---- detonation-1
     | 6: access mgmt                                        | ---- dns-2
     +-------------------------------------------------------+
     main-1 spare NIC (enp65s0f1) ------- direct cable -------- sensor-1 (capture NIC B)
```

The sensor sees two copies:

- **Capture NIC A** sees the switch's copy of the uplink: everything between zones and to the
  internet.
- **Capture NIC B** sees `main-1`'s own copy of every frame its guests send, including the
  guest-to-guest traffic that never reaches the switch
  ([node mirror](compute-model.md#node-mirror)).

Guest-to-internet traffic therefore arrives on both NICs. What neither copy shows is listed under
[node mirror](compute-model.md#node-mirror) and
[mirror ports](network-model.md#mirror-ports-13).

## The files

- **`site.yml`**:
  - five zones: `mgmt`, `services`, `data`, `edge` and the one-way `sandbox`;
  - the switch ports above;
  - the firewall. Detonation telemetry leaves `sandbox` only to the bus (4222), and DFIR
    collection only to `sensor-1` (8000). Every zone may reach both resolvers.
  - both resolvers, served by Technitium.
- **`services.yml`**: the registry.
  - `dns` (primary, `dns-1`) and `dns-secondary` (`dns-2`; its upstream is the primary, the
    zone transfer).
  - the IDS (`network-sensor`) and the DFIR server (`dfir`) on `sensor-1`.
  - `detonation` on `detonation-1`.
  - the bus, the object store, the SIEM, the IdP, the edge proxy and the status hub on `main-1`'s
    guests.
- **`guests/`**: one file per machine and per guest.
  - Seven guests run on `main-1`, each with its inbound firewall rules (SSH from `mgmt` plus its
    own service ports).
  - The three VMs carry a `cloudinit` deploy account for Ansible.
  - `_nodes.yml` sizes `main-1`: 256 threads and 1 TiB of memory, less a reserve for Proxmox and
    the ZFS ARC; the `fast`, `write` and `bulk` pools; and the mirror.

## Check it, then render it

```sh
hnx site validate examples/four-box-lab/site.yml
hnx guests validate examples/four-box-lab/guests --site examples/four-box-lab/site.yml
hnx site render examples/four-box-lab/site.yml --adapter unifi --out /tmp/four-box/site
for t in terraform-proxmox cloudinit firewall-rules inventory backup-jobs node-mirror; do
  hnx guests render examples/four-box-lab/guests --site examples/four-box-lab/site.yml \
    --target "$t" --out "/tmp/four-box/$t"
done
```

`hnx site validate` gives two warnings, and both are expected:

- the console certificate pin is a placeholder;
- the mirror on port 4 copies `mgmt` and `sandbox` traffic.

`hnx guests validate` prints what `main-1`'s guests use:
`main-1: 7 guests, cores 32/496, memory 54/864 GiB, ...`.

## Make it yours

Copy the directory into the private overlay's `lab/` ([private overlay](private-overlay.md)), then
replace, in this order:

1. **Names and addresses.**
   - `site.id`, `site.domain` and every zone's `subnet`, `gateway` and `vlan_id`.
   - The `hosts` in `services.yml` and each guest's `network.ip`. They must agree:
     `hnx site validate` refuses a registry zone whose CIDR differs from the site's.
2. **The switch.**
   - `device_mac`, and the port numbers you actually cabled.
   - Keep the uplink a trunk, and the mirror's source the uplink port. A UniFi switch mirrors one
     source port to one port.
3. **The router.** The console certificate's SHA-256 in `router.tls_pin`.
4. **`main-1`.**
   - Its NIC and bridge names from `ip -br link` (`mirror.to`, `mirror.bridges`).
   - The pool sizes from `zfs list` (what guests may allocate).
   - The memory reserve, if you cap the ARC differently.
5. **The power.** Your UPS ids, and which machine each one feeds.
6. **The guests.**
   - vmids, sizes and pools.
   - Each one's `inbound_allow`, for the services you actually run.
   - The SSH key names in each `cloudinit` (the keys themselves go in the overlay's keys file).
7. **Products.** The `impl` and `version` of each service in `services.yml`. Only the registry
   names products; the guests name capabilities.

Then run the two `validate` commands again. Each refusal names the file and field to fix.

## Where the defaults may not fit

- **The sensor in `services`.** Its management NIC sits in `services` with the SIEM, which it
  sends to. Moving it to `mgmt` is one zone and one port change. Either way, its capture NICs have
  no address and belong to no zone.
- **DFIR from the sandbox** is a deliberate hole in the one-way zone: one port, to one host.
  Remove that `service_exceptions` entry if you collect from the detonation box another way.
- **The secondary DNS** shares the UPS with the switch, so names resolve for as long as the
  network is up. A single-board computer with 512 MB of memory should keep Technitium's cache
  small and its logging low.
