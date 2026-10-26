---
summary: 'A worked four-machine lab (hypervisor, physical sensor, detonation box, secondary DNS) that validates and renders end to end, and how to make it yours.'
summary_of: outline:sha256:0727cbe8c10da361
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
  - the firewall. Only management reaches whole zones, on SSH and HTTPS. Everything else is a
    named service, so the edge reaches only what it publishes and what its agents need. Detonation
    telemetry leaves `sandbox` only to the bus (4222), and DFIR collection only to `sensor-1`
    (8000).
  - both resolvers, served by Technitium, reachable from every zone but the sandbox.
- **`services.yml`**: the registry.
  - `dns` (primary, `dns-1`) and `dns-secondary` (`dns-2`; its upstream is the primary, the
    zone transfer).
  - the IDS (`network-sensor`) and the DFIR server (`dfir`) on `sensor-1`.
  - `detonation` on `detonation-1`.
  - the bus, the object store, the SIEM, the IdP, the edge proxy and the status hub on `main-1`'s
    guests.
  - `dns-upstream`, `apt-cache` and `ntp` on `egress-1`, in the edge. Only the edge has the
    internet. The resolvers forward through `egress-1`, and every other host installs packages and
    keeps time through it. Without it, a first boot cannot resolve, update or trust a certificate.
- **`guests/`**: one file per machine and per guest.
  - Eight guests run on `main-1`, each with its inbound firewall rules (SSH from `mgmt` plus its
    own service ports). A rule open to another zone is only useful if the site lets that zone
    through, and the test checks every one.
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
`main-1: 8 guests, cores 34/496, memory 56/864 GiB, ...`.

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

## The sandbox has no way in

The one-way zone means nothing reaches `detonation-1`: no SSH, no Ansible, no sample submission.
Nor does it reach a resolver, the package cache or the time source, so give it addresses, not
names, for the bus and the DFIR server. Manage it, update it and feed it samples out of band (its
console, a dedicated management link you unplug, or a reimage). That is the zone working, not a
gap.

## Before it holds real data

- **The deploy account has passwordless sudo** on the three VMs, so SSH to them is root.
  SSH is allowed from the whole `mgmt` zone. Narrow `source` to your admin workstation's `/32`
  (and that of the deploy's runner) as soon as you know it.
- **The sensor collects everything.**
  - It receives every zone's traffic, including the sandbox's and anything in clear text, and it
    parses hostile traffic.
  - Keep its capture NICs receive-only, with no address.
  - Allow SSH to it from `mgmt` only, on the host's own firewall: physical hosts get no rendered
    rules.
  - Keep it patched.
- **The bus is open to the sandbox** on 4222. Give the detonation box a NATS user that may only
  publish, and only to its own subject, so malware cannot poison what the SIEM reads.
- **The edge is internet facing.**
  - Its agents reach the SIEM, including enrolment on 1515. Use the SIEM's enrolment password
    (`secret:siem/enrollment-password`), and remove `edge` from that exception once `proxy-1` and
    `egress-1` are enrolled.
  - The identity provider and the hub accept only `proxy-1`'s address from the edge.
- **Zone transfers.** Both resolvers answer TCP/53 to every zone. In Technitium, allow zone
  transfer (and NOTIFY) to `dns-2` only. The `zonefile` adapter renders the records as a zone file
  to import into the primary; after that the primary owns the zone, and the secondary copies it.
- **The console pin.** Replace the placeholder with the certificate's SHA-256 before applying
  anything to the router.

## Where the defaults may not fit

- **The sensor in `services`.** Its management NIC sits in `services` with the SIEM, which it
  sends to. Moving it to `mgmt` changes its zone, its switch port and its address (in
  `services.yml` and its guest file). It also needs a `mgmt` to `data` rule for the bus (4222):
  `services` already has one.
- **DFIR from the sandbox** is a deliberate hole in the one-way zone: one port, to one host.
  Remove that `service_exceptions` entry if you collect from the detonation box another way.
- **The secondary DNS** shares the UPS with the switch, so names resolve for as long as the
  network is up. A single-board computer with 512 MB of memory should keep Technitium's cache
  small and its logging low.
