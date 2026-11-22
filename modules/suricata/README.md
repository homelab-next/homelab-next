<!-- SPDX-License-Identifier: Apache-2.0 -->
# suricata: the network sensor

Fills the `network-sensor` slot (provisional: no contract yet, [ADR-0049](../../docs/adr/0049-the-soc-data-plane-and-the-lab-checks-move-as-modules.md)
decision 4) with Suricata from the OS package on a **capture host**: a physical sensor box or a
guest. It is not a container: a capture needs the host's NICs and raw sockets, which the
`compose_app` guardrails refuse by design.

| Piece | What it does |
|---|---|
| Package | `suricata` pinned by exact package version, plus `suricata-update` and `logrotate`. |
| `suricata.yaml` | `af-packet` on every capture interface; two eve logs; HOME_NET included from the generated file. |
| HOME_NET | The existing `suricata_enroll` role (called by this role) renders every address of every enrolled guest, extra addresses and IPv6 included, and tests it with the whole configuration before it goes live. |
| Deploy gate | A full `suricata -T` of the live configuration and ruleset before any restart (LL-281). A failed gate restores the previous configuration and stops the run; the running sensor is untouched. |
| Rules | `suricata-update enable-source` for each configured source (it ships with none enabled, so a never-enabled feed loads only the decoder rules and nothing says so), one fetch at install (a scheduled update is not in this module yet, see below). |
| Logs | `eve.json` (pipeline) and `eve-alert.json` (alerts only, SIEM agent). Both rotate through the distribution's daily logrotate with a `maxsize` bound (LL-145: an unbounded eve log reached 131 GB; an hourly check needs a catalogued fleet unit, below). |
| Health | Service active, **capture running** (kernel packets > 0), **kernel drops under a bound** (default 5 % of captured), **eve output growing** (a stats heartbeat is written every `suricata_stats_interval`, so a quiet network still writes). |

## Not in this module yet

* **Scheduled rule update and hourly rotation check.** A timer in this repo must be a catalogued fleet
  unit (script header, last-run records; CI's `scripts reality` refuses a bare timer). Until that is
  added, rules are fetched at install and each time the module is first applied to a host; run
  `suricata-update` then `suricatasc -c reload-rules` by hand or by the site's own job. Tracked as the
  follow-up to this module.
* **Absorbing `suricata_enroll`** (moving the role and clearing its product-name baseline entries): this
  module calls the existing role.

## Shipping (who reads what)

* **Log pipeline.** The `vector` module's agent on this host tails `/var/log/suricata/eve.json`
  (JSON lines, `event_type` field; `community_id` on every event). The remap to OCSF
  `network_activity` and `detection_finding` and the label (`hnx_runtime`, `hnx_tlp`) live in the
  `vector` module, not here. Coordinate through its README; this module only guarantees the path,
  the format and rotation.
* **SIEM manager.** The SIEM agent control (`siem-agent`, its own module) reads
  `/var/log/suricata/eve-alert.json` as a JSON localfile. This role adds that `<localfile>` block
  (its own marked `<ossec_config>` section, which the agent merges) when `/var/ossec/etc/ossec.conf`
  exists, and says so in the run when it does not. It never installs the agent.
* The lab's own sensor rules are native rules in the overlay's `lab/modules/wazuh/detections/native/`
  (decision 2), not content of this module. Upstream rules are product content.

## What the overlay adds

* `lab/modules.yml`: slot `network-sensor`, provider `suricata`, an instance id (the registry row's
  key, e.g. `sensor`), placement `sensor: <host>`; `grants.egress.suricata.sensor: [internet]` for the
  rule feed.
* `lab/services.yml`: the row exactly as bound (`host:` the sensor host, `version: 7.0.10`).
* Host vars for the sensor host: `suricata_capture_interfaces` (the NICs, by their stable names),
  and `suricata_guests`, which the baseline-playbook target already computes for the
  `network-sensor` control (`suricata_enroll_guests`; the same list).
* No secrets: the module has no credential.

## Re-homing the old-lab sensor mini PC (physical host)

The mini PC is an old-lab host (a container Suricata and a Zeek stack, a Velociraptor server, three
capture paths: a USB NIC on the switch mirror, and two GRE taps from the old hypervisors). Re-homing
it makes it a new-lab sensor host managed from the overlay; the old-lab stack is left until the
module's health is green, then stopped and removed (nothing is deleted: its data is a rotating
buffer).

1. **Prove the capture path before touching software.** From the host: `ip -s link show <capture
   NIC>` shows the packet counter rising with the mirror cabled; the NIC is unmanaged by the host's
   network manager (otherwise it can win the default route and take the host off the network, LL
   on the mirror-NIC incident) and holds **no address** (this role's readiness refuses an address).
2. **Name the host in the overlay** as a `kind: host` machine of the new lab (the guest model has no
   VM for it), in the management zone, reachable by the deploy account with passwordless sudo.
3. **Apply the module** with `suricata_service_manage: false` first (a dry build): package, config,
   rules, HOME_NET and the `suricata -T` gate run; nothing starts. Read the gate's result.
4. **Cut over** in one window: stop the old container Suricata, then run the module with
   `suricata_service_manage: true`. The two never capture the same NIC at once (the old one is
   stopped first; the module's service is started after the gate).
5. **Verify** with the role's `health` hook (capture, drops, growth), then confirm alerts arrive: an
   ET test signature from a guest through the mirror produces a line in `eve-alert.json` and, once
   the pipeline modules are live, an alert in the SIEM.
6. **Rollback:** `systemctl disable --now suricata`, and start the old
   container again (`docker compose up -d` in its project directory, untouched). The module keeps the
   previous `suricata.yaml` beside the live one (`.hnx-prev`).

The mini PC has one wired NIC that is down, a USB NIC on the mirror and a wireless management link;
the GRE taps arrive over the management link. For anything but a light guest mirror a wired path is
better: see the hypervisor mirror below.

## Hypervisor mirror (guest-to-guest traffic)

A switch mirror never sees two guests of one hypervisor talking over its bridge. The platform
already renders the fix: a node's `_nodes.yml` entry `mirror: {to: <nic>, bridges: [...]}` and
`hnx guests render --target node-mirror` write `hnx-mirror.sh` plus a systemd timer
([compute model](../../docs/compute-model.md#node-mirror)). It uses only `tc` matchall + `mirred`
(in-tree, standard: no kernel module is built or loaded), it puts the filter on each **guest port's
ingress** (`fwpr<vmid>p<n>`, `tap...`, `veth...`), changes nothing about the guests or the bridge, and
`--remove` takes every filter off again.

Two ways to carry the copies to this sensor; the module works with either as a second capture
interface:

* **Direct cable (preferred):** a spare, addressless NIC of the node (`to:`) cabled to a second
  capture NIC on the sensor. No load on any shared network.
* **GRE tap (no cable):** a `gretap` device on the node (`ip link add <name> type gretap local <node
  mgmt address> remote <sensor address>`) used as `to:`, and a matching `gretap` on the sensor listed in
  `suricata_capture_interfaces`. It reuses the management network, so bound the guest set (`bridges:`)
  and watch the health hook's drop ratio.

**Safe apply on a hypervisor (a host change: needs the operator's go):** render, read the script,
run `sh -n` and a `--check` style dry read (the generator's own output is deterministic and the script
refuses a missing `to`, a bridge or bond port, an address on `to`, or an OVS bridge before it changes
anything); run it once by hand, confirm with `tc filter show dev <guest port> ingress`
and a `tcpdump -c 20 -i <to>` that copies appear; only then enable the timer. **Rollback:**
`/usr/local/sbin/hnx-mirror.sh --remove` and `systemctl disable --now hnx-mirror.timer`; the guests'
networking never changed, so nothing else needs undoing.
