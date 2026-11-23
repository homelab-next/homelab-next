<!-- SPDX-License-Identifier: Apache-2.0 -->
# zeek: the network monitor

Fills the `network-sensor` slot (provisional, [ADR-0049](../../docs/adr/0049-the-soc-data-plane-and-the-lab-checks-move-as-modules.md)
decision 4) with Zeek, next to the [`suricata`](../suricata/README.md) provider: the IDS says *what
matched*, this says *what happened* (connections, DNS, TLS, HTTP, SSH, files, certificates). A site
selects both as two instances of the slot on the same capture host.

| Piece | What it does |
|---|---|
| Image | The official image pinned by tag **and digest**, plus the fingerprint and analytics packages (JA3, JA4, HASSH, ATT&CK analytics) each pinned to a release tag or a commit, built once into a local image tagged by a hash of its inputs. A package that does not install fails the build, so no half-built image is ever tagged. The distribution has no package, which is why this is a container. |
| Process | One container **per capture interface** (Zeek reads one interface per process), by a systemd unit that calls the engine directly: `compose_app` cannot give a capture the host network by design. Host network, all capabilities dropped but `NET_RAW` and `NET_ADMIN`, `no-new-privileges`, read-only root, a memory limit, the log directory as the only writable path. A fault on one NIC blinds that capture only. |
| Scripts | JSON logs, a flow id (`community_id`) shared with the IDS for correlation, the stats heartbeat, and a local script carried over from the old lab that adds a `self_signed` boolean to the x509 log (the SIEM's rule engine cannot compare two fields). |
| Logs | `/var/log/hnx-zeek/<slug>/*.log`, one JSON event per line. Truncated in place by the distribution's logrotate (`copytruncate`, `maxsize`): standalone Zeek does not rotate. |
| Health | Per capture: unit active; `stats.log` written within the age bound; packets processed over the last window; drops under a bound (default 5 %). |

## Shipping

The `vector` module's agent tails `/var/log/hnx-zeek/*/*.log` (JSON lines; the stream name is the
file name: `conn`, `dns`, `ssl`, `http`, `ssh`, `files`, `x509`, `notice`, `weird`; `stats`,
`loaded_scripts`, `packet_filter` and `telemetry` are not events and the agent should skip them). The
remap to OCSF `network_activity`, the labels (`hnx_runtime`, `hnx_tlp`) and the JA3/JA4/HASSH fields
belong to the `vector` module (decoders for them are owed in the SIEM module's native rules, which
must carry the old zeek decoder). This module guarantees the path, the format and the rotation.

## What the overlay adds

* `lab/modules.yml`: slot `network-sensor`, provider `zeek`, an instance id different from the other
  sensor's, placement `sensor: <host>`; `grants.egress.zeek.sensor: [internet]` (image pull and package
  fetch at build time only).
* `lab/services.yml`: the row exactly as bound (`version: 8.0.8`).
* Host vars: `zeek_capture_interfaces` (`[{slug, interface}]`, the same NICs the IDS reads; a capture
  NIC is unmanaged by the host's network manager and holds no address).
* The container engine on the host (its own control, applied first). No secrets.

## Re-homing the old-lab sensor (same procedure as the IDS)

Follow the [IDS's procedure](../suricata/README.md#re-homing-the-old-lab-sensor-mini-pc-physical-host):
dry build first (`zeek_service_manage: false`: the image builds, units are written, nothing starts),
stop the old container stack's Zeek, then apply with `true`, then run `health`. Two captures never run
on one NIC at once for the old and new stacks; the old stack is stopped first.
**Rollback:** `systemctl disable --now 'hnx-zeek-*'` and start the old stack's containers again
(untouched; the built image and the logs stay).

## Not in this module yet

* A Zeek **watchdog** (the old lab restarted a wedged capture): the health hook detects it and the
  units restart on exit (`Restart=always`); a wedged-but-alive process needs a catalogued fleet unit.
* **Scripts policy beyond the carried-over one**: site tuning stays in the module's script until a
  need appears.
