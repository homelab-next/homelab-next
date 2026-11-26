<!-- SPDX-License-Identifier: Apache-2.0 -->
# Module `prometheus`: the metrics provider

A provider module ([module manifest](../../docs/modules.md), draft, ADR-0027 proposed) that fills
the `metrics` slot with [Prometheus](https://prometheus.io), a pull-based time-series store with
alert rules. It is a **service, not a machine**: the guest it runs on is the site's guest file, and
the site's selection places the module's one host role (`server`) on it. Nothing in this directory
names a real host, address, VM id or secret value; those live only in the private overlay.

| | |
|---|---|
| Slot | `metrics`, provisional (no contract yet; see "The slot") |
| Adapter | the shared `homelabnext.conform.adapters.metrics:make`, a read-only client of the query, alert, rule and target endpoints |
| Product | Prometheus 3.15.1, `docker.io/prom/prometheus` pinned by tag and digest |
| Host role | `server`: kind `vm`, baseline `base`, footprint 2 vCPU, 1 GB, 40 GB |
| Role | `prometheus` (role interface v1), a wrapper of the core `compose_app` |
| Beside it | the core role `node_exporter` (control `metrics-agent`), applied to every guest |
| Requires | `cap:secrets` (the publish token, scrape credentials), `cap:notify` (the alerts) |
| Egress | none (the scrapes are in-lab; the interface and the alerts are the only traffic) |
| Public route | none; **no web login**: the interface is reached on the guest's address (see "Reaching the interface") |

## What it does

- **Scrape targets are generated from the registry, never listed by hand.** The role runs the
  metrics generator on the controller (`hnx registry generate <registry> <scratch> --only
  prometheus --node-exporter-port N [--node-exporter-exclude HOST]...`) and installs its output:
  every service row with a `metrics:` block is a scrape job (the scheme and the secret-referenced
  basic or bearer authentication of registry 2.11 included; the credential is written from the
  secret store, group-readable by the container, and removed again when the registry stops naming
  it), and every host of the registry is a host-exporter target on the one port. The lab's registry
  holds the new lab only, so no other lab's host can become a target. An appliance with no exporter
  is named in `prometheus_node_exporter_exclude`, never left to alert as down.
- **The service scrapes itself inside its own container.** The generated job for the instance's
  own row targets port 9090 on `localhost` inside the container (no round trip through the guest's address),
  with the `instance` label kept as the registry's address, so series, dashboards and alerts do not
  change. Only a plain-http row is rewritten.
- **Host metrics on every guest** are the core role `node_exporter` (below), bound to a baseline
  control the overlay attaches to every guest.
- **Retention** is `prometheus_retention_time` (default `30d`), with an optional size cap
  (`prometheus_retention_size`), both in `prometheus.yml` (`storage.tsdb.retention`: the command-line
  flag is deprecated in 3.x). Health reads the running value back.
- **A small default rule set**, rendered with the thresholds as settings:

  | Alert | Fires when | For | Severity |
  |---|---|---|---|
  | `TargetDown` | `up == 0` | 10m | critical |
  | `NoTargets` | no host target is scraped at all (the generated list is empty or was not loaded) | 10m | critical |
  | `DiskAlmostFull` | a filesystem is over 90 % used | 10m | warning |
  | `FilesystemReadOnly` | `node_filesystem_readonly == 1`, less the mount points of `prometheus_alert_readonly_ignore` (deliberate read-only mounts) | 2m | critical |
  | `MemoryPressure` | under 10 % of memory available | 10m | warning |
  | `UpsOnBattery` | `nut_ups_on_battery == 1` (a host with a UPS, control ups-protection, lost mains) | 1m | critical |
  | `UpsLowBattery` | `nut_ups_low_battery == 1` (the host is shutting down) | 0 | critical |
  | `UpsMonitorDown` | `nut_monitor_active == 0` (no automatic shutdown on power loss) | 5m | critical |
  | `UpsUnreadable` | `nut_ups_up == 0` (driver or USB cable) | 5m | warning |
  | `UpsCheckStale` | the UPS check has written no metrics for 5 minutes | 5m | warning |

  A host with no UPS exposes none of the `nut_*` families, so the five UPS rules never fire there.

  The rules are proved with the product's own `promtool test rules` against series that should
  and should not fire them (`tests/roles/test_prometheus_role.py`).
- **HTTP(S) up/down probes (opt-in, `prometheus_probes_enabled: true`)**: the function an uptime
  monitor serves. A **blackbox exporter** (a second container of the same compose project, pinned by
  digest, no published port) is probed through by a `probe` job. The target list is generated from
  the registry (`hnx registry generate --only prometheus --probe-targets`): every service row that
  is published at the edge (`public_hostname`) or declares an `http` health endpoint, less
  `prometheus_probe_exclude`. A routed row is probed by its **edge name** (what a user types: name,
  certificate, edge and backend), any other by the name it answers by. An edge answer of 2xx, 3xx,
  401 or 403 is up (a sign-in redirect is the edge working); a 5xx, a refused connection, a bad
  certificate or no answer inside `prometheus_probe_timeout` is down. The `ProbeDown` rule
  (`probe_success{job="probe"} == 0`, `for: 5m` = `prometheus_alert_probe_down_for`, critical) goes through the
  same state-diffed forwarder as every other alert, so a probe going red posts once, and its
  recovery posts once. Limit: a row behind the edge's forward auth answers with the sign-in redirect
  whether or not its backend is up, so for those the probe proves the name, certificate and edge;
  the row's own health check is the backend's proof.
- **The alert path reuses the one the lab's alerting controls already use**: a timer
  (`hnx-prometheus-alerts.timer`, every 60 s) runs `prometheus-alert-notify`, which asks the local
  service which alerts fire and posts to the notify service by logical id (`prometheus_notify_id`),
  with a publish token by secret reference, as the `needrestart` and `lynis` roles do: state-diffed
  (a message only when the set of firing alerts changes, naming new and resolved ones, "cleared"
  once when it empties; a failed post stays owed), no redirect followed, no proxy taken from the
  environment, the token never in an error, a critical alert posted at priority 4, `--test` at
  deploy when the channel changed (LL-567: a control deployed green whose channel could never
  deliver fails the play), and the last send's outcome recorded for `health`. No second server
  (an alert manager) is run: this is one rule set and one channel. **It also covers the case the
  service cannot cover itself**: when the service cannot be asked for
  `prometheus_unreachable_after_minutes` in a row, that is posted once, and so is its recovery.
- **Who watches the watcher.** The service cannot page about itself, and the forwarder runs on
  the same guest, so three things look from outside or at the forwarder: (1) the forwarder alerts
  once if the service cannot be asked, and on its recovery; (2) every forwarder run writes the
  shared **last-run record** (`/var/lib/homelabnext/last-run/timer%3Aprometheus%2Falerts.json`,
  role `last_run`), which the status hub's `job-last-run` mapping reads and judges for lateness from
  the calendar the record carries, so a dead timer or a dead guest is a red item on the hub, not
  silence; the unit's `ReadWritePaths` names that directory, and the role's `health` hook fails when
  the record is missing or older than five runs (the unit ignores a writer failure by design, so
  health is what makes it visible: LL-567); (3) the registry row's `health` probe (`/-/healthy`) is
  what the hub and the hypervisor-side checks poll. The overlay should ship the last-run directory
  to the hub as it does for the other role timers.
- **The outside dead-man (LL-571).** (1)-(3) all live on this guest or ask this guest, so a stopped
  metrics container, a dead timer, a dead guest or a rule file that never loaded are silent to
  them. On 2026-11-16 the container sat `Exited` for 16 hours after a power cycle and nothing paged.
  So the forwarder also posts a **heartbeat**: one minimum-priority message to the topic
  `prometheus_heartbeat_topic` (default `hnx-heartbeat-metrics`) of the notify service, at most
  every `prometheus_heartbeat_every_minutes` (5), and **only on a run that proved the whole chain**:
  the metrics service answered AND the always-firing `Watchdog` rule (`vector(1)`, severity `none`,
  never posted as an alert) is firing, i.e. rules loaded and evaluated. A timer on the notify
  service's host (module `ntfy`, `ntfy_deadman_beats`) pages once when that topic goes quiet and
  once when it returns. The heartbeat is silent on a failed post (it stays owed; the unit exits 2).
  **The receiver must not be on this guest**: the role compares the metrics row's and the notify
  row's registry `host_id` (and the endpoint's address against loopback and this guest's own
  addresses) and refuses a heartbeat whose receiver would die with it. It also **resolves the
  receiver's name as this guest does** (`getent ahosts`: DNS, aliases, CNAMEs, IPv4 and IPv6) and
  refuses when any answer is loopback or one of this guest's own addresses, or when the name does not
  resolve (`prometheus_heartbeat_allow_unresolved: true` accepts that). A failing alert post skips
  that run's heartbeat on purpose (the notify path is broken, so the watch's silence is the signal); `prometheus_heartbeat_topic: ""`
  turns the heartbeat off, and with it any outside monitor.
- **A boot unit** (`prometheus_boot_unit`, default true; `compose_app_boot_unit`): a oneshot
  `hnx-compose-prometheus.service` runs `docker compose up -d` after docker at every boot, so a
  container that did not come back after a power cycle is started and a failure to start it is a
  failed unit. `remove` disables and deletes it, and so does `prometheus_boot_unit: false` (an
  existing unit is disabled and deleted, so the opt-out opts out).
- **Nothing reloads through an HTTP API.** The lifecycle API stays off (anyone who could reach the
  port could shut the server down); a changed configuration is a `SIGHUP`, sent once the service
  reports ready (a signal sent earlier kills a process that has not installed its handler).

## Hardware alerts

A rule group `hnx-hardware`, always rendered (a host without a family never fires its rules), on the
host exporter's own temperature sensors and on the families the core role `hardware_metrics`
(control `hardware-metrics`, docs/compute-model.md) writes to the exporter's textfile directory:

| Alert | Fires when | For | Severity |
|---|---|---|---|
| `CpuTemperatureHigh` / `Critical` | a CPU package sensor (hwmon `k10temp`, `coretemp`) over `prometheus_alert_cpu_temp_warning_celsius` (85) / `_critical_celsius` (92) | 5m / 1m | warning / critical |
| `NvmeTemperatureHigh` / `Critical` | an NVMe composite temperature over 70 / 80 C (settings) | 10m / 2m | warning / critical |
| `GpuTemperatureHigh` / `Critical` | a GPU over 85 / 92 C (settings) | 5m / 1m | warning / critical |
| `GpuPowerOverCap` | a GPU's draw (`hw:gpu_power_watts`: its reading, or the rate of its energy counter) over `prometheus_alert_gpu_power_cap_watts` (200) for the window (a spike during prefill is accepted) | 5m | warning |
| `GpuPowerCapNotApplied` | a GPU's power limit in force is over the cap (a restarted guest whose cap script did not run) | 10m | critical |
| `GpuLost` | the driver reports a card it cannot reach, or the host has more GPU PCI functions than the driver lists (fallen off the bus) | 2m | critical |
| `GpuCountDropped` | fewer GPUs are reachable than at any time in the last day | 5m | critical |
| `GpuDriverError` | a new driver fault report (an Xid, a wedged device) in the kernel log; clears after `prometheus_alert_board_event_window` | 0 | critical |
| `GpuNotComputing` | a host marked `expect_gpu_processes` has no process holding GPU memory: the inference server fell back to the CPU or stopped | `prometheus_alert_gpu_idle_for` (10m) | critical |
| `PoolUnhealthy` / `PoolDataErrors` / `PoolDeviceErrors` | a pool not ONLINE / files with permanent errors / device error counters over 0 (until `zpool clear`) | 1m / 0 / 0 | critical / critical / warning |
| `PoolAlmostFull` | a pool at `prometheus_alert_pool_used_percent` (85) or more | 15m | warning |
| `BoardSensorCritical` / `Warning` | a board sensor past its critical (or non-critical) threshold, or a discrete sensor (a power supply) asserting a fault | 1m / 10m | critical / warning |
| `FanFailed` / `FanReadingLost` | a fan under its critical speed or at 0 RPM / a fan that had a reading in the last day has none | 2m / 5m | critical |
| `BoardCriticalEvent` | a new critical, non-recoverable or failure entry in the board's event log (a thermal trip), with its sensor and event; clears after the window | 0 | critical |
| `GuestDown` | a hypervisor guest set to start at boot is not running | 5m | critical |
| `HardwareMetricsStale` / `HardwareCollectorDown` | the metrics file is over 5 minutes old / a collector cannot read its source | 5m / 10m | warning |

All of them go through the same state-diffed forwarder as every other alert. The rules are proved
with `promtool test rules`, each firing on its series, silent on the healthy twin, and the event
rules clearing after their window (`tests/roles/test_prometheus_role.py`).

## SNMP polling (opt-in)

`prometheus_snmp_enabled: true` runs an SNMP exporter beside the service (a third container of the
compose project, pinned by digest, no published port). Every entry of `prometheus_snmp_targets`
(`{host: <registry host id>, modules: [...], watch_ports: <ifName regex>}`) is a job `snmp-<host>`:
the address is the registry host's (a host the registry lacks is refused by name), the modules are
the exporter's bundled ones (`if_mib`, `system`, ...) or the role's `nas_storage` (a storage
appliance's disk, fan and volume tables), and the community is read from the store by reference
(`prometheus_snmp_community_ref`) into a file only that container mounts. An interface whose
`ifName` matches the job's `watch_ports` is labelled `watched="1"`; only watched ports alert:
`NetworkPortDown` (enabled, no link, 5m, critical), `NetworkPortErrors` (over
`prometheus_alert_port_errors_per_minute`, 15m), `NetworkPortSpeedDropped` (linked below its speed
of the last week, 15m). `NasDiskUnhealthy`, `NasDiskTemperatureHigh`, `NasVolumeNotReady`,
`NasVolumeAlmostFull` and `NasFanStopped` read `nas_storage`. A device that does not answer is the
`TargetDown` of its job.

## Inference probes (opt-in)

With the probes on, `prometheus_llm_probe_roles` (model role names) are asked every
`prometheus_llm_probe_interval` (5m) for a one-token chat completion through the gateway row
`prometheus_llm_probe_gateway`, with the gateway key `prometheus_llm_probe_key_ref` (a file only the
probe exporter mounts). A refusal, a 5xx (the gateway's `upstream_unavailable`) or no answer in
`prometheus_llm_probe_timeout` is down: `LlmProbeFailed` after 10m (critical); an answer slower than
**`LlmDecodeCollapsed` (critical, always rendered)** reads the llama.cpp servers' own metrics: tokens generated per second of generation over `prometheus_alert_llm_decode_window` (15m), below `prometheus_alert_llm_decode_min_tps` (5) for 10m while the server is generating. It exists because a model server that loses its GPU falls back to the CPU and keeps answering: on 2026-11-25 the large model ran at 0.46 tok/s (normal ~19) for 17 h, the one-token probe still passed in time, and only `GpuNotComputing` fired. This alert names the impact (tokens/s) so the page reads as "every AI job is crawling". `prometheus_alert_llm_probe_slow_seconds` for 15m is `LlmProbeSlow` (warning). This is the caller's
own path; `GpuNotComputing` is the earlier, cheaper signal of a server that fell back to the CPU.

## The slot

`metrics` has no contract yet, so it is **provisional** in `examples/modules/slots.yml`
(`contract: null`, not required in core): the obvious standard is the exposition format the scrape
reads plus the query and alerts API. The shared adapter
`homelabnext.conform.adapters.metrics` is that API as a read-only Python client (`query`,
`alerts`, `rule_names`, `targets`), on `HNX_ENDPOINT_METRICS`; it is what a future suite would
drive. There is no conformance target here because there is no suite to bind.

## The host-metrics role and its control

`ansible/roles/node_exporter` installs the distribution's `prometheus-node-exporter` package and
sets its arguments: it **listens on the guest's own address only** (never all interfaces; the
package starts on all of them until the first restart, which the role does at once), with the
textfile collector off and pseudo filesystems excluded, so the alert rules read real disks. Its
`port` is required (no default): the one number the overlay also gives the generator
(`prometheus_node_exporter_port`). `health` asks `/metrics` and requires the metric families the
default rules read. The endpoint has no authentication, so **the guest's `firewall_rules` must
admit only the metrics guest** on that port (as ntfy's), and, on the metrics guest itself, the
container's subnet (next section).

The role is bound to a baseline control by the overlay's `guests/_baselines.yml` (the example
baselines are the platform's and bind none, so every site chooses; the control id is the
overlay's):

```yaml
controls:
  metrics-agent:
    layer: detection
    description: Host metrics (CPU, memory, filesystems, network) are exposed to the metrics service.
    role: node_exporter
    settings: [port]
    verify: the exporter answers /metrics on the guest's address and exposes the filesystem and memory families
```

and listed in the baseline every guest names (`base`), with `with: {port: 9100}`.

**The hypervisor (pm205 in the first lab) is a target too** and is not a module guest: it is
covered by the same control through its own baseline. The `hypervisor` baseline (or whatever the
overlay names the one its nodes use) lists `metrics-agent` with the same `port`; `hnx guests
baselines` then shows the hypervisor covered, and the role runs on it as on any Debian-family
host (`apt`, `ansible_host` as the bind address). The hypervisor's own host firewall
(`host_firewall` in `_nodes.yml`) admits the metrics guest on that port. A hypervisor that is not
Debian-family, or that the site does not manage with this role, is named in
`prometheus_node_exporter_exclude` and monitored another way; it is never left as a permanent
`TargetDown`.

## The guest's own exporter (the metrics guest scrapes itself)

Prometheus runs in the compose network `prometheus_default`. A packet from the container to the
guest's **own** address never leaves the VM: it arrives on the guest's `INPUT` chain with the
container's address as the source, where a guest with the `host-firewall` baseline drops it unless a
rule names it. (The hypervisor's per-VM firewall never sees it.) So the target for the metrics
guest's own exporter, `<guest address>:<port>`, is down ("context deadline exceeded") until the
guest admits the container. The platform has no hook by which a module contributes a rule to a
guest's firewall (the rules are the guest file's `firewall_rules`, one language for the hypervisor
and the guest), so the module does two things and the site does one:

1. **The module pins the network** (`prometheus_network_subnet`, **required**, no default: an
   address range is the site's), so the source address is stable across recreates. It is judged in
   one place (`compose_app`'s `network_subnet.yml`): an RFC 1918 network address (host bits zero)
   with a prefix from /16 to /29, never loopback, link-local, multicast or public space, and not
   overlapping the guest's own network (`ansible_default_ipv4`, when facts are gathered) or
   containing its address. A /24 is plenty for one project, and the narrower the range the fewer
   sources the guest's rule admits. The first apply after pinning recreates the network and the
   container.
2. **The site admits exactly that subnet to exactly that port** on the metrics guest, nothing wider
   (the overlay's guest file, beside the other readers):

   ```yaml
   firewall_rules:
     inbound_allow:
       - {name: metrics-self-exporter, proto: tcp, ports: "9100", source: <prometheus_network_subnet>}
   ```

   The rule's `ports` is `prometheus_node_exporter_port`. The container's own port 9090 needs no
   rule (see "What it does").

Still pick a range no other docker bridge on the guest uses (the role cannot see them).

## Reaching the interface (the decision)

**Not through the edge.** The row has no `public_hostname`, so the edge renders no site for it, and
Prometheus has no login of its own (`auth: none` states that). The documented production shape
(docs/architecture.md: "behind the forward-auth proxy") is a public route with `auth: idp`; this
module does not ship it, because the lab's alerts and status already reach the operator by the
notify service and the status hub, and a UI with a query language that can read every label of every
host is better one SSH tunnel away than one session cookie away. The interface is on
`<guest>:9090`, reachable from the zones the guest's firewall admits (the status hub and the
operator's management host). A site that wants the SSO'd route adds it as a **module change**, not
an overlay edit: the row's `public_hostname`, `auth: idp` and `roles` (a public route also needs
`grants.public_routes` and a name on the edge's certificate), because the registry-row equality
check refuses a row that gains a public route on its own.

## Secrets (names only)

| Secret | What | Read by |
|---|---|---|
| `secret:prometheus/notify-token` | a publish token for the notify service (write-only is enough) | the role at deploy; the forwarder reads the owner-only copy `/etc/homelabnext/prometheus-notify.auth` |
| the secrets a registry row's `metrics.auth.secret` names | scrape credentials | the role at deploy; written under `<data root>/scrape-credentials/` |

A missing entry is refused **by name before anything is written** (readiness, and `main` again): the
message names every `secret:` reference the store has no value for. The notify token may be the
notify module's publisher token copied under this name (one writer, one store), or a token of its
own; the overlay decides.

## Hooks

| Hook | What it checks or does |
|---|---|
| `readiness` (also the module's preflight) | `docker_engine` readiness, the settings, the targets render from the registry, every secret reference exists in the store and has its form |
| `health` | every container running and healthy; `/-/ready`; the running configuration is the one on disk (the last reload succeeded), with the configured retention; the default rules (and ProbeDown, when probes are on) are loaded and healthy; the host job (and the probe job, when on) has targets; the forwarder's last send (or `--test`) reached the notify service. A target that is down is an alert, not a failure of the service. |
| `backup` | `compose_app`'s manifest naming the data root (the window and the scrape credentials ride along, so a backup of this host holds them) |
| `export`, `restore` | nothing: the samples are a rolling window the targets produce again |
| `upgrade` | refuses a target not pinned by tag and digest or from another repository, then records the bump (`compose_app` upgrade). A kept 2.x data directory opens in 3.x, but can then be downgraded only to 2.55. |

## Using it in a site

The overlay carries every real value ([selection](../../docs/modules/selection.md),
[registry rows](../../docs/modules/registry-rows.md), [apply path](../../docs/modules/apply.md)):

1. **A guest file** (`lab/guests/<name>.yml`): a VM, baseline `base`, resources covering the
   footprint (and the docker engine), `firewall_rules` admitting the readers on 9090 and SSH from
   the deploy host, and the exporter port from the metrics guest on **every** guest; a `backup:`
   policy if the window is worth keeping.
2. **The selection** (`lab/modules.yml`): `hosts.<name>: {guest: guest:<name>}` and
   `slots.metrics: [{provider: prometheus, instance: <instance>, placement: {server: <name>}}]`.
3. **The registry row** (`lab/services.yml`): `registry/services.yml`'s `metrics` row renamed to the
   instance, `host` the guest's name, `version: "3.15.1"`, plus at most `standing`, `backup_job` and
   `scope`. Rows of the other services that expose metrics carry their own `metrics:` block: they
   become jobs without a line of configuration here.
4. **The secrets**, by name, in the store (above).
5. **The role's variables** (`group_vars/mod_prometheus_server.yml`): `prometheus_logical_id:
   <instance>`, `prometheus_registry: <absolute path of lab/services.yml on the controller>`,
   `prometheus_node_exporter_port: 9100`, `prometheus_network_subnet: <a CIDR of the site's own>` (and the guest's rule for it, above), and the `hnx` command (`prometheus_hnx_cli`, default
   `[hnx]`), optionally `prometheus_node_exporter_exclude`, `prometheus_retention_time`,
   `prometheus_notify_id`/`prometheus_notify_topic`, `prometheus_heartbeat_topic`/`prometheus_heartbeat_every_minutes`, `prometheus_alert_readonly_ignore`, `prometheus_alert_schedule` (every minute, or every 30 seconds), and `prometheus_notify_allow_plain_http: true`
   while the notify service has no TLS (LAN only; the role says so in the run).
   **The dead-man's other half is in the notify module's variables** (`group_vars/mod_ntfy_server.yml`):
   `ntfy_deadman_beats: [{name: metrics, topic: <the same as prometheus_heartbeat_topic>,
   max_age_minutes: 15}]` (`ntfy_deadman_alert_topic` defaults to the forwarder's alert topic); the
   notify service must be placed on a guest other than the metrics guest.
6. **Apply**: `docker_engine` on the module group (`mod_prometheus_server`), the exporter role on
   every guest (the baseline), then the rendered `modules.yml` twice (the second `changed=0`),
   then `checks/prometheus.yml`.

## Known limits

- **Plain HTTP and no login inside the lab.** Prometheus listens on the guest's own address with
  no authentication, and the alert token travels in clear to a notify endpoint without TLS (the
  explicit opt-in). The guest's `firewall_rules` are the control for traffic from other machines
  (the hypervisor's per-VM firewall, and the guest's own where it has the `host-firewall`
  baseline); a container's traffic to the guest's own address is only ever seen by the guest's own
  firewall (above).
- **Targets are addressed by the registry's alias names** (`<capability>.svc.<domain>`), so the lab's
  resolver must serve them to the metrics guest; a name that does not resolve is a `TargetDown`.
- **One channel, no inhibition or grouping.** A burst of unrelated alerts is one message per
  change of the set. An alert manager is the answer if the lab outgrows that.
- **The exporter never listens on all interfaces**: the role writes its arguments before the package
  can start the service (the package keeps an existing argument file).
- **The container's network is Docker's default bridge**, so `egress: none` is what the service is
  configured to do, not a network rule.
- **Removal** stops the timer, removes its units, the script and the token, and takes the container
  down; the data root (the window, the rendered configuration, the scrape credentials) and the
  compose project stay for the operator.
