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
- **Host metrics on every guest** are the core role `node_exporter` (below), bound to a baseline
  control the overlay attaches to every guest.
- **Retention** is `prometheus_retention_time` (default `30d`), with an optional size cap
  (`prometheus_retention_size`), both in `prometheus.yml` (`storage.tsdb.retention`: the command-line
  flag is deprecated in 3.x). Health reads the running value back.
- **A small default rule set**, rendered with the thresholds as settings:

  | Alert | Fires when | For | Severity |
  |---|---|---|---|
  | `TargetDown` | `up == 0` | 10m | critical |
  | `DiskAlmostFull` | a filesystem is over 90 % used | 10m | warning |
  | `FilesystemReadOnly` | `node_filesystem_readonly == 1` | 2m | critical |
  | `MemoryPressure` | under 10 % of memory available | 10m | warning |

  The rules are proved with the product's own `promtool test rules` against series that should
  and should not fire them (`tests/roles/test_prometheus_role.py`).
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
- **Nothing reloads through an HTTP API.** The lifecycle API stays off (anyone who could reach the
  port could shut the server down); a changed configuration is a `SIGHUP`, sent once the service
  reports ready (a signal sent earlier kills a process that has not installed its handler).

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
default rules read. The endpoint has no authentication, so **the hypervisor's per-VM firewall must
admit only the metrics guest** on that port (the guest file's `firewall_rules`, as ntfy's).

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
| `health` | every container running and healthy; `/-/ready`; the running configuration is the one on disk (the last reload succeeded), with the configured retention; the four default rules are loaded and healthy; the host job has targets; the forwarder's last send (or `--test`) reached the notify service. A target that is down is an alert, not a failure of the service. |
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
   `prometheus_node_exporter_port: 9100`, and the `hnx` command (`prometheus_hnx_cli`, default
   `[hnx]`), optionally `prometheus_node_exporter_exclude`, `prometheus_retention_time`,
   `prometheus_notify_id`/`prometheus_notify_topic`, and `prometheus_notify_allow_plain_http: true`
   while the notify service has no TLS (LAN only; the role says so in the run).
6. **Apply**: `docker_engine` on the module group (`mod_prometheus_server`), the exporter role on
   every guest (the baseline), then the rendered `modules.yml` twice (the second `changed=0`),
   then `checks/prometheus.yml`.

## Known limits

- **Plain HTTP and no login inside the lab.** Prometheus listens on the guest's own address with
  no authentication, and the alert token travels in clear to a notify endpoint without TLS (the
  explicit opt-in). The hypervisor's per-VM firewall is the control, not a firewall inside the
  guest (Docker publishes the port through its own NAT).
- **Targets are addressed by the registry's alias names** (`<capability>.svc.<domain>`), so the lab's
  resolver must serve them to the metrics guest; a name that does not resolve is a `TargetDown`.
- **One channel, no inhibition or grouping.** A burst of unrelated alerts is one message per
  change of the set. An alert manager is the answer if the lab outgrows that.
- **The exporter starts on all interfaces for the seconds between the package install and the
  role's restart**; the per-VM firewall covers it.
- **The container's network is Docker's default bridge**, so `egress: none` is what the service is
  configured to do, not a network rule.
- **Removal** stops the timer, removes its units, the script and the token, and takes the container
  down; the data root (the window, the rendered configuration, the scrape credentials) and the
  compose project stay for the operator.
