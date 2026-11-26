<!-- SPDX-License-Identifier: Apache-2.0 -->
# Module `vector`: the log-pipeline provider

A provider module ([module manifest](../../docs/modules.md), draft, ADR-0027 proposed; the SOC
bundle of [ADR-0049](../../docs/adr/0049-the-soc-data-plane-and-the-lab-checks-move-as-modules.md) step 7) that fills the
`log-pipeline` slot with a [Vector](https://vector.dev) aggregator and a small enrichment sidecar.
It is a **service, not a machine**: the guest it runs on is the site's guest file (the SIEM guest,
beside the manager whose alert files it tails), and the site's selection places the module's one
host role (`aggregator`) on it. Nothing here names a real host, address, VM id or secret value; those
live only in the private overlay.

| | |
|---|---|
| Slot | `log-pipeline` (contract `conformance/protocols/log_pipeline.py`, [log pipeline](../../docs/log-pipeline.md)), stateless |
| Adapter | the module's own `hnx_modules.vector.log_pipeline:make` (`roles/vector/files/hnx_modules/vector/`) |
| Product | Vector 0.46.1 (`docker.io/timberio/vector`, debian build), pinned by tag and digest |
| Host role | `aggregator`: kind `vm`, baseline `base`, footprint 1 vCPU, 1536 MB, 10 GB |
| Role | `vector` (role interface v1), a wrapper of the core `compose_app` with two services |
| Requires | `cap:secrets`, `cap:object-store` (the staging bucket) |
| Egress | none |
| Public route | none |

## What it does

```text
                         UDR7 / router  --514/udp-->  syslog_udp ----+--> raw_syslog --> manager's syslog input (unchanged)
   senders that can   --6514/tcp+TLS-->  syslog_tls ----+            |
   sensors' Vector   ----6000/tcp------>  sensors   -----+--> stamp --+--> sidecar --> remap --> staging (object store)
   manager alerts.json / archives.json -> file sources --+  (route,    (labels)       (OCSF)     one prefix per table
                                                            peer, raw)                           -> lake writer
```

1. **Receive** (Vector). Syslog on 514/udp (the router sends UDP only, decision D4), syslog over TLS
   on 6514/tcp, the sensors' vector protocol on 6000/tcp (TLS, optionally mutual), and the manager's
   `alerts/alerts.json` and `archives/archives.json` under the manager's `logs` directory (mounted read-only, supplementary group 999, followed by inode across the daily rotation), tailed with checkpoints from the start of each file. Every
   listener is published on the guest's own address only; the guest's firewall file admits each
   one's senders and no one else.
2. **Stamp** (Vector, one `remap` per input). Each event becomes an envelope
   `{route, peer, line}` (or `{route, event}` for a sensor event that arrives structured). The route
   is a constant of the configuration; the peer is the socket source's own field; the line is the
   raw text. The stamp reads **no field of the event body** (a test holds every stamp to that).
3. **Label and remap** (the sidecar, `roles/vector/files/hnx_modules/vector/sidecar.py` and `ocsf.py`).
   - `labels.hnx_runtime` and `labels.hnx_tlp` are set by the core library's own rules,
     `homelabnext.logpipeline.enrich` and `enrich_tlp`, from the rendered `runtime-labels.json` and
     `tlp-sources.json` (see below). The role copies the library's files **verbatim**
     (`homelabnext/tlp.py`, `homelabnext/logpipeline/*`) beside the sidecar; a test proves the list is
     the complete import closure, standard library only, and that a layout built from the copies
     labels a corpus exactly as the core does. The rule on the guest is the library's bytes, not a
     port of it.
   - The labelled event is archived whole (`raw_archive`) and remapped to its OCSF classes.
4. **Stage** (Vector). Each row goes to `s3://<bucket>/<prefix><table>/dt=YYYY-MM-DD/hour=HH/<id>.ndjson.gz`
   (gzipped newline-delimited JSON), batched at 32 MiB or 60 s, through a disk buffer that blocks its
   source when full and never drops. The lake writer commits each table to the lake.
5. **Forward** (Vector). The raw syslog goes on, byte for byte, to the manager's syslog input, so the
   router's decoders and rules keep working. The manager sees the aggregator as the sender; the
   original sender is in the CEF record, and in the aggregator's own archive.

## The labels and the observed address

`docs/log-pipeline.md` is the contract. The sidecar adds one thing it needs and the contract
leaves to the collector: *what address did the collector see* for each record. It is per route
(`observe` in the rendered `enrich.json`), and it is never read out of the event body:

| Route kind | `observe` | The observed address |
|---|---|---|
| syslog (UDP, TLS) | `recorded` | the peer of the connection; **when the peer is one of `vector_trusted_recorders`** (the router), the client address the router recorded in the CEF record's `src`, else the peer |
| SIEM streams | `agent` | `agent.ip`, the address the manager recorded for the agent that sent the event (an event with none, the manager's own, has none) |
| sensors | `recorded` | the client the sensor's capture recorded (`src_ip`, `id.orig_h`) |

An address the runtime table does not hold, none, and anything that is not a bare IP address leave the
event **without** `hnx_runtime`; the sidecar counts those per route in its status file
(`counters.<route>.unlabelled`), the metric the contract asks a provider to keep, because an unknown
address and `none` read the same to the detections.

`hnx_tlp` is set from the **route**: each input feeds exactly one dataset, `<module>/<dataset>`, a
constant of the configuration. The defaults (`vector/syslog-udp`, `vector/syslog-tls`,
`vector/sensor-stream`, `vector/siem-alerts`, `vector/siem-archives`) hold no declaration, so every
event is `red`, the safe answer; a site that declares a looser label for a dataset names that
dataset's route in the overlay (for instance the SIEM module's own alert dataset), and a change of
route is a change of declaration (review it as one). A TLP label the event arrived with is replaced.

The tables are rendered by the platform and copied by the role:

```text
hnx guests render <guests> --site <site> --target runtime-labels --out <dir>   # runtime-labels.json
hnx modules render ...                                                          # tlp-sources.json
```

`vector_runtime_labels_src` and `vector_tlp_sources_src` name them (absolute paths on the
controller). The sidecar reloads a changed file without a restart and **keeps the last good table**
when a new one does not read, naming the error in its status; the health hook compares the digests the
sidecar reports with the deployed files, so a stale or refused table fails health instead of
labelling by the older guests, silently.

## OCSF classes and severity

One event gives its labelled raw row and one row per class it maps to (a Wazuh authentication alert
gives `raw_archive`, `detection_finding` and `authentication`). Row ids (`uid`) are the SHA-256 of the
table, the route and the event: the same event always has the same id, which is the lake's replay key.

| Table | class_uid | Fed by |
|---|---|---|
| `detection_finding` | 2004 | manager alerts; sensor alerts |
| `authentication` | 3002 | manager alerts and archives (sshd, pam and the authentication groups); a NAS connection-log login (`Users: .., Source IP: .., Action: Login OK/Fail`) forwarded by syslog |
| `vulnerability_finding` | 2002 | the manager's vulnerability detector |
| `compliance_finding` | 2003 | the manager's configuration assessment |
| `file_activity` | 1001 | file integrity events |
| `process_activity` | 1007 | audit and Sysmon process events |
| `network_activity` | 4001 | router CEF records with a source and a destination; sensor flows |
| `dns_activity` | 4003 | sensor DNS records |
| `http_activity` | 4002 | sensor HTTP records; the edge's access log (Caddy JSON via the host's SIEM agent: client, site, method, URI, status, bytes) |
| `raw_archive` | none | every event, labelled, whole (`route`, `location`, `decoder_name`, `agent_*`, `rule_id`, `full_log`, `raw`) |

The first five (authentication, detection_finding, dns_activity, network_activity,
vulnerability_finding) are written in exactly the columns of the pinned lake schemas
(`schemas/ocsf/*.v1.json`; a test validates the golden rows against them). `compliance_finding`,
`file_activity`, `http_activity` and `process_activity` have **no pinned schema yet**: their rows
follow the same flat conventions and are staged under their own table names for the lake writer to take
once a schema is pinned (an undecided item in the PR). `raw_archive` is the source census's table; its
columns are the module's contract.

**Severity** is OCSF's `severity_id` (1 informational, 2 low, 3 medium, 4 high, 5 critical), derived from
the severity the **source** grades, through a documented band table, never a rule level copied across
(the old pipeline wrote the manager's 0-15 `rule_level` into the column, so a level 12 read as "severity
12" next to a sensor's 3):

| Source | Mapping |
|---|---|
| Manager `rule.level` | 0-3 informational, 4-6 low, 7-11 medium, **12-14 high**, 15 critical (level 12 is the manager's own "high importance" line, so the paging line `severity_id >= 4` is the old level >= 12 set) |
| Sensor alert | the signature's own `signature_severity` grade when it has one (informational 2, minor 3, major 4, critical 5), else the numeric `alert.severity` (1 high, 2 medium, 3 low) |
| CEF (router) | the header's 0-10: 0 informational, 1-3 low, 4-6 medium, 7-8 high, 9-10 critical |
| No grade of its own (flows, DNS, HTTP, access logs) | informational; an authentication failure is low |

An event cannot bring its own severity: a `severity_id` in the event is ignored (a test holds it).
`detection_id` is `det:siem-unmapped` unless `vector_detection_ids` maps the rule id to a logical id,
and the rule number stays in `finding_uid`: a detection id is never an engine rule number.

## Staging contract (for the lake writer and the source census)

- Bucket `vector_s3_bucket`, prefix `vector_s3_prefix` (default `lake-writer/staging/`); key
  `<prefix><table>/dt=%Y-%m-%d/hour=%H/<id>.ndjson.gz`. `dt` and `hour` are the **write** time (UTC),
  not the event's; the row's `time` is the event's.
- A line is one JSON object: the row. Each row has `labels` (`hnx_tlp`, and `hnx_runtime` when set).
  The lake writer turns it into the lake row with `homelabnext.lake.rows.row_from_event` (the row's
  `tlp` is `labels.hnx_tlp`, never an event field) and refuses a row without a canonical label.
- Delivery is **at least once**: a replayed line is the same `uid`, and the lake's content key makes it
  a no-op. Staged objects are the lake writer's to delete after its commit; the module keeps none of
  its own bookkeeping in the bucket. The dataset's retention (14 days) is the ceiling.
- The lake writer is the **only** writer of each table (the one-writer rule, LL-067): this module never
  writes the lake, only stages.

## Role and hooks

- **Images** are pinned by tag and digest: the aggregator (`role:vector/vector_image`) and the
  interpreter the sidecar runs on (`role:vector/vector_sidecar_image`, the repository's own python pin),
  both watched by `tools/pin_freshness.py`.
- **Containers** run as `vector_uid:vector_gid` (61005), every capability dropped, `no-new-privileges`,
  read-only root. The listeners are on unprivileged ports inside (host 514 is published to 5514). The
  sidecar has no network port: two unix sockets in `<data root>/run` join the containers.
- **Backpressure, not loss.** Vector's disk buffers block their source when full. The sidecar reads no
  more input while it cannot hand rows to Vector, so the pressure lands in Vector's buffer. A crash can
  lose the few lines in flight between the two processes' sockets; `vector_buffer_max_bytes` bounds the
  disk the buffers take (a full disk stopped the old pipeline, LL-585: the guest's disk criterion is the
  other half).
- **The configuration is validated by Vector** (`vector validate` in the pinned image, no network,
  dummy secrets) before it replaces the one in use. A startup-only health check failure of the staging
  sink is logged and not fatal (LL-258); the role's health hook judges the running pipeline.
- **`main`** validates, refuses a malformed credential or table (object-store key forms, PEM forms,
  table schemas), builds the compose project, copies the code, the label rules, the tables and the
  certificate, validates and installs the configuration, and starts both containers; the changed ones are
  restarted. A second run is `changed=0`.
- **`readiness`**: the container engine, every credential in its form, both tables, the object store
  answering, the manager's stream directory present.
- **`health`**: both containers healthy; the TCP listeners answer and the UDP one is bound; the
  sidecar's status is fresh, listening, free of table errors, and names exactly the deployed tables.
- **`export` / `restore` / `backup`**: the file checkpoints (where Vector has read in each stream) as an
  object-tree with a sha256 listing; restore checks sizes and hashes and refuses a tampered export. The
  disk buffers are not exported. A lost checkpoint replays the stream and the lake's content key absorbs
  it.
- **`upgrade`**: a bump of the aggregator image, refused unless pinned by tag and digest in the same
  repository; the checkpoints are exported first.
- **Secrets** (by reference, all in the module's own namespace): `s3-access-key`, `s3-secret-key` (the staging
  bucket's key pair, in the 0600 env_file only), `tls-cert`, `tls-key` (the listener certificate, files
  the container reads; the key is 0640 `root:<gid>`, never in the compose file).

## What the overlay adds

- `lab/modules.yml`: `log-pipeline: [{provider: vector, instance: log-pipeline, placement: {aggregator: <host>}}]`.
- `lab/services.yml`: the row exactly as bound (`host` the guest, `version` 0.46.1), `impl: vector-aggregator`.
- Group variables: `vector_s3_region`, `vector_siem_logs_dir` (the manager's `logs` directory on the
  same guest), `vector_siem_syslog_host`/`port` (the manager's syslog input: **not** 514, which the
  listener holds), `vector_runtime_labels_src`, `vector_tlp_sources_src`, `vector_trusted_recorders`
  (the router's address), `vector_detection_ids`, and the SIEM routes
  (`vector_route_siem_alerts`/`archives`, the SIEM module's own datasets, to give them their declaration).
- The guest's firewall file: 514/udp from the router and the other UniFi gear, 6514/tcp from the guests
  that can use TLS, 6000/tcp from the sensor hosts, and the object store reachable on its port.
- The four secrets, seeded create-only; the certificate from the lab CA.
- The SIEM manager's syslog `<remote>` input on `vector_siem_syslog_port`, allowing the aggregator.

## Limits

- **Router syslog is UDP** (the router sends nothing else): a datagram's source can be spoofed on a
  shared segment. The controls are the allowed-source firewall rule and the labels by observed source
  (`docs/log-pipeline.md`, "Limits"); where a sender can use TCP+TLS it should.
- **The vector protocol carries no peer address** (checked on 0.46.1: a forged `host` or `source_ip` in
  a sensor's event arrives as written). A sensor event's identity is therefore the route, the firewall
  rule on 6000 and, with `vector_sensor_ca_ref`, the client certificate; its observed address is the
  client its capture recorded. A compromised sensor can label by what it records.
- **A trusted recorder is trusted.** `vector_trusted_recorders` names the services whose CEF `src` is
  taken as the client; list only the router.
- **The manager attributes forwarded syslog to the aggregator**, not to the router; its allowed-ip list
  must name the aggregator's address.
- **At-least-once, bounded in-flight loss** (above). The raw forward to the manager is best effort (UDP
  or TCP with no retry beyond the sink's).

## Conformance

```text
PYTHONPATH=modules/vector/roles/vector/files hnx conform run log-pipeline --target modules/vector/conformance/target.yml
```

The adapter drives the sidecar's own labelling path (`observed_for`, then `label_event`, which composes
`enrich` and `enrich_tlp`); a test plants four defects in the sidecar and requires the suite to fail on
each. The end-to-end evasion fixtures (`tests/logpipeline/evasion`) are run through the sidecar's
envelope path and then the detection rules. The sidecar's remaining duties (the observed-address policy,
the remap, the tables) are proved by `tests/modules/test_vector_pipeline.py` with goldens in
`tests/modules/golden/log-pipeline/`; the role by `tests/roles/test_vector_role.py`.

The pipeline was also rehearsed once against the real images: the validated configuration, the sidecar
and Vector together over their unix sockets, a manager alert line and a router CEF datagram in, the
labelled rows out.
