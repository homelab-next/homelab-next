<!-- SPDX-License-Identifier: Apache-2.0 -->
# honeypot: event receiver, lake writer and daily intel report

A feature module (docs/modules.md) for the receiving side of a remote honeypot. The honeypot
(a decoy the site runs outside the lab, on its own account) pushes newline-delimited JSON events
one way to this module; the module spools them, lands them daily in the lake's honeypot events
table through the query service, and renders a daily intel report. Which query service, gateway
and network carry any of it is the site's selection; every real value is the overlay's.

```
 honeypot (remote) --push, one way--> receiver --> spool/events.json
                                                     |  daily (OnCalendar)
                                                     v
                                  lake writer --INSERT--> <catalog>.<schema>.events   (query service, TLS, password)
                                                     |
                                  daily report <-----+--- enrichment (public sources), model tier (gateway)
                                       |
                                       v  reports/honeypot-report.html (+ dated copies)
```

## What it installs (role `honeypot`, host role `receiver`)

| Piece | Unit | What it does |
|---|---|---|
| receiver | `hnx-<id>-receiver.service` (always on) | Listens on `honeypot_port`, appends each line to the spool. **Ingest only**: no reply, no outbound socket, no command channel back (`RestrictAddressFamilies=AF_INET AF_INET6`, nothing else writable). Each object line gets `peer_ip`, the address the connection really came from, overwriting whatever the sender claimed. A line over `honeypot_max_line_bytes`, or any line once the spool is at `honeypot_spool_max_bytes`, is dropped and counted, never written in part. |
| lake writer | `hnx-<id>-lake.timer` / `.service` | Daily (`honeypot_lake_oncalendar`). Reads the spool from a saved byte offset, maps each event onto the table's 26 columns, INSERTs through the query service, saves the offset after every statement. |
| report | `hnx-<id>-report.timer` / `.service` | Daily (`honeypot_report_oncalendar`). Queries the last 24 h and the longer high-value windows, enriches the attacker addresses, asks the model tier for a 4-bullet brief, writes `reports/honeypot-report.html` and a dated copy (older ones pruned after `honeypot_report_keep_days`). |
| rotation | `/etc/logrotate.d/hnx-<id>` | Rotates the spool (`copytruncate`: the receiver holds it open); the `prerotate` runs the lake writer first and has no `|| true`, so a failed landing aborts the rotation instead of truncating unlanded events. |

Scripts are the role's `files/`, installed at fixed paths (the script catalog resolves a unit's
`ExecStart` through them): `/usr/local/libexec/homelabnext/hnx-honeypot-receiver` (standard library
only, `/usr/bin/python3`), `hnx-honeypot-lake` and `hnx-honeypot-report` (shebang
`/opt/hnx/current/bin/python`, see "Host precondition"). Their configuration is
`/etc/hnx/<id>/honeypot.env` (no secret in it). The lake login reaches the two jobs in a root-only
`EnvironmentFile` (`HNX_SECRET_HONEYPOT_LAKE_LOGIN`, the name the platform's lake client reads) and
the gateway key as a systemd credential.

**Host precondition (no module provides it): the homelab-next runtime release.** The lake writer
and the report do not carry a query-protocol client of their own: they import the platform's lake
client (`homelabnext.conform.adapters.lake`) from the runtime release, which the site applies to
the guest with role `hnx_runtime` (as the `publishing` module's `hnx` command does). The readiness
hook proves the release's interpreter can import it and says how to supply it when not. Because the
platform's client factory builds both lake clients, the unit's environment names the query service
for `HNX_ENDPOINT_LAKE_QUERY` and, unused, `HNX_ENDPOINT_LAKE_CATALOG`; that client signs in only
over https with the certificate verified (a lab CA via `honeypot_lake_ca_ref`), follows no redirect
and uses no proxy, and retries an INSERT only when the service says it has not taken it, so a
gateway error can never write a statement twice.

## The table contract (schema identical to the existing table)

The events table has 26 columns (`event_time`, `ingested_at` as `timestamp(6) with time zone`;
`source`, `honeypot_host`, `peer_ip`, `event_type`, `src_ip`, `dest_ip`, `proto`,
`alert_signature`, `alert_category`, `http_*`, `dns_query`, `raw`, `http_content_type`, `payload`,
`cred_username`, `cred_password` as `varchar`; `src_port`, `dest_port`, `alert_severity`,
`http_status`, `payload_len` as `bigint`), Parquet/ZSTD, format v2, partitioned `day(event_time)`.
It is the table an earlier lake already holds, so the writer **never creates, alters or drops
it**: before its first INSERT it runs `DESCRIBE` and refuses (exit 2, nothing written) unless the
columns, their types and their order are exactly the contract; the health hook runs the same
check. `honeypot_ensure_table: true` is the one explicit creation, for a fresh lake only
(`CREATE ... IF NOT EXISTS`, the contract's columns, the partitioning above).

Event mapping (`to_row`) is the one the previous receiver used, kept deliberately so rows landed
before and after a cutover are queryable together: Suricata EVE lines (alert, http, dns), the HTTP
bait's captures (`http_visit`, `http_probe`, `http_payload`, with the full body in `payload`), and
the SSH decoys' sessions (`cowrie.*` and `beelzebub.*` event types, commands in `payload`, creds in
`cred_*`, the decoy's real port in `dest_port`).

Landing is one INSERT per statement of at most 500 000 characters (under the query service's
default query-length limit). **Every statement is a lake commit**, so the writer is daily, never an
interval: an earlier version ran every two minutes and left thousands of snapshots on one table.
The lake module's maintenance timer expires them; the writer's size is the thing to keep small.
The offset is saved after each statement; a crash between a statement and the save lands that one
statement again on the next run (at-least-once, one statement wide). A line that cannot be parsed is
quarantined, never dropped silently and never able to stop the writer: every record is validated to the
SQL it will become (a non-object, a string where an object is expected, a number out of range), a bad
line goes to `state/dead-letter.jsonl` (capped at 10 MiB, each entry cut to 4000 characters, with the
reason; past the cap lines are only counted), a running counter (`state/dead-letter-count`) is reported
by the health hook, and the offset always moves past it. A run in which every line failed exits 1.

## Secrets

| Reference (default) | Used by | Form |
|---|---|---|
| `secret:honeypot/lake-password` (`honeypot_lake_login_ref`) | writer, report, health | 8 to 512 characters from `A-Za-z0-9._~+/=:@%^-` (it is written into a systemd environment file, which reads quotes, backslashes and spaces specially); the query-service account `honeypot_lake_user` needs INSERT on the events table, SELECT on it, and SELECT on `honeypot_cti_table` when set |
| `secret:honeypot/gateway-key` (`honeypot_gateway_key_ref`) | report | only when `honeypot_gateway_id` is set |
| `honeypot_lake_ca_ref` (default empty) | all | the lab CA in PEM; empty uses the system roots. **TLS is always verified**; there is no switch to turn it off, and a login is never sent over clear text |

A reference with no secret behind it is refused by the readiness hook and by the install before any
file is written.

## The report's model settings (read before changing them)

The brief is written by whatever sits behind `honeypot_gateway_id` (an OpenAI-compatible
chat-completions endpoint), asking for the alias `honeypot_gateway_model`. A **reasoning** model
spends its output budget thinking before it writes anything. Measured against a local reasoning
model: a 350-token budget returned reasoning only and an empty answer, and even 2 500 intermittently
did. So the defaults are `honeypot_llm_max_tokens: 4000`, `honeypot_llm_timeout_s: 240` per attempt
and `honeypot_llm_attempts: 3` with `honeypot_llm_retry_sleep_s: 20` between them (a shared model
tier is often busy). Do not try to switch thinking off with a request flag (serving stacks differ and
several ignore it); give it room. If the content is empty but reasoning came back, the report shows
the reasoning under a plain warning rather than a blank card; if the tier never answers, the brief
says so in words (never a stack trace) and the data below it is complete. The unit's
`TimeoutStartSec` is derived from these settings so a patient retry is never killed by the unit.

## What the overlay adds

* `lab/modules.yml`: `features: {honeypot: {placement: {receiver: <host>}}}` and
  `grants.egress.honeypot.receiver: [internet]` (the report's enrichment; set `honeypot_enrich:
  false` and the egress need not be granted).
* The runtime release on the guest (role `hnx_runtime`), applied before this module.
* group_vars: `honeypot_logical_id`, `honeypot_lake_catalog` (required: the site's name for its lake), `honeypot_bind` (the interface the pushes arrive on),
  `honeypot_port`, `honeypot_lake_query_id` (or `honeypot_lake_url`), `honeypot_lake_user`,
  `honeypot_lake_ca_ref`, `honeypot_gateway_id` + `honeypot_gateway_model`, `honeypot_site_label`,
  `honeypot_friendly_ips` (the site's own egress addresses: probes from them are not catch),
  optionally `honeypot_cti_table`.
* **The receiver has no authentication (as in the deployment it replaces): it is network-ACL-only.** The
  overlay firewall must admit the receiver's port from the AWS honeypot sender's address (its tunnel
  address) only; the module does not enforce it. `honeypot_bind` is required, is the guest address the
  pushes arrive on, and all interfaces (`0.0.0.0`, `::`) is refused unless `honeypot_allow_any_bind`.
  A connection idle for `honeypot_idle_timeout_s` (120) is closed and connections past
  `honeypot_max_connections` (32) are refused.
* Firewall: the receiver's port admitted from the sender's address only (the one-way property is
  this rule plus the unit's sandbox); the guest's egress to the query service, the gateway and, for
  enrichment, the internet.
* Secrets in the store under the references above; the query-service account's INSERT/SELECT grant
  in the lake's access rules.
* The report's serving (a static route or a published directory over `reports/`) is the overlay's
  choice; the module only writes the files.

## Health

`hnx modules` runs the readiness hook before an install and the health hook after: the receiver
active and accepting, the timers armed, scripts, environment and credentials present, **something
received within `honeypot_spool_max_age_h`** (a silent sender is a finding), the last landing
succeeded within `honeypot_landing_max_age_h`, the table is exactly the contract, and **the table's
newest event is within `honeypot_freshness_max_age_h`** (an empty table never passes). Set an age to
0 to stop judging it. This is the freshness watch the previous deployment ran as a separate check.

## Cutover (one publisher at a time) and the honeypot's repoint

The honeypot's push target is the **sender's** configuration, not this module's. It is an overlay /
operations step, documented here and never done by this module:

1. Deploy the module empty (`honeypot_ensure_table` false when the lake already holds the imported
   table); health is green except "something was received" until a sender pushes. The first landing
   proves the writer against the imported table's contract.
2. Admit the sender's address to the receiver's port (the overlay's firewall; and the sender's side
   network policy, if one limits where it may push).
3. On the honeypot, change the shipper's sink address to the new receiver and restart the shipper
   (the sender's own deploy path; for a baked image, re-bake and bump its image reference, or the
   next replacement silently reverts the change). The old receiver keeps its own spool; nothing is
   sent to both.
4. Verify: the new spool grows, the next landing adds rows with a new `ingested_at`, and the
   freshness check passes; then stop the old receiver and its writer after its spool is landed.
   Rollback is the shipper's sink address back.
5. Do not touch the honeypot's cloud identity or its permissions in this step: the sender's own
   infrastructure account keeps the whole of its policy.

The lake side of the move (the table's history) is the lake's own cutover, not this module's; this
module starts landing from an empty spool.

## Not included

The honeypot's sample-pull and quarantine tooling (fetching captured malware from the honeypot to
an analysis sandbox) is a different, reserved capability and is not part of this module; the
module only receives events and writes reports.

## Lifecycle

`playbooks/install.yml` converges (readiness first), `upgrade.yml` is a validated re-converge (no
pinned artefact: it refuses when the live table is not the installed writer's contract, exports
first), `remove.yml` exports first then removes units, rotation, credentials and scripts and keeps
the data root and the lake table. Export (`export/<stamp>/`: the writer's offset, its last-run
record, the rendered report) and restore (the offset) are the role's hooks; the events are the
lake's.
