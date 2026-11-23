<!-- SPDX-License-Identifier: Apache-2.0 -->
# Module `trino`: the lake-query provider

A provider module ([module manifest](../../docs/modules.md)) that fills the `lake-query` slot with
[Trino](https://trino.io), a single-node SQL engine (coordinator and worker in one JVM) with one
Iceberg catalog named `iceberg`. It is the third of the three modules that carry the lake (`garage`,
`iceberg-rest`, `trino`) and installs the lake's maintenance timer. Nothing in this directory names
a real host, address, VM id or secret value.

| | |
|---|---|
| Slot | `lake-query` (contract `conformance/protocols/lake.py`), stateless |
| Adapter | the shared `homelabnext.conform.adapters.lake:make_lake` |
| Product | Trino 484, `docker.io/trinodb/trino` pinned by tag and digest |
| Host role | `server`: kind `vm`, baseline `base`, 4 vCPU, 20 GB, 20 GB |
| Role | `trino` (role interface v1), a wrapper of the core `compose_app` plus the maintenance timer |
| Requires | `cap:secrets`, `cap:lake-catalog`, `cap:object-store`, `cap:notify` |
| Egress | none |
| Public route | none |

## What the role does

- **One container**, as `trino_uid:trino_gid` (61003), every capability dropped, `no-new-privileges`,
  a memory limit, the image's own healthcheck. **Only HTTPS is published** (`trino_bind`:
  `trino_port`, 8443); the engine's plain listener serves its internal communication inside the
  container and is not published. A certificate and key from the lab's internal CA (one PEM,
  group-readable by the container's gid: a key owned `root:root` 0600 crash-loops the engine,
  LL-500).
- **Every reader signs in** with a password: the file authenticator over a password file
  (`secret:trino/password-db`, one `user:bcrypt` line per reader, the maintenance user included,
  reloaded every 5 s), the internal-communication shared secret (`secret:trino/internal-secret`).
  **Access rules are required**: the role refuses an empty `trino_access_rules_src` unless the site
  sets `trino_access_unrestricted: true` on purpose (otherwise every signed-in user may drop and
  alter tables). `files/lake-access.example.json` is the shape to start from: the `maintenance`
  user owns the lake's schemas and tables (it creates and drops them; the file rules do not
  check a table procedure at all, see below) and every other user is `SELECT` only on the `iceberg` catalog, with
  no access to `system`. Add a rule for each writer user (INSERT, DELETE; UPDATE if it needs it)
  before it writes. Checked against the real engine: a reader is refused INSERT and DROP and the
  `system` catalog. The file rules do **not** cover table procedures: see the next section.
- **The `iceberg` catalog** (the name is fixed: the lake's writers say `iceberg.<schema>.<table>`)
  is the REST catalog (`iceberg_rest` row) over the S3 object store, path-style, region `garage`,
  warehouse `s3://iceberg-warehouse/`; the key pair is read from the container's environment
  (`${ENV:...}`), never from a rendered file. For a catalog that serves its API under a path and
  names its warehouses (the lake-catalog provider `lakekeeper`), set `trino_catalog_path`
  (`/catalog`) and `trino_warehouse` to the warehouse's **name**; the defaults keep the reference
  catalog's shape (no path, `s3://<bucket>/`).
- **Pinned behaviour the old lake learned the hard way**: the session time zone is forced to UTC
  server-side (LL-392), a per-query memory bound keeps a runaway query from taking the JVM down
  (`ExitOnOutOfMemoryError` kills every in-flight query), and the retention floors below.

## Table procedures and readers

Measured on the real engine (Trino 484, a reader user with the shipped example rules, table in the
`iceberg` catalog): `ALTER TABLE ... EXECUTE` **succeeds** for a read-only user with `optimize`,
`optimize_manifests`, `expire_snapshots`, `remove_orphan_files` and `drop_extended_stats`.
`add_files` is refused ("disabled" in the engine) and `add_files_from_table` is refused (it needs
INSERT). The file rules never see a table procedure, so a reader can compact, expire (not below
the 7 day floor) and remove orphans (not below the 3 day floor) on any table. The floors bound the
damage; they do not make it zero.

The mechanism that does close it is the connector's own security mode: a catalog with
`iceberg.security=read-only` refuses every write **and every table procedure** (checked: all seven
above are `Access Denied` for the same reader, and for any user). `trino_reader_catalog: iceberg_ro`
renders such a second catalog over the same lake. Using it means readers say `iceberg_ro.<schema>.<table>`
(not the name the lake's readers use today) and the rules deny them the writable `iceberg`
(the writers and the maintenance user keep `iceberg`). Moving the readers is a follow-up
(docs/modules/follow-ups.md); the catalog is available now and is off by default.

## The maintenance timer (the lake's snapshot and orphan hygiene)

The old lake grew to 10.5k snapshots on one table and 1.6 TB of storage for 195 GB of live data,
because nothing expired snapshots or removed orphan files. `hnx-lake-maintenance.timer` (nightly,
`trino_maintenance_schedule`, an `OnCalendar` with `Persistent=true`, never a boot-relative timer)
runs `hnx-lake-maintenance`, which for **every Iceberg base table** the engine lists:

1. `ALTER TABLE ... EXECUTE expire_snapshots(retention_threshold => '7d', retain_last => 10,
   clean_expired_metadata => true)`: snapshots older than 7 days, **always keeping the last 10**;
2. `ALTER TABLE ... EXECUTE remove_orphan_files(retention_threshold => '3d')`: files no snapshot
   references and older than 3 days (a separate call: expiry never removes them, LL-052).

`retain_last` is spelled out on every call because the engine defaults it to 1. The values are
`trino_expire_retention`, `trino_retain_last` and `trino_orphan_retention`; the engine's own
floors under them (`iceberg.expire-snapshots.min-retention` 7d, `iceberg.remove-orphan-files.min-retention`
3d, set in the catalog properties from `trino_expire_min_retention` / `trino_orphan_min_retention`)
make it refuse a shorter retention from anyone, so a typo cannot delete live data (the engine's
default floor for orphans is 7 days, which would refuse the 3 asked for).

### Guards (RCA of the first run on a restored lake, 2026-11-17)

The first maintenance run on a lake restored from another one (a current-snapshot-only data copy under
a catalog that still lists every old snapshot) hung for hours, kept writing after it was stopped and
deleted history. The script now refuses each of those shapes:

- **Cancel, never abandon.** A statement past its deadline, or a stop (SIGTERM, `systemctl stop`), is
  cancelled on the engine: `DELETE` of the query's `nextUri`, then `CALL system.runtime.kill_query`, then
  the script polls `system.runtime.queries` (up to `trino_cancel_confirm_timeout`, default 45 s) until the
  query is no longer live. **If it is still live the whole run stops**: no further table is touched, the
  run is degraded, `run:aborted` is alerted once and the exit status is 1.
  **Unproven:** that a cancel also stops Iceberg's post-commit file cleanup (the retry loop over missing
  manifest lists that hung the first run) has only been exercised against a fake engine. Treat the first
  armed run on any real lake as attended (watch the Trino log and `system.runtime.queries`).
  Before, the client merely stopped polling and the engine kept running the query until its own client
  timeout, blocking the next table's statement. On SIGTERM the script also writes its state and sends
  ONE alert naming the unfinished tables (exit 143).
- **Preflight per table.** Before any procedure the script reads `"<t>$snapshots"` and
  `"<t>$all_manifests"` (each bounded by `trino_preflight_timeout`, default 300 s; `$all_manifests` reads
  every retained snapshot's manifest list and fails fast on a missing one). A table that cannot be read
  is logged `skipped: unreadable history`, **nothing is done to it**, and the run is **degraded**: the
  failing set includes `<table>:preflight` (so the alert fires and the `health` hook fails), the state
  file says `"degraded": true` and the exit status is 3 (the last-run record shows a failed run).
- **No orphan removal behind a failed expiry.** `remove_orphan_files` runs on a table only when its
  `expire_snapshots` succeeded in the same run (a timed-out expiry may still be committing); otherwise
  the step is recorded under `skipped` in the state file.
- **Allow and deny lists, per-schema retention.** Patterns and override keys are **lower case only**
  (the engine's names are; an upper-case pattern would validate and silently match nothing, which for the
  deny list means a table is maintained that was meant to be spared, so `main` refuses it). `trino_maintenance_schemas` (allow, default `["*"]`) and
  `trino_maintenance_skip` (deny; wins) take globs of a schema (`cti`) or a table (`cti.nrd_*`). 
  `trino_maintenance_overrides` is `{schema: {expire, retain_last, orphan_retention, orphan}}` (every key
  optional; `orphan: false` turns orphan removal off for the schema). `main` refuses a malformed glob, an
  unknown key, a duration under the engine's floor or a `retain_last` outside 1..1000.
- **No unattended arming on a restored lake.** The role cannot see how the lake got here, so arming is an
  explicit act: the timer is enabled and started only when `trino_maintenance_enabled` **and**
  `trino_maintenance_acknowledged_restore` are both true (default false). Otherwise the script and units
  are installed and the timer is **stopped and disabled**, and `health` checks that it is not running.
  **The timer does not catch up a missed run** (`trino_maintenance_catch_up: false`, i.e. `Persistent=false`),
  so arming never starts a run by itself: the first run is the next `OnCalendar` time. With `true`, a
  run missed while the host was off fires the moment the timer is started. To attend the first run:
  `hnx-lake-maintenance --dry-run` by hand, set the acknowledgement, then watch at the next scheduled time
  (or start the service by hand while watching).
  Set the acknowledgement only after `tools/migrate/lake_verify.py` (its all-history check) passes on the
  lake, or when the lake was never restored, and with the allow/skip lists and retention you want.
- **Off means off.** With `trino_maintenance_enabled: false` an already-installed timer is stopped and
  disabled (and a run in flight stopped); a host that never had one is left alone.

**Failure alert, state-diffed.** The script keeps an owner-only state file. When the **set** of
failing steps changes it posts one message to the notify channel (`trino_notify_*`, a publish token
by secret reference, `https` unless `trino_notify_allow_plain_http` opts a LAN endpoint in), one more
when the set empties, and nothing while it is unchanged. Exit status: 0 all steps ran, 1 some failed,
2 the tables could not be listed, 3 degraded (a table skipped as unreadable), 143 terminated. The `health` hook fails when the last run had a failing step.
`--dry-run` prints the preflight and procedure statements; `--test-notify` sends one low-priority message through the
alert path. The script, the units and the owner-only env file holding the maintenance password and
the notify token are the role's; `contributes.scheduler_jobs` names the timer.

## Hooks

| Hook | What it checks or does |
|---|---|
| `main` | validates, writes the configuration, the PEM, the password file and the rules, renders and starts the engine, restarts it when its configuration changed, installs the timer |
| `readiness` | docker_engine ready; every credential in its form; the catalog and the object store answer |
| `health` | container healthy; `/v1/info` over HTTPS verified against the lab CA, started; an anonymous statement refused; the maintenance user signs in; the timer enabled and active (only when armed; when not armed, including `trino_maintenance_enabled: false`, it must be neither active nor enabled); the last run clean |
| `backup` | names the data root (the engine is stateless) |
| `export`, `restore` | nothing to do: stateless (the lake's data is the catalog's and the object store's) |
| `upgrade` | validates a tag@digest bump of the same repository and records it |

## Known limits

- One engine, one JVM: a maintenance statement on a very large table is heavy (the old lake's
  honeypot table needed a 24 GB heap for `expire_snapshots` at 10k snapshots). The defaults assume
  the first run after the old lake's data is loaded finds the tables already compacted to the
  current snapshot.
- The timer runs on the same host as the engine; it shares the engine's CA file (`ca.pem`).
