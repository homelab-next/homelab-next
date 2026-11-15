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
  user owns the lake's schemas and tables (table procedures such as `ALTER TABLE ... EXECUTE`
  need the table's ownership) and every other user is `SELECT` only on the `iceberg` catalog, with
  no access to `system`. Add a rule for each writer user (INSERT, DELETE; UPDATE if it needs it)
  before it writes. Checked against the real engine: a reader is refused INSERT and DROP and the
  `system` catalog. One limit: the engine's file rules do not govern table procedures, so a
  reader can still run `ALTER TABLE ... EXECUTE` (the retention floors below are what bound the
  damage; ADR-0033's row filters refuse it on filtered tables).
- **The `iceberg` catalog** (the name is fixed: the lake's writers say `iceberg.<schema>.<table>`)
  is the REST catalog (`iceberg_rest` row) over the S3 object store, path-style, region `garage`,
  warehouse `s3://iceberg-warehouse/`; the key pair is read from the container's environment
  (`${ENV:...}`), never from a rendered file.
- **Pinned behaviour the old lake learned the hard way**: the session time zone is forced to UTC
  server-side (LL-392), a per-query memory bound keeps a runaway query from taking the JVM down
  (`ExitOnOutOfMemoryError` kills every in-flight query), and the retention floors below.

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

**Failure alert, state-diffed.** The script keeps an owner-only state file. When the **set** of
failing steps changes it posts one message to the notify channel (`trino_notify_*`, a publish token
by secret reference, `https` unless `trino_notify_allow_plain_http` opts a LAN endpoint in), one more
when the set empties, and nothing while it is unchanged. Exit status: 0 all steps ran, 1 some failed,
2 the tables could not be listed. The `health` hook fails when the last run had a failing step.
`--dry-run` prints the statements; `--test-notify` sends one low-priority message through the
alert path. The script, the units and the owner-only env file holding the maintenance password and
the notify token are the role's; `contributes.scheduler_jobs` names the timer.

## Hooks

| Hook | What it checks or does |
|---|---|
| `main` | validates, writes the configuration, the PEM, the password file and the rules, renders and starts the engine, restarts it when its configuration changed, installs the timer |
| `readiness` | docker_engine ready; every credential in its form; the catalog and the object store answer |
| `health` | container healthy; `/v1/info` over HTTPS verified against the lab CA, started; an anonymous statement refused; the maintenance user signs in; the timer enabled and active; the last run clean |
| `backup` | names the data root (the engine is stateless) |
| `export`, `restore` | nothing to do: stateless (the lake's data is the catalog's and the object store's) |
| `upgrade` | validates a tag@digest bump of the same repository and records it |

## Known limits

- One engine, one JVM: a maintenance statement on a very large table is heavy (the old lake's
  honeypot table needed a 24 GB heap for `expire_snapshots` at 10k snapshots). The defaults assume
  the first run after the old lake's data is loaded finds the tables already compacted to the
  current snapshot.
- The timer runs on the same host as the engine; it shares the engine's CA file (`ca.pem`).
