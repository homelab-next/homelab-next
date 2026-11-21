<!-- SPDX-License-Identifier: Apache-2.0 -->
# Module `misp`: the threat-intel provider

A provider module ([module manifest](../../docs/modules.md), draft, ADR-0027 proposed) that fills
the `threat-intel` slot with [MISP](https://www.misp-project.org), a threat-intelligence platform:
events, attributes, objects, galaxies and feeds, read back by programs through its REST API. It is
a **service, not a machine**: the guest is the site's guest file and the site's selection places the
module's one host role (`server`) on it. Nothing here names a real host, address, account or
domain; those live in the private overlay.

| | |
|---|---|
| Slot | `threat-intel` (provisional: no contract or suite yet), stateful, object-tree export |
| Product | MISP v2.5.44 with its modules service v3.0.9, MariaDB 10.11.19, Valkey 7.2.14: four images, each pinned by tag **and** digest (`role:misp/misp_*_image` in `tools/pin_freshness.py`) |
| Host role | `server`: kind `vm`, baseline `base`, footprint 4 vCPU, 28 GiB, 120 GB |
| Role | `misp` (role interface v1), a wrapper of the core `compose_app` |
| Secrets | `secret:misp/{admin-password, admin-api-key, mysql-password, mysql-root-password, redis-password, encryption-key, gpg-passphrase}`; every consumer's key is a reference the site names (below) |
| Egress | the internet: the feeds' own sites. **Every feed is untrusted input** |
| Public route | **none** in the row. The platform serves HTTPS on its own port with a certificate it generates; a site that fronts it adds the route and the grant itself |

The pins are the versions of the instance this module carries over, on purpose: a database dump
loads into the engine and the schema version it was taken on, and the application never migrates
backwards (the upgrade hook refuses an older target).

## What the role does

`roles/misp` renders one `compose_app` project of four services:

- `misp-core`, the application (nginx, PHP and the supervisor that runs its background workers),
  published on `misp_bind:misp_port` (the guest's own address, never all interfaces) and nowhere else;
- `misp-modules`, the enrichment and import/export modules service (no published port);
- `db`, MariaDB with the buffer pool (`misp_innodb_buffer_pool_size`) and packet size a 40 million
  row attribute table needs (no published port);
- `redis`, the Valkey cache with a password, no snapshots (no published port).

Every container drops all capabilities but the few its entrypoint needs, runs `no-new-privileges`,
carries a memory limit and joins the role's slice (`cgroup_parent`), whose **CPU quota and memory
limit are the module's footprint**. That slice is the control for LL-504 (a runaway query on the
attribute table pinned the database at 100 % of a core for hours and starved the whole guest):
whatever the database or a consumer does, the project cannot take more than the footprint. Data
lives under `misp_data_root` (`/var/lib/hnx-modules/misp`): `mysql/`, `cache/`, `configs/`,
`logs/`, `files/` (attachments, taxonomies, galaxies), `gnupg/`, `ssl/` and `export/`.

**Secrets** reach the containers only through compose_app's 0600 env files; the compose file and
`docker inspect` hold none. Each is read by `lookup('hnx_secret', ...)` under `no_log`, and a
reference with no value is **named** and refused before anything is rendered.

### The workers (LL-386)

The image ships every job-processing program (default, prio, email, cache, update) with
`autostart=false`, so that the cache's permissions can be fixed first, and nothing in the image
ever starts them. With only the scheduler running, feed jobs queue forever at "Starting..." while
every container reports healthy: nine days of silently stale feeds on the old instance. The role
starts `misp-workers:*` after every start (main, the end of an export, the end of an import) and
**health fails unless at least five workers are `RUNNING`**.

### The first start (found against the real image)

Three things the image does that a role has to know, each met by running the pinned images:

- **Healthy long before ready.** The application answers its heartbeat, and every container reports
  healthy, minutes before the first start has built the schema and created the first account. The
  role therefore waits for the database to hold its first account, then for the entrypoint's
  `INIT | Done` line **of this start** (logs since the container's own start time, so an earlier
  start's line is never counted), before it touches an API key.
- **A first start can leave the web tier broken.** The entrypoint ends with
  `supervisorctl restart php-fpm`; against the pinned image that restart left the first PHP master
  running (the new one stops with "Another FPM instance seems to already listen") and the survivor
  had cached the table list from before the schema updates, so every API call was an internal error
  (`Table bookmarks ... was not found`). The role asks the API with the administrator's key and
  **restarts the application once** when the answer is an internal error (a second start of an
  initialised database, seconds); a start that is already good is left alone, and an application that
  still answers with an error after the restart fails the run.
- **The entrypoint owns its mounts.** It takes the ownership of the configuration, logs, files and
  key directories (the configuration is mode 0770 for the web server's user). The role only
  **creates** those directories and never holds them to an owner or a mode; holding them to root's
  fought the entrypoint (a second run failed on the chown, and as root it would have locked the
  application out of its own configuration).

The supervisor's control socket needs the credentials the image's entrypoint sets for it; an exec
does not inherit them, so the role passes the image's own fixed defaults (local to the container,
not a secret of the lab's).

### API keys (consumers)

The application keeps only a hash of an API key, so a key can never be read back; the role
therefore **sets** keys from secrets and **asks the API** whether each is already accepted:

- the administrator's key is `secret:misp/admin-api-key` (40 alphanumeric characters), also given to
  the first start as the initial key;
- every other reader is an entry of `misp_consumers`, a mapping of `email` (an existing account:
  in the imported database, or created in the UI) and `key_ref` (a `secret:` reference the site
  names, 40 alphanumeric characters, distinct from every other credential):

  ```yaml
  misp_consumers:
    - email: enrich@example.internal
      key_ref: secret:<ns>/misp-enrich-key
  ```

For each account the role calls `/users/view/me` with the key from **inside the application
container against its own loopback**; only when that is not accepted does it run
`cake user change_authkey`, with the address and key in the environment of that one command. A
second run is `changed=0`. Nothing about a key crosses the network and no certificate has to be
trusted. Rotating a key is changing the secret and running again.

## Hooks

| Hook | What it checks or does |
|---|---|
| `readiness` (also the module's preflight) | the container engine, `zstd`, the settings, and every credential in its form: each password and the encryption key 16 to 128 of `A-Z a-z 0-9 . _ ~ -`, each API key exactly 40 of `A-Z a-z 0-9`, all distinct; a reference with no value is **named** |
| `health` | every container running and healthy; the published port accepts a connection; the sign-in page answers 200; a call with **no key** and a call with a **key that is no account's** are refused (401/403: the platform is private); every account's own key is accepted and the version the API reports **is the pinned one**; at least five workers RUNNING; the database holds at least `misp_expected_min_counts`. Read-only |
| `export` | the application **stopped** for the dump (the counts are then the dump's own), `mariadb-dump --single-transaction` of every table but `audit_logs`, compressed with zstd into `export/.new/`; the dump must decompress whole and end with the dump's completion line; `manifest.json` (format `misp-export-1`, version, tables, counts, the dump's size and sha256) and `listing.jsonl`; renamed to `export/latest` only when whole (the previous copy is kept on failure); the application is started again, and its workers, whatever happened |
| `backup` | the backup manifest naming the data root (and so the last export) |
| `restore` | see "Importing the old instance" |
| `feeds_resync` | queues `fetchFromAllFeeds` and `cacheFeeds/all` through the API as the administrator; the platform's workers do the fetching |
| `upgrade` | refuses a target not pinned by tag and digest, of another repository, or **older than the running version** (for the application and the modules service), then records the bump; the playbook exports first |

`export` stops the application for the length of the dump (minutes for a database of this size) and
reports `changed` on every run.

### Why the audit log is excluded

`audit_logs` is the platform's record of its own changes: 25.7 GB, 92.7 million rows on the old
instance, own-system telemetry rather than intelligence (decision D-12 of the decommission plan).
The dump excludes the table entirely (`--ignore-table`); on an import the freshly built, empty
table stays. The manifest says so (`excluded_tables`).

## Importing the old instance

The source is a zstd `mysqldump` of the `misp` database without `audit_logs` (the form `export`
writes, and the form the old lab's archive holds), plus, optionally, the old instance's `files`
tarball for the attachments. The platform is **imported into**, never merged: the hook refuses a
database that already holds events, attributes or objects.

1. **Secrets first.** Set every secret the manifest lists (the `misp` namespace) in the secret store. Carry over, from the
   old instance, the **encryption key** (`Security.encryption_key` in its `config.php`, the
   `ENCRYPTION_KEY` of its `.env`: stored credentials cannot be read without it), the **administrator's
   API key** (so no consumer changes), and the administrator's email and the organisation name
   (`misp_admin_email`, `misp_admin_org`, which must be the dump's own). Everything else may be new.
2. **Deploy empty.** Run the install playbook (or the apply path) with `misp_expected_min_counts`
   unset. The first start builds the schema and starts the workers; `health` passes.
3. **Stage the dump** on the guest, state its sha256 and the **source's counts** (take them on the
   old instance beforehand, read-only, e.g. `SELECT COUNT(*) FROM events` for each):

   ```yaml
   misp_restore_dump: /var/lib/hnx-modules/misp/import/misp-excl-audit_logs.sql.zst
   misp_restore_sha256: <sha256 of that file>
   misp_restore_counts: {events: <n>, attributes: <n>, objects: <n>, galaxy_clusters: <n>, feeds: <n>, users: <n>}
   # optional, the attachments (only the numeric event directories are extracted):
   misp_restore_files_tar: /var/lib/hnx-modules/misp/import/files-configs.tar
   misp_restore_files_sha256: <sha256 of that file>
   ```

4. **Run the `restore` hook** (`tasks_from: restore`). It checks, **before writing anything**, that
   the dump is the pinned file (a regular file, not a link, the stated sha256), that it decompresses
   whole and ends with the dump's completion line, and that the stated counts are present for
   events, attributes, objects, galaxy clusters and feeds with events and attributes above zero (an
   import that expects nothing proves nothing). It then refuses a database that holds data,
   **stops the application**, loads the dump (hours: asynchronous, `misp_import_timeout`), and reads
   the counts **before the application starts again**; every one must **equal** the source's. A
   mismatch fails the run with the application still stopped: a platform started on half a database
   would begin fetching feeds into it. Only then are the attachments extracted (a listed, checked
   subset: no link, no device, no `..`, regular files and directories under `files/<digits>/`; never
   configuration), the application started, the workers started and every account's key set.
5. **Set `misp_expected_min_counts`** to the source's counts, so `health` and `export` hold the
   database to them from now on, and run `health`.
6. **Resync the feeds** (`tasks_from: feeds_resync`): the dump holds the feed definitions; the jobs
   fetch what has changed since. Feeds that roll (an abuse feed ages entries out upstream) are why
   the import, not a fresh fetch, is the way to keep their history. Watch the newest event's age
   afterwards (a feed that fetches nothing is a different fault from a worker that does not run).
7. **Compare what the dump does not carry**: server settings changed in the old instance's UI
   live in its `config.php` (not imported, by design: the new platform is configured from the
   role). Diff the old `configs/config.php` against the new one and carry deliberate settings over
   by hand; do not copy the file (it holds the old database password and salts).

### What the dump does not carry, and the cost of that

The old instance's Redis state (queued jobs, sessions: nothing to keep), its `audit_logs`, its
GnuPG key ring (a new key is made from `misp-gpg-passphrase`) and its TLS certificate (the image
makes its own). A user's sessions end; an API key does not, because auth keys are rows.

## Consumers to repoint

After the import and a green `health`, point every program that talked to the old instance at the
new platform's address and keep its key. The key does not change (step 1), so this is the **URL
alone**:

| Consumer | What to change |
|---|---|
| The CTI pipeline's **enrichment** (the `cti-agent` enrich stage) | its MISP base URL setting; its key is the same. Verify with one enrichment run that returns a match for an indicator the dump holds |
| The **Cortex ingest** that pushes MISP indicators to the graph store (the `misp-cortex-ingest` job) | its MISP base URL; its state (watermarks) is the job's, not the platform's, so a cold start walks the whole attribute table: **keep the job's keyset checkpointing** and run it only against the capped slice (LL-504: deep `OFFSET` paging of an unbounded attribute table pins the database for hours) |
| The platform's other readers (the incident-response platform's MISP module, dashboards) | the same URL |

The platform's certificate is the image's own; a consumer that verifies TLS needs that certificate
(from `ssl/` in the data root) as its CA file, a consumer that cannot is pointed at the lab's edge
proxy instead. Then stop the old instance (the decommission plan's retire step: a clean shutdown
and a seven-day soak, never a delete).

## Overlay needs

- a guest (the slot's `server` role placed on it) with `docker_engine` and `zstd`;
- the selection `slots.threat-intel: [{provider: misp, instance: <id>, placement: {server: <host>}}]`
  with an egress grant `egress.misp.server: [internet]`;
- the lab registry row as bound (`registry/services.yml`, renamed to the instance);
- group variables: `misp_logical_id`, `misp_admin_email`, `misp_admin_org`, optionally
  `misp_base_url`, `misp_consumers`, `misp_expected_min_counts`;
- every secret the manifest lists, and each consumer's key, in the secret store;
- the guest's firewall: the platform's port from the consumers only.

## Backup and restore

The data root is the backup target (`backup` writes the manifest). The database files are written
while the service runs, so a backup of the guest is crash-consistent (the engine recovers from
that); the consistent copy is `export/latest`, refreshed by `export`, which the upgrade and remove
playbooks do first. A restore from your own export is the import above with `misp_restore_dump`
pointing at `export/latest/dump.sql.zst`, its sha256 from `listing.jsonl` and the counts from
`manifest.json`.
