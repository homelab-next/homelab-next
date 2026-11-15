<!-- SPDX-License-Identifier: Apache-2.0 -->
# Module `openproject`: the projects provider

A provider module (id `openproject`, the product's, as `keycloak` and `ntfy` are: `projects` is the slot and the instance; a module id may not be a registry row's name) ([module manifest](../../docs/modules.md), draft, ADR-0027 proposed) that fills
the `projects` slot ([projects](../../docs/projects.md)) with
[OpenProject](https://www.openproject.org) and its own PostgreSQL. It is a **service, not a
machine**: the guest it runs on is the site's guest file, and the site's selection places the
module's one host role (`server`) on it. Nothing in this directory names a real host, address,
public name, VM id or secret value; those live only in the private overlay.

| | |
|---|---|
| Slot | `projects` (contract `conformance/protocols/projects.py`), stateful, migration format `object-tree` |
| Adapter | `homelabnext.conform.adapters.openproject:make` (the instance's `openproject.yml`) |
| Product | OpenProject 15.5.1 (`docker.io/openproject/openproject`, the `-slim` image), PostgreSQL 17.10, memcached 1.6.44, all pinned by tag and digest |
| Host role | `server`: kind `vm`, baseline `base`, footprint 4 vCPU, 6144 MB, 20 GB |
| Role | `openproject` (role interface v1), a wrapper of the core `compose_app` |
| Requires | `cap:secrets` (the three credentials, read by name at deploy time) |
| Egress | none |
| Public route | only through the edge: `public_hostname` (the site's name) with `auth: own` and `tls: none` |

## What runs

Four containers in the module's slice (`hnx-openproject-server.slice`):

| Service | Image | Port | Notes |
|---|---|---|---|
| `web` | the app image | 8080, published on the guest's own address | command `./docker/prod/web`; healthy when `/health_checks/default` answers |
| `worker` | the same image | none | command `./docker/prod/worker` (background jobs: mail, exports, reminders) |
| `postgres` | PostgreSQL | none | `pgdata/` under the data root, its own uid |
| `cache` | memcached | none | no data |

The data root is `/var/lib/hnx-modules/openproject/`: `pgdata/`, `assets/` (the attachments, owned by
uid 1000: the image's own user, not a setting), `export/` (root's) and `export/db/`.

**The seeder.** The product migrates and seeds its database with a one-off command. `main`
renders the project, brings up the database and the cache, runs
`docker compose run --rm web ./docker/prod/seeder` when the image changed since the last run (a
marker in the data root holds the digest), and only then starts the app. An empty database gets
one administrator (login `admin`) with the password `secret:openproject/admin-password`; a restored
database keeps its own accounts and the seed password is ignored.

**HTTPS.** The app is told `https` and the public name. The edge must send
`X-Forwarded-Proto: https`; a missing header (not the app's `https` setting) is what puts the
"HTTPS" warning banner on every page (LL-427).

## What the overlay adds

- the guest (`hnx-projects-01` in the cutover plan) and the module's `server` placement;
- the instance and `grants.public_routes` for the public row;
- the registry row as the module declares it plus the site's `public_hostname`
  (`projects.<domain>`) and, at most, `standing`, `backup_job` and `scope`;
- `openproject_logical_id` (the row's id) and `openproject_hostname` (the same public name) as group
  variables;
- the three secrets in the secret store: `secret:openproject/db-password` (24 to 128 of
  `A-Z a-z 0-9 . _ ~ -`), `secret:openproject/secret-key-base` (64 to 256 characters; **the source
  instance's value when migrating**, so its sessions and encrypted settings still open) and
  `secret:openproject/admin-password` (16 to 128 characters, three of lower, upper, digit, special).

## Migrating in (from another instance of the same product)

`tools/migrate/openproject.py` (generic: the source and the target are described by an ssh
destination and container names, never by this repository) does the copy over ssh pipes:

An endpoint names the ssh destination, the database container and the attachments (a running
container for a source, a host directory inside a named data root for a target) and **every
container that writes** (`--writer`, repeatable: the web app, the worker, any scheduler).

1. **Rehearse** (the source keeps serving): `dump(source, out_dir)` runs `pg_dump -Fc` and a tar of
   the attachments in the source's containers, streams both to files in `out_dir` (a private
   directory the caller names; never `/tmp`) and writes `manifest.json`: sizes and sha256, the row
   counts of nine tables (projects, work packages, users, attachments, journals, time entries,
   members, versions, custom fields), a content fingerprint of those tables, the number and
   digest of the attachment files, and whether every writer was stopped (`frozen`). The source is
   only read. `restore(target, out_dir)` checks the manifest, stops the target's writers,
   restores in one transaction, builds the attachments in a sibling directory, **verifies the target** (counts,
   fingerprint, the sha256 of every attachment file; zero rows where the source has rows is an error), swaps the attachments in by rename (the old ones are removed only then), runs the seeder and starts it. Any failure
   leaves the target stopped and says so. The rehearsal passes when the restore returns.
2. **Cutover: freeze, final delta, re-count.** Writes on the source do not stop by themselves, so
   a copy taken while people work is already stale. The cutover is:
   1. *Freeze* the source: `freeze(source)` stops **every** writer, checks that none runs and
      prints the counts read after they stopped (the database keeps running so it can be dumped).
   2. *Re-dump* the frozen source: `dump(source, final_dir)`; the manifest records `frozen: true`.
      This is the **final delta** (the whole database again, not a diff: it is small, and
      `--clean` makes a repeat restore exact).
   3. *Restore* it: `restore(target, final_dir, expect_counts=<what freeze printed>,
      require_quiescent=True)` (CLI: `--expect-counts '<json>'|@file --require-quiescent`). It
      refuses a dump that is not of a frozen source or that differs from the freeze counts before
      writing anything, replaces the database and the attachments, and checks the result against
      the freeze counts and the dump's fingerprint and files, so an edit that moves no count is
      caught too.
   4. Only then move the public name.
   5. *Rollback* is `unfreeze(source)` (start the writers again) and the old route; the target is
      simply wiped by the next restore.

**When the verification fails.** `pg_restore` commits before the checks run, so a failed check
means the target's database is already replaced while its attachments are still the old ones, and
its writers stay stopped (correct). That target is not usable: **restore again, or unfreeze the
source and stay on it; never start the target as it is.** The error names what differed (for a
fingerprint, the tables).

The content fingerprint is one md5 per table, computed under pinned session settings (time zone
UTC, ISO/MDY dates, `postgres` intervals, `extra_float_digits = 3`, hex bytea) so a source and a
target whose servers are configured differently render the same value as the same text. If the
rehearsal shows a table that still differs for a rendering reason (same data, different text),
do not loosen the check for the others: for that table fall back to what the dump already
proves, the source being frozen and quiescent for the whole dump (counts and per-table
fingerprints unchanged, recorded in the manifest), plus the row counts and the attachment file
digests on the target, and record the exception in the cutover notes.

The only recursive deletes are on the attachments directory's `.restore-old`/`.restore-new` siblings, which (like the directory) must be an absolute canonical path of at least three components, inside the target's data root, and which the endpoint must resolve to itself (no link anywhere in it); a sibling left by an earlier restore is refused, not removed. A dump of a source with no projects, work packages or accounts, or with attachment rows and no files, is refused (`--allow-empty` for a genuinely empty one).

Not carried by this module or tool: the calendar (ICS) bridge and its feed token; the cutover
plan must give them an owner.

The role's own `restore` hook does the same from an export already on the host
(`openproject_restore_source`: a directory with `listing.jsonl`, `db/projects.dump` and
`attachments.tar`, which the `export` hook writes), for a restore drill or a disaster.

## Export, backup, restore drill

`export` and `backup` write `export/db/projects.dump` (`pg_dump -Fc --no-owner --no-acl`, written in
the database's container as its own user), `export/attachments.tar` and `export/listing.jsonl`
(key, size, sha256). `restore` refuses a source that is not exactly what its listing says before
it writes anything.

Drill: on a scratch guest, install the module with the same three secrets, run `export` on the
live one, copy `export/` over, run `restore` with `openproject_restore_source`, then `health`, and
compare `counts` with the live one.

## Upgrading

A pinned image bump, validated and recorded by the `upgrade` hook, exported first, then
converged; the seeder migrates the database for the new app image before the app opens it.
PostgreSQL moves within its major version only (a major one is a dump and a restore into a new
cluster). The app moves one minor series at a time, as the product requires.
