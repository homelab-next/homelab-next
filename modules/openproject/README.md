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

- the guest (`hnx-openproject-01` in the cutover plan) and the module's `server` placement;
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

1. **Rehearse** (the source keeps serving): `dump(source, out_dir)` runs `pg_dump -Fc` and a tar of
   the attachments in the source's containers, streams both to files in `out_dir` (a directory
   the caller names; never `/tmp`) and writes `manifest.json` with the sizes, sha256 and the
   source's counts. The source is only read. `restore(target, out_dir)` checks the manifest,
   stops the target's web app and worker, restores in one transaction, replaces the attachments,
   runs the seeder and starts them again. `counts(target)` returns
   `{projects, work_packages, users, attachments}`; the rehearsal passes when it equals the
   source's counts in the manifest.
2. **Cutover: freeze, final delta, re-count.** Writes on the source do not stop by themselves, so
   a copy taken while people work is already stale. The cutover is:
   1. *Freeze* the source: stop its web and worker containers (`freeze(source)`; the database
      keeps running so it can be dumped). From here nothing writes to the source.
   2. *Re-dump* the frozen source: `dump(source, final_dir)`. This is the **final delta** (the
      whole database again, not a diff: it is small, and `--clean` makes a repeat restore exact).
   3. *Restore* it onto the target (`restore(target, final_dir)`): the target's database is
      replaced by the frozen state and the attachments directory is emptied and unpacked again, so
      a file deleted on the source after the rehearsal does not linger.
   4. *Re-count*: `counts(target)` must equal `counts(source)` taken **after** the freeze (the
      manifest records them at the dump). Only then move the public name.
   5. *Rollback* is `unfreeze(source)` (start the containers again) and the old route; the target
      is simply wiped by the next restore.

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
