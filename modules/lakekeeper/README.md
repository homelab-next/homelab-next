<!-- SPDX-License-Identifier: Apache-2.0 -->
# Module `lakekeeper`: the lake-catalog provider

A provider module ([module manifest](../../docs/modules.md)) that fills the `lake-catalog` slot with
[Lakekeeper](https://docs.lakekeeper.io), the Iceberg REST catalog the architecture names
([architecture](../../docs/architecture.md): "Lakekeeper over Postgres"), instead of the single-file
reference catalog that [`iceberg-rest`](../iceberg-rest/README.md) carries over. Nothing in this
directory names a real host, address, VM id or secret value.

| | |
|---|---|
| Slot | `lake-catalog` (contract `conformance/protocols/lake.py`) |
| Adapter | the shared `homelabnext.conform.adapters.lake:make_lake` |
| Product | Lakekeeper `v0.14.1` (`quay.io/lakekeeper/catalog`) and PostgreSQL 18, both pinned by digest |
| Host role | `server`: kind `vm`, baseline `base`, 1 vCPU, 1.5 GB, 10 GB |
| Role | `lakekeeper` (role interface v1), a wrapper of the core `compose_app` |
| Requires | `cap:secrets`, `cap:object-store` |
| Egress | none |
| Public route | none; **no sign-in** (`auth: none`): the network is the only control |

## What the role does

- **Two containers**, the database (no published port, the project's own network) and the catalog, as
  ids no account on the host has, every capability dropped, memory limits, healthchecks. The catalog is
  published on the guest's own address (`lakekeeper_bind`; all interfaces is refused) at
  `lakekeeper_port` (8181, the registry row's port).
- **Migration before start.** The server refuses a database its binary has not migrated, so `main`
  starts only the database, asks the binary (`wait-for-db -m`) whether it is migrated and runs
  `migrate` only when it is not, then starts the catalog. The migration is **one way**: the upgrade
  playbook dumps the database first, and that dump is the way back.
- **Bootstrap once, warehouse once.** The catalog is bootstrapped (the product's terms accepted) when
  it is not, and the warehouse is created when absent: the bucket `iceberg-warehouse` **at its root**
  (no key prefix), path-style access against the object store, region `garage`, `sts-enabled: false`,
  `remote-signing-enabled: true`, an access-key credential, and **soft deletes** (a dropped table stays
  recoverable for `lakekeeper_soft_delete_seconds`, a year by default). A warehouse that exists is
  CHECKED against these and a difference stops the run: the role never changes a live warehouse.
- **Nothing here reads or writes a table.** Bootstrap and warehouse creation touch only the catalog
  database, except that creating a warehouse makes the catalog write and delete one probe object under
  the bucket's root to validate the storage.

### Why the base is the bucket root

A registered table keeps its location. The lake's tables live at
`s3://iceberg-warehouse/<namespace>/<table>-<id>/`, wherever the earlier catalog put them. A warehouse
whose base is a key prefix would not contain them; with the bucket root as the base every existing
location is inside it, and `catalog_register.py` refuses (before any call) a table whose metadata file is
outside the warehouse's bucket and prefix. Tables created later land at `<base>/<table uuid>`.

## Secrets

| Reference | What | Rule |
|---|---|---|
| `secret:lakekeeper/pg-password` | the database role's password | 24 to 128 of `A-Z a-z 0-9 . _ ~ -` (it goes into a connection URL) |
| `secret:lakekeeper/encryption-key` | encrypts the stored warehouse credential | **create-only, never changed**; 32 to 256 characters; not the password |
| `secret:lakekeeper/s3-access-key`, `.../s3-secret-key` | the object store's lake key pair | the form the object store issues; stored (encrypted) in the warehouse |

The database dump holds the warehouse's credential **encrypted**: a restore needs the encryption key
the dump was made under, so back the key up with the secret store's own backup, and never rotate it
in place. Rotating the object store key is an API call on the warehouse (update its storage
credential), not a redeploy.

## Client settings (what the engine and the writers change)

The API is served under `/catalog` and a client names the warehouse by **name**, not by `s3://` path:

| Client | Setting |
|---|---|
| Trino | `iceberg.rest-catalog.uri=http://<host>:<port>/catalog`, `iceberg.rest-catalog.warehouse=<warehouse name>`, `iceberg.rest-catalog.vended-credentials-enabled=false` (Trino keeps its own storage key) |
| PyIceberg | `uri=http://<host>:<port>/catalog`, `warehouse=<warehouse name>` (reads and writes through remote signing) |
| NiFi's catalog service | the same URI and warehouse name |

The conformance target sets `api_root: /catalog`; `LAB_WAREHOUSE` is the warehouse name.

## The catalog has no sign-in: the network is the only control

`auth: none` (the catalog runs with its allow-all authorization backend and no identity provider, the
same posture as the catalog this replaces; Keycloak OIDC machine clients are a follow-up work package,
not part of taking the lake over). Anything that can reach the port can create, drop and register
tables. So, as for the catalog it replaces:

1. **The control is the Proxmox VM-level firewall rendered from the overlay's guest file** (the NIC
   firewall of the guest). A firewall on the guest does **not** protect this port: Docker publishes it
   through its own NAT chain, which bypasses the guest's `INPUT` chain.
2. Inbound is limited to **named consumers**: the query engine and the lake's writers.
3. **Negative probe**, part of any cutover and of any change to the guest's rules: from a host that is
   *not* admitted, `curl -m5 http://<host>:<port>/health` must **time out**; from an admitted host it
   answers 200.

## Taking over a lake that already has tables

Nothing is copied. The catalog holds only `(namespace, table) -> metadata_location`; the data, the
manifests and the metadata JSON stay in the object store. `tools/migrate/catalog_register.py`
registers each table at its current metadata file from a **copy** of the old catalog's SQLite file,
and verifies the result:

```text
catalog_register.py plan     --source-db <copy> --url http://<host>:<port> --warehouse lake
catalog_register.py register --source-db <copy> --url ... --warehouse lake --apply
catalog_register.py verify   --source-db <copy> --url ... --warehouse lake \
    --reference-url http://<old catalog> --listing <key listing> --expect-tables <n>
```

It never issues a DROP, a purge, an `overwrite` or a table procedure; it refuses the live SQLite file,
a vacuous run, a location outside the warehouse and an entry already registered elsewhere. `register`
sets **table protection** on every table it registers, so a later `DROP TABLE` (with or without purge)
is refused with HTTP 409 unless forced. `verify` compares the metadata location, the current snapshot
id, the table uuid, the location and the snapshot count with the old catalog, and checks that every
object a writer or reader of the current state opens exists in the key listing: the metadata file, the
current snapshot's manifest list and every statistics and partition-statistics file (LL-586: a read-only
check passes on a table that cannot be written). Older metadata files and older snapshots' manifest
lists are reported as history, not failures; an import that copied only the current snapshot does not
hold them in either catalog. The rollback is the same tool the other way: `register --source-url
<this catalog> ... --url <old catalog>` writes a NEW catalog file for the old server from this catalog's
current pointers.

## Hooks

| Hook | What it checks or does |
|---|---|
| `main` | validates, resolves the object store, renders; database up, migrates when behind, starts the catalog, bootstraps once, creates the warehouse once |
| `readiness` | docker_engine ready; every credential in its form; the object store's address resolves |
| `health` | both containers healthy; the database answers; the catalog's health is ok; bootstrapped; the warehouse is as stated (bucket root, no STS, remote signing, soft deletes). Read-only |
| `backup` | `pg_dump` (custom format) in the database's container, listed (key, size, sha256), then names the data root |
| `export` | `db/lakekeeper.dump` and `listing.jsonl` in the data root's `export/` |
| `restore` | checks an export (links, owners, size, sha256), stops the catalog, restores in one transaction, starts it, proves it |
| `upgrade` | validates a tag@digest bump of the same repository (the database: same major) and records it |

## Restore drill

Restore the export into a scratch instance (another data root and port), start it with the same
encryption key, and run `health`; then `catalog_register.py verify` against the live catalog. A restore
that boots but cannot read the warehouse credential is a wrong encryption key.

## Upgrading

`playbooks/upgrade.yml -e lakekeeper_target_image=<repo>:<tag>@sha256:<digest>` validates the bump,
dumps the database, converges, and the migration runs before the new image starts. It cannot be undone
in place: restore the dump taken just before. A database major version is a dump and a restore into a
new cluster, never an in-place start (the entrypoint refuses an older cluster).

## Changing the warehouse

The role never changes a live warehouse. A change of the storage profile or credential is a deliberate
call on the management API (`POST /management/v1/warehouse/<id>/storage`, `.../storage-credential`),
followed by `health`, and the module's settings changed to match, because `health` fails on a
difference.

## Known limits

- No authentication (above). Taking authentication on is a follow-up that changes every client in one
  window.
- Soft-deleted tables are purged by the catalog after the retention window; protect (`register` does)
  and never let a real table sit in the deleted list.
