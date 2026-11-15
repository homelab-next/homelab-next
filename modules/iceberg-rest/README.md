<!-- SPDX-License-Identifier: Apache-2.0 -->
# Module `iceberg-rest`: the lake-catalog provider

A provider module ([module manifest](../../docs/modules.md)) that fills the `lake-catalog` slot with
the [Apache Iceberg](https://iceberg.apache.org) REST catalog server, over one SQLite file. It is the
second of the three modules that carry the lake (`garage`, `iceberg-rest`, `trino`). Nothing in this
directory names a real host, address, VM id or secret value.

| | |
|---|---|
| Slot | `lake-catalog` (contract `conformance/protocols/lake.py`) |
| Adapter | the shared `homelabnext.conform.adapters.lake:make_lake` |
| Product | the Apache Iceberg REST catalog server, `docker.io/apache/iceberg-rest-fixture` pinned by digest |
| Host role | `server`: kind `vm`, baseline `base`, 1 vCPU, 2 GB, 4 GB |
| Role | `iceberg_rest` (role interface v1), a wrapper of the core `compose_app` |
| Requires | `cap:secrets`, `cap:object-store` |
| Egress | none |
| Public route | none; the server has no sign-in of its own (`auth: none`) |

## The image, and why it is pinned by digest

The old lab's lake runs a build of the project's main branch (commit `b0df3ca`, 2026-04-29) that
the project published only as `:latest`; no tag names it. This module pins that **very build by
digest** (`sha256:db8de90b...`), so the catalog that reads the old SQLite file is the one that wrote
it. The tag in `iceberg_rest_image` (`2026.4.29-b0df3ca`: the build date and commit, which is also the product version) is a label for humans and for
`compose_app`, which refuses an untagged image: Docker resolves the digest. The registry still
serves the digest (checked 2026-11-15). The project's own images for this server are called a
testing *fixture*; the cost is below, and a move to a database-backed catalog is an open follow-up,
not part of carrying the lake over.

## What the role does

- **One container**, as `iceberg_rest_uid:iceberg_rest_gid` (61002, an id no account on the host
  has), every capability dropped, `no-new-privileges`, a memory limit, a healthcheck on `/v1/config`.
  Published on the guest's own address (`iceberg_rest_bind`; all interfaces is refused) at
  `iceberg_rest_port` (8181, the registry row's port).
- **The same settings as the old lake**: the JDBC catalog over `jdbc:sqlite:/data/iceberg_catalog.db`,
  `CATALOG_WAREHOUSE=s3://iceberg-warehouse/` (fixed: the tables' metadata embeds the path), the S3
  file IO with path-style access against the object store, region `garage`, and
  `AWS_REQUEST_CHECKSUM_CALCULATION=WHEN_REQUIRED` (Garage rejects the SDK's default checksum
  mode: every write fails with "Invalid payload signature" without it).
- **`busy_timeout=30000`** on the JDBC URL (LL-407): SQLite allows one writer at a time and this one
  file backs every writer of the lake; without a timeout a transaction that meets the lock fails at
  once and the writer drops its whole batch (the old lab lost an hour of `wazuh_archive.events` this
  way). The wait is `iceberg_rest_busy_timeout_ms`. It does not remove the single-writer ceiling.
- **The object store** is found by its registry id (`iceberg_rest_object_store_id`, default
  `object-store`; the registry row must be an `object-store`), or by `iceberg_rest_s3_url`.
- **Secrets** (`secret:iceberg-rest/s3-access-key`, `secret:iceberg-rest/s3-secret-key`: the same
  values as the object store's own `secret:garage/access-key` and `secret:garage/secret-key`, held
  under this module's own names) reach only the compose env_file (0600).

Data lives under `iceberg_rest_data_root` (`/var/lib/hnx-modules/iceberg-rest`): `catalog/`
(`iceberg_catalog.db`), the container's user's, 0700.

## Loading the old lake's catalog

The archived catalog (`iceberg_catalog.db`, a SQLite online backup taken after the bucket copy) is
restored with the **restore hook** from an export directory holding it and a `listing.jsonl`
(`key`, `size`, `sha256`): the source is checked without writing, the server is stopped, the file
is installed as the container's user's and the server started again. Load the bucket first (the
catalog points at objects in it). At the final cutover (Task 3.4) freeze the old writers of the kept
tables and take the final delta **before** the reference counts are produced: the verification
pins counts to snapshot ids, so it cannot tell a reference taken while writers were still running. `tools/migrate/lake_verify.py` then compares per-table counts.

## Migration

The slot's migration format is Parquet. The tables' Parquet (and manifest) files are the object
store's: `garage` exports and restores them as an object-tree. This module exports and restores
the catalog's database - the namespaces, the tables and the pointer to each table's current
metadata file. The two together are the lake; a catalog that replaces this one registers each table
from its metadata file in the bucket. This module does not write Parquet itself.

## Hooks

| Hook | What it checks or does |
|---|---|
| `main` | validates, resolves the object store, renders and starts the stack |
| `readiness` | docker_engine ready; both credentials in their form; the object store answers |
| `health` | container healthy; `/v1/config` answers; `/v1/namespaces` lists (the SQLite file opens) |
| `backup` | a consistent copy of the catalog file (SQLite online backup), then names the data root |
| `export` | `iceberg_catalog.db` and `listing.jsonl` (key, size, sha256) in `iceberg_rest_export_dir` |
| `restore` | checks an export, stops the server, installs the file, starts it again |
| `upgrade` | validates a tag@digest bump of the same repository and records it |

## The catalog has no sign-in: the network is the only control

`auth: none`. Anything that can reach port 8181 can create, drop and purge tables, register
arbitrary metadata locations and write the bucket with the catalog's object-store key: that is,
destroy the lake. So these are hard requirements of the deployment, not advice:

1. **The control is the Proxmox VM-level firewall rendered from the overlay's guest file** (the
   NIC firewall of the guest). A firewall on the guest itself does **not** protect this port:
   Docker publishes the port through its own NAT chain, which bypasses the guest's `INPUT` chain
   (ufw, nftables input rules).
2. Inbound 8181 is limited to **named consumers**: the query engine (same guest) and the lake's
   writers (the pipeline flows, the log-lake writers). Nothing else, and no public route, ever.
3. The object store's port (3900) is limited the same way, to the same named consumers.

**Negative probe, part of the cutover verification (and of any change to the guest's rules):** from
a host that is *not* on the allow list, `curl -m5 http://<catalog host>:8181/v1/config` must **time
out** (not refuse, not answer); the same for `:3900`. From an admitted host it answers 200. A
catalog that answers a non-admitted host is a failed cutover, whatever else passed.

## Preserving the exact image

The digest has no tag upstream, so it can be garbage-collected from the registry, and the build that
wrote the SQLite file must be the one that reads it. Keep a `docker save` of this exact digest
(`docker save apache/iceberg-rest-fixture@sha256:db8de90b... | zstd -o <name>.tar.zst`) in the
PBS-backed backup directory, with its sha256, and set `iceberg_rest_image_archive` to its path on
the guest: when the daemon lacks the digest, the role runs `docker load -i` on it and refuses to go
on if the digest is still missing (the daemon must keep image digests across save and load, as the
containerd image store does). Cutover step: record the archive's sha256 when it is made
(`sha256sum <name>.tar.zst > <name>.tar.zst.sha256`, kept beside it and in the cutover notes), and
**verify it (`sha256sum -c`) before `docker load`** on the guest; a mismatch stops the cutover. The
role does not hash the archive itself: it checks that the pinned digest is present after the load,
which is the proof that the right image came in. The image has no CVE feed; see
[the follow-ups](../../docs/modules/follow-ups.md).

## Known limits

- Single writer. Concurrent committers queue on SQLite's lock for up to the busy timeout; a commit
  that waits longer fails. The lake's writers must keep their commit rate low (LL-330: a timer that
  fires every N minutes regardless of new data is what floods snapshots).
