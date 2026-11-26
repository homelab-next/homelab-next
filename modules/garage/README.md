<!-- SPDX-License-Identifier: Apache-2.0 -->
# Module `garage`: the object-store provider

A provider module ([module manifest](../../docs/modules.md)) that fills the `object-store` slot with
[Garage](https://garagehq.deuxfleurs.fr), a single-node S3-compatible object store. It is the first
of the three modules that carry the lake (`garage`, `iceberg-rest`, `trino`): each fills one slot
with one product, as a provider module must, and the three are placed on one guest by the site.
Nothing in this directory names a real host, address, VM id or secret value.

| | |
|---|---|
| Slot | `object-store` (contract `conformance/protocols/object_store.py`) |
| Adapter | the shared `homelabnext.conform.adapters.s3:make_object_store`, feature `metadata` |
| Product | Garage 2.5.0, `docker.io/dxflrs/garage` pinned by tag and digest |
| Host role | `server`: kind `vm`, baseline `base`, 2 vCPU, 2 GB, 300 GB |
| Role | `garage` (role interface v1), a wrapper of the core `compose_app` |
| Requires | `cap:secrets` |
| Egress | none |
| Public route | none |

## Why 2.5.0 when the old lab runs 2.3.0

Both are Garage v2, whose breaking changes against v1 are in the admin API and the configuration
file; the S3 API and the stored objects are the same. The old lake's objects do not move as files
of Garage's own: the loader copies them through the S3 API (key for key, the same bucket name), so
the on-disk format of the old node never meets the new one. This module therefore starts from an
empty data root on the current v2 release the rest of the repository already pins
(`compose/lab-in-a-box`), and the upgrade hook refuses a bump across a major version.

## What the role does

- **One container**, `garage server --single-node --default-bucket`, as `garage_uid:garage_gid`,
  every capability dropped, `no-new-privileges`, a memory limit and a healthcheck (`garage status`).
  With `--default-bucket` the server creates the bucket (`garage_bucket`, default
  `iceberg-warehouse`: the table metadata embeds `s3://iceberg-warehouse/` paths, so the name is
  fixed) and imports the lake key from `GARAGE_DEFAULT_ACCESS_KEY` / `GARAGE_DEFAULT_SECRET_KEY`
  at every start, so there is no layout or key step to run by hand.
- **The S3 API** is published on the guest's own address (`garage_bind`, default the inventory's
  `ansible_host`; all interfaces is refused) at `garage_s3_port` (3900, the registry row's port);
  the admin API is not published (it listens inside the container's network; `garage_admin_port` is gone). Region `garage`
  (`garage_region`): the catalog and the query engine sign with it.
- **Secrets** reach only the compose env_file (`secrets/garage.env`, 0600), through `hnx_secret`
  in `no_log` tasks: `secret:garage/rpc-secret`, `secret:garage/admin-token`,
  `secret:garage/access-key`, `secret:garage/secret-key`. Each is checked for Garage's form before
  the server sees it (a malformed one would stop it at start).
- **No secret is in the rendered configuration** (`garage.toml`).

Data lives under `garage_data_root` (`/var/lib/hnx-modules/garage`, `root:<gid>` 0750): `meta/`
(the metadata database) and `data/` (the blocks), both the container's user's, 0700.

## Hooks

| Hook | What it checks or does |
|---|---|
| `main` | validates, renders the configuration, reads the credentials, renders and starts the stack |
| `readiness` | docker_engine ready; every credential resolves in its form |
| `health` | container healthy; `garage status` lists the node healthy; `garage bucket info` shows the lake key with read and write on the bucket; an unsigned S3 request is refused |
| `backup` | names the data root (the VM backup job takes it whole) |
| `export` | `garage meta snapshot` first, then `garage.tar.gz` of the data root in `garage_export_dir` |
| `restore` | stops the server, unpacks `garage_restore_source/garage.tar.gz` over the data root, restarts |
| `upgrade` | validates a tag@digest bump of the same repository and major version and records it |

## The scheduled copy

With `compose_app_export_timer` on (the lab's group variable), a nightly timer (`hnx-export-garage`, 07:30 UTC) runs `/garage meta
snapshot` inside the container (the server's own consistent copy of the LMDB metadata, written to `meta/snapshots/<ts>`), then writes
a gzip tar of the whole `meta/` directory into `export/db/object-store-meta/object-store-meta.tar.gz` with a sha256 listing and a
manifest that names what the dump does not carry. The data blocks are immutable files and are not in the scheduled copy: they travel
in the guest's image backup. The previous copy is kept once (`.prev`). The service is not stopped.

## Network exposure

The S3 API is signed, but the lake key it admits can read and delete the whole lake. Limit inbound
3900 at the **Proxmox VM-level firewall rendered from the overlay's guest file** to the named
consumers (the catalog and the query engine on the same guest, and the lake's writers): a firewall
on the guest does not protect a Docker-published port. Cutover check: from a non-admitted host,
`curl -m5 http://<store host>:3900/` must time out.

## Known limits

- The exit copy is a crash-consistent archive of a running store: the metadata is snapshotted first
  and the data blocks are immutable, but a write after the snapshot may or may not be in the
  archive. Freeze the writers first for a copy that must be exact (the lake's cutover does).
- The conformance target needs a key that may create buckets (`createBucket`); run it with a key
  made for the purpose, never by widening the lake key.
- Garage never re-imports a key id it has held: changing the key pair on a kept data root needs a
  fresh data root.
