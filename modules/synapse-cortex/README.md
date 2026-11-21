<!-- SPDX-License-Identifier: Apache-2.0 -->
# Module `synapse-cortex`: the graph store

A provider module ([module manifest](../../docs/modules.md), draft) that fills the `graph-store`
slot with **Synapse Cortex**, the hypergraph server (a Vertex Synapse service) the CTI graph lives
in. The CTI pipeline's graph sync writes indicators, actors and their relationships into it and its
weekly graph report reads them back, over the HTTPS API. It is a **service, not a machine**: the
guest is the site's guest file and the site's selection places the module's one host role
(`server`) on it. Nothing here names a real host, address, VM id, account or domain; those live in
the private overlay.

**Not the analyzer engine.** This is the hypergraph server. TheHive's analyzer engine, also called
"Cortex", is a different product that was retired with its host; nothing in this module relates to
it. Read the address, never the name, before retiring or repointing either.

| | |
|---|---|
| Slot | `graph-store` (provisional: no contract or suite yet), stateful, object-tree export |
| Product | Synapse Cortex 2.247.0 (the version the old lab runs), `docker.io/vertexproject/synapse-cortex` pinned by tag and digest |
| Host role | `server`: kind `vm`, baseline `base`, footprint 2 vCPU, 8 GB, 100 GB (the graph is 23 GB and two sealed backups are kept) |
| Role | `synapse_cortex` (role interface v1), a wrapper of the core `compose_app` |
| Secrets | `secret:synapse-cortex/root-password`; every other account's **name** and **password** are the site's references (below) |
| Egress | none |
| Public route | **none**. The row declares no `public_hostname`; the consumers call it directly |

## Decisions that matter

- **Same version as the old lab.** 2.247.0, pinned by digest (the digest of the tag's manifest on
  the registry, pushed more than a month before this module). The service migrates its own storage
  forward on first start and cannot be taken back, so a restore into an older image is refused and
  an upgrade to an older tag is refused. Bump the tag and the digest together with
  `product.version` and the lab registry's `version`.
- **The HTTPS API is the consumers' interface; telepath is optional.** The lab's consumers (the CTI
  pipeline's graph sync and graph report, and the MISP indicator ingest) call the HTTPS API with a
  user name and password. `synapse_cortex_telepath_port` (default 0, none) adds the service's native
  telepath listener, TLS only, certified for `synapse_cortex_telepath_hostname`; the role renders
  it, the guest's firewall must admit it, and it is not exercised by this module's health hook.
- **The certificate is part of the data.** The service makes its own self-signed certificate on its
  first start and keeps it in its directory. The consumers pin it. A restored graph brings its
  certificate with it, so a pin taken against the old instance stays valid; a fresh (empty) graph
  makes a new one, and the consumers' pins must be updated (verify out of band).
- **No secret in any file.** The compose file carries no password. The service starts with a root
  that has none (it cannot sign in over the network); the role then sets root's password, makes the
  roles and the accounts through the service's own API from inside the container, with the values in
  the environment of that one command (`no_log`). They are **not** hidden from local users of the
  guest: for the instant the command runs they are in the process list of the docker client. Keep the
  guest's local users to the operator.
- **Accounts and roles by reference.** Roles are literal (`name`, `rules`: permission strings in
  the service's own dotted grammar, a leading `!` for a deny); accounts are secrets by reference,
  the name too:

  ```yaml
  synapse_cortex_roles:
    - {name: cti-writer, rules: ["node", "storm"]}      # the site's grant; nothing is granted by default
  synapse_cortex_users:
    - name_ref: secret:<ns>/graph-username
      password_ref: secret:<ns>/graph-password
      admin: false
      roles: [cti-writer]
  ```

  A second run is `changed=0`: an account whose password already signs in is no change, a role
  already holding exactly these rules is no change. An account the site did not name (a restored
  graph's own) is left alone. The role refuses a reference with no value, naming it, before anything
  is rendered, a name or password of the wrong form, root as a name, and a repeated name or password.
- **Runs unprivileged.** The container runs as the image's own account (`synuser`, 999), every
  capability dropped, `no-new-privileges`, one memory limit (`synapse_cortex_mem_limit`). The storage
  is the container's, the data root is root's.
- **Health is more than "the port answers".** The image's own health check passes; the service
  answers as the active one; a storm call with no session is **refused** (401); root and every
  configured account sign in; and with `synapse_cortex_expected_min_nodes` set, the graph holds at
  least that many nodes (a graph that lost its nodes is never "healthy" empty). The calls are made
  from inside the container, trusting the service's own certificate and nothing else, with the
  certificate's name checked (verification is never turned off).

## Data root layout

`<data_root>/storage/` (the service directory: every slab of the graph, its accounts and roles, its
certificate; the container's) and `<data_root>/export/backups/hnx-<UTC stamp>/` (sealed backups).
The guest backup names **only** `export/`: a file-level copy of live LMDB slabs is not a consistent
graph, and a guest backup must not stand in for the export. Take an export before a copy that must
hold the graph (the overlay schedules the export hook).

## Hooks

`readiness` (engine ready, inputs valid, every secret resolves), `health`, `backup` (names the export
directory), `export`, `restore`, `upgrade`.

## Backup and restore

**Export** takes a backup with the service's own backup machinery, never a copy of the live files:

- `live` (default): the running service writes the backup itself (`synapse.tools.service.livebackup`,
  which runs the service's backup under one consistent hold across all its slabs, the same code as
  the offline backup tool). No stop.
- `offline`: the service is stopped cleanly, the offline tool `synapse.tools.service.backup` runs on
  the stopped directory in a one-off container of the same pinned image, and the service is started
  again whatever happened.

The node count of **every form** is read from the service before and after the backup. The backup is
then **sealed**: `hnx-manifest.json` (the two counts, the version, the image, the mode) and
`hnx-listing.jsonl` (every file's size and sha256). It is sealed only if the two counts are equal and
not empty: a backup taken while the graph was changing, or of an empty graph, is refused (stop the
writers, or use `offline`, and take it again). The oldest sealed backups beyond
`synapse_cortex_export_keep` (default 2) are then removed, by name pattern, from the backups
directory only; an unsealed (interrupted) directory is never touched.

A failed export (the service's backup fails, or the seal is refused) **discards its unsealed
directory** (`discard`: only an `hnx-` directory that does not pass the check, never a sealed one), so
repeated failures cannot fill the disk; the previous sealed backups are untouched.

**Live export needs the writers frozen.** The seal refuses a backup if any form's count moved during
it, so before a `live` export pause every writer: the CTI pipeline's graph sync (`cti-graph-sync`
daily 05:00) and graph report (read-only, may stay), the MISP indicator ingest (`misp-cortex-ingest`
daily) and any other account with write rules. Resume them after. Or use `offline` mode, which needs no
freezing because the service itself is stopped.

**Restore** (`restore` hook with `synapse_cortex_restore_source=<...>/export/backups/hnx-<stamp>`):

1. Deploy with `synapse_cortex_start: false` (the compose file and the directories, nothing running).
2. The source is checked and nothing is written until it passes: sealed, the listing names exactly the
   files that are there (no more, no fewer, no link), each of its listed size and sha256, the
   manifest's two counts equal and not empty, a service directory (`cell.guid`, an LMDB slab), and not
   of a newer version than the pinned image.
3. The service must be stopped and `storage/` **empty**: a restore never merges and never overwrites a
   graph (move an old one aside yourself).
4. The files are copied into a sibling directory (hashed as written, re-read against the listing),
   given to the container's account, and renamed into place. Nothing is deleted.
5. The service is started and the node count of **every form** must equal the backup's, with a graph
   that is not empty: a different count, or no nodes where nodes are expected, is an error, and the
   storage is left in place for inspection.
6. Root's password and the site's accounts are made what the secrets say (the restored graph's own
   passwords are replaced; its other accounts and roles are kept).

## Migrating in from the old lab

The old lab's graph is the same product and the same version, 2.247.0, in a container whose storage
volume is the 23 GB service directory. To bring it over without a file copy of live slabs:

1. Stop the writers (the CTI pipeline's graph sync, the MISP indicator ingest) so the graph is
   quiet, and record the node count of every form on the old instance (the same call the role makes:
   `python -m synapse.tools.service.healthcheck` is not enough, use the form counts).
2. Take the backup on the old host with the service's own tool, in a one-off container of the same
   pinned image against the stopped service directory (`python -m synapse.tools.service.backup
   /vertex/storage /backup/<name>`), or with its live backup (`python -m
   synapse.tools.service.livebackup`) while it runs; copy the directory to the new guest with rsync
   (checksums) and put the two count records beside it.
3. On the new guest, write a `hnx-manifest.json`-bearing sealed copy with the role's tooling: place
   the directory under `export/backups/hnx-<stamp>/` and seal it
   (`python3 -I files/synapse_cortex_backup.py seal <dir> < manifest.json`, the manifest holding the
   counts of step 1 as `counts_before` and `counts_after`, the version and the image), then restore
   as above. The restore's count check compares the new instance to the manifest; the manifest was
   written from the old instance's counts, so equality is the **old = new** proof.
4. Repoint the consumers (the CTI pipeline's `SYNAPSE_BASE_URL`, the ingest's target) and verify
   with a graph report run; keep the old instance stopped, not deleted, for the soak.

The old lab's accounts are inside the backup; the role resets root's password and the named accounts'
passwords from the secrets. The consumer accounts' names and passwords are the site's secrets; the
pipeline's own references are `cti/synapse-username` and `cti/synapse-password` in the old lab.

## Using it in a site

The overlay binds the row (`lab/services.yml`) exactly as this module contributes it (`graph-store`
renamed to the instance, `host` the guest, `version` the product's), selects the module in
`lab/modules.yml` with the guest, adds the guest's firewall rules admitting only the consumers on
the HTTPS port, and holds the secrets. Group variables: `synapse_cortex_logical_id`,
`synapse_cortex_users`, `synapse_cortex_roles`, and `synapse_cortex_expected_min_nodes` once the
graph is loaded. The conformance adapter is a probe (`homelabnext.conform.adapters.graph_store`), not
a suite: it needs `HNX_ENDPOINT_GRAPH_STORE`, the path of the service's certificate (`ca_file`) and the name that certificate carries (`server_name`; the old instance's is its service name), and it verifies both.

The role was run end to end against the real pinned image on a scratch host (not the old lab's
instance and not CI): install, root and account creation (a second run `changed=0`), health with real
logins, a live export, an offline export, and a restore of a sealed backup into a fresh instance whose
node count of every form equalled the backup's, with the service's certificate carried over. CI runs
the role against fakes. The first use on the real guest should still be an empty-graph install, a
health run, an export and a restore drill, before the old lab's graph is brought over.
