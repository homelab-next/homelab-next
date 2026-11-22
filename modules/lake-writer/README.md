<!-- SPDX-License-Identifier: Apache-2.0 -->
# Module `lake-writer`: the log pipeline's lake writer

A feature module ([module manifest](../../docs/modules.md), draft; [ADR-0049](../../docs/adr/0049-the-soc-data-plane-and-the-lab-checks-move-as-modules.md)
decision 3). The `log-pipeline` slot stages labelled OCSF batches in the object store
([log pipeline](../../docs/log-pipeline.md)); this module commits each batch to a **fresh table of the
lake's `soc` namespace**, one writer per table, through `LakeClient.write_batch` with the
commit-then-checkpoint rule of `homelabnext/lake/checkpoint.py`. It names no product: the object
store, catalog and query service are the site's selection.

| | |
|---|---|
| Needs | `cap:secrets`, `cap:object-store`, `cap:lake-catalog`, `cap:lake-query`; prefers `cap:log-pipeline` (the producer of the batches) |
| Host role | `writer`: kind `vm`, baseline `base`, 2 vCPU, 2 GB, 10 GB. Place it where the object store and the lake answer |
| Role | `lake_writer`: one script, one template service and one template timer (an instance is a table) |
| Config secrets | the lake password and the object store key pair (names in `module.yml`); an optional catalog token and CA by role variable |
| Egress | none declared |
| Registry rows | none: the module listens on nothing (like `honeypot` and `intel-ingest`) |
| Host precondition | the homelab-next runtime release (`hnx_runtime`), whose interpreter the script runs under |

## The tables

Ten tables, all in the namespace **`soc`**, all created fresh (nothing is imported or backfilled: the
old lab's SIEM archive, `ocsf` and `obs` data was dropped, decision D-12, and stays in the archive):

| Table | Class | Pinned in |
|---|---|---|
| `authentication`, `detection_finding`, `dns_activity`, `network_activity`, `vulnerability_finding` | OCSF 3002, 2004, 4003, 4001, 2002 | the core's `schemas/ocsf` |
| `compliance_finding`, `file_activity`, `http_activity`, `process_activity` | OCSF 2003, 1001, 4002, 1007 | this module, `roles/lake_writer/files/schemas/` |
| `raw_archive` | none (the platform's own, class uid 0): every event the SIEM manager archived, before the remap | this module |

`raw_archive` is the table the source census reads (`location` and `decoder_name` are its source
key, `time` the manager's event time). Every table has the `uid` content key, a `tlp` column and
`day(time)` partitioning, and a `platform/lake_table` record in `lake/` (owner `lake-writer`, retention,
snapshot expiry, freshness). The records are in namespace `soc`, which is not the module id's
(`lake_writer`): the operator's decision D1 fixed the name, so a site lists `soc` in its selection's
`lab_table_namespaces` (`why`: the SOC's fresh tables, written by lake-writer only).

## The staged batch (the contract with the pipeline)

```
<bucket>/<prefix><table>/<name>        bucket: soc-staging   prefix: lake-writer/staging/
```

An object is newline-delimited JSON, one event per line, a flat OCSF event of the table's pinned
shape plus **`labels.hnx_tlp`**, the label the pipeline sets from the route's declaration. `<name>`
should sort in arrival order (a timestamp first) and be unique per batch: the object key is the
batch's idempotency key, so **a producer must never reuse a name for different content**. A pipeline
that writes an object in several steps stages it complete (a rename or a final PUT); the writer treats
any listed object as whole.

## What a run does (per table, `hnx-lake-writer commit --table T`)

1. List `<prefix>T/` (never `_rejected/`), oldest name first.
2. For each object: turn every line into a row with `homelabnext.lake.rows.row_from_event` (the row's
   `tlp` is `labels.hnx_tlp`, the event's own `tlp` is dropped) and validate it exactly as the lake will.
   A line the lake would refuse (not JSON, not an object, a field outside the pinned schema, **no
   canonical label**) is written with its reason under `<prefix>T/_rejected/` and counted; it never
   blocks the rest of its batch and is never given a label.
3. Commit the good rows with `write_batch(idempotency_key=<object key>, source=lake-writer/T,
   high_water=<object key>)`, **then** save the checkpoint (`Ingestor`), **then** delete the object.

A crash between any two steps leaves the object staged and the replay adds no row: the lake's batch
ledger answers `replayed`; where the ledger was expired, the rows' `uid` skips every row already stored;
and `Ingestor.start` fast-forwards a checkpoint that is behind the lake's own mark
(`tests/modules/test_lake_writer_script.py`: crash before the checkpoint, after the checkpoint,
lost checkpoint, the same events under another batch name).

## Guards

* **Only `soc`.** The namespace is not an input of the role (derived, asserted in `validate`) and the
  script refuses any other, at four places: configuration, the writer, the client it was handed
  (`_ns`), and `open_lake` before a client is built. The refusal names the protected namespaces (the
  imported and migrated ones: CTI, risk, sandbox, honeypot, archive, OCSF, observability); every
  other namespace, case, padding or qualified name is refused alike. Exit 2, nothing read or written.
* **Only its own tables.** A table name outside the ten, or any qualified name, is refused.
* **One writer per table.** One timer per table, a per-table lock taken without waiting (a run that
  finds it held does nothing and exits 0), one checkpoint and source (`lake-writer/<table>`) per table.
  Split the tables over guests with `lake_writer_tables`; the loader refuses a second owner of a table.
* **No label, no row.** Pass-through (no pipeline) means no label, so nothing lands: it is loud
  (every row refused makes the run fail), never a silent `red`.

## Failure behaviour (from the old writers' lessons)

* A lake that is away or a commit conflict is retried `lake_writer_max_attempts` times with backoff
  (replay-safe, so a retry cannot duplicate; LL-007), then the table's run stops, exits 1 and keeps
  its objects. One table's failure never stops another table's turn but fails the run (LL-008).
* A run in which every row was refused exits 1 (a pipeline shipping unlabelled events is not a green
  unit over an empty table).
* A store that cannot read one object fails that object only.
* Timers are on the calendar (`*:0/10`), never an interval (LL-041).

## Hooks

| Hook | What it checks or does |
|---|---|
| `readiness` (the module's preflight) | systemd, the inputs, every secret in its form (a missing one is named), the three services' registry rows, the runtime release importing the lake library and clients |
| `main` | validates, writes the script, the schemas, the environment (no secret), the root-only logins file and the template units, arms one timer per table, creates the `soc` namespace and tables (`lake_writer_ensure_tables`, an existing table is checked against its pinned schema, never altered) |
| `health` | files present, every timer active, `schema-check` (the soc tables exist with exactly the pinned columns), `status` (every table has run, its last run succeeded and is no older than `lake_writer_health_max_age_s`, its backlog is at most `lake_writer_health_max_pending`). Nothing is written |
| `export` / `backup` | every table's checkpoint and last-run record under `export/<stamp>/state/`, built beside and renamed into place |
| `restore` | checks each exported checkpoint, stops the timers, waits for a running writer, replaces the checkpoints, arms the timers |
| `upgrade` | no pinned artefact: refuses when a live table is not its pinned columns; the converge is the install |

## Variables

Required: `lake_writer_logical_id`, `lake_writer_lake_user`, `lake_writer_lake_warehouse`, `lake_writer_s3_region`, and for each
of the lake query service, the catalog and the object store either its registry id or its URL. Everything
else has a default in `defaults/main.yml`. The lake is reached over https only and verified.

## What the overlay must add

The selection places `writer` on a guest and lists `soc` in `lab_table_namespaces`; the lab registry
holds the three services; the secrets exist (the lake password, the object store key pair: a key that
may read, list and delete in the staging bucket and nothing else); the lake guest's firewall admits the
writer's host on the lake query and catalog ports and the object store's; the log-pipeline provider's
output (its S3 sink) points at `soc-staging` / `lake-writer/staging/<table>/`.

## Cutover

The tables are fresh and the writer is the first to write them, so there is no old writer to hand
over from within the lake. When the old SIEM keeps running beside it, the old and new paths write
different namespaces. For each source's cutover, check the **boundary** on the new table, not the old
one: a bounded `min/max/count` across the moment the old sender stopped and the new path started
(LL-067: neither side errors, a gap is invisible to both).

## Limits

* Retention and snapshot expiry are declared in the table records; running them is the lake
  maintenance's job, not this writer's.
* A staged object is read whole (the object store client's limit applies); a pipeline stages batches
  of a few MiB, not gigabytes.
* The writer trusts the pipeline's label. It cannot tell a pipeline that mislabelled an event from one
  that labelled it right: the route's declaration is reviewed where it is made
  ([log pipeline](../../docs/log-pipeline.md#limits)).
