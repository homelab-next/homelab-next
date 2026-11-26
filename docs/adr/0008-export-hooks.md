---
summary: Every stateful product ships an export hook that a restore drill exercises.
summary_of: outline:sha256:2fdd5ae7b30885dd
---
# ADR-0008: Every stateful product ships an export hook, exercised by the restore drill

- **Status:** proposed
- **Date:** 2026-10-15
- **Related:** ADR-0004, ADR-0005
- **Status note (2026-11-22):** decision 1's schedule and decision 2's drill now exist as code. `compose_app_export_timer`
  (`ansible/roles/compose_app/tasks/export_timer.yml`) installs a nightly `hnx-export-run` that dumps every PostgreSQL and
  MariaDB/MySQL service of an application from inside its container (`pg_dump -Fc` per database plus the globals, `--single-transaction`
  for MariaDB), verified and atomically replaced, into `<export dir>/db` with a sha256 listing and a manifest that says what the
  dump does not carry. `restore_drill_timer` installs a daily `hnx-restore-drill` that restores one guest's newest backup to scratch
  (alternating the primary and the second copy), checks the image, re-verifies every application export in it against its listing,
  destroys the scratch and records the result (`drills.json`, `guests` and `services`); `hnx recovery drills check` judges those
  records. Still open: an open-format dump (STIX, JSON) for the products whose own export hook is not a database dump, and the
  results transport that carries `drills.json` to the status hub (ADR-0049 decision 7).
  Since 2026-11-25 the same timer also copies products whose state is SQLite or plain files (`compose_app_export_files`: a `sqlite`
  job through SQLite's online backup with an integrity check, a `tree` job as a gzip tar): the forge, the feed reader, the DNS server
  and the status hub. Since 2026-11-26 a `tree` job also accepts `pre_exec: {service, argv}` (a snapshot command the product runs
  inside its own container before the copy) and `stop_service: true` (`docker compose stop` before the tar and `docker compose up
  -d` after it, in a `try/finally`), so the object store's metadata (the `/garage meta snapshot` command writes an LMDB snapshot
  the tar then captures) and the dataflow server's state (the stored flow, users, authorizations and state repositories, archived
  with the service stopped) are on the same timer.
- **Status note (2026-10-28):** decisions 1 and 2 are not yet met as written; the decision is unchanged. Today `ansible/roles/compose_app/tasks/export.yml` exports a tar.gz of the live data directory, not an open-format dump (JSON, STIX, SQL), and the `restore_drill` role runs the backup product's image-level drill (`restore_drill_cli`), not a restore from an export.
- **Amended:** 2026-11-07 by ADR-0040 (decision 6): export and import become methods of each
  stateful slot's protocol, with a round-trip requirement; and by ADR-0042 (decision 2): a dump
  restores the same product, while the export of decision 1 is for leaving it and stays a separate,
  open-format hook
- **Amended-by:** ADR-0040, ADR-0042

## Context

Open table formats make the data lake portable, but identity providers, case managers,
threat-intelligence platforms, context stores and password managers hold state only in their own
databases. Image-level backups restore the product, not the data's portability, so an exit from a
product is assumed rather than rehearsed.

## Decision

1. Each stateful role implements the `export` hook (ADR-0004): an open-format dump (JSON, STIX,
   SQL) to the backup path on a schedule.
2. The periodic restore drill restores at least one product from its export, not only from its
   image-level backup.
3. A new stateful product is adopted only after export and import are demonstrated on staging.
4. Each hook documents what the export does not carry.

## Consequences

- Product exits are rehearsed, not assumed.
- Some exports are lossy; the documentation of the loss is part of the deliverable.

## Alternatives

Rely on image-level backups alone: restores the product, not the data.
