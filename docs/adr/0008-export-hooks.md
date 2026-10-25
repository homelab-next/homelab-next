---
summary: 'Every stateful product ships an export hook that a restore drill exercises.'
summary_of: outline:sha256:2fdd5ae7b30885dd
---
# ADR-0008: Every stateful product ships an export hook, exercised by the restore drill

- **Status:** proposed
- **Date:** 2026-10-15
- **Related:** ADR-0004, ADR-0005

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
