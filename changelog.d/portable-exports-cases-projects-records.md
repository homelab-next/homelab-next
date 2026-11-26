---
group: Added
---
open-format leave-the-product exports for the `cases`, `projects` and `records` fakes (ADR-0008 decision 1, ADR-0040 decision 6): `conformance/fakes/portable.py` adds `PortableCaseStore` (IRIS-aligned `jsonl`), `PortableProjectStore` (OpenProject-aligned `object-tree`) and `PortableRecordsTarget` (`markdown-tree` lane copy); each satisfies `conformance.protocols.migration.Migratable` (`slot`, `export_formats`, `export(dest, fmt) -> manifest`, `import_(src, manifest, limits) -> int`) and passes the full 13-check migration suite including round-trip; `MIGRATION_PROOF` promotes those three slots from `reference` to their adapter.
