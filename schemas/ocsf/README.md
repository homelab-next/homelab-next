# schemas/ocsf

Pinned **subsets** of five [OCSF](https://schema.ocsf.io) event classes (OCSF 1.3.0), written as
JSON Schema 2020-12 and used as the single source for the lake: the Arrow schema, the Iceberg
schema, the Trino / DuckDB / SQLite DDL and row validation are all generated from these files by
`homelabnext.lake` and pinned by goldens in `tests/lake/golden/`.

| File | OCSF class | `class_uid` | Lake table |
|---|---|---|---|
| `authentication.v1.json` | Authentication | 3002 | `authentication` |
| `network_activity.v1.json` | Network Activity | 4001 | `network_activity` |
| `dns_activity.v1.json` | DNS Activity | 4003 | `dns_activity` |
| `detection_finding.v1.json` | Detection Finding | 2004 | `detection_finding` |
| `vulnerability_finding.v1.json` | Vulnerability Finding | 2002 | `vulnerability_finding` |

Conventions

* Only the attributes the platform stores are included; `additionalProperties` is `false`, so an
  unknown column is refused rather than silently dropped. Adding an attribute is an additive
  schema change (see `tools/schema_check.py`).
* Columns are flat at the top level with a few one-level structs (`metadata`, `src_endpoint`,
  `dst_endpoint`). Types: string, integer (`long`), number (`double`), boolean, `date-time`
  (`timestamp`, UTC, microseconds), arrays of scalars (`list<...>`).
* The `x-lake` block carries what JSON Schema cannot: `table`, `key` (the **content key**, `uid`,
  used for idempotent replay), `time_column`, `partition` (`day(time)`), `ocsf_class_uid`,
  `ocsf_version`.
* `tlp` (1.1) is the row's TLP 2.0 label (ADR-0033 decision 5), a top-level string column limited
  to the five canonical spellings. It labels the **row**, set by the writer from the source's
  declaration; it is not OCSF's `osint.tlp`, which is the label an intelligence source gave one
  indicator. The column is optional in the schema (a row written before 1.1 has none and reads as
  `red`), and the lake refuses every new row without one.
* Timestamps need an explicit offset. Detections are referenced by logical id (`det:...`), never an
  engine rule number.
* Each schema has examples (`examples/`) that validate and negatives (`negative/`) that must not.

The OCSF names and attribute semantics are from the Open Cybersecurity Schema Framework
(Apache-2.0); only a subset is reproduced, with the upstream version pinned above.
