---
group: Added
---
TLP labels on status sources and lake tables (ADR-0033 decisions 3 and 5). Service schema 2.16 adds `tlp` to a `status_sources` entry (the label of what the source reads into the hub; `red` when absent), shown by `hnx status sources`, the status catalog and `status.json`'s source list, and `hnx status views check` refuses a released view or export whose release transform takes a looser `input` than a source it can show. The `platform/lake_table` draft adds `tlp` (the most restrictive label a row may carry, `red` when absent); the module loader refuses a `lake-table` dataset labelled above its table, and every lake-writer table and the example table declare `red`.
