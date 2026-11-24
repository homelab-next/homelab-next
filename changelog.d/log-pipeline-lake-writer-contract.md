---
group: Fixed
---
The log pipeline and its lake writer share one table contract: the raw archive takes the pipeline's `route`, `source_kind` and `raw` columns, a sensor event's location is its route, compliance_finding takes `compliance_status` and file_activity `user_name`; the writer adds a pinned optional column an existing soc table lacks (`evolve_additive`, ADD COLUMN only). A contract test runs every golden pipeline row through the writer.
