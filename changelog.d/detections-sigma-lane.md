---
group: Added
---
the Sigma lane on the engine: logsource bindings in `mappings/<backend>.yml` (one engine base per Sigma logsource, the decoder's field names, raw-line fields for values only the raw line carries) so a compiled rule chains where the engine reaches its telemetry; `hnx_source: awaiting-source` for a rule ported and tested whose telemetry is not collected yet (compiled, never shipped, never coverage); engine fixtures (raw lines, the expected rule from the det map) run through the manager's rule tester by `run --engine`; `compile --out` and `map --base`; and the SIEM role's `wazuh_sigma_roots`, which proves, compiles and loads each root's bundle after the native rules under the same configuration test and rollback.
