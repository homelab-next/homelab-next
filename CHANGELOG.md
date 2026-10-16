# Changelog

All notable changes are recorded here, following [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and [Semantic Versioning](https://semver.org/). The release workflow refuses a tag whose version
has no section below.

## [Unreleased]

### Added

- Self-contained wheel: `homelabnext.paths` is the one place that locates `schemas/`, `profiles/` and `examples/` (env override, then packaged `homelabnext/_data`, then the source tree, with an error listing every place tried); `setup.py` copies the top-level directories into the wheel at build time, a minimal example lab ships as `examples/minimal/`, and the wheel test now installs into a clean venv and runs `hnx site|guests|registry validate` and `hnx custom list` against it.
- Conformance harness: `hnx conform list|run|mutants|report`, a suite format (named checks, severities, features, waivers) that runs against any implementation named by a target file, 14 capability suites with fakes, deliberately broken fakes that each suite must catch, three extended suites (`backup`, `dns`, `edge`), the `capabilities without a passing test` JSON export and invariant X-10 (`docs/conformance.md`).
- `homelabnext.notify`, `homelabnext.state` and `homelabnext.records`: state-diffed paging with registered recovery pairs and an ntfy-style sender, crash-safe versioned state files with a keyed check API, and the records lifecycle (single validated agent write path, separate operator movers).
- Customizations: schema, loader, linter, plan-only applier, invariant X-09, register view, three synthetic optional profiles and `hnx custom list|check|plan|register` (`docs/customization.md`).
- Customization schema 1.1 (additive): `maintained_upstream` exempts project-shipped profiles from `review_by` expiry; honoured only for the shipped `profiles/` directory, rejected with `CU015` in any overlay; `hnx custom check`, invariant X-09 and the register honour it.
- Schemas, logical-id library, service registry and generators, role interface and linter,
  detections as code, register generators and invariants runner (first wave of workers).
- `hnx` console script (`homelabnext/cli.py`) dispatching to registry, new, gen, detections,
  registers, invariants, ids and schema-check.
- Inference and decision building blocks: model-role resolver with `/v1/models` mismatch probe
  (`homelabnext.registry.models`), fake OpenAI-compatible server (`conformance/fakes`), golden
  tasks (`homelabnext.golden`), decision cascade with impact scan, replay gate, synthetic eval and
  `/v1/systemone` adapter (`homelabnext.decide`); `model_roles` and `decision_spec` schemas 1.1.
- `make check` now runs lint, tests, strict schema check, endpoint and role gates, detections,
  registers, SPDX, leak scan and changelog check; CI runs the same gates and a pinned gitleaks CLI.
- Pinned OCSF 1.3.0 schema subsets (`schemas/ocsf/`) and the `homelabnext.lake` library: `LakeClient` protocol, `FakeLake`, DuckDB/Iceberg/Trino adapters, cassette parity, and commit-then-checkpoint idempotent writes.
- Site/network model: `schemas/platform/site.schema.json`, `homelabnext/network/` (validation, vendor-neutral IR, `linux`, `dnsmasq`, `zonefile` and dry-run `unifi` adapters, `opnsense` deferred) and `hnx site validate|plan|render`, with golden files from a synthetic site.
- Guest (compute) model: `guest.schema.json`, `homelabnext.compute` loader, validation and renderers (Terraform for a Proxmox-style provider, libvirt, cloud-init, Ansible inventory, registry hosts, backup jobs, plan diff) and `hnx guests validate|render|plan`.
- Swap kit: `hnx swap plan|start|status|advance|rollback|record` (nine-step resumable state machine with gates, evidence and a hash-chained `swap_record` schema), `homelabnext.parity` (row, table, schema-drift, event-stream and notification parity), a dual-write helper, the registry flip with its exact inverse, and `tools/decommission_check.py` (`docs/swap.md`).

### Changed

- Wave-2 integration: `lake` extra pins (`duckdb>=1.5`, `pyarrow>=26`, `pyiceberg[sql-sqlite,pyiceberg-core]>=0.12`), package data for example specs, the X-09 invariants entry point, CI matrix with and without the lake extras, `hnx custom check` gate, `role_lint` expands a directory of roles, guests read zones through the network loader, registry merge keeps extra registry fields, schema contract test covers every schema, cross-package integration tests and a wheel-install smoke test.
- Core install is dependency-free; PyYAML, jsonschema and friends are extras.
- Leak scanner accepts exactly the `Claude-Session:` commit trailer shape.

## [0.1.0] - 2026-10-15

### Added

- Repository skeleton: licence and policy files, CI, pre-commit configuration, Makefile.
- Architecture decision log with twelve ADRs (`docs/adr/`).
- Interface index for parallel work (`docs/interfaces.md`) and glossary.
- Generic public-repo leak scanner (`tools/leak_scan.py`) with fixture tests.
