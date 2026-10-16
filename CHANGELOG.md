# Changelog

All notable changes are recorded here, following [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and [Semantic Versioning](https://semver.org/). The release workflow refuses a tag whose version
has no section below.

## [Unreleased]

### Added

- `homelabnext.notify`, `homelabnext.state` and `homelabnext.records`: state-diffed paging with registered recovery pairs and an ntfy-style sender, crash-safe versioned state files with a keyed check API, and the records lifecycle (single validated agent write path, separate operator movers).
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

### Changed

- Core install is dependency-free; PyYAML, jsonschema and friends are extras.
- Leak scanner accepts exactly the `Claude-Session:` commit trailer shape.

## [0.1.0] - 2026-10-15

### Added

- Repository skeleton: licence and policy files, CI, pre-commit configuration, Makefile.
- Architecture decision log with twelve ADRs (`docs/adr/`).
- Interface index for parallel work (`docs/interfaces.md`) and glossary.
- Generic public-repo leak scanner (`tools/leak_scan.py`) with fixture tests.
