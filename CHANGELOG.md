# Changelog

All notable changes are recorded here, following [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and [Semantic Versioning](https://semver.org/). The release workflow refuses a tag whose version
has no section below.

## [Unreleased]

### Added

- Schemas, logical-id library, service registry and generators, role interface and linter,
  detections as code, register generators and invariants runner (first wave of workers).
- `hnx` console script (`homelabnext/cli.py`) dispatching to registry, new, gen, detections,
  registers, invariants, ids and schema-check.
- `make check` now runs lint, tests, strict schema check, endpoint and role gates, detections,
  registers, SPDX, leak scan and changelog check; CI runs the same gates and a pinned gitleaks CLI.
- Pinned OCSF 1.3.0 schema subsets (`schemas/ocsf/`) and the `homelabnext.lake` library: `LakeClient` protocol, `FakeLake`, DuckDB/Iceberg/Trino adapters, cassette parity, and commit-then-checkpoint idempotent writes.

### Changed

- Core install is dependency-free; PyYAML, jsonschema and friends are extras.
- Leak scanner accepts exactly the `Claude-Session:` commit trailer shape.

## [0.1.0] - 2026-10-15

### Added

- Repository skeleton: licence and policy files, CI, pre-commit configuration, Makefile.
- Architecture decision log with twelve ADRs (`docs/adr/`).
- Interface index for parallel work (`docs/interfaces.md`) and glossary.
- Generic public-repo leak scanner (`tools/leak_scan.py`) with fixture tests.
