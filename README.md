# HomelabNext

What a homelab grows into after the first lab and the question "what can I do next?": a modular,
swappable security-and-AI platform in which every capability sits behind a contract, so any one
component can be replaced by a DNS flip and an adapter instead of a rewrite.

HomelabNext is **contracts, libraries and conformance tests**, not a platform, framework or product.
It gives you JSON Schemas, a service registry and generators, small shared client libraries with
in-memory fakes, a conformance harness, a role interface for Ansible, detections as code, register
generators and a swap kit. Everything runs on a laptop or a CI runner. Items that are not built yet
are listed as such in [docs/checklist.md](docs/checklist.md).

> **Status: pre-alpha.** This drop is contracts and libraries only: JSON Schemas (including pinned
> OCSF subsets), the service registry and generators, the role interface and linter, detections as
> code, register and invariant tooling, shared libraries with in-memory fakes (lake, notify, state,
> records, decision cascade, golden tasks), the site/network, guest/compute and customization
> models, and the `hnx` command line. All of it is proven by unit tests, golden files and fakes on a
> laptop or CI runner. **Nothing here has been tested on real hardware or against a live
> deployment**, the conformance harness and the swap kit are not in this drop yet, and parts that
> need a real server are tagged SERVER and ship an interface and a fake only. Expect breaking changes.

## The capabilities and their seams

| Capability | Seam (contract) | Conformance test |
|---|---|---|
| `lake-query`, `lake-catalog`, `object-store` | query results, table catalog, S3-style objects | `conformance/<capability>/` |
| `inference`, `fast-classifier` | OpenAI-compatible chat, model-role aliases | golden tasks, tool-call checks |
| `notify`, `events`, `orchestration`, `broker` | dedup-keyed send, event envelope, workflow, approvals | fixture events and table tests |
| `secrets`, `idp` | key issue and revoke, claim-to-role mapping | issue/expire/revoke checks |
| `cases`, `records`, `detections` | case round-trip, propose/approve/complete, Sigma + fixtures | lifecycle and fixture runs |

The authoritative list and the Python interfaces are in [docs/interfaces.md](docs/interfaces.md).
The vocabulary is in [docs/glossary.md](docs/glossary.md).

## Quick start

<!-- quick-start:begin (owned by the lab-in-a-box task; do not edit outside this marker pair) -->
Python 3.11 or newer. The core install has no dependencies; the `dev` extra adds PyYAML, jsonschema,
pytest and ruff, and the `lake` extra adds DuckDB, PyArrow and PyIceberg (without it the lake tests
skip and `hnx` still runs).

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
make check          # lint, tests, schemas, gates, detections, registers, SPDX, leak scan, changelog
hnx --help          # registry, new, gen, detections, registers, invariants, ids, decide, golden, site, guests, custom, schema-check
hnx registry validate examples/services.yml
```

`pip install homelabnext` (a wheel or sdist) is self-contained: it carries the schemas, the shipped
profiles and a minimal example lab (`examples/minimal/`) inside the package, so `hnx site validate`,
`hnx guests validate`, `hnx registry validate` and `hnx custom list` work without a checkout. An
editable install (`pip install -e .`) reads the same directories from the checkout instead. Every
lookup goes through `homelabnext/paths.py`: an explicit override (`HNX_SCHEMAS_DIR`,
`HNX_PROFILES_DIR`, `HNX_EXAMPLES_DIR`, or `HNX_DATA_DIR` for all three), then the packaged copy,
then the source tree; a miss prints every place that was tried. The top-level `schemas/`,
`profiles/` and `examples/` stay the single source of truth (the build copies them into the wheel,
and a test fails if the copy ever differs). The developer gates under `tools/` (`hnx schema-check`,
`hnx new` linting) still need a checkout.

`make check` is the one command CI also runs. It needs `ruff` importable as a module; pass
`RUFF=/path/to/ruff` if yours lives elsewhere. A fuller walkthrough (conformance against fakes, then
against containers) arrives with the lab-in-a-box stack.
<!-- quick-start:end -->

## Repository map

| Path | What is there |
|---|---|
| [docs/interfaces.md](docs/interfaces.md) | the index of contracts, Python interfaces and who owns them |
| [docs/checklist.md](docs/checklist.md) | what is done, what is public-now, what needs a server |
| [docs/adr/](docs/adr/README.md) | architecture decision records |
| `schemas/` | JSON Schemas (ids, events, records, registers, platform, OCSF subsets) with examples, negative cases and frozen baselines |
| `examples/` | synthetic lab: `services.yml` registry and example registers |
| `homelabnext/` | the Python package: registry, generators, ids, lake, notify, state, records, decide, golden, network, compute, customization, detections, registers, invariants, scaffolds, `cli.py` |
| `profiles/` | shipped optional customization profiles (inert until enabled; see [docs/customization.md](docs/customization.md)) |
| [docs/network-model.md](docs/network-model.md), [docs/compute-model.md](docs/compute-model.md) | the site/network and guest models |
| `ansible/` | role interface example roles, playbook and inventory |
| `detections/` | Sigma-subset rules, fixtures and the ATT&CK map |
| `tools/` | gates run by `make check` (schema check, endpoint gate, role lint, leak scan, SPDX, changelog) |
| `tests/` | unit tests, golden files, negative fixtures, cross-package integration tests (`tests/integration/`) |

## How it is meant to be adopted

Registry (names, not addresses) -> model-role aliases -> shared libraries -> conformance harness ->
role interface. Each step is useful alone; each makes the next swap cheaper. The swap procedure is
fixed in [ADR-0005](docs/adr/0005-swap-procedure-and-conformance.md).

## Decisions

Twelve architecture decision records live in [docs/adr/](docs/adr/README.md): schemas in git,
registry and DNS aliases, shared libraries, role interface, swap procedure, detections as code,
model roles, export hooks, bus placement, records lifecycle, the public/private split, and the
deliberately non-modular substrate.

## Contributing, security, conduct

[CONTRIBUTING.md](CONTRIBUTING.md) - [SECURITY.md](SECURITY.md) - [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) -
[CHANGELOG.md](CHANGELOG.md). Examples use only documentation values (`example.internal`,
`192.0.2.0/24`); `make leak-scan` enforces it.

## Licence

Apache-2.0, see [LICENSE](LICENSE) and [NOTICE](NOTICE). Every source file carries an SPDX header.
