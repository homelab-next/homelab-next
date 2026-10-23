# HomelabNext

What a homelab grows into after the first lab and the question "what can I do next?": a modular,
swappable security-and-AI platform in which every capability sits behind a contract, so any one
component can be replaced by a DNS flip and an adapter instead of a rewrite.

HomelabNext is **contracts, libraries and conformance tests**, not a platform, framework or product.
It gives you JSON Schemas, a service registry and generators, small shared client libraries with
in-memory fakes, a conformance harness, a role interface for Ansible, detections as code, register
generators and a swap kit. Everything runs on a laptop or a CI runner. Items that are not built yet
are listed as such in [docs/checklist.md](docs/checklist.md).

> **Status: pre-alpha.** Contracts, libraries and tooling now exist end to end: JSON Schemas
> (including pinned OCSF subsets), the service registry and generators, the role interface and
> linter, detections as code, register and invariant tooling, shared libraries with in-memory fakes
> (lake, notify, state, records, decision cascade, golden tasks), the site/network, guest/compute
> and customization models, the **swap kit** (`hnx swap`, parity tools), the **conformance harness**
> (`hnx conform`, 16 capability suites) and the **lab-in-a-box** compose environment. All of it is
> proven by unit tests, golden files and fakes on a laptop or CI runner. **Nothing has been tested
> on real hardware or against a live deployment**; the only thing that has run against real
> containers is the lab-in-a-box smoke test, on a laptop-class host. Parts that need a real server
> are tagged SERVER and ship an interface and a fake only. Expect breaking changes.

### What works today

* `hnx registry|site|guests validate` and `hnx gen`: check the synthetic lab and render artefacts
  from it (resolver config, Terraform, cloud-init, Ansible inventory, network configs) against goldens.
* `hnx conform list|run|mutants|report`: 16 capability suites run against a built-in fake, against a
  deliberately broken fake (every suite must catch its mutants) or against your own adapter named in
  a target file; `hnx conform report --json` lists capabilities without a passing test (invariant X-10).
* `hnx swap plan|start|status|advance|rollback|record`: the nine-step swap procedure with gates,
  hash-chained records, the registry flip and its exact inverse, dual-write and parity tools, and a
  decommission scan; proven end to end between two in-memory lakes.
* `hnx detections|registers|invariants|custom|schema-check`: detections as code, generated register
  pages, standing invariants (X-01..X-10 plugins), customizations, schema contract checks.
* `make lab-smoke`: a pinned Docker Compose stack within a 4 GB budget, checked service by service
  (needs Docker; the compose smoke on a laptop-class host is the only live test so far).
* `make check`: lint, tests, schemas, gates, detections, registers, SPDX, leak scan, changelog and a
  conformance coverage check that fails if any of the 16 capabilities lacks a passing test.

## The capabilities and their seams

| Capability | Seam (contract) | Conformance test |
|---|---|---|
| `lake-query`, `lake-catalog`, `object-store` | query results, table catalog, S3-style objects | `conformance/<capability>/` |
| `inference`, `fast-classifier` | OpenAI-compatible chat, model-role aliases | golden tasks, tool-call checks |
| `notify`, `events`, `orchestration`, `broker` | dedup-keyed send, event envelope, workflow, approvals | fixture events and table tests |
| `secrets`, `idp` | key issue and revoke, claim-to-role mapping | issue/expire/revoke checks |
| `cases`, `records`, `detections` | case round-trip, propose/approve/complete, Sigma + fixtures | lifecycle and fixture runs |
| `context` | scoped retrieval over the knowledge graph for agents | scope, inactive-record, ranking and stale-copy checks |
| `projects` | projects, steps and tasks under board rules, linked to strategy records by uid | board-rule, idempotency, version-conflict and change-feed checks |

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
make check          # lint, tests, schemas, gates, detections, registers, SPDX, leak scan, conformance coverage, changelog
hnx --help          # registry, new, gen, detections, registers, invariants, ids, decide, golden, site, guests, swap, conform, custom, schema-check
hnx registry validate examples/services.yml
hnx conform list                      # the 16 capabilities and their suites (needs a checkout)
hnx conform run lake-query --target fake
hnx swap plan                         # the nine steps, their gates and evidence
```

The package is not on PyPI yet; install the wheel attached to a [GitHub release](https://github.com/homelab-next/homelab-next/releases)
(`pip install ./homelabnext-<version>-py3-none-any.whl`). A wheel or sdist is self-contained: it carries the schemas, the shipped
profiles and a minimal example lab (`examples/minimal/`) inside the package, so `hnx site validate`,
`hnx guests validate`, `hnx registry validate`, `hnx custom list` and `hnx swap plan` work without a
checkout (the conformance suites, `compose/` and `tools/` stay in the source tree: from a wheel,
`hnx conform list` names the 16 capabilities and says no suite is installed). An
editable install (`pip install -e .`) reads the same directories from the checkout instead. Every
lookup goes through `homelabnext/paths.py`: an explicit override (`HNX_SCHEMAS_DIR`,
`HNX_PROFILES_DIR`, `HNX_EXAMPLES_DIR`, or `HNX_DATA_DIR` for all three), then the packaged copy,
then the source tree; a miss prints every place that was tried. The top-level `schemas/`,
`profiles/` and `examples/` stay the single source of truth (part of Veritas,
[ADR-0028](docs/adr/0028-veritas-single-source-of-truth.md); the build copies them into the wheel,
and a test fails if the copy ever differs). The developer gates under `tools/` (`hnx schema-check`,
`hnx new` linting) still need a checkout.

`make check` is the one command CI also runs; `make conform` runs every capability suite on its own. It needs `ruff` importable as a module; pass
`RUFF=/path/to/ruff` if yours lives elsewhere.

### Try it

The lab-in-a-box is a laptop-sized reference environment of real containers for the capability
seams (object store, Iceberg REST catalog with Postgres, a single-node query engine, an event bus,
secrets in dev mode, notifications) plus the project's own fakes (an
OpenAI-compatible inference server and a case system). It needs Docker with the compose plugin and
about 2 GB of free RAM (the stack is capped well inside 4 GB); every credential in it is a
throwaway placeholder from `compose/lab-in-a-box/.env.example`.

```bash
make lab-up       # build the fakes, start everything, wait until every healthcheck passes
make lab-smoke    # up, check each service end to end, run `hnx conform` if present, tear down
make lab-broker   # only the broker end to end: broker, hub and edge containers, the scenario, down
make lab-down     # remove the stack and its volumes
```

Inside the compose network each service answers on its registry alias, for example
`lake-query.svc.example.internal`; from your machine the ports are published on loopback only
(see `.env.example` to change them). The stack has no authentication and OpenBao runs in dev mode
with a known root token, so `make lab-up` and `smoke.sh` refuse a non-loopback `LAB_BIND` unless
`LAB_I_UNDERSTAND_UNAUTHENTICATED=1` is set and every credential has been changed. `smoke.sh` writes `build/lab-smoke/report.json`; the same
script runs in the scheduled `nightly` workflow, which never blocks a pull request. Without
Docker, `pytest tests/compose` still validates the compose contract (healthchecks, pinned images,
memory budget) and skips the parts that need a daemon. The architecture behind it is in
[docs/architecture.md](docs/architecture.md) and the build order in
[docs/build-order.md](docs/build-order.md).
<!-- quick-start:end -->

## Repository map

| Path | What is there |
|---|---|
| [docs/interfaces.md](docs/interfaces.md) | the index of contracts, Python interfaces and who owns them |
| [docs/checklist.md](docs/checklist.md) | what is done, what is public-now, what needs a server |
| [docs/adr/](docs/adr/README.md) | architecture decision records |
| [docs/private-overlay.md](docs/private-overlay.md) | the public/private split: a real lab in a private overlay repository, credentials in OpenBao, deploys dispatched by hand from an Actions Environment (skeleton: `examples/private-overlay/`) |
| `schemas/` | JSON Schemas (ids, events, records, registers, platform, OCSF subsets) with examples, negative cases and frozen baselines |
| `examples/` | synthetic lab: `services.yml` registry, example registers and the minimal example lab (`examples/minimal/`) |
| `conformance/`, `capabilities.yml` | the 16 capability suites (protocol, fake, broken twin, pytest glue), target files, and the list of capabilities the tree declares ([docs/conformance.md](docs/conformance.md)) |
| `compose/` | the lab-in-a-box reference environment (not shipped in the wheel) |
| [docs/agent.md](docs/agent.md) | agent profile compiler, context packs and the broker contracts (`hnx agent`, `schemas/agent/`, `schemas/broker/`) |
| [docs/swap.md](docs/swap.md) | the swap kit: record, gates, parity, flip, decommission |
| [docs/projects.md](docs/projects.md) | project management: projects, steps and tasks under board rules (`hnx projects`), the Projects hub page, OpenProject setup, strategy sync and change feed |
| `homelabnext/` | the Python package: registry, generators, ids, paths, lake, notify, state, records, decide, golden, network, compute, customization, conform, swap, parity, agent, broker, detections, registers, invariants, scaffolds, `cli.py` |
| `profiles/` | shipped optional customization profiles (inert until enabled; see [docs/customization.md](docs/customization.md)) |
| [docs/network-model.md](docs/network-model.md), [docs/compute-model.md](docs/compute-model.md) | the site/network and guest models |
| `ansible/` | role interface example roles, playbook and inventory |
| `detections/` | Sigma-subset rules, fixtures and the ATT&CK map |
| `tools/` | gates run by `make check` (schema check, endpoint gate, role lint, leak scan, SPDX, changelog) |
| `tests/` | unit tests, golden files, negative fixtures, cross-package integration tests (`tests/integration/`) |

## Scope: auditing and internal assessment

Everything this project says about auditing and assessment (detection tests, conformance checks
that try hostile inputs, prompt-injection evaluations, deliberately broken fakes: the project's
auditing tools) is internal assessment and validation by the operator, against the operator's own
lab and with the operator's authorization. Nothing in it targets, scans or probes systems the
operator does not own or run. [Terms and scope](docs/terms.md) defines the vocabulary; every agent
session's context pack carries it.

## How it is meant to be adopted

Registry (names, not addresses) -> model-role aliases -> shared libraries -> conformance harness ->
role interface. Each step is useful alone; each makes the next swap cheaper. The swap procedure is
fixed in [ADR-0005](docs/adr/0005-swap-procedure-and-conformance.md).

## Decisions

Twelve architecture decision records live in [docs/adr/](docs/adr/README.md): schemas in git,
registry and DNS aliases, shared libraries, role interface, swap procedure, detections as code,
model roles, export hooks, bus placement, records lifecycle, the public/private split, and the
deliberately non-modular substrate. Where a real lab lives (a private overlay repository read by
the same commands, credentials in OpenBao, deploys dispatched by hand from an Actions Environment) is
[ADR-0021](docs/adr/0021-public-and-private-repositories.md), with the full guide in
[docs/private-overlay.md](docs/private-overlay.md).

## Contributing, security, conduct

[CONTRIBUTING.md](CONTRIBUTING.md) - [SECURITY.md](SECURITY.md) - [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) -
[CHANGELOG.md](CHANGELOG.md). Examples use only documentation values (`example.internal`,
`192.0.2.0/24`); `make leak-scan` enforces it.

## Licence

Apache-2.0, see [LICENSE](LICENSE) and [NOTICE](NOTICE). Every source file carries an SPDX header.
