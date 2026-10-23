# ADR-0028: Veritas: the single source of truth

- **Status:** accepted
- **Date:** 2026-10-23
- **Related:** ADR-0001 (schemas, `_frozen/`), ADR-0002 (the registry), ADR-0005 (conformance),
  ADR-0011 and ADR-0021 (the public/private split), ADR-0018 (generated maps), ADR-0020
  (OpenProject as a view), ADR-0022 (gateway config), ADR-0024 (MCP catalog), ADR-0027 (modules,
  the loader); [private overlay](../private-overlay.md), [systems](../systems.md),
  [modules](../modules.md), [glossary](../glossary.md)

## Context

The project already says "source of truth" in many places, each about one thing: the registry for
addresses (ADR-0002), the role table for model aliases (ADR-0007, ADR-0022), the MCP catalog for
client configs (ADR-0024), the strategy records for OpenProject (ADR-0020), the repository's
models for the maps (ADR-0018), `schemas/`, `profiles/` and `examples/` for the wheel's copies
(README). Read together they describe one rule, but nothing names the whole, so each new generator
re-argues it, and a reader cannot tell which of two disagreeing files wins. The operator decided
on 2026-10-23 to give the whole one name: **Veritas**.

This is a naming and definition decision. It renames no module, directory, command, schema id or
file.

## Decision

1. **Veritas is the project's single source of truth**: the authored, reviewed files every other
   copy is generated from or checked against. It has two tiers.
2. **The public tier** is this repository's contracts: the JSON Schemas under `schemas/`,
   including the append-only frozen baselines in `schemas/_frozen/` (ADR-0001,
   `tools/schema_check.py --base`); the shipped `profiles/`; the capability contracts
   (`conformance/protocols/`) and conformance suites (`conformance/suites/`, ADR-0005); the gates
   (`tools/` and the `--check` steps of `.github/workflows/ci.yml` and the `Makefile`); and the
   fictional examples under `examples/`, which stand in for a site's private tier.
3. **The private tier** is one site's overlay repository (ADR-0021, `docs/private-overlay.md`):
   the service registry (`lab/services.yml`), the site facts (`lab/site.yml`), guests, registers,
   strategy records, customizations, the MCP catalog (`lab/mcp/`), sealed files (`lab/sealed/`,
   SOPS), the module selection and its grants (`lab/modules.yml`, ADR-0027, a draft schema), and
   secret **names** (`secret:<name>`). Secret values are not part of Veritas: they live only in
   the secret store (OpenBao), and the offline keys stay offline (ADR-0021 decisions 3 and 4).
4. **Every other copy is generated from Veritas or checked against it; a hand-edited copy is
   drift.** A page that mixes both kinds of text keeps them apart: its `hnx:gen` blocks are
   derived, its `hnx:todo` blocks are authored (`docs/systems.md`). Code is not part of Veritas; it
   reads it. Where a generator also reads code (the capability pages list adapters, the script
   catalog reads script headers), that code is the input and the output is still derived.
5. **The derived artifacts today, and what checks each** (only those that exist):

   | Derived artifact | Generated from | Drift check |
   |---|---|---|
   | System SOP pages, `docs/systems/*.md` (generated blocks) | the registry | `hnx docs systems check examples/services.yml docs/systems` (CI) |
   | Capability reference pages, `docs/capabilities/` | contracts, suites, adapters | `hnx docs capabilities check` (CI) |
   | Module schemas, examples and negatives (`platform/module` and kin) | `homelabnext.schemas` generators | `python -m homelabnext.schemas --check` (CI) |
   | MCP client configs, `examples/mcp/clients/*/` | the MCP catalog and profiles | `make mcp-check` (CI) |
   | Agent keyring, `examples/keyring/keyring.json` | `examples/keyring/sources.yml`, the registry | `hnx agent keyring check` (CI) |
   | LLM gateway config, `compose/lab-in-a-box/config/llm-gateway/` and `examples/model-serving/gateway/` | role table, profiles, gateway spec | `make gateway-check`, `make models-check`; pytest `tests/generators/test_llm_gateway.py` (CI) |
   | Register records' Links blocks | the records | `hnx registers links --check` (CI) |
   | Strategy index `docs/strategy/README.md` and Links blocks | the strategy records | `make strategy`; pytest `tests/strategy/` (CI) |
   | Script catalog | script headers | `hnx scripts catalog --check` (CI) |
   | Detections ATT&CK map and coverage report | the Sigma rules | `hnx detections map --check`, `coverage --check` (CI) |
   | Injection and model-evaluation golden reports | templates, corpus, pins | `agent injection run --check`, `golden pins check` (CI) |
   | StackStorm pack, `workflows/stackstorm/` | workflow packs and the binding | `hnx workflows st2 check`; pytest `tests/workflows/` (CI) |
   | Status source catalog `docs/status/sources.md`, `examples/status/views.yml` | the registry | `hnx status catalog check`, `status views check` (`make gates`); the catalog also by pytest `tests/status/` (CI) |
   | Terms page `docs/terms.md` | `homelabnext/agent/terms.md` | `hnx agent terms --check` (`make gates`; pytest `tests/agent/`) |
   | The wheel's copies of `schemas/`, `profiles/`, `examples/` | the top-level directories | `tests/packaging/` (CI) |
   | Knowledge graph | the whole repository | never committed (`docs/graph.md`); `hnx graph check` checks integrity (CI) |
   | Maps (ADR-0018) | the site, guest, registry, dataflow models | never committed: rendered on request; goldens pin the renderer |
   | Registry artefacts (the registry's eleven generators: DNS zones, Caddy sites with the `hnx_forward_auth` snippet, scrape and probe targets, firewall matrix, ...) | the registry | never committed here: `hnx registry generate`, `hnx registry check REGISTRY DIR` compares an output directory; goldens in `tests/generators/golden/` |

6. **Records.** Strategy records are Veritas: ADR-0020 decision 5 makes "the strategy repository"
   their source of truth, which for a real lab is the overlay's `lab/strategy/` (ADR-0021; the
   public example is `examples/strategy/`). OpenProject is a one-way view of them: the sync upserts
   by uid, writes back and reports an edit made in OpenProject, and never closes or deletes a
   record on its own (`homelabnext/projects/openproject/sync.py`). Project work items are held by
   the selected `projects` backend (ADR-0020 decisions 3 and 4), not by Veritas.
7. **Not yet enforced at deploy time.** Nothing compares Veritas with what actually runs. The
   loader's two-way check (every running unit, row, MCP server, agent, table and recovery pair has
   a manifest entry, and every entry a running thing) is **specified, not implemented**
   (ADR-0027, `docs/modules.md` "What the loader checks", item 4). Until it exists, Veritas is
   authoritative for what is committed and generated, not for what a host is running: a change
   made by hand on a host is invisible to every check above.

## Consequences

- A disagreement has one answer: the Veritas file wins, and the other copy is regenerated or
  fixed. A generator or page added later names its Veritas inputs and gets a `--check` step.
- Docs can say "Veritas" instead of re-explaining the split; `docs/glossary.md` carries the term.
- Several inputs it names rest on proposed ADRs (0002, 0011, 0018, 0020, 0021, 0024, 0027); the
  definition follows them as they change, and the module selection is a draft schema.
- `main` has no branch protection, so the CI checks in decision 5 are advisory until it does
  (ADR-0027 records the same limit).
- Deploy-time authority waits on the loader (decision 7): the follow-up is ADR-0027's item 9.

## Alternatives

- **Keep "source of truth" per subsystem, unnamed.** The status quo: each generator restates the
  rule, and nothing says which tier a fact belongs to.
- **Rename modules, commands and directories to carry the name.** Rejected now: several open
  branches touch those paths, and a rename would churn them all for no change in behaviour.
- **Make the secret store or a live system the source of truth.** A live system cannot be
  reviewed or diffed, and the secret store holds values only; both are checked against Veritas,
  not the other way round.
