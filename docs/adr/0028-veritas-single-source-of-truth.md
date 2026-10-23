# ADR-0028: Veritas: the single source of truth

- **Status:** accepted (the name and the rule; see Consequences)
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
2. **The rule for any file.** A file is part of Veritas when it is *authored* (no generator writes
   it) and a generator or a gate reads it as an input or as the standard to check against.
   - **Contracts and gates count even where they are code**: the capability protocols
     (`conformance/protocols/`), the conformance suites (`conformance/suites/`), the gates in
     `tools/` and the `--check` steps of `.github/workflows/ci.yml` and the `Makefile`. They define
     what conforms, so they are the standard, not a reader of it.
   - **All other code reads Veritas and is not part of it**: `homelabnext/` (apart from the data
     files named below), the adapters, the Ansible roles. Where a generator also reads code (the
     capability pages list adapters, the script catalog reads script headers), that code is an
     input and the output is still derived.
   - **Prose is not Veritas** (ADRs, guides, this page), except where a generator reads it as data:
     the tables of `docs/build-order.md` and `docs/checklist.md` feed the roadmap map (ADR-0018).
   - **`schemas/_frozen/` is written once** by `tools/schema_check.py --freeze` and is then
     authoritative history: append-only, checked against the base by `--base`.
3. **The public tier** is this repository's authored inputs. By the rule above it includes:
   - the JSON Schemas under `schemas/` with `schemas/_frozen/` (ADR-0001), and `capabilities.yml`;
   - the shipped `profiles/`;
   - the contracts and gates named in decision 2;
   - the Sigma rules (`detections/sigma/`, ADR-0006);
   - the workflow packs (`workflows/packs/`) and the StackStorm binding (`workflows/stackstorm.yml`);
   - the prompt templates and the injection corpus (`homelabnext/agent/prompts/`), the terms source
     (`homelabnext/agent/terms.md`) and the decision safety specs
     (`homelabnext/decide/safety_specs/`);
   - the fictional examples under `examples/`, which stand in for a site's private tier: the
     registry, the role tables, gateway and serving specs (`examples/model-serving/gateway.yml`,
     `serving.yml`, and the lab's `compose/lab-in-a-box/config/llm-gateway/gateway.yml`), the
     keyring sources, the MCP catalog and its render specs, the status views, registers and
     strategy records.
4. **The private tier** is one site's overlay repository (ADR-0021, `docs/private-overlay.md`):
   - under `lab/`: the service registry (`services.yml`), the site facts (`site.yml`), guests,
     registers, strategy records, customizations, the MCP catalog (`mcp/`), sealed files
     (`sealed/`, SOPS), and the module selection with its grants (`modules.yml`, ADR-0027, a draft
     schema);
   - the Ansible inventory (`ansible/inventory/production/`), its confidential variables in
     ansible-vault `vault.yml` files (ADR-0021 decision 3);
   - the deploy tools' pins, `locks/deploy.in` (the hash-locked `locks/deploy.txt` is compiled from
     it). The public commit a deploy uses, `HNX_REF`, is an Actions Environment variable, outside
     git;
   - secret **names** (`secret:<name>`). Secret values are not part of Veritas: they live only in
     the secret store (OpenBao), and the offline keys stay offline (ADR-0021 decisions 3 and 4).
5. **Every other copy is generated from Veritas or checked against it; a hand-edited copy is
   drift.** A page that mixes both kinds of text keeps them apart: its `hnx:gen` blocks are
   derived, its `hnx:todo` blocks are authored (`docs/systems.md`). Some Veritas files are also
   checked against each other without either being derived (`examples/status/views.yml` against
   its schema and the registry, by `hnx status views check`).
6. **The derived artifacts today, and what checks each** (only those that exist). A committed file
   that marks itself generated ("generated by ... do not edit" in its first lines, or a
   `generated_from` key) must appear here with its check: `tools/tests/test_generated_files_have_checks.py`
   fails otherwise. Derived files with no room for a marker (JSON gateway outputs, module schemas)
   and derived blocks inside authored files (Links blocks, `hnx:gen` blocks) are listed by hand.

   | Derived artifact | Generated from | Drift check |
   |---|---|---|
   | System SOP pages, `docs/systems/*.md` (generated blocks) | the registry | `hnx docs systems check examples/services.yml docs/systems` (CI) |
   | Capability reference pages, `docs/capabilities/` | contracts, suites, adapters | `hnx docs capabilities check` (CI) |
   | Module schemas, examples and negatives (`platform/module` and kin) | `homelabnext.schemas` generators | `python -m homelabnext.schemas --check` (CI) |
   | MCP client configs, `examples/mcp/clients/*/` | the MCP catalog, the render specs `examples/mcp/clients/*.yml`, the profiles | `make mcp-check` (CI) |
   | Agent keyring, `examples/keyring/keyring.json` | the files `examples/keyring/sources.yml` names: the registry, the agent profiles, the broker manifest | `hnx agent keyring check` (CI) |
   | LLM gateway config, `compose/lab-in-a-box/config/llm-gateway/` | role table, profiles, the lab's gateway spec | pytest `tests/generators/test_llm_gateway.py` (CI); `make gateway-check` (`make check`) |
   | LLM gateway config, `examples/model-serving/gateway/` | role table, profiles, gateway and serving specs | pytest `tests/models/test_serving_plan.py` (CI); `make models-check` (`make check`) |
   | vLLM instances, `examples/model-serving/vllm_server/instances.yml` | `examples/model-serving/serving.yml`, the model store, the role table | `hnx models serving check` (`make models-check`); pytest `tests/models/test_serving_plan.py` (CI) |
   | Register records' Links blocks | the records | `hnx registers links --check` (CI) |
   | Strategy index `docs/strategy/README.md` and Links blocks | the strategy records | `make strategy`; pytest `tests/strategy/` (CI) |
   | Script catalog, `docs/scripts/catalog.md` | script headers | `hnx scripts catalog --check` (CI) |
   | Detections ATT&CK map `detections/det_map.yml` and coverage report | the Sigma rules | `hnx detections map --check`, `coverage --check` (CI) |
   | Injection and model-evaluation golden reports | templates, corpus, pins | `agent injection run --check`, `golden pins check` (CI) |
   | StackStorm pack, `workflows/stackstorm/` | workflow packs and the binding | `hnx workflows st2 check`; pytest `tests/workflows/` (CI) |
   | Status source catalog `docs/status/sources.md` | the registry's status sources | `hnx status catalog check` (`make gates`); pytest `tests/status/test_status_views.py` (CI) |
   | Terms page `docs/terms.md` | `homelabnext/agent/terms.md` | `hnx agent terms --check` (`make gates`); pytest `tests/agent/test_agent_terms.py` (CI) |
   | The wheel's copies of `schemas/`, `profiles/`, `examples/` | the top-level directories | `tests/packaging/` (CI) |
   | Knowledge graph | the whole repository | never committed (`docs/graph.md`); `hnx graph check` checks integrity (CI) |
   | Maps (ADR-0018) | the site, guest, registry, dataflow models | never committed: rendered on request; goldens pin the renderer |
   | Registry artefacts (the registry's eleven generators: DNS zones, Caddy sites with the `hnx_forward_auth` snippet, scrape and probe targets, firewall matrix, ...) | the registry | never committed here: `hnx registry generate`, `hnx registry check REGISTRY DIR` compares an output directory; goldens in `tests/generators/golden/` |

7. **Records.** Strategy records are Veritas: ADR-0020 decision 5 makes "the strategy repository"
   their source of truth, which for a real lab is the overlay's `lab/strategy/` (ADR-0021; the
   public example is `examples/strategy/`). OpenProject is a one-way view of them: the sync upserts
   by uid, overwrites an edit made in OpenProject with the record and reports it, and never closes
   or deletes a record on its own (`homelabnext/projects/openproject/sync.py`). Project work items
   are held by the selected `projects` backend (ADR-0020 decisions 3 and 4), not by Veritas, even
   where the reference backend keeps them as files: they are operational state that changes as
   work moves, and nothing is generated or checked from them.
8. **Not yet enforced at deploy time.** Nothing compares Veritas with what actually runs. The
   loader's two-way check (every running unit, row, MCP server, agent, table and recovery pair has
   a manifest entry, and every entry a running thing) is **specified, not implemented**
   (ADR-0027, `docs/modules.md` "What the loader checks", item 4). Until it exists, Veritas is
   authoritative for what is committed and generated, not for what a host is running: a change
   made by hand on a host is invisible to every check above.

## Consequences

- A disagreement has one answer: the Veritas file wins, and the other copy is regenerated or
  fixed. A generator added later names its Veritas inputs and gets a `--check` step; for a file
  that marks itself generated, `tools/tests/test_generated_files_have_checks.py` fails until the
  table in decision 6 lists it with a check that exists.
- Docs can say "Veritas" instead of re-explaining the split; `docs/glossary.md` carries the term.
- **What acceptance covers.** This ADR accepts the **name** and the **rule** (decisions 1, 2 and 5).
  The tier contents (decisions 3 and 4), the table (decision 6) and the records (decision 7)
  describe what earlier ADRs decided, and every earlier ADR (0001 to 0027) is still proposed; those
  parts follow them as they change, and the module selection is a draft schema. ADR-0027 withholds
  its own acceptance until its loader and pilot have run; this ADR has no mechanism to run, and the
  enforcement it lacks is stated in decision 8 rather than waited for.
- `main` has no branch protection, so the CI checks in decision 6 are advisory until it does
  (ADR-0027 records the same limit).
- Deploy-time authority waits on the loader (decision 8): the follow-up is ADR-0027's item 9.

## Alternatives

- **Keep "source of truth" per subsystem, unnamed.** The status quo: each generator restates the
  rule, and nothing says which tier a fact belongs to.
- **Rename modules, commands and directories to carry the name.** Rejected now: several open
  branches touch those paths, and a rename would churn them all for no change in behaviour.
- **Make the secret store or a live system the source of truth.** A live system cannot be
  reviewed or diffed, and the secret store holds values only; both are checked against Veritas,
  not the other way round.
