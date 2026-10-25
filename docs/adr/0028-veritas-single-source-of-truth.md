---
summary: 'Veritas names the single source of truth: authored files a generator or gate reads as the standard or copy source; every other copy is generated or checked.'
summary_of: outline:sha256:2d17b354386bbaa7
---
# ADR-0028: Veritas: the single source of truth

- **Status:** accepted (the name and its two rules; see Consequences)
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
   copy is generated from or checked against. Today it has two tiers, public and private
   (decisions 3 and 4).
2. **The rule for any file.** A file is part of Veritas when it is *authored* (no generator writes
   it) and a generator or a gate reads it **as the standard, or as a source it copies from**, not
   merely as the subject of a check. A linter reading a role, or a leak scan reading a page, does
   not make the role or the page Veritas.
   - **Contracts and gates count even where they are code**: the capability protocols
     (`conformance/protocols/`), the conformance suites (`conformance/suites/`), the schema
     generators (`homelabnext/schemas/`, the one place the module schemas are written), the gates
     in `tools/`, and the `--check` steps of `.github/workflows/ci.yml` and the `Makefile`. They
     define what conforms, so they are the standard, not a reader of it. **A gate's configuration
     counts as part of the gate**: `pyproject.toml` (its test policy, `skip_reasons` and budgets),
     `.gitleaks.toml`, `tools/*.allow.yml` and the other gate allowlists and baselines,
     `MANIFEST.in`, and `ansible/inventory/example/hosts.yml` as `role_lint --inventory` reads it.
   - **All other code reads Veritas and is not part of it**: the rest of `homelabnext/`, the
     adapters, the Ansible roles. Where a generator also reads code (the capability pages list
     adapters, the script catalog reads script headers), that code is an input and the output is
     still derived.
   - **Tests.** A test module that is a drift check (decision 6 names them) is a gate. Everything
     else under `tests/` is test data, not Veritas: fixtures are inputs made up for one test, and
     goldens are generated snapshots that pin a renderer, regenerated when the renderer changes on
     purpose. The same holds for `conformance/fixtures/`. `conformance/targets/` (where a suite is
     aimed) is site configuration of the harness, not Veritas; the fakes in `conformance/fakes/`
     are code.
   - **Prose is not Veritas** (ADRs, guides, this page), except where a generator reads it as data:
     the tables of `docs/build-order.md` and `docs/checklist.md` feed the roadmap map (ADR-0018).
   - **`schemas/_frozen/` is written once** by `tools/schema_check.py --freeze` and is then
     authoritative history: append-only, checked against the base by `--base`.
   - **Append-only events count as authored**, whoever appends them. A record's `<uid>.events/`
     sidecar (ADR-0014) holds reviews, `value` readings appended by a tool and `transition` events
     written only by the decider; each file is written once, never regenerated and never edited,
     and the gates and the rollup read them as the record's history. They belong to the record's
     tier. What is derived is the state computed from them (a record's current status, a rollup).
3. **The public tier** is this repository's Veritas files. The lists below are examples of the
   rule, not a closed inventory; by the rule it includes:
   - the JSON Schemas under `schemas/` with `schemas/_frozen/` (ADR-0001), their authored examples
     and negatives, and `capabilities.yml`. Excluded: every file `python -m homelabnext.schemas`
     writes, which is exactly
     `schemas/platform/{module,lake_table,module_selection}.schema.json` and
     `schemas/platform/{examples,negative}/{module,module_selection,lake_table}.*`
     (`tools/tests/test_generated_files_have_checks.py` compares these globs with the generator's
     own output list);
   - the shipped `profiles/`;
   - the contracts, gates and gate configuration named in decision 2;
   - the detections (ADR-0006): the Sigma rules (`detections/sigma/`) with their fixtures
     (`detections/fixtures/`), the field mappings (`detections/mappings/`) and the pinned ATT&CK
     snapshots (`detections/attack_snapshots/`), but
     not the derived `detections/det_map.yml` and `detections/attack_coverage.json`;
   - the workflow packs (`workflows/packs/`) and the StackStorm binding
     (`workflows/stackstorm.yml`);
   - the prompt templates (`homelabnext/agent/prompts/templates/`) and the injection corpus
     (`homelabnext/agent/prompts/injection/corpus.yml`), the terms source
     (`homelabnext/agent/terms.md`) and the decision safety specs
     (`homelabnext/decide/safety_specs/`);
   - the fictional examples under `examples/`, which stand in for a site's private tier: the
     registry, the role tables, the model store, the gateway and serving specs
     (`examples/model-serving/gateway.yml`, `serving.yml`, and the lab's
     `compose/lab-in-a-box/config/llm-gateway/gateway.yml`; not the rendered `litellm/` and
     `bifrost/` beside them), the keyring sources, the MCP catalog and its render specs, the
     status views, the review policy (`examples/review-policy.yml`), registers and strategy
     records with their `.events/` sidecars. The derived files under `examples/` are the ones
     decision 6 lists.
4. **The private tier** is one site's overlay repository (ADR-0021, `docs/private-overlay.md`):
   - under `lab/`: the service registry (`services.yml`), the site facts (`site.yml`), guests,
     registers, strategy records, customizations, the MCP catalog (`mcp/`), sealed files
     (`sealed/`, SOPS), and the module selection with its grants (`modules.yml`, ADR-0027, a draft
     schema);
   - the authored part of the Ansible inventory: `ansible/inventory/production/group_vars/`, with
     confidential variables in ansible-vault `vault.yml` files (ADR-0021 decision 3). `hosts.yml`
     and `host_vars/` are Veritas only where a site writes them by hand; a site that renders them
     with `hnx guests render --target inventory` from `lab/guests/` holds a derived copy
     (decision 6);
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
6. **The derived artifacts today, and what checks each** (only those that exist).
   `tools/tests/test_generated_files_have_checks.py` is a heuristic backstop for this table: a
   tracked file whose first lines carry a marker comment ("generated ... do not edit", or a
   `generated_from` key) must match a row there that names a CI step or a CI-run test module. It
   does not see a derived file without such a marker. Those are listed here by hand: the JSON
   gateway outputs (`.../litellm/keys.json`, `.../bifrost/*.json`), the schema generators'
   output (decision 3), `docs/scripts/catalog.json`, the golden reports
   (`homelabnext/agent/prompts/injection/report.json`, `examples/model_roles.eval.json`,
   `detections/attack_coverage.json`), and derived blocks inside authored files (Links blocks,
   `hnx:gen` blocks).

   | Derived artifact | Generated from | Drift check |
   |---|---|---|
   | System SOP pages, `docs/systems/*.md` (generated blocks) | the registry | `hnx docs systems check examples/services.yml docs/systems` (CI) |
   | Capability reference pages, `docs/capabilities/` | contracts, suites, adapters | `hnx docs capabilities check` (CI) |
   | Module schemas, examples and negatives, every file `python -m homelabnext.schemas` writes: `schemas/platform/{module,lake_table,module_selection}.schema.json`, `schemas/platform/{examples,negative}/{module,module_selection,lake_table}.*` | `homelabnext/schemas/`, the example modules `examples/modules/*/module.yml`, the site profiles `examples/modules/sites/` and the module lake tables `examples/modules/*/lake/` | `python -m homelabnext.schemas --check` (CI) |
   | MCP client configs, `examples/mcp/clients/*/` | the MCP catalog, the render specs `examples/mcp/clients/*.yml`, the profiles | `make mcp-check` (CI) |
   | Agent keyring, `examples/keyring/keyring.json` | the files `examples/keyring/sources.yml` names: the registry, the agent profiles, the broker manifest | `hnx agent keyring check` (CI) |
   | Code Mode stubs and search index, `examples/codemode/<profile>/{types.d.ts,stubs.pyi,search.json}` (ADR-0031) | the example broker manifest `examples/broker/manifest.yml` and its handler documents | `hnx codemode gen --check` (`make gates`, CI) |
   | LLM gateway config, `compose/lab-in-a-box/config/llm-gateway/{litellm,bifrost}/` | role table, profiles, the lab's `gateway.yml` | pytest `tests/generators/test_llm_gateway.py` (CI); `make gateway-check` (`make check`) |
   | LLM gateway config, `examples/model-serving/gateway/{litellm,bifrost}/` | role table, profiles, gateway and serving specs | pytest `tests/models/test_serving_plan.py` (CI); `make models-check` (`make check`) |
   | vLLM instances, `examples/model-serving/vllm_server/instances.yml` | `examples/model-serving/serving.yml`, the model store, the role table | `hnx models serving check` (`make models-check`); pytest `tests/models/test_serving_plan.py` (CI) |
   | Register records' Links blocks | the records | `hnx registers links --check` (CI) |
   | Strategy index `docs/strategy/README.md` and Links blocks | the strategy records | `make strategy`; pytest `tests/strategy/` (CI) |
   | Script catalog, `docs/scripts/catalog.md` and `catalog.json` | script headers | `hnx scripts catalog --check` (CI) |
   | Detections ATT&CK map `detections/det_map.yml` and coverage report `detections/attack_coverage.json` | the Sigma rules and the ATT&CK snapshots | `hnx detections map --check`, `coverage --check` (CI) |
   | Golden reports: injection `homelabnext/agent/prompts/injection/report.json`, model evaluation `examples/model_roles.eval.json` | templates and corpus; model pins and golden suites | `agent injection run --check`, `golden pins check` (CI) |
   | StackStorm pack, `workflows/stackstorm/` | workflow packs and the binding | `hnx workflows st2 check`; pytest `tests/workflows/` (CI) |
   | Status source catalog `docs/status/sources.md` | the registry's status sources | `hnx status catalog check` (`make gates`); pytest `tests/status/test_status_views.py` (CI) |
   | Terms page `docs/terms.md` | `homelabnext/agent/terms.md` | `hnx agent terms --check` (`make gates`); pytest `tests/agent/test_agent_terms.py` (CI) |
   | The wheel's copies of `schemas/`, `profiles/`, `examples/` | the top-level directories | `tests/packaging/` (CI) |
   | Knowledge graph | the whole repository | never committed (`docs/graph.md`); `hnx graph check` checks integrity (CI) |
   | Maps (ADR-0018) | the site, guest, registry, dataflow models | never committed: rendered on request; goldens pin the renderer |
   | Registry artefacts (the registry's eleven generators: DNS zones, Caddy sites with the `hnx_forward_auth` snippet, scrape and probe targets, firewall matrix, ...) | the registry | never committed here: `hnx registry generate`, `hnx registry check REGISTRY DIR` compares an output directory; goldens in `tests/generators/golden/` |
   | Guest renders (`hnx guests render`, nine targets: terraform-proxmox, libvirt, cloudinit, inventory, registry-hosts, backup-jobs, firewall-rules, baseline-playbook, tailscale-acl) | the guests (with their nodes, policies, keys and baselines) and the site | never committed here; a site that commits a render (for example its inventory) owns the drift check; goldens in `tests/compute/golden/` |

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
  fixed. A generator added later names its Veritas inputs, gets a `--check` step and a row in
  decision 6; if its output carries a marker comment, the backstop test fails until it has both.
- Docs can say "Veritas" instead of re-explaining the split; `docs/glossary.md` carries the term.
- **What acceptance covers.** This ADR accepts the **name** (decision 1) and **two rules**: what
  counts as Veritas (decision 2) and that every other copy is derived from it or checked against it
  (decision 5). The examples inside those decisions, the tier lists (decisions 3 and 4), the table
  (decision 6) and the records (decision 7) are descriptive: they restate ADR-0001 to ADR-0025 and
  ADR-0027 (0026 is reserved and does not exist yet), every one of them still proposed, and they
  follow those ADRs as they change; the module selection is a draft schema. ADR-0027 withholds its
  own acceptance until its loader and pilot have run; this ADR has no mechanism to run, and the
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
