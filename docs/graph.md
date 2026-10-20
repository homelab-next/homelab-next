<!-- SPDX-License-Identifier: Apache-2.0 -->
# Knowledge graph

Everything in the repository that names something else -- the service registry, the conformance
suites and adapters, the schemas, the registers, the script catalog, the agent profiles and
keyring, the customizations, the Ansible playbooks and these pages -- as one typed graph, so a
task can pull in exactly what is directly related to it. `homelabnext.graph` builds it in about
a second. `hnx graph build` writes a local copy, `docs/graph/graph.json` (the data) and
`docs/graph/README.md` with one index page per node kind (navigation, e.g. for Obsidian's graph
view). That directory is **not committed**: nearly every change in the repository would make a
committed copy stale, so CI checks the graph's integrity instead, and `related` always builds fresh.

**Facts only.** Every edge is read from a field of a source file, and the edge's `source` names
the file and field. Nothing is inferred from prose similarity. Where names have to be matched (a
lesson's system tag against the registry, a command line against the script catalog) the match is
exact and documented with the reader that does it (`homelabnext/graph/sources.py`). Ids inside
code spans of a register's text are quoted literals, not references.

## Commands

```
hnx graph build                                # write the local docs/graph/ (gitignored)
hnx graph check                                # integrity (make check, CI, invariant L-05)
hnx graph related cap:lake-query               # ranked neighbourhood of a node
hnx graph related homelabnext/conform/adapters/openbao.py --depth 2 --json
```

`hnx graph check` **fails** on

* a dangling edge: an edge naming an id no source defines -- a lesson naming a runbook that does
  not exist, a page linking a missing page or file, a service depending on an unknown service;
* a duplicate id: two places defining the same node;
* with `--out DIR`, a stale, missing or orphan file in that directory.

It **reports**, without failing, orphan nodes (no edge at all) and lesson or runbook system tags
that resolve to no service, capability or product, each as a count and a list.

## Querying

The query functions are pure, over a loaded graph (`homelabnext.graph.load(path)` on a local build, or
`build(root)`):

* `neighbours(graph, ids, depth=1, edge_types=None, direction="both")` -- every node within
  `depth` hops, nearest first then by id;
* `related(graph, seeds, budget, weights)` -- at most `budget` nodes, ranked by distance, then by
  the product of the edge-type weights along the best path (`DEFAULT_WEIGHTS`; a weight of 0 is
  not followed), then by id. Every direct neighbour ranks above every two-hop node;
* `seeds_for(graph, paths=[], text="")` -- seed nodes for a task: the nodes defined by the files
  being edited (else the package owning them), plus what such a node implements or documents (an
  adapter file seeds its capability); and nodes whose id, bare name or multi-word title appears
  in the text as a whole word.

**Who calls the queries.** The context pack (`homelabnext.agent.knowledge`, profile `include:`
rules, `docs/agent.md` "Linked knowledge") calls `seeds_for` for `from: task` rules and `related`
for every rule, over a fresh `build(root)` with the access-bearing nodes the profile is not
granted removed; it reads review summaries to apply `require_reviews` and lists inactive records
as exclusions. `hnx graph related` is the same query on the command line.

**Inactive records.** A lesson or runbook whose `status` is `retired` (a pitfall fixed for good,
`retired_by` naming an invariant or test) or `superseded` (a practice replaced, `superseded_by`
naming the lesson that replaces it) or `incorporated` (a practice absorbed into a runbook or
system page, `incorporated_into` naming it; runbook steps cite it with `from_lessons`) is left out
of all three functions and of `hnx graph related` unless `include_inactive=True` /
`--include-inactive`: a retired lesson is history and must stop costing context tokens, and a
question about a system gets the runbook that now carries the knowledge, not the absorbed
lesson. The index pages list such records under **Archive**.

**Review provenance.** Lessons, runbooks and criteria carry `author` and a review summary in
their attrs when the record has them: `reviewed` lists the tiers whose most recent review passed
(`agent_check` -- an agent's `check` review; `challenge`; `human` -- a human review of any
role) and `review_count` counts the reviews. Reviewers are not nodes; the summary is there so a
context pack can prefer records with full human and challenge validation.

The registers are read through one function, `_register_entries(path)` in
`homelabnext/graph/sources.py`, so the record storage format can change in one place.

## Node kinds

| kind | id form | defined by |
|---|---|---|
| `svc` | `svc:<service>` | examples/services.yml services |
| `host` | `host:<host>` | examples/services.yml hosts |
| `zone` | `zone:<zone>` | examples/services.yml zones (also keyring network principals) |
| `product` | `product:<impl>` | registry impl; compose images |
| `cap` | `cap:<name>` | conformance list + extended suites, registry, capabilities.yml, tool_classes.yml, inventory cap_\* groups, profile provenance |
| `check` | `check:<cap>/<check-id>` | conformance/suites/&lt;cap&gt;.py SUITE.specs |
| `adapter` | `adapter:<module>:<factory>` | target files (conformance/targets, compose/\*/targets), client adapters a contract imports, each suite's make_fake |
| `compose` | `compose:<stack>/<service>` | compose/&lt;stack&gt;/docker-compose.yml |
| `schema` | `schema:<path>` | schemas/&lt;family&gt;/\*.json |
| `make` | `make:<target>` | Makefile rules |
| `ci` | `ci:<workflow>/<job>` | .github/workflows/\*.yml jobs |
| `pre-commit` | `pre-commit:<hook>` | .pre-commit-config.yaml hooks |
| `pkg` | `pkg:homelabnext[.<sub>]` | homelabnext/ packages |
| `script` | `script:<id>` | docs/scripts/catalog.json |
| `lesson` | `lesson:LL-NNN` | examples/registers/lessons.yml |
| `runbook` | `runbook:RB-NNN` | examples/registers/runbooks.yml |
| `inv` | `inv:<criterion>` | examples/registers/invariants.yml criteria |
| `system` | `system:<tag>` | lesson/runbook systems tags |
| `test` | `test:<path>` | a lesson's retired_by naming a test file |
| `profile` | `profile:<name>` | keyring sources' profile specs; keyring agent principals without a spec |
| `human` | `<issuer>:<subject>` | keyring human principals (broker approvers) |
| `skill` | `skill:<name>` | a compiled profile's provenance (parts library) |
| `persona` | `persona:<name>` | a compiled profile's provenance (parts library) |
| `mdl` | `mdl:<role>` | examples/model_roles.json roles |
| `mcp` | `mcp:<slug>` | tool_classes.yml mcp; registry mcp.name |
| `manifest` | `manifest:<id>` | context manifests found by the agent lint |
| `broker` | `broker:<manifest_id>` | the keyring sources' broker manifest |
| `action` | `action:<name>` | broker manifest actions |
| `custom` | `custom:<name>` | profiles/\*/customization.yml |
| `role` | `role:<name>` | ansible/roles/\* |
| `playbook` | `playbook:<name>` | ansible/playbooks/\*.yml |
| `doc` | `doc:<path>` | tracked Markdown pages (not tests, examples or docs/graph/) |
| `adr` | `adr:<slug>` | docs/adr/NNNN-&lt;slug&gt;.md |

## Edge types

| type | from | to | asserted by |
|---|---|---|---|
| `provides` | svc, compose | cap | registry capability; a compose service named after a cap |
| `runs` | svc, compose | product | registry impl; compose image |
| `runs_on` | svc | host | registry host |
| `in_zone` | host | zone | registry hosts.zone |
| `depends_on` | svc | svc | registry upstreams |
| `serves` | svc | zone | registry clients |
| `exposes` | svc | mcp | registry mcp |
| `implements` | adapter | cap | target binding, contract import, make_fake |
| `faked_by` | cap | adapter | suite make_fake |
| `for` | adapter | product | a compose stack's target file + that stack's image |
| `checked_by` | cap | check | suite specs |
| `loads_schema` | cap | schema | schema paths the contract's code loads |
| `refs` | schema | schema | $ref |
| `triggered_by` | script | make, ci, pre-commit, compose, script, pkg | catalog trigger |
| `enforces` | script | inv | catalog invariant |
| `reads` | script | any node owning the path | catalog inputs |
| `about` | lesson, runbook | system | systems tags |
| `resolves_to` | system | svc, cap, product | a tag exactly equal to the name |
| `operates` | runbook | svc | a systems tag resolving to a service |
| `controlled_by` | lesson | runbook, inv, lesson | an id in preventive_control |
| `mentions` | lesson, runbook | lesson, runbook, inv | an id in another text field |
| `verified_by` | lesson | script, pkg, make | verification.observable command |
| `invokes` | runbook | script, pkg, make | commands in step do/verify |
| `checks` | inv | script, pkg, make | observable command; plugin owner |
| `retired_by` | lesson | inv, test | retired_by |
| `superseded_by` | lesson | lesson | superseded_by |
| `incorporated_into` | lesson | runbook, doc | incorporated_into |
| `from_lesson` | runbook | lesson | from_lessons (runbook or step) |
| `uses` | profile, manifest | skill, persona, cap, mcp | parts, persona, skills, tools |
| `uses_model` | profile | mdl | model_role |
| `backed_by` | mdl | svc | model role bindings[].backend |
| `falls_back_to` | mdl | mdl | model role fallback |
| `defines` | broker | action | broker manifest actions |
| `grants` | profile, human, zone | cap, mcp, action, svc, broker | keyring principals[].grants (attrs: level, approval) |
| `applies_to` | custom | cap, svc, host | customization scope |
| `governed_by` | custom | adr | customization contract |
| `links` | custom, doc, adr | any | customization links; Markdown and `[[wiki]]` links |
| `documents` | doc | svc, cap | docs/systems/&lt;svc&gt;.md, docs/capabilities/&lt;cap&gt;.md |
| `targets` | playbook | cap | a cap_&lt;name&gt; hosts group |
| `applies` | playbook | role | play roles |

`grants` edges carry `level` (and `approval` when the grant needs one); `runs` edges from services
carry the registry `version`; `exposes` carries the MCP transport.

## Not in the graph (yet)

Detection rules (`detections/`), decision specs, golden tasks and workflow packs are not read;
the minimal example registry (`examples/minimal/`) is not either. Script `outputs` are prose in
the catalog, so there is no `produces` edge until the header has a structured field for it.
