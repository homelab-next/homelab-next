<!-- SPDX-License-Identifier: Apache-2.0 -->
# Feature and provider modules: the module manifest

> **Draft for operator review** ([ADR-0025](adr/0025-feature-and-provider-modules.md), proposed).
> This page, the schema `platform/module` 1.0
> ([`schemas/platform/module.schema.json`](../schemas/platform/module.schema.json)), the fictional
> examples in `examples/modules/` and their contract tests
> (`tests/schemas/test_module_1_0.py`) exist. **There is no loader yet**: nothing reads a manifest at
> deploy time, no check compares contributions with what runs, and the product-name lint is
> specified here but not implemented. Everything this page says "the loader checks" is the
> specification for that next step.

## Why

A lab's products change often: a DNS server, a case manager, three project trackers, a classifier
swapped four times in ten days, models and agent runtimes, a lake query engine, an object store. The
operator's rule is that **a swap is a configuration change plus a conformance run plus a data
migration, never a code change in the core or in a feature.** Two things stand in the way today:

1. **Products live inside core code.** Adapters sit in core packages and are imported directly;
   CLIs construct a product by name; schema enums list products. Nothing marks where a product may
   appear, so nothing stops one leaking into shared code.
2. **The core keeps lists of features.** A recovery-pair table, a scheduler list, a preflight
   script, a topology generator's inline data, a lake maintenance list, runtime homes with one block
   per agent. A new feature edits six to ten of them; a cutover that edits twenty of twenty-two
   places makes no noise about the two it missed. A real cutover in the reference lab left a legacy
   timer armed beside the new one for three days and left the agent's production lane writing where
   no consumer read.

A **module manifest** fixes both: every product sits in a **provider module**, every optional
mission is a **feature module**, and each declares what it needs, what it offers and every entry it
adds to a registry the core builds. The core enumerates manifests; it keeps no list of its own.

## Words

| Term | Meaning |
|---|---|
| **slot** | A capability (`cap:<name>`): a contract (`conformance/protocols/<slot>.py`), a conformance suite and a fake. Where a standard interface exists the contract *is* that interface (S3, SQL, DNS, the OpenAI-compatible API, Markdown files with links). |
| **provider module** | Fills one or more slots with **one product**. The only place a product name may appear. |
| **feature module** | An optional, removable mission (the external data collector, a sandbox, publishing, ...). Names slots, model roles, interfaces and host roles, never products. |
| **interface** | Something a feature module offers *other modules* (a sample handoff, a publishable output). Named by what it carries, never by the module that offers it. |
| **interchange format** | The neutral format at a slot or interface boundary (OCSF events, Sigma rules, CloudEvents, the S3 API, ...). Naming it is what makes a swap testable. |
| **bundle** | A set of feature modules a site installs together (the SOC bundle), each still removable. |
| **site selection** | The private overlay's file that says which provider fills which slot, where each module's host roles land, and the real configuration values. |
| **core** | Everything that is not a module: the registry, the generators, the status hub, the invariants runner, the swap kit, the agent compiler, the broker. |

"Pack" is not used: it already means a workflow pack (`workflows/packs/`) and an agent context pack
(`homelabnext/agent/pack.py`). The status hub's `module` field on a status source is a display
grouping of tiles, not a module in this sense; a module's status sources default their hub `module`
to the module id (open question 9).

## Where modules live

```text
modules/<id>/module.yml           a module shipped with homelab-next (none yet: this is the target)
  python/hnx_modules/<id>/        its code, importable as hnx_modules.<id with - as _>
  roles/<role>/                   its Ansible roles (role interface v1, tools/role_lint.py)
  registry/ mcp/ agents/ prompts/ units/ invariants/ detections/ interfaces/ docs/ conformance/
                                  its declarative records, each of an existing record type
examples/modules/<id>/module.yml  the fictional examples (this draft)
<overlay>/lab/modules/<id>/       a lab's private modules
<overlay>/lab/modules.yml         the lab's site selection
```

The id equals the directory name and is the graph node `module:<id>`. A module's directory is the
unit of review, of removal and of the product-name lint.

## The manifest at a glance

```yaml
id: external-collector            # == directory name
kind: feature                     # or provider
title: / description: / owner: / status: draft|active|deprecated|retired (+ reason, replaced_by)
version: 0.1.0                    # the module's own version
bundle: {id: soc, group: threat-intel}           # feature only, optional
product: {name, display, aliases, version}       # provider only, required
licence: {kind, spdx|expires, tier, renewal}     # provider only, required
credentials: [{secret: secret:..., identity, purpose}]   # provider only
control_plane: [{kind, reader, description}]     # provider only: config a vendor holds
identifiers: [{kind: dns-name|vmid|bucket|..., name, on_remove}]
requires:  {capabilities, model_roles, interfaces, hosts}   # hard
prefers:   {capabilities, interfaces}                       # soft, each with a fallback
provides:  [one entry per slot] (provider)  |  {interfaces: [...]} (feature)
contributes: {roles, services, status_sources, notify_pairs, scheduler_jobs, lake_tables,
              preflight, mcp_servers, agents, tooling, invariants, entry_points, detections,
              workflow_packs, docs, shared_config}
data:      [{id, kind, description, export, import, retention}]
lanes:     {production: real, real: {writes}, shadow: {writes, compare_to}}   # feature only
config:    {<key>: {type, description, default, overlay: required|optional}}
lifecycle: {install, upgrade, remove: {playbook, export_first, audit: [planes]}}
author: / reviews:
```

One schema covers both kinds; `kind` switches the conditional fields, and every object is strict
(`additionalProperties: false`), so an unknown key is an error, not a silent no-op. References are
the repository's existing ids: logical ids (`cap:`, `svc:`, `mdl:`, `profile:`, `table:`, `det:`,
[`schemas/ids/`](../schemas/ids/README.md)) and graph node ids (`role:`, `status:`, [graph.md](graph.md)).
Contributed records are files of **existing** record types, never copies of their fields.

Full examples: [example-object-store](../examples/modules/example-object-store/module.yml) and
[other-object-store](../examples/modules/other-object-store/module.yml) (two providers of one slot),
[example-siem-suite](../examples/modules/example-siem-suite/module.yml) (one provider, four slots),
[example-static-host](../examples/modules/example-static-host/module.yml) (a provisional slot),
[external-collector](../examples/modules/external-collector/module.yml),
[example-sandbox](../examples/modules/example-sandbox/module.yml) and
[publishing](../examples/modules/publishing/module.yml) (features), and three site profiles in
`examples/modules/sites/`. All names and values are fictional.

## The two kinds

### Provider modules

A provider fills slots with one product, and is the **only** place that product's name may appear:
its manifest, its adapter code, its roles, its registry rows (`impl:`), its quirks.

`provides` is a **list**, one entry per slot, because an all-in-one product fills several (the
example SIEM suite fills `siem-source`, `hot-index`, `detections` and `notify`, so a single-box
site needs no lake for a first pass). Each entry:

| Field | Meaning |
|---|---|
| `slot` | `cap:<name>` |
| `adapter` | `package.module:factory`, the same form as a conformance target file's `adapter` ([conformance.md](conformance.md)) |
| `formats` | the interchange formats it speaks at that boundary |
| `features` | the contract's optional features it claims (`metadata`, `streaming`, ...), as the suite names them |
| `conformance.target` | a conformance target file in the module; its `features` must equal the entry's |
| `provisional` + `reason` | instead of `conformance`, when the slot has no contract yet (below) |
| `migration` | the slot's neutral export/import format and the roles whose `export`/`import` hooks write and read it |
| `calibration` | per (decision spec × provider) thresholds, maximum input length and calibration; they belong to the binding, never to the neutral spec |

The conformance **evidence** is the `homelabnext.conform.report/1` a run writes at install and at
every swap, kept in the swap record. It is never copied into the manifest, where it would go stale.

Provider-only top-level fields cover what real swaps showed the slot itself does not:

- `licence` (`kind`: open-source with `spdx`, or trial / subscription / commercial with `expires`,
  plus the `tier` the site relies on). An invariant warns ahead of `expires`: a lapsed licence is a
  forced swap, and in the reference lab one stopped case creation for two days before anyone noticed.
- `credentials`: every credential and identity the product holds or is given (API keys, service
  accounts, an identity-provider application), by `secret:` name. A swap issues the new provider's and
  revokes these; the decommission audit's `secret-names` plane looks for them afterwards.
- `control_plane`: configuration the product's vendor holds outside the repository (access rules,
  lifecycle rules, tunnel routes) and the code that reads it through the vendor's API for the
  conformance run. Nothing is copied into git.
- `contributes.shared_config` (either kind, mostly providers): a quirk the product needs in a shared
  component, such as a proxy header or a client timeout, as an entry that component's generator
  merges and that disappears with the provider. Never an edit to the shared component's own config.

### Feature modules

A feature is optional and removable. It names slots, model roles, interfaces and host roles, never a
product, and may not carry `product`, `licence`, `credentials` or `control_plane` (its own secrets
are `config` keys of type `secret`). It may belong to a bundle and may own agents with lanes.

### Bundles

A bundle is membership on the member: `bundle: {id: soc, group: threat-intel}`. We chose this over a
bundle record that lists its members, because a list is exactly what rule 5 forbids the core to
keep: removing a module would leave a stale entry in the bundle's list, and adding one would need an
edit somewhere else. With membership on the member, removal is self-contained and a site installs a
bundle by selecting every module whose `bundle.id` matches. Shared interfaces need no bundle-level
home: they are ordinary interfaces the members provide. Providers carry no bundle; they join through
the slots they fill.

The SOC bundle's groups: `detect-respond`, `threat-intel`, `purple-audit`, `exposure-management`.

## `requires:` and `prefers:`

`requires` is **hard**: without it the module does not install. `prefers` is **soft**: each entry
names a `fallback` with a `behaviour` and optionally a lighter slot to fall back `to`. Together they
make "what still works if I remove X" a computation, not a guess.

| Key | Entry | Notes |
|---|---|---|
| `capabilities` | `{cap, version, features, formats, instance, provisional, purpose}` | `version` is the contract's `MAJOR.MINOR` (same major, equal or higher minor). `instance` picks one of several providers of the slot. |
| `model_roles` | `{role: mdl:<role>, purpose}` | A role alias (ADR-0007); the model id is bound once, in the site's role table. |
| `interfaces` | `{interface, version, cardinality: one\|all, purpose}` | Never names the offering module. `all`: consume every selected provider (publishing). |
| `hosts` | `{role, kind, count, exposure, footprint, roles, purpose}` | By role, never by name; `kind: external` for a host outside the hypervisors. |

The external data collector **prefers** the lake (`lake-catalog`, `lake-query`) and falls back to the
detection suite's hot index, so it runs on the single-box profile; it prefers the detection engine
(its one Sigma rule simply does not run without it) and the SIEM data source.

**A requirement on a slot with no contract yet** sets `provisional: true`. It is recorded and checked
by name like any other, but no conformance run can prove a provider of it, so:

- a provider of that slot sets `provisional` + `reason` instead of `conformance`;
- a swap of that slot is attestation-only (the swap kit's `ManualBackend`, [swap.md](swap.md));
- the module may be `active`, and the hub shows the slot as "unproven";
- contract work on that slot is a dependency the manifest makes visible, which is the point.

Slots the examples mark provisional today: `siem-source`, `hot-index`, `agent-runtime`,
`exposure-management`, `static-hosting`.

### Footprint

Every host role carries a `footprint` (`cpu`, `memory_mb`, `disk_gb`, optional `gpu_memory_mb`). A
site sums the footprints of every module placed on each host and refuses a plan where the sum exceeds
the host's `memory_mb` less its `headroom_mb`. That is the lab-in-a-box rule
(`compose/lab-in-a-box/docker-compose.yml`, asserted by `tests/compose/test_lab_in_a_box.py`:
`mem_limit` values summed against a 3584 MB budget) generalised from one compose file to a site;
the contract tests apply it to the three reference profiles.

## `provides:` for features: interfaces

```yaml
provides:
  interfaces:
    - id: sample-handoff
      version: "1.0"
      kind: object-prefix          # object-prefix | event | lake-table | agent-handoff | records-prefix | service
      schema: interfaces/collected-sample.schema.json   # or schema_id: a shipped $id
      via: {cap: cap:object-store, prefix: samples/}
      formats: [...]
      description: ...
```

An `agent-handoff` interface is an [`agent/handoff`](../schemas/agent/handoff.schema.json) record
(G-04): reader, actor, output schema, broker actions. An `event` interface names an event type under
`schemas/events/`. The loader checks that every hard interface requirement is provided by exactly one
selected module (or, with `cardinality: all`, by any number), and that versions match like contracts.

## Interchange formats

A format names the boundary. The repository already pins several; align with them, never redefine:

| Format | Where it lives today | Used at |
|---|---|---|
| `ocsf` 1.3.0 | pinned class subsets in [`schemas/ocsf/`](../schemas/ocsf/README.md) (`x-lake`: table, key, time column, partition) | collect, move & shape, store; findings (`vulnerability_finding`, `detection_finding`) |
| `sigma` | [`detections/sigma/`](../detections/README.md), `det:` ids, `det_map.yml` (engine numbers live only there) | detect |
| `cloudevents` 1.0 | [`schemas/events/envelope.schema.json`](../schemas/events/envelope.schema.json) | respond (the bus) |
| `action-request` | [`schemas/broker/`](../schemas/broker/README.md) request records | act on hosts |
| `s3`, `sql`, `openai-compatible` | the object-store, lake-query and inference contracts | store, inference |
| `markdown-records` | the records lifecycle ([records](capabilities/records.md)) | understand, findings |
| `stix` 2.1, `sarif` 2.1.0 | **not in the repository yet** | triage, understand, assess |

`formats` on a requirement, a provider entry or an interface is `{format, version, schema_id,
classes}`. The conformance suite for a slot must test field **meanings** in that format, not only
that the provider answers: in the reference lab a feed move silently changed what a rule id meant,
and a split-horizon wildcard was caught only by a parity sweep.

### The SOC bundle, by pipeline stage

The SOC bundle is one bundle outside and one slot per pipeline stage inside, several providers per
slot, a neutral format at each boundary. "Contract today" means a protocol in
`conformance/protocols/` with a suite.

| # | Stage | Slots | Contract today | Boundary format |
|---|---|---|---|---|
| 1 | collect | `siem-source`, sensors (network, endpoint, cloud, the external data collector) | no (provisional) | OCSF events |
| 2 | move & shape | `log-pipeline` (aggregate, normalise, route); may be **pass-through** | no; `events` is the bus, not this | OCSF in and out |
| 3 | store | `object-store`, `lake-catalog`, `lake-query`; optional `hot-index` | yes (`object_store.py`, `lake.py`); `hot-index` no | S3, SQL |
| 4 | detect | `detections` (rule engine, correlation) | yes (`detections.py`) | Sigma |
| 5 | triage | `fast-classifier`, `ioc-enrichment`, intel lookup | `fast-classifier` yes (`classifier.py`); others no | STIX indicators |
| 6 | respond | `orchestration`, `cases`, `events`, `broker`; `soar` | yes for the first four; `soar` no | CloudEvents |
| 7 | act on hosts | `remote-admin`, always behind the broker's approval | no; the action record exists (`broker/request`) | action-request |
| 8 | assess | `exposure-management` (scanning, exploit research, patching, sandbox) | no | SARIF or the lake's findings (OCSF) |
| 9 | understand | `threat-intel`, CTI pipeline, deep research; `records` | `records` yes; the rest no | STIX + Markdown records |
| 10 | share | `static-hosting`, used only by the publishing module | no | a rendered static site |

**Carving the pipeline down.** A resource-constrained site selects fewer providers, not different
modules: one provider may fill several stages (the SIEM suite in
[single-box](../examples/modules/sites/single-box.yml)); a stage whose neighbours share a format may
be `pass-through` (the log pipeline when the sensors already emit what the store reads); a slot may
be `none` when every selected module only *prefers* it; and a module's `prefers.fallback.to` binds it
to the lighter slot (lake -> hot index; SOAR -> broker workflows; classifier -> none). Reference
profiles: [single-box](../examples/modules/sites/single-box.yml),
[small-lab](../examples/modules/sites/small-lab.yml), [full](../examples/modules/sites/full.yml).

## `contributes:` — what a module adds to core registries

The core builds each registry by reading every selected module's entries. **The core keeps no list.**
Each key's entries are records of an existing type in the module directory:

| Key | Record type | Replaces the central list |
|---|---|---|
| `roles` | an Ansible role, [role interface v1](role-interface.md), with its `role_interface` record | hand-kept role lists |
| `services` | rows of [`platform/service`](../schemas/platform/service.json) (`services:` map); `host` names a module host role | hand-kept registry rows; from these the generators already derive health checks, metrics targets, front-door routes, DNS, **topology and dataflow** ([ADR-0018](adr/0018-generated-maps.md)) |
| `status_sources` | `status:<id>` refs to sources declared on the module's own service rows | status collector lists |
| `notify_pairs` | **provisional inline** `{problem, recovery, sender}`: pairs are registered in code (`Notifier.register_pair`) today | a title-keyed recovery-pair dictionary |
| `scheduler_jobs` | a [`fleet_units`](role-interface.md) spec file, or a role timer's job id `timer:<role>/<name>` | a scheduler role's per-feature blocks |
| `lake_tables` | **provisional inline** `{table, schema_id\|schema, retention_days, maintenance, freshness}`; columns come from the table schema (`schemas/ocsf`, `x-lake`) | a lake-maintenance table list; and freshness judged against a table's own batch, not a fixed age |
| `preflight` | `{role, hook: readiness\|health}`: a role's own hook, never a function in a shared script | a preflight monolith with product branches |
| `mcp_servers` | a [`platform/mcp_server`](mcp-catalog.md) record | hand-kept client configurations per runtime home |
| `agents` | one block per feature agent (below) | ~15 definition sites per agent |
| `tooling` | tooling catalog records (hook, plugin, skill, agent, settings, instruction); **that design is proposed, not merged** | hand-written runtime settings |
| `invariants` | a criteria file in the [`registers/invariant`](../schemas/registers/invariant.schema.json) shape | criteria in one central register |
| `entry_points` | `{group, name, object}`, like `pyproject.toml` entry points | core dicts of adapters (below) |
| `detections` | a Sigma rule with its `det:` id ([detections.md](detections.md)) | rule numbers in charters |
| `workflow_packs` | a workflow pack ([workflows.md](workflows.md)) | — |
| `docs` | a Markdown page the docs index lists under the module | a hand-edited docs index |
| `shared_config` | `{target: cap:<slot>, file, reason}` | provider quirks inside shared config |

**What a module never contributes: authority.** Ceiling policies, broker manifest actions and
approvers, and the review policy are owned separately by design (docs/agent.md, ADR-0017). A module
that needs a broker action or a wider ceiling says so in its docs; the overlay's owner grants it.
`contributes.ceilings` is a schema error, on purpose.

**Entry points are the contribution pattern for code.** Today one group exists,
`homelabnext.invariants.checks` (`pyproject.toml`, [homelabnext/invariants/api.py](../homelabnext/invariants/api.py)).
The proposed groups replace the core's hand-edited registries one at a time:
`homelabnext.generators`, `homelabnext.status.collectors` (slot-named kinds such as `poll-metrics`,
with the product mapping in the provider), `homelabnext.compute.targets`,
`homelabnext.network.adapters`, `homelabnext.detections.backends`, `homelabnext.models.engines`,
`homelabnext.mcp.clients`, `homelabnext.conform.adapters` and `homelabnext.capabilities` (so
`capabilities.yml`, the conformance registry's list and `docs/interfaces.md` are derived from the
loaded manifests instead of kept three times).

**The check that makes a miss loud** (loader): every contributed file exists and validates against
its record type; contributed ids are unique across modules; and, in the other direction, every
running thing has a manifest entry (a unit, a registry row, an MCP server, an agent, a table, a
recovery pair the notifier saw) and every manifest entry has a running thing. That catches a partial
add (a new agent whose toolsets nobody registered) and an orphaned removal (a retired agent still
named by a tool config).

### Agents: one block

A feature agent is **one** `contributes.agents` entry, and everything a runtime needs is generated
from it: the compiled profile (through the separately owned ceiling policy), every runtime home's
tool wiring (through the MCP catalog and the proposed tooling catalog; in the controller, its grants
catalog and per-job homes are the existing seed for generating tool wiring from the profile), the
scheduler entry and timer, state paths, the recall roster and code maps.

```yaml
agents:
  - key: collector-analyst
    profile: profile:collector-analyst
    charter: agents/collector-analyst.md        # the one copy every runtime renders from
    spec: agents/collector-analyst.spec.yml     # hnx agent compile input
    model_role: mdl:main-reasoner               # never a model id
    needs:                                      # scoped grants on slots
      - {cap: cap:lake-query, access: read, scope: ['table:collector.sessions']}
      - {cap: cap:records, access: write, scope: [findings/external-collector/]}
    tools: [lake-query.query, records.write_note, collector-probe.status]   # slot-named
    prompts: {real: prompts/....real.yml, shadow: prompts/....shadow.yml}  # agent/prompt_template
    schedule: {on_calendar: '*-*-* 06:10:00 UTC', lanes: [real, shadow]}
    state: [cursor.json]
    roster: {recall: true}
```

**Tools are slot-named** (`<slot>.<tool>`): a profile grants `lake-query.query`, and the selected
lake provider's MCP server implements it. A product's tool name in a profile (today one lake
engine's query tool appears in most of the controller's profiles) turns every lake swap into a profile
edit across agents. **Staff agents** (the J-staff, the project manager, the RFI manager, the proposal
validator) belong to the agent runtime, not to a feature module; feature agents belong to their
module and leave with it.

### Lanes

```yaml
lanes:
  production: real                 # the lane consumers read
  real:   {writes: [findings/external-collector/, state/external-collector/]}
  shadow: {writes: [findings/external-collector-shadow/], compare_to: real}
```

This is the MCP catalog's real/shadow convention made a module property. The loader compares
`production`'s write prefixes with the scope the agent is granted and with what consumers read (the
interfaces other modules require), so a cutover cannot leave production writing where nobody reads.
Each agent needs a prompt per declared lane; a shadow lane is graded against `compare_to`.

## `data:` — what a module owns

```yaml
data:
  - id: sessions
    kind: lake-table               # lake-table | object-prefix | records-prefix | files | database | state
    table: table:collector.sessions
    export: {format: parquet, via: role:collector_receiver}
    import: {format: parquet, via: role:collector_receiver}
    retention: {days: 180}         # or {keep: forever} / {keep: transient}
```

Every owned dataset needs an `export` and an `import` in a **neutral format** (`parquet`, `jsonl`,
`csv`, `json`, `markdown-tree`, `object-tree`, `zone-file`, `sigma`), written and read by a role's
hooks, and a retention. Removal exports first (`lifecycle.remove.export_first`, default true).
"Start empty" after a swap is a recorded decision with a reason, never the default: the reference
lab dropped thousands of cases in one swap and abandoned a tracker's history in another.

### Slot-level export and import (rule 3)

Today **no contract defines export or import**; role `export.yml` hooks copy native formats or do
nothing, and there is no import hook. X-07 ("every stateful product's export hook exercised in a
restore drill") is keyed on products and always skips. The proposal:

1. Each stateful slot's protocol gains `export(dest) -> manifest` and `import_(src)` in the slot's
   neutral format: Parquet with OCSF columns for the lake; the object tree (keys, bytes, a JSONL
   listing of key, size, sha256, metadata) for the object store; JSONL plus Markdown for cases,
   projects and records; Sigma for detections; RFC 1035 zone files for DNS; encrypted key-value JSON
   for secrets; a JSONL message log for events; a JSONL job record (a superset of
   `agent.job.finished`) for orchestration, which today has **no** export at all.
2. Each suite gains a MUST round-trip check: export from one fake, import into a fresh one, compare.
3. Role interface v1.1 adds `tasks/import.yml` beside `export.yml`.
4. **X-07 becomes slot-keyed**: "every selected provider of a stateful slot passes that slot's
   export -> import round trip" — PUBLIC-NOW against the fakes, SERVER in a drill on the real
   providers. A provider's `migration.format` must equal the slot's declared format.

## `config:`

```yaml
config:
  ingest_token: {type: secret, description: ..., default: secret:collector/ingest-token, overlay: required}
  batch_every_s: {type: duration_s, description: ..., default: 900, overlay: optional}
  mode: {type: enum, values: [full, quiet], default: quiet, overlay: optional}
```

Types: `string`, `integer`, `boolean`, `duration_s`, `path`, `svc`, `secret`, `enum`. Defaults are
fictional and serve examples and tests; `overlay: required` means a real site must set the value in
its selection. A `secret` default is a `secret:` name, a `svc` default an `svc:` id, and a string
default may not hide a `secret:` reference. Client environment names are **slot-named**
(`OBJECT_STORE_ENDPOINT`, `LAKE_QUERY_URL`, `NOTIFY_URL`), mapped by the provider; a product-named
variable makes the variable itself a lock (the reference lab had one product's endpoint variables in
34 files and a notification default copied 68 times).

## `identifiers:` — state that outlives a product

Hostnames, DNS names, vmids, lake namespaces, buckets, IaC variables and secret names are **state**,
not code: renaming them is a migration of its own. Each is listed with `on_remove: release | keep |
tombstone`. `tombstone` means never reuse: in the reference lab a reused vmid made old backups
restore the wrong product. Identifiers are slot-named (`objects`, not the product's name), so a swap
keeps them.

## `lifecycle:`

`install`, `upgrade` and `remove` each name a playbook in the module. `remove.audit` lists the
[decommission](decommission.md) planes the removal must come back clean on, plus the proposed
**`contributions`** plane: every entry the manifest contributed (units, rows, pairs, MCP records,
agents, tables, criteria, docs) is looked for by id, and any still present is a `REMNANT`. A removal
also lists every dependant: a module that **requires** what is being removed blocks it; one that
**prefers** it is reported degraded, with its declared fallback behaviour. "None" is a choice with
consequences, and the dependants are told.

## Site selection: which provider fills which slot

Selection is site configuration in the private overlay (`lab/modules.yml`); the public repository
ships only the fictional profiles in `examples/modules/sites/`. The schema of this file is open
question 2.

```yaml
hosts:
  box: {kind: host, cpu: 8, memory_mb: 16384, disk_gb: 1000, headroom_mb: 2048}
slots:
  object-store:                    # several providers per slot: one per instance (a registry service)
    - {provider: example-object-store, instance: objects, placement: {store: data-core}}
    - {provider: other-object-store,   instance: samples, placement: {store: sandbox-core}}
  hot-index: none                  # valid only if no selected module requires it
  log-pipeline: pass-through       # valid only if neighbours share the format
features:
  external-collector:
    placement: {edge: collector-edge, receiver: data-core}   # module host role -> site host
    config: {edge_region: region-example-3}                  # the real values
```

At run time a consumer resolves its slot through **one** `provider_for(slot)` lookup over the
selection; the pattern already exists once, in `homelabnext/broker/cli.py`, which resolves the bus
through `load_target(target).binding("events")` instead of constructing a product. Today a dozen
places choose their product in code instead, for example: the notification sender
(`status/cli.py`), the event bridge (`workflows/cli.py`), the detection backend default
(`detections/cli.py`), the projects target choices (`projects/cli.py`), the secrets lookup
(`ansible/plugins/lookup/hnx_secret.py`), the front-door identity header defaults
(`status/agents/config.py`), serving engines (`models/serving.py`), MCP client runtimes
(`mcp/clients.py`), the swap rehearsal's candidate (`swap/rehearsal.py`), compute targets and network
adapters, and the generators that run whatever the site selected. Each becomes a `provider_for` call.

**Model choice is a role binding in exactly one place**: the site's role table maps `mdl:<role>` to a
backend; every profile, prompt and runtime home names the role. In the reference lab one model id
lived in about a hundred files across repositories, and backends were addressed by instance name in
a locality ladder rather than by gateway role.

## How a swap works, end to end

A swap is a **phased record**, never a one-shot edit. The swap kit already has the procedure and
the record ([swap.md](swap.md), `platform/swap_record`, nine gated steps); the manifest supplies its
inputs. Swapping the `samples` object store from `example-object-store` to `other-object-store`:

1. **Plan.** Change one line of the selection: `provider: other-object-store` for instance `samples`.
   The loader lists the dependants of that instance (the external data collector and the sandbox
   require it; publishing reads it) and the fields whose meaning may change, and opens a swap record.
2. **Conformance.** Run the slot's suite against the incumbent first (it must pass) and then the
   candidate's `conformance.target`. A MUST failure stops the swap. The suite tests the data plane and
   field meanings in the boundary format, not liveness.
3. **Dependants re-checked.** Every module that requires the slot is re-validated against the
   candidate's `version`, `features` and `formats`; every module that prefers it is re-checked too.
   A dependant that no longer holds blocks the cutover and is named. So are downstream consumers:
   scorecards, dashboards and invariants that read the incumbent (the reference lab kept a scorecard
   measuring a dead system for weeks).
4. **Migration.** Export from the incumbent in the slot's neutral format (`object-tree`), import into
   the candidate, then parallel-run and compare (dual-write and parity, swap kit steps 2 to 5) with a
   boundary check: production min, max and count across the cut.
5. **Cutover and rollback window** (steps 6 and 7): flip the registry row; the instance name and the
   slot-named identifiers stay, so consumers never change.
6. **Decommission audit** (step 8): the old provider's credentials revoked, its identifiers released
   or tombstoned, and `hnx decommission` plus the `contributions` plane clean, including the deploy
   chain (a real swap left the new product out of the full deploy) and defaults that still pointed
   at the dead product.
7. **Close** (step 9) with an ADR reference.

## The product-name lint (rule 1): specification

Modelled on `tools/no_raw_endpoints.py` (exit 0 clean, 1 findings, 2 usage or bad allowlist; a
census mode). Not implemented in this draft.

- **What counts as a product name:** every provider module's `product.name`, `product.display`
  (lower-cased, spaces as `-` and `_` variants) and `product.aliases`, from the tree and from the
  overlay when it is present; plus `tools/product_names.yml`, which lists products that have no
  provider module yet (today's real products in core code) and words that look like product names but
  are not (each with a reason).
- **Where a product name may appear:** inside a provider module's directory; in site configuration
  (the overlay's `lab/`, and the public example site data under `examples/`); in ADRs and the
  changelog; and in prose.
- **What is linted:** code, config keys and values, schema `enum`, `default` and `const` values, CLI
  defaults and choices, file and directory names, in the core (`homelabnext/`, `conformance/`,
  `schemas/`, `ansible/`, `tools/`, `generators/`) and in feature modules.
- **What is skipped:** comments, docstrings and Markdown prose. In the reference lab most product
  mentions in shared files are incident history in comments; a lint that flagged them would be muted.
- **Matching:** case-insensitive, bounded by non-alphanumerics (so `objects` does not match
  `objectstore`), with `-` and `_` treated alike.
- **Suppression:** only a path glob in the allowlist, each with a mandatory reason, plus a committed
  baseline of today's findings that may only shrink (the `dup_check` ratchet). No inline waiver.
- **Wired as** an X-criterion (Modularity pillar) and a `make check` gate, once the baseline exists.

The contract tests already apply the rule to the examples: no provider's product name occurs in a
feature module's directory or in a site profile.

## Core components declare `requires:` too

Cross-slot reach-ins exist inside the core: the approval gate reads classifier fields, lake retention
reads cases, the notification digest reads the detection data source. A provider swap must report
which *core* dependants still hold, not only which features. Core components therefore get the same
`requires`/`prefers` block (open question 3: a `core` kind, or a manifest per core package).
`schemas/platform/role_interface.schema.json` already defines `provides`/`requires` capability lists
per role but nothing reads it; the module manifest **generalises** it rather than inventing a
parallel shape. Each contributed role keeps its `role_interface` record, and the loader checks that a
provider's roles `provides` include its slots and that the module's `requires` include the union of
its roles' `requires`.

## Migration path (no code moves in this draft)

1. **Product-shaped code inside core packages** (about 28 adapter-shaped files) moves to provider
   modules, one slot at a time, each behind the existing contract and an entry point:
   `lake/trino*`, `lake/iceberg`, `lake/rest_catalog`, `lake/ddl` (lake providers);
   `projects/openproject/` (projects); `workflows/st2*` (automation); `detections/backends/`
   (detections); `status/products.py` (status collectors, renamed to slot kinds);
   `generators/builtin.py`'s front-door, metrics and identity renderers, and
   `generators/llm_gateway.py` (front door, metrics, identity, gateway providers); `models/serving.py`
   engines (inference); `compute/gen/` and `network/adapters/` (compute and network targets);
   `notify/senders.py` (notify); the `conform/adapters/*` adapters; and the secrets lookup's backend.
   Order: the slots whose contracts are standard first (object store, lake query, inference), then
   the ones with a single real adapter.
2. **Contracts that import from adapters** are inverted first: `conformance/protocols/inference.py`
   and `classifier.py` take their result types from adapter modules.
3. **Hard-coded selections** become `provider_for(slot)` (the list above).
4. **Central lists** become entry-point groups or contributions (the tables above).
5. **Agents**: each feature agent's ~15 definition sites collapse into its module's agent block; the
   controller's agent-runtime dependency moves behind an `agent-runtime` slot.
6. **The first pilot** is the external data collector (the highest proven cost of scatter), then a
   greenfield module born as one, then the sandbox (the first real inter-module interface).

## Contract follow-ups (per slot)

| Slot | Follow-up |
|---|---|
| `events` | The contract is shaped like one bus product (subject wildcards, message-id dedupe, redelivery limits); state it over CloudEvents with the bus semantics as features. The bus wire protocol is in the shared registry and HTTP layer. |
| `dns` | A custom zone API; make the contract the DNS protocol and RFC 2136 dynamic update, with zone files as export. Promote `dns`, `edge` and `backup` from EXTENDED to capabilities. |
| `idp` | A custom issue/verify/revoke; make it OIDC (discovery, JWKS, introspection). |
| `secrets` | Shaped like one vault product's KV with leases; keep the semantics, add a neutral encrypted export. |
| `lake-catalog` | A custom write-batch API; state the Iceberg REST catalog as the contract. |
| `records` | State "Markdown files with front matter and relative links" as the contract. |
| `inference`, `fast-classifier` | Move the result types out of the adapters. Expose generically the signals routing and admission use today through one engine's metrics: load, KV-cache pressure, progress, tool-call parse errors (`classify_error`), and the gateway request tag (today one gateway's header). Parser workarounds for one model belong to the provider, never in tool schemas. |
| `orchestration` | No export of job history; neutral JSONL job records. Store and API fields named after one runtime (`*_session_id`) become neutral. |
| `agent-runtime` | **New slot**: dispatch a job with a prompt, a tool grant and a deadline; report usage, exit reason, session id. The current runtime becomes its provider. |
| `metrics`, `siem-source`, `hot-index`, `soar`, `threat-intel`, `ioc-enrichment`, `remote-admin`, `exposure-management`, `static-hosting`, `compute`, `network`, `status`, `mcp-catalog` | No contract yet (provisional). Standards to start from: the Prometheus query API (metrics), OCSF (siem-source), STIX/TAXII (threat-intel, ioc-enrichment), SARIF (exposure-management). |
| every stateful slot | Export/import and a round-trip MUST check (above); every suite tests field meanings in its boundary format. |

## Open questions

1. **ADR number.** This draft takes ADR-0025, the next free number on `main`. The proposed tooling
   catalog design also planned to use 0025; whichever merges second renumbers.
2. **The selection's schema**: a `modules` block in site schema 1.3 (it is site configuration), or
   its own `platform/module_selection` 1.0 beside the site.
3. **Core components**: a third `kind: core` (required, never removable) with the same
   `requires`/`prefers`, or one manifest per core package.
4. **Module criterion ids.** Invariant ids are checklist rows (`^[A-Z]-NN$`); module criteria need a
   namespaced form (`<module>/<slug>`), which is a `registers/invariant` 1.1 change. The examples use
   `X-NEW` placeholders.
5. **Provisional inline records** (`notify_pairs`, `lake_tables`): promote each to its own record
   type, or keep them inline in the manifest.
6. **Slot declarations.** `platform/capability` (the capability descriptor) is where a slot would
   name its interchange formats, its pipeline stage and its export format; it also lists
   `implementations` by product name, which is a central list rule 5 forbids. Bump it to 1.1 with
   `formats` and `stage`, and derive `implementations` from provider manifests?
7. **External hosts.** `kind: external` (a cloud instance) has no compute model: its IaC, image
   bake, remote access and one-way data path need one.
8. **Exclusive resources.** Some providers cannot run together on one host or GPU; declare
   `exclusive_with` on a footprint, or leave it to the placement?
9. **The status hub's `module` field** (a tile grouping) shares the word; rename it (`group`), or
   define it as the module id by default?
10. **Where real modules live**: `modules/<id>/` in this repository for shipped providers and
    features, and `lab/modules/<id>/` in the overlay for private ones — confirm, and confirm the
    `hnx_modules.<id>` Python package convention.
11. **Licence probes**: a warning window ahead of `expires` (30 days?), and who it pages.
12. **Reviews**: should module manifests join `review-policy.yml` with their own tiers (provider,
    feature), as MCP records did?

## See also

[ADR-0025](adr/0025-feature-and-provider-modules.md) ·
[capabilities](capabilities/README.md) · [conformance](conformance.md) · [swap kit](swap.md) ·
[decommission audit](decommission.md) · [role interface](role-interface.md) ·
[MCP catalog](mcp-catalog.md) · [agent profiles](agent.md) · [private overlay](private-overlay.md) ·
[status sources](status/sources.md)
