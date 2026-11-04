---
summary: 'Module manifest reference: a site''s module selection (draft platform/module_selection 1.0): hosts, slot choices, bindings and grants.'
summary_of: outline:sha256:14c502670559e594
---
<!-- SPDX-License-Identifier: Apache-2.0 -->
# Modules: site selection

> Part of [the module manifest](../modules.md) ([[modules]]), the draft for operator review
> ([ADR-0027](../adr/0027-feature-and-provider-modules.md), proposed).

## Site selection (`platform/module_selection` 1.0, a draft schema)

[`schemas/platform/module_selection.schema.json`](../../schemas/platform/module_selection.schema.json)
(`x-draft`) is the shape; the three example profiles are its examples, and a misspelt or unknown
grant kind is refused rather than read as "no grants". Every cross-reference in it (a provider
fills the slot, an agent key exists, a grant is allowed, a config value is the module's own) is a
loader rule. Its own schema, beside the site model (profiles validate without a network model, and the selection
changes far more often than the site). Shape, as in the three profiles:

```text
profile: full
hosts:      {<name>: {kind, isolated, capacity: {cpu, memory_mb, disk_gb, gpu_memory_mb}, resources: [{name: gpu0, kind: gpu}], headroom: {memory_mb}}}
slots:      {<slot>: [{provider, instance, placement: {<host role>: <host>}}] | none | pass-through}
features:   {<module>: {placement, config, agents: {<key>: {lanes: {real: <orchestration instance>, shadow: ...}}}}}
core:       {<module>: {placement, config, agents: {...}}}   # core modules are always selected
providers:  {<module>: {agents: {...}}}             # a provider's agents (placement and config are per instance)
grants:     {publish: [...], egress: {<module>: {<host role>: [internet|external|svc:...]}},
             internet_facing: {<module>: [<host role>]}, secrets: {<reader>: [secret:...]},
             public_routes: {<module>: [<row>]}, shared_config: {<module>: [cap:idp|cap:edge|cap:remote-admin]},
             units: {<module>: [<unit>]}, upstreams: {<module>: [cap:broker|cap:idp|cap:remote-admin]},
             cloud_models: {<module>: [mdl:<role>]}}
scope:      {trusted: {wan, nets, tooling}, target, exclude: {unattended_mutation, offensive}}
lab_table_namespaces: [{namespace, why}]          # the lake namespaces that are the lab's own
tlp_readers: [{reader, ceiling, write?, why}]     # every lake reader's TLP ceiling (ADR-0033)
lake_catalog: <name>                              # the catalog their rules reach (with tlp_readers)
```

`tlp_readers` (optional) gives every reader of the lake its TLP ceiling (ADR-0033 decision 6; see
[TLP labels](tlp.md#tlp-labels-adr-0033)). A reader is `profile:<id>` (an agent), `module:<id>` (a
module's query consumer), `analyzer:<name>` (a platform analyzer), `user:<name>` or `group:<name>`
(people signing in to the query engine);
`ceiling` is a canonical label; `write: true` also lets it insert and delete, never update (an
update could rewrite a stored label), and only a `red` reader may write: a deliberate choice, since
a writer sees what it writes. The one exception is an `analyzer:<name>` reader (a platform
analyzer such as the novelty analyzer, ADR-0036, which amends ADR-0033 decision 6), which may
carry `writes: [<table>, ...]`: the declared analyzer-output tables it appends its own derived
rows to (today `novelty_finding`, in the core's `ocsf` namespace), `INSERT` only (no `DELETE` or
`UPDATE`), at any ceiling. The engine applies the row filter to an insert too, so it refuses a row
labelled above the analyzer's ceiling; a label set lower than the row's inputs it cannot see, so
the analyzer's code labels each row with the strictest label it read, and the grant is bounded to
appending to the named tables. No other kind may have `writes`, nor an
analyzer `writes` and `write: true` together (schema and loader). `lake_catalog` (required with the list) is the engine's name for the
lake catalog. With the list, the loader requires every selected module that requires or prefers
`cap:lake-query`, and every selected agent with a `cap:lake-query` need, to be listed (an unlisted
one would read nothing), and refuses a reader listed twice or a writer below `red`; without it,
and with lake readers selected, it notes that no row is filtered by its label.
`hnx modules render` writes `lake-access.json`, the query engine's file-based access rules
(`homelabnext.modules.lake_access`, first match wins):

- `catalogs`: each reader reaches `lake_catalog` only (read-only; a writer, or an analyzer with
  `writes`, all, which the table rules then narrow); every other
  catalog, the engine's own system catalog included, is `none`;
- `schemas`: nobody owns a schema through these rules; schema changes (a table created, the
  `tlp` column added) run under the lake's own administrator, outside this file;
- `tables`: per reader, the catalog's `information_schema` (metadata the engine narrows to what
  the reader may see), then every table, `SELECT` with the row filter
  `coalesce(tlp, 'red') IN (<labels at or below the ceiling>)` below `red` and no filter at `red`;
  a table without a `tlp` column cannot be read below `red` (the filter fails the query); an
  analyzer's `writes` tables come first, each `SELECT` and `INSERT` with the same filter;
- `procedures`: no `CALL` procedure for anyone. A table procedure (`ALTER TABLE ... EXECUTE`) is
  refused by file-based access control only on a table whose rule carries a row filter: every
  rule below `red` has one, an analyzer's own tables included, so only a `red` reader (whose rule
  has no filter) could run one;
- `queries`: everyone may run queries; seeing or stopping another's is not granted.

A principal matching several rules (a user in a group) gets the first, so user rules come before
group rules and each tier runs from the lowest ceiling up: the most restrictive applies, whatever
order the list was written in. One exception to "most restrictive": a principal that has an entry
of its own (`user:`, `profile:`, `module:` or `analyzer:`) is judged by that entry, even when it is also in a
group with a stricter one, because user rules come before group rules; give such a principal the
ceiling it should have in its own entry. A principal no rule names reads nothing. An operator step: the
lake-query adapter must sign each reader in to the engine as the user named by its whole reader id
(`profile:x`, `module:y`, `analyzer:novelty`, `user:alice`; an `analyzer:` is a platform
analyzer such as the novelty analyzer, ADR-0036), and a `group:` reader is the engine group named after the
colon. Any change to the list or the catalog is human-approve (`hnx site review-tier`).

`lab_table_namespaces` (optional) lists the lake namespaces that are the lab's own, outside every
module and the core (the full profile lists `archive` and `scratch`); the runtime check judges a
gathered table in any other namespace that no module id binds (see "Lake tables, from the catalog").
The loader refuses a namespace listed twice, the core's (`ocsf`), or a module id's (the id with `-`
read as `_`, any module the tree holds): listing one would let a table there pass as the lab's
instead of being judged as that module's or the core's; a module that was read and failed its own
validation counts too (one `discover` refused, a manifest it could not read, is reported there and
is not in the tree). In the private overlay, adding a namespace or dropping the list is
human-approve (`hnx site review-tier`); removing a namespace, changing a `why` or declaring the list
where it was absent (every other namespace is then judged) is owner, and a list that is not a list
of distinct `{namespace, why}` at either end (a `null` included) fails the gate.

A provider's agents have one lane binding for the module, under `providers.<id>`: it covers every
instance the site selects of that provider (per-instance agent bindings would be a later, additive
field). A config value must be a key the module declares; a secret-typed value is a secret in the module's
own namespace or one granted to it in `grants.secrets`, the same rule as a manifest default.
`capacity` stands in for the host's `platform/guest` `resources`, which a real selection references
by guest id instead of re-declaring. A multi-slot provider is placed once per instance. At run time a
consumer resolves a slot with **`provider_for(slot, instance)`** from the selection
(`homelabnext.modules.providers.provider_for(site, mods, slot, instance)`: the serving module with
its product and licence, `None` for `none` or `pass-through`, and a refusal, never a guess, for a
slot the selection does not name, an instance it does not select, or several instances and none
named). `hnx modules providers --site FILE [--examples] [--overlay DIR] [--json]` lists every
selected instance that way. `hnx modules check` compares the core registry's `impl:` with it: a row
whose capability is a selected slot names the product (or an alias) of a provider selected for that
slot, and a row for a slot the site selects `none` or `pass-through` for is a problem; with the
repository's example registry (another lab) the comparison is a note. Nothing consumes it at run
time yet (`homelabnext/broker/cli.py` still reads a conformance target file), the baselines'
`role` bindings are not compared, and the registry is not generated from the selection (an
operator decision). Model choice stays one line in the role table.
