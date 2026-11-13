---
summary: 'Module manifest reference: a site''s module selection (draft platform/module_selection 1.0): hosts, slots, incumbents, bindings, grants and registry rows.'
summary_of: outline:sha256:8104a981a869101a
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
hosts:      {<name>: {guest: guest:<id>, isolated, resources: [{name: gpu0, kind: gpu}], headroom: {memory_mb}}}   # a guest record (below)
            # or a stand-in: {<name>: {kind, isolated, capacity: {cpu, memory_mb, disk_gb, gpu_memory_mb}, addresses, resources, headroom}}
slots:      {<slot>: [{provider, instance, placement: {<host role>: <host>}}] | none | pass-through}
incumbents: {<slot>: {service: <core registry row>, why}}   # served outside modules (below)
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
analyzer `writes` and `write: true` together, nor `writes` at a `red` ceiling, so its own-table
rule always carries a row filter (schema, loader and renderer). `lake_catalog` (required with the list) is the engine's name for the
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
- `procedures`: no `CALL` procedure for anyone. A table procedure (`ALTER TABLE ... EXECUTE`)
  passes file-based access control's own check; the query engine refuses it on a table with a
  row filter. Every rule below `red` has one, so only a `red` reader (whose rule has no filter)
  could run one, which is why an analyzer with `writes` must be below `red`;
- `queries`: everyone may run queries; seeing or stopping another's is not granted;
- `impersonation`: nobody may act as another user, so a signed-in reader cannot name a `red`
  reader as its session user ([engine sign-in](tlp.md#engine-sign-in)).

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

### Incumbents: slots served outside modules

A lab takes up modules one at a time, and until a module provides a slot something else already
serves it: a core role (the secret store, the broker, the events bus, the status hub) or a service
of the lab that predates modules. `incumbents` (optional) says so, per slot, by the core registry
row (`lab/services.yml`) that serves it:

```yaml
incumbents:
  secrets: {service: secrets, why: "the core's secret store role on the control-plane host"}
  orchestration: {service: orchestrator, why: "the lab's existing orchestrator, not yet a module"}
```

The loader judges each one against the registry it reads (`--services`, or the overlay's
`lab/services.yml`): the slot must be in the slot registry; it must not also be under `slots` (a
provider, `none` or `pass-through`: one answer per slot); the row must exist, its `capability` must
be the slot's name (a row of `edge-proxy` does not serve `edge`), and it must be its capability's
primary (an `eval`, `retiring` or `legacy` row serves no consumer, ADR-0039). Without a registry
every incumbent is a problem, never taken on trust. A selection that names a required core slot in
neither `slots` nor `incumbents` is the same error as before ("a required core slot has no
provider").

An incumbent counts as selected for a required core slot, for a module that requires or prefers the
slot, for a dataset's slot and for a service row's upstream (an authority upstream still needs
`grants.upstreams`). A required `instance` of an incumbent slot is, deliberately, the incumbent's
registry row name (for a provider it is the instance the site names; the two cannot collide, since
an instance may not take a core row's name). A `pass-through` stage next to an incumbent is
refused: the selection declares no formats for an incumbent, so the formats cannot be shown to
meet. It is never a
provider or an instance: `provider_for` refuses the slot with "served outside modules", `hnx
modules providers` lists it as an incumbent, and the registry's `impl:` for it is not compared.
Nor is it an egress target: `svc:<slot>` or `svc:<row>` is refused as no service, and `hnx modules
render` opens no path to it (DNS included, when `dns` is an incumbent), so a placed module role
reaches an incumbent only once the egress generator learns the registry's addresses, which is a
later change. Moving a slot from its incumbent to a module is a cutover-ledger step (ADR-0043) and
one selection edit that removes the incumbent and adds the provider, not a module swap (`hnx
modules swap-*` moves a slot between two modules; its check counts an incumbent as selected for
the incoming module's requirements, but a swap record cannot name an incumbent as its outgoing
side). A registry promotion that demotes an incumbent's row (ADR-0039) is caught by the next
check ("not its capability's primary"), so the `incumbents` edit goes in the same change.

Two limits to know: `hnx modules check` notes each selected module whose requirements reach an
incumbent (the egress render opens no path to it), and an agent lane binds only to a module
`orchestration` instance, so with `orchestration` an incumbent a module that contributes agents
cannot be bound yet ("lane ... bound to unselected instance"). `hnx modules providers` lists the
incumbents as declared; only `hnx modules check` judges them.

### Hosts that are guests

A site host is the guest it runs on. `hosts.<name>.guest` names that guest's `platform/guest`
record by id, and the loader reads it instead of trusting a copy:

```yaml
hosts:
  apps: {guest: guest:apps-01, headroom: {memory_mb: 512}}   # lab/guests/apps-01.yml
features:
  example-feature: {placement: {server: apps}}
```

`hnx modules check` and `render` read the guest records from `--guests DIR`, or with `--overlay`
from `DIR/lab/guests/`, with the guest loader `hnx guests` uses (the same schema, the same refusal
of a file whose name is not its id), and only when the selection references a guest. A host that
references a guest takes from it, before any other rule reads the selection:

- `kind`: the guest's `kind` (`vm`, `lxc` or `host`);
- `capacity`: `cpu` its `resources.cpu.cores`, `memory_mb` its `resources.memory.size_mb`,
  `disk_gb` the sum of its `resources.disks` (`gpu_memory_mb` 0: a role with a GPU footprint stays
  on a stand-in host for now);
- `addresses`: its `network.ip`, then `network.extra_addresses`, which the egress policy takes as
  the host's own.

So `kind`, `capacity` and `addresses` are not written beside `guest` (the schema refuses them);
`isolated`, `resources` and `headroom` are the selection's and go with either form. The footprint
sum, the slices and the egress policy then judge the guest's real size and addresses.

The loader refuses, each problem naming the host and the guest:

- a reference with no guest records read (neither `--guests` nor `lab/guests/`);
- an unknown guest, or one whose file fails the guest schema (`hnx guests validate` says why);
- a `retired` guest (a `live` or `planned` one takes a placement);
- a guest with no `resources`, whose capacity is unknown;
- one guest named by two hosts (its capacity would count twice).

And for each host role placed on a guest it refuses, naming the module, the role, the host and the
guest:

- a role `kind` of `vm`, `lxc` or `host` that is not the guest's (`any` takes every kind; an
  `external` role lands only on an external stand-in, as before);
- a footprint the guest cannot hold on its own: the role's `cpu` (vCPUs), `memory_mb` (against
  the guest's memory less the host's headroom) and `disk_gb`, times its `count`; the host's sum
  over every role on it is the footprint rule as before, the guest named beside the host;
- the role's guest requirements, which a manifest states on the role
  (`requires.hosts[].guest`): `capability`, a list the guest's own `capability` must be one of,
  and `baselines`, each of which must be among the guest's baselines (`baseline.names`, with every
  baseline they `extend` when the guest directory holds its baseline set, `_baselines.yml`). A
  role on a stand-in host has no guest to judge, so `hnx modules check` notes its requirements as
  not checked.

A role too big for its guest is named twice when it is the host's only occupant: once by the role
and once by the host's sum. A role with a GPU footprint on a guest host is refused with one line
saying so (a guest record holds no GPU memory yet). Every lab host's own address, a guest's or a
stand-in's (an `external` host aside), must be private or in `scope.trusted.nets`, since the egress
policy lets a role reach it and counts it as never the internet. The guest directory's files must
be its own regular files (a symbolic link is refused), and two files with one id refuse that id.

The selection names no hypervisor node, so a guest's `placement.node` is not judged; nor is a
guest's own validity beyond its schema (zones, firewall rules, backup), which is
`hnx guests validate`'s. The stand-in form stays for an external host and for a host with no guest
record (the public example profiles, whose labs ship none).

A provider's agents have one lane binding for the module, under `providers.<id>`: it covers every
instance the site selects of that provider (per-instance agent bindings would be a later, additive
field). A config value must be a key the module declares; a secret-typed value is a secret in the module's
own namespace or one granted to it in `grants.secrets`, the same rule as a manifest default.
A stand-in host's `capacity` stands in for a guest's `resources`; a host that references its guest
record takes them from it ([above](#hosts-that-are-guests)). A multi-slot provider is placed once per instance. At run time a
consumer resolves a slot with **`provider_for(slot, instance)`** from the selection
(`homelabnext.modules.providers.provider_for(site, mods, slot, instance)`: the serving module with
its product and licence, `None` for `none` or `pass-through`, and a refusal, never a guess, for a
slot the selection does not name, an instance it does not select, or several instances and none
named). `hnx modules providers --site FILE [--examples] [--overlay DIR] [--json]` lists every
selected instance that way. `hnx modules check` compares the core registry's `impl:` with it: a row
whose capability is a selected slot names the product (or an alias) of a provider selected for that
slot, and a row for a slot the site selects `none` or `pass-through` for is a problem; with the
repository's example registry (another lab) the comparison is a note. Nothing consumes it at run
time yet (`homelabnext/broker/cli.py` still reads a conformance target file), and the baselines'
`role` bindings are not compared. The registry is not generated from the selection (an operator
decision); its rows are checked against the modules instead
([below](#registry-rows-checked-not-generated)). Model choice stays one line in the role table.

### Registry rows: checked, not generated

The lab's registry (`lab/services.yml`) stays hand-written: it is the one file every generator
(DNS, proxy, monitoring, firewall) reads, and the operator chose to **check it for equality**
rather than generate it from the selection. So `hnx modules check` (and `render`, which runs the
same check) requires every service row a selected module contributes (`contributes.services`) to
appear in the lab registry **identically, as the site binds it**
(`homelabnext.modules.registry_rows`):

- a provider's row is keyed by its slot and becomes one row per instance the site selects of that
  provider for that slot, named by the instance, with `version` the provider's `product.version`
  (a provider's row never repeats it); a feature's or core module's row keeps its name;
- `host` is the module's host role in the contributed row; in the registry it is where the site
  places that role: the guest's name for a host that references a guest
  (`hosts.<name>.guest: guest:<id>` gives `<id>`, the key the guest registry fragment uses), else
  the site host's own name;
- every other field must be equal, whole values compared (a mapping or list is one value). Each
  difference is its own problem under `registry`, naming the row, the field, the module (and
  instance) and both values, with `(absent)` for a field one side lacks:

  ```text
  registry: services.notify-eval.port: example-notify (instance notify-eval) contributes 80 (its row notify), the lab registry has 8080
  registry: services.notify-eval: example-notify (instance notify-eval) contributes this row (its row notify), but the lab registry has no such row (copy it as the site binds it)
  ```

- three fields are the lab's own facts about a row, which a generic module cannot know:
  `standing` (ADR-0039: eval, retiring or legacy, with `until` and `why`), `backup_job` and
  `scope` (which only narrows what agents file about the service). The registry may add them;
  they are compared only when the module's row sets them. `clients` is **not** one of them: extra
  zones widen who may reach the service, so a registry that adds them differs from the module.
  So the overlay's copy of a module's row is the bound row plus, at most, these three (an eval
  instance beside the primary: the module's fields exactly, and `standing`);
- a provider's row never sets `version` (the loader refuses one that does), so the product's
  version is the only one there is;
- a host role the site places on no host is a problem of its own (the registry's `host` cannot be
  judged); the row's other fields are still compared. A `version` is compared as text, so an
  unquoted YAML version equals its quoted form.

The comparison runs only against the lab's own registry (the overlay's `lab/services.yml`, or
`--services`); with the repository's example registry, which describes another lab, the report
notes that the rows were not compared. The comparison is one-directional: only the selected
modules' rows are judged, and a registry row that no selected module contributes is the lab's own
and is not compared. Values in a problem are
printed as JSON (control characters escaped) and cut at 120 characters.
