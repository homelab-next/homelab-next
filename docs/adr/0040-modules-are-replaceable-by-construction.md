---
summary: Modules declare their state class, never touch another module's storage, label and collect what they create, and are replaced by one gated protocol.
summary_of: outline:sha256:a525f3d29d81eaf8
---
# ADR-0040: Make modules replaceable by construction

- **Status:** proposed
- **Date:** 2026-11-07
- **Related:** ADR-0002 (registry and capability aliases), ADR-0007 (model-role aliases), ADR-0009
  (the bus), ADR-0013 (the status hub over registered sources), ADR-0017 (approved broker
  actions), ADR-0033 (TLP ceilings and grants), ADR-0034 (SSO behind a neutral contract);
  this batch: ADR-0039 (one primary product per capability), ADR-0041 (versioned capability
  contracts), ADR-0042 (tested restores and cold start), ADR-0043 (the cutover ledger), ADR-0044
  (the broker carries the vault's lifecycle), ADR-0045 (per-principal, short-lived credentials),
  ADR-0046 (repository governance), ADR-0048 (verification beyond one reviewer), ADR-0049 (the SOC
  data plane and the lab's checks move as modules) and the ADR-0026 amendment;
  [modules](../modules.md), [data and lifecycle safety](../modules/data.md),
  [contributions](../modules/contributes.md), [how a swap works](../modules/swap-flow.md),
  [census](../modules/census.md), [decommission audit](../decommission.md), [swap kit](../swap.md)
- **Depends-on:** ADR-0027
- **Amends:** ADR-0004, ADR-0005, ADR-0008, ADR-0025, ADR-0027

## Context

ADR-0027 promises that a swap is "a configuration change, a conformance run and a data
migration, never a code change". The machinery for the first two exists: slots, manifests, the
loader, the census, the product-name lint, the swap record 1.2 rules and the canary-gated
model-role rebind (`hnx modules swap-check` and `swap-gate`, evidence read from the base commit).
The third, and the clean removal that must follow it, does not. A drop-in audit of `main` and of
the lab the overlay was translated from found five gaps, each of which today turns a replacement
into hand work.

**State is not classified, and some of it is not even seen.** A manifest's `data:` lists datasets
(`lake-table`, `object-prefix`, `records-prefix`, `files`, `database`, `state`), each with
`export` and `import`, but nothing says whether a module holds state at all, and nothing ties a
volume on a host to a declared dataset. The role interface's `restore` hook (ADR-0004 decision 1)
restores from `<role>_restore_source` but states no consistency method; the module lifecycle has
only `install`, `upgrade` and `remove`. The generic `compose_app` backup hook writes a list of
*absolute bind-mount sources* plus the data root, so a named Docker volume, which the same role
accepts without any bind root, is in no backup manifest; its restore hook copies a directory back,
a cold copy that is not consistent for a running database. Across the lab, backup is guest-image
only: no application-consistent dump exists in any role source.

**Modules read each other's storage.** In this repository the status hub opens the orchestration
telemetry SQLite file directly, as another user (`homelabnext/status/cli.py`, `_orchestration_site`
→ `TelemetryStore(..., read_only=True)`), and `homelabnext/orchestration/store.py` shapes its
journal mode around that reader. In the lab the overlay came from, scripts open a task-board
app's SQLite file in its container volume, a notifier's cache database (twice), the agent
controller's database (four readers, one of which also **writes** to it), and run a SQL client
inside the previous IdP's database container. Each pins a product's private schema and volume
path; any of them blocks replacing that product. The counter-example already exists: the gateway
turn source reads LiteLLM's spend-log API with a viewer key, explicitly not a database grant
(`homelabnext/conform/adapters/litellm_spend_log.py`).

**What a module creates elsewhere is not collected.** The realm generator makes one OIDC client
per `auth: idp` service row, labelled only `description: owner <owner>`; DNS aliases come from
the registry (ADR-0002); the egress generator writes nftables per host; fleet units, lake tables,
secrets (`secret:<id>/...`) and MCP records are bound to the module id by name. Contributed alert
rules and dashboards are "a follow-up contribution key" (`docs/modules/contributes.md`). The census
already catches leftover units, service rows, MCP servers, agents and lake tables
(`INVENTORY_KINDS` in `homelabnext/modules/loader.py`), plus notify pairs, but nothing removes an
SSO client, a DNS record, a firewall rule, a secret's value or policy, a dashboard or an alert
rule. The decommission planes in `homelabnext/decommission/planes.py` are read-only probes keyed by
guest ("`plan` prints these; nothing here executes"), and the `contributions` plane that every
example manifest lists in `lifecycle.remove.audit` is "specified, not implemented": the loader
accepts the name (`AUDIT_EXTRA_PLANES`) and no plane reads it.

**Consumers can still be tied to a product by name.** The product-name lint reads code, YAML and
JSON, but skips site configuration and prose by design. The names consumers actually address are
born in site configuration: a service row's name becomes its DNS alias, its OIDC `clientId` and
the name of its client-secret reference in the secret store. A row named after its product therefore
puts the product into DNS, into the IdP and into the secret store, and the lint never sees it. The
naming audit found product-named service ids and secret names in both the example data and the
overlay.

**There is no general replace protocol and no neutral exit format.** The swap kit (`hnx swap`,
nine steps from `declare` to `close`) flips a network route; the model-role rebind gates an
inference swap on a pinned, live evaluation of the new binding. Every capability has a suite and a
fake, but **no core capability protocol has an `export` or `import_`**: only the extended
`migration` protocol does (`conformance/protocols/migration.py`), and the import-validation suite
runs only the reference importer labelled as each stateful slot (`MIGRATION_PROOF` in
`tests/modules/test_import_validation.py`). ADR-0027 decision 8 and its follow-up 11 are not done.
`docs/modules/follow-ups.md` already commits `secrets` to "a neutral encrypted export", and
nothing implements it.

## Decision

1. **Every module declares its state class, and the loader refuses state nobody declared.**
   - The draft `platform/module` schema gains a required top-level `state`, one of exactly four
     names: `none` (no persistent data anywhere), `git` (everything it needs is in its directory
     or the overlay: rendered config, rules, content), `platform` (all its data lives in platform
     slots whose contract is the canonical schema: `lake-table` with a `platform/lake_table`
     record, `object-prefix`, `records-prefix`), or `private` (it also keeps `files`, `database`
     or `state` datasets on its own host). A rebuildable view (decision 7) is `private`. The
     schema is `x-draft`, so it changes in place (ADR-0027, Consequences). Other ADRs name a
     state class only by these four names.
   - `homelabnext.modules.rules` gains `state_problems`: `none` or `git` with any `data:` entry is
     refused; `platform` with a host dataset is refused; `private` without one is refused.
   - **This ADR owns the requirement; ADR-0042 owns the method.** Every `private` dataset must be
     covered by an entry of the `recovery` block on its registry row (ADR-0042 decision 2, which
     owns the method vocabulary, its one declaration site and the rule for when a cold copy is
     allowed). The dataset names its entry (`recovery: <entry>`); `state_problems` refuses a
     `private` dataset no entry covers, and an entry that covers no declared dataset. The one
     exception is a dataset carrying `view_of` and `rebuild_from` (decision 7): it may declare
     `recovery: rebuild` instead, with no backup, because its restore is the rebuild.
   - **The loader refuses an undeclared persistent volume.** Statically, `hnx modules check` reads
     each module role's container spec and unit paths: a named volume, a bind source or a
     `read_write_paths` entry that is not under the module's data root
     (`/var/lib/hnx-modules/<id>/<dataset>/`, the root `homelabnext.modules.limits` already caps)
     or that no dataset names is a problem. A spec the loader cannot resolve to concrete mounts
     (an unresolvable Jinja expression, a variable with no default in the role) is a problem and
     is refused, never skipped. At run time the census gains a `volumes` kind (the mounts and
     named volumes under each placed host's data roots, names only, never contents), and
     `running_problems` flags one that no selected module declares; it is the backstop for what
     the static check cannot see, and a host that was not gathered stays in `not_gathered`.
   - **One backup hook contract, owned by ADR-0042.** The `backup` hook's contract (dumps plus a
     manifest, ADR-0042 decision 2) gains this ADR's clause: the manifest names every named
     volume and bind source the role mounts, so nothing a role persists is outside it.
   - **Backup and restore join the module lifecycle.** `lifecycle` gains `backup` and `restore`
     playbooks, required for `state: private`. Role interface 1.1 gains the `import` hook
     (ADR-0027) and gives the existing `backup`/`restore` hooks (ADR-0004 decision 1) the declared
     method of their `recovery` entry; `lifecycle.backup`/`restore` call them. ADR-0042 drills
     them.

2. **No module reads or writes another module's storage.** Integration is through a slot's API,
   an event (ADR-0009) or the lake, never a file, socket, container or database another module
   owns.
   - The loader refuses any path a module role mounts, binds, names in a unit or passes to a
     contributed command that lies in another module's data root, and the role lint refuses a
     task that executes inside another module's container (`docker exec`, `community.docker`
     exec modules) or opens a client against a `database` dataset it does not own. A `database`
     dataset's port is never a service row another module may require, so the egress generator
     opens no flow to it.
   - **Data leaves a module only through its own hooks.** Its `backup` hook writes a consistent
     dump into its own data root or hands it to the `backup` slot's API, so the backup provider
     never mounts another module's root. The census reads mount names only, never contents. Any
     other exception (the swap and parity tools ADR-0033 already grants) is an overlay grant with
     a reason (ADR-0027 decision 6), never a loader exemption.
   - Today's violations and their fixes:

     | Violation | Fix |
     |---|---|
     | The status hub opens the telemetry SQLite file (`--orchestration DB`) | The telemetry store's owner serves a read-only status source registered in the registry (ADR-0013); the hub reads it like any other source. This replaces the arrangement in which the hub opens the store directly (ADR-0025 decision 5). `--orchestration` stays for one release as a deprecated alias, then goes, and the store's journal-mode accommodation for a foreign reader with it. A test fails if any status code path opens a SQLite file outside its own state directory. |
     | A task-board sync opens the board app's SQLite in its volume | The board is a view of the `projects` capability (ADR-0020) through its adapter; the legacy board retires under ADR-0039. |
     | A notification digest and a delivery heartbeat read the notifier's cache database | The notifier emits a delivery event per message (ADR-0009) into the lake; the digest is a lake query, and the heartbeat is a canary send through the `notify` contract. |
     | Fleet-health, detection-latency, failed-job and duration reports read the controller's database, one also writing to it | They read the `orchestration` contract's job records and the `agent.job.finished` events (ADR-0025) in the lake; the write becomes a controller operation through the broker (ADR-0030). |
     | An identity inventory runs SQL inside the previous IdP's database container | It retires with that IdP (Keycloak is the single SSO). The inventory reads users, groups and clients (names and attributes only, no credentials) through the provider module's read-only admin view, the same read decision 3's census uses, or reads the realm the registry renders. It never reads an `idp` export. |

     The lab-side rows are carried as rows of the cutover ledger (ADR-0043) and rebuilt as modules
     under ADR-0049; none of them is ported as written.

3. **Everything a module creates elsewhere is generated from its manifest, labelled with its id,
   and collected when it goes.**
   - **Generated**: an object outside the module's directory exists only because a generator
     rendered it from a selected module's manifest or rows. The contribution keys gain
     `dashboards` and `alert_rules` (closing the follow-up in contributes.md).
   - **Labelled**: each kind has one label carrier, kept in `homelabnext.modules.labels`
     (`CARRIERS`), and a test refuses a contribution key or generator output kind without one:
     SSO clients an `hnx.module` client attribute; DNS records a managed-record ownership marker
     the `dns` provider keeps; firewall rules a per-module chain and an `hnx:<id>` rule comment;
     secrets the existing `secret:<id>/` namespace plus a metadata key; dashboards a tag; alert
     rules an `hnx_module` label; lake tables the `table:<id_>.` namespace; timers the bound unit
     name. A generator test asserts every rendered object of a module carries its id.
   - **Labels are stamped by generators only.** A manifest or contributed file that itself
     carries a label key (`hnx.module`, `hnx_module`, an `hnx:` comment, the DNS ownership marker)
     is refused by the loader. Reconcile deletes only an object whose label matches the module
     **and** that the previous render produced (compared against the base commit's render), so a
     forged label or a hand-edited object cannot get another object deleted.
   - **Reserved owners.** Objects the core or the overlay own carry the reserved labels `hnx:core`
     and `hnx:site`, stamped by their generators. A provider module lists its product's built-in
     objects (default clients, default chains, the zone's own records) as `builtin`. Only an
     object with none of these labels and no `builtin` entry is a problem, so a break-glass
     client the overlay renders or a provider default is not a standing red.
   - **Collected**: the census gains the kinds `sso_clients`, `dns_records`, `firewall_rules`,
     `secrets` (names and metadata, never values), `dashboards` and `alert_rules`, read through
     the owning provider's read API (an IdP's admin read lives in its provider module; platform
     code still depends on OIDC only, ADR-0034 decision 1). The identity for these reads is a
     read-only scoped role per kind (a client view on the IdP, a metadata list on the secret
     store), never realm admin and never secret read. `running_problems` fails on any labelled
     object whose module is not selected, and on an object of a carrier kind that carries no
     module, reserved or `builtin` label. A kind it cannot read stays in `not_gathered`, as today.
   - **The `contributions` plane runs.** `hnx decommission check --module ID` builds a module
     target from that module's manifest as of the base commit and reports every labelled object
     that still carries the id as `REMNANT`, with the existing statuses, the `UNMEASURED` exit 100
     and the positive control (a selected module must come back non-clean). The audit stays
     read-only, as docs/decommission.md says. **Removal acts**: `hnx modules remove ID` exports
     every owned dataset first (`export_first`, decision 6's rules), runs `lifecycle.remove`, asks
     each provider to reconcile its kind to the render without the module (which deletes only
     objects labelled with that id that the previous render produced), tombstones identifiers,
     and exits 1 unless the `contributions` plane is then clean. SSO client ids, secret paths and
     DNS names are tombstoned, never released, for at least one release, so a different module
     cannot inherit a predecessor's redirect URIs, audiences or policies. A destructive kind
     (secrets, lake tables, SSO clients) is deleted through a broker action the operator approves
     (ADR-0017), never by the CLI's own credentials.

4. **Consumers address capabilities, not products, and so do the names consumers resolve.** The
   product-name lint gains an identifier mode (`tools/product_name_lint.py --identifiers`, run in
   the overlay's checks as well): it reads, **including in site configuration**, the names a
   consumer resolves: service row names and so their DNS aliases, rendered OIDC client ids,
   secret names outside a provider's own namespace, MCP tool names and the lake namespaces of
   `platform` datasets (which carry the capability's name and canonical schema), and refuses the
   product vocabulary in them.
   - **A provider module's own namespace is exempt.** A provider module's id may be its
     product's name (ADR-0049's provider modules are), and identifiers that exist only inside that
     namespace (`secret:<id>/...`, the module's bound fleet units, its own criterion ids, its
     private tables) go when the module goes, so the lint does not read them. What it refuses is a
     product name in a name some *other* module or a person addresses.
   - Existing names enter the lint's own shrinking baseline, as the code baseline did, and that
     baseline is listed in `tools/ratchets.yml` (ADR-0048 decision 4). Renames ride the
     overlap-release rule already in force for wire names (old name aliased for one release). A
     human-facing public hostname may carry a product name only through an `allow:` entry with a
     reason.

5. **Replacing a module is one protocol: `hnx modules replace FROM TO`.** It generalises the
   canary-gated model-role rebind to every slot and drives one record, the draft
   `platform/module_swap` (folded into swap record 1.2 when ADR-0027 is accepted; until then the
   swap record stays at 1.1), in order, each step a gate:
   1. **plan**: every slot instance FROM serves in the site, the dependants including core
      modules (`rules.dependants`), the datasets that move, the contributions to regenerate and
      the credentials to reissue, written as the record's `selection_diff`, `legs` and
      `dependants.report`;
   2. **shadow**: TO deployed beside FROM, bound to no consumer, its contributions rendered and
      labelled as TO's but not routed (no public route, agents on `shadow` lanes only). A shadow
      of a slot the registry marks `privileged` or `authority` (secrets, idp, broker) gets no
      `grants.upstreams`, default-deny egress and the slot's TLP ceiling, and is stopped and its
      data destroyed if the replacement is abandoned;
   3. **conformance**: the slot's suite against TO at the contract version every dependant
      requires (ADR-0041);
   4. **migrate into the shadow**: each declared dataset exported from FROM and imported into TO
      through the slot protocol (decision 6), with the boundary check; `start_empty` stays a
      recorded decision with a reason. The export's mark (the point it was taken at) is recorded;
   5. **compare**: a recorded input corpus replayed against FROM and the migrated TO, and the
      outputs compared under the slot's declared equivalence; for `inference` (stateless) this is
      today's `hnx golden pins check` with live evidence. As with the model-role gate, everything
      that vouches for TO is read from the base commit, so a change cannot vouch for itself;
   6. **switch**: FROM is stopped for writes, a final delta export of FROM's writes since step 4's
      mark is imported into TO, and then one reviewed change is applied after `cutover_problems`
      holds. That change is both halves together, in one commit: the selection diff applied by
      `apply_selection_diff`, and the registry standing flip computed by ADR-0039's
      `plan_promote`. In the overlay it is one pull request the operator merges (ADR-0046);
   7. **rollback window**: for the length of the ledger row's `rollback_days` (ADR-0043 decision 2,
      the one source of the window; ADR-0039's `standing.until` is derived from it), FROM kept
      read-only, not destroyed, its data and contributions kept
      (its SSO client disabled, its DNS alias already moved); for a `privileged` or `authority`
      slot, FROM's own outbound credentials are reduced to read-only for the window. A rollback
      reverts the diff. It imports TO's writes since the cut into FROM only if the slot declares
      `import_mode: merge` with a tested conflict rule; otherwise the record states that those
      writes are lost, and the operator approves the rollback with that loss shown;
   8. **decommission**: `hnx modules remove FROM` (decision 3), with credentials revoked
      (`decommission_problems`) and the census clean of FROM's label;
   9. **close**: FROM marked `status: retired`, `replaced_by: TO`, with a ledger row (ADR-0043)
      and, for a primary, the ADR-0039 record.
   `hnx swap` remains the leg for a network-route move inside step 6.

6. **Every core capability protocol gains export and import.**
   - **Scope.** Each slot the slot registry marks `stateful` (object-store, lake-catalog,
     detections, cases, secrets, idp, dns, backup, events, broker, orchestration, records), plus
     `projects` and `context`, which are added to the slot registry as `stateful: true`, gains
     `export(dest, fmt) -> manifest` and `import_(src, manifest, limits=None)` in the shape of
     `conformance.protocols.migration.Migratable`, in the formats the registry already lists
     (`jsonl`, `markdown-tree`, `zone-file`, `object-tree`, `parquet`, `json`, `sigma`). The
     methods for the lake sit on the lake-catalog part of `lake.py` (lake-query, which shares the
     file, is stateless). `hot-index` has no contract yet (`contract: null`): it gains the methods
     when its contract is written and is provisional until then. The slots ADR-0049 adds
     (`threat-intel`, `cti-graph` and `ioc-enrichment`, all `private`) join through ADR-0049, which adds `stix` to the
     format vocabulary when it registers them.
   - Each addition is a contract minor version (ADR-0041) and starts after ADR-0041's contract
     claims (its step 5). Every fake implements both; each suite gains a MUST round trip (export,
     import into an empty fake, export again: equal manifest digests apart from the loss the slot
     documents, ADR-0008 decision 4); `MIGRATION_PROOF` names the suite instead of the harness
     self-check. A coverage test fails when a `stateful: true` slot's protocol lacks either
     method, apart from the slots in its shrinking allowlist (`hot-index` until its contract
     exists), listed in `tools/ratchets.yml`.
   - **Privileged exports.** An export of a slot the registry marks `privileged` or `authority`
     (secrets, idp, broker) is encrypted to a recipient the overlay names and is never written as
     plaintext, and it is started only through a broker action the operator approves (ADR-0017),
     like decision 3's destructive deletes. Its round-trip MUST compares the decrypted canonical
     content in the fake. Every export manifest carries the dataset's `tlp`, and `export_first`
     writes only to a destination whose ceiling is at or above it (ADR-0033).
   - **The checklist.** A new PUBLIC-NOW row, X-14 (reserved by this batch, after ADR-0039's X-12 and
     ADR-0043's X-13), asserts that every stateful
     slot's suite carries the round-trip MUST and that every in-tree fake passes it. X-07 ("every
     stateful product's export restored once in a drill") stays ADR-0042's: it is automated over
     the restore drills there, and this ADR does not redefine it.

7. **The lake is the system of record, and apps are replaceable views, where practical.** Data
   whose truth can be an append-only record (events, job records, deliveries, findings,
   detections fired) lives in a `platform` dataset with a canonical lake schema. An app that keeps
   a private copy declares it with `view_of: <dataset>` and `rebuild_from:` (the candidate fields
   of the follow-ups' open question); such a module is `private`, its view dataset declares
   `recovery: rebuild` (decision 1), and replacing that app is `start_empty` plus a gated rebuild,
   not a migration. Where the app is the authority (IdP users and factors, secrets, case
   narratives, the task board while it is primary) the data stays `private` with export and
   import.

### Out of scope

- The hypervisor, physical network and base storage (ADR-0012): not modules.
- Which product is primary for a capability (ADR-0039), how contract versions are numbered and
  tested (ADR-0041), the backup method vocabulary, restore drills and X-07, off-site copies and
  cold-start order (ADR-0042), the old lab's per-service cutover and whether the old lake's
  history is carried (ADR-0043), the vault's records and their history (ADR-0044), credential
  lifetimes and rotation (ADR-0045).
- Sandboxing third-party module code, the licence probe and external hosts (ADR-0027 open
  questions).
- Ordered-downtime migrations; deliberate obfuscation of product names (review catches that).
- Several modules per guest (the `platform/guest` follow-up), though decision 1's `volumes` kind
  does not depend on it.

## Consequences

- A replacement becomes the nine steps of one record; a removal leaves nothing behind that the
  census can see, and what it cannot see is listed as `not_gathered` rather than read as clean.
- Every stateful provider must now ship a real, round-tripping export and import, and a private
  module a consistent backup and a restore. Some products export lossily; the documented loss is
  part of the deliverable, and some may not be adoptable at all until it is written.
- A secrets, IdP or broker export is ciphertext that only the overlay's recipient can open, and
  taking one needs an approved broker action; that includes the export `hnx modules remove` takes
  first.
- Generators must stamp labels and providers must reconcile by label against the previous render.
  A provider whose product cannot carry a label for a kind cannot provide that slot until it can,
  or until the carrier table names an alternative (an ownership record kept by the provider).
- The status hub loses its direct database read, and the lab's direct readers are rebuilt rather
  than ported; until their ledger rows close, the old lab keeps them.
- Renaming product-named identifiers costs a re-seed of secrets and a one-release DNS and client
  alias; the identifier baseline only shrinks. Tombstoned identifiers cannot be reused for a
  release.
- A rollback without a merge-capable import loses TO's writes, and the record says so before the
  operator approves it.
- The IdP admin read and the reconcile calls are product code: they live in the provider module,
  are human-approve under the review tier, and run with a read-only scoped or broker-mediated
  identity.

### Implementation plan (each step one pull request)

1. **This ADR**, with **Amended-by: ADR-0040** on ADR-0004, ADR-0005, ADR-0025 and ADR-0027 and
   their **Amended:** lines, and on ADR-0008 one **Amended-by:** list naming ADR-0040 (export and
   import become slot protocol methods with a round-trip MUST) and ADR-0042 (a dump restores the
   same product; an export leaves it), written once with ADR-0042's note; summaries restamped.
   Proves: `tools/tests/test_adr_log.py` accepts the reciprocal pairs and the index.
2. **State class in the schema**: `state`, the dataset `recovery` reference, `lifecycle.backup`/
   `restore`, `rules.state_problems`; examples updated; one negative per rule. Lands with or
   after ADR-0042's `recovery` block. Proves: each planted defect (data under `none`, `private`
   without a host dataset, a private dataset no recovery entry covers, `recovery: rebuild`
   without `view_of`) is refused by the named rule, and every example passes.
3. **Undeclared volumes, statically, and the backup manifest clause**: the loader rule over role
   specs and unit paths, including refusal of an unresolvable spec; `compose_app`'s manifest
   names named volumes (inside ADR-0042's hook contract). Proves: a planted named volume, a bind
   outside the data root and an unresolvable mount are refused; the backup-manifest test fails on
   the parent commit.
4. **Census `volumes`**: gather and `running_problems`. Proves: a stray volume on a fixture host is
   a problem; an ungathered host is `not_gathered`, not clean.
5. **Status hub through a status source**: the telemetry source, the deprecated flag, the guard
   test. Proves: the Orchestration page renders from the source fixture; the guard fails if a
   status path opens a foreign SQLite file.
6. **Cross-module storage rules**: loader path rule, role-lint exec and client rule, egress
   exclusion of database ports. Proves: each planted violation is refused by name, a backup role
   that mounts another module's root is refused, and the example lab passes.
7. **Export/import on the records, cases, secrets and projects protocols**, fakes, round-trip
   MUSTs, encrypted export for `secrets`; `projects` and `context` added to the slot registry as
   `stateful: true`; the coverage test, with every slot still lacking the methods in a shrinking
   allowlist that refuses growth. After ADR-0041 step 5. Proves: each fake round-trips; a planted
   lossy fake fails the MUST; a plaintext secrets export fails; adding a slot to the allowlist
   fails.
8. **Export/import on the remaining stateful protocols** (lake-catalog, idp, dns, events, broker,
   orchestration, detections, object-store, backup, context), the broker-approved start for
   privileged exports, the TLP check on export destinations, the new X row. The allowlist is left
   holding only `hot-index`. Proves: the coverage test passes; an export to a lower-ceiling
   destination is refused; the X row reports per slot.
9. **Label carriers**, first for SSO, DNS, firewall and secret kinds (`homelabnext.modules.labels`,
   reserved `hnx:core`/`hnx:site` labels, `builtin` lists, loader refusal of authored label keys,
   label stamping in the realm and nftables generators); the `dashboards` and `alert_rules` keys
   and their generators when the first provider of that kind is a module. Proves: every rendered
   object of each example module carries its id; an authored label is refused; a key without a
   carrier fails the suite.
10. **Census of labelled kinds** through provider read adapters and fakes, SSO, DNS, firewall and
    secrets first (dashboards and alert rules when the first provider of that kind is a module),
    each with its read-only scoped identity. Proves: a labelled leftover of an unselected module,
    and an object with no module, reserved or builtin label, fail the check; a provider builtin
    does not.
11. **The `contributions` plane**: `hnx decommission check --module`. Proves: a removed example
    module's leftovers are `REMNANT`, a clean removal is `CLEAN`, the positive control fails on a
    selected module, and nothing measured gives exit 100.
12. **`hnx modules remove`**: export first, remove playbook, reconcile by label against the
    previous render, tombstones, broker-approved deletion of destructive kinds, plane must be
    clean. Proves on fakes: only that module's objects go, never another's, and a forged label on
    an object the previous render did not produce deletes nothing; an interrupted removal resumes;
    a pending approval stops before deletion.
13. **Identifier lint** (`--identifiers`), its baseline in `tools/ratchets.yml`, the provider
    namespace exemption, the overlay job. Proves: a product-named row, consumer-facing secret,
    client id or alias is refused; a provider module's own `secret:<id>/` path is not; the baseline
    refuses growth.
14. **`hnx modules replace`, steps 1 to 5** (plan, shadow, conformance, migrate into the shadow,
    compare) over the example object-store swap, with the authority-slot shadow restrictions.
    Proves: the record is computed and compared, never trusted; compare runs against the migrated
    TO; compare evidence from the change itself counts for nothing; a failed round trip blocks; a
    shadow idp fake with an upstream grant is refused.
15. **`hnx modules replace`, steps 6 to 9** (switch with the final delta, rollback window,
    decommission, close), extending the draft `platform/module_swap`; the fold into swap record
    1.2 happens at ADR-0027's acceptance. Proves: writes made to FROM between migrate and switch
    reach TO; a rollback with `import_mode: merge` restores FROM with TO's writes, and without it
    records the loss and needs approval; close refuses while the census still sees FROM's label.
16. **Views and rebuilds**, when the first module with a view is selected: `view_of`,
    `rebuild_from`, `recovery: rebuild`, and the swap gate on a completed rebuild. Proves: a view's
    replacement passes only with `start_empty` and a finished rebuild.

## Alternatives

- **Keep relying on guest-image backups and the per-role export hook.** Rejected: an image
  restores the product, not the exit (ADR-0008), and a named volume is today in no manifest at all.
- **Allow read-only cross-module database grants** (the hub's current pattern, made explicit).
  Rejected: a read-only reader still pins the owner's private schema, path and journal mode, which
  is exactly what blocks a replacement; the spend-log API shows the alternative costs little.
- **Garbage-collect by name match alone** (extend the decommission planes' word-bounded matching).
  Rejected for deletion: name matching is ambiguous by the audit's own account (`AMBIGUOUS`), so it
  stays a review aid, and deletion keys on an explicit, generator-stamped label.
- **Make the decommission audit itself delete.** Rejected: the audit's value is that it is
  read-only and can run anywhere; acting is `hnx modules remove`, gated on the audit.
- **A replace protocol per capability.** Rejected: that is the status quo the swap kit and the
  model-role gate each reinvented; one record and one step list with per-slot `compare` and
  `migrate` implementations keeps the gates in one place.
- **Plaintext exports kept on an access-controlled share.** Rejected for authority slots: a full
  dump of secrets or IdP credentials is the highest-value file in the lab, and access control on
  one share is one mistake from disclosure; encryption to a named recipient plus an approved start
  costs one broker round trip.
