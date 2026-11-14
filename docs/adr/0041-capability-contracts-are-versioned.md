---
summary: Each capability contract and suite carries a semver; providers declare the versions they meet, CI tests each claim, breaking changes get an overlap release.
summary_of: outline:sha256:cd644884ec416538
---
# ADR-0041: Version capability contracts and test every version claimed

- **Status:** proposed
- **Date:** 2026-11-07
- **Related:** ADR-0001 (schemas evolve additively), ADR-0005 (swap procedure and conformance),
  ADR-0026 (its amendment's overlap release for wire names), ADR-0027 (modules, slots and
  `requires`), ADR-0028 (one source of truth); this batch: ADR-0039 (one primary product per
  capability), ADR-0040 (modules are replaceable by construction), ADR-0043 (the cutover ledger),
  ADR-0044 (the broker carries the vault's lifecycle), ADR-0046 (repository governance, review
  tiers and release cadence), ADR-0048 (verification does not rest on one reviewer), ADR-0049 (the
  SOC data plane and the lab's checks move as modules); [conformance](../conformance.md),
  [capabilities](../capabilities/README.md),
  [interfaces, section 6](../interfaces.md#6-version-policy), [slots](../modules/slots.md),
  [how a swap works](../modules/swap-flow.md), `homelabnext/conform/`, `conformance/`,
  `tools/schema_check.py`
- **Depends-on:** ADR-0001, ADR-0005, ADR-0027

## Context

A capability is a seam: a protocol in `conformance/protocols/`, a suite in `conformance/suites/`,
a fake, and the adapters that bind real products (ADR-0005). The suites are the strongest thing
this repository has for a product swap, and they have no version.

- **Nothing in the harness carries a version.** `homelabnext.conform.core.Suite` has a name, a
  summary, a protocol and a tier; a check has an id, a severity and required features. A report
  (`homelabnext.conform.report/1`) records the git commit it ran at, so "this provider passed the
  object-store contract" means "passed whatever the suite said at that commit".
- **Modules already ask for a version that nothing answers.** A module manifest's
  `requires.capabilities[]` and `prefers.capabilities[]` entries must carry `version` (unless
  `provisional`), typed by the draft manifest schema as `contract_version`, "MAJOR.MINOR of a
  contract: met by the same major and an equal or higher minor"
  (`homelabnext/schemas/module_manifest.py`). Every in-tree manifest and example says `'1.0'`. But
  a provider's `provides.slots.<slot>` entry declares no contract version, the slot registry
  (`examples/modules/slots.yml`) names only the protocol file, and the swap flow says so plainly:
  "the contract version a dependant requires is the slot's, not the provider's, so it is not
  re-checked" (`docs/modules/swap-flow.md`). The field is validated for shape and then ignored.
- **A rule the schema states is not enforced either.** The manifest schema describes a provider
  entry's conformance target as "a conformance target file in the module; its features equal the
  entry's", but `homelabnext/modules/loader.py` only yields the target path as a contributed file;
  no code compares the features.
- **The only evolution rule forbids most evolution.** `docs/interfaces.md` section 6: "a
  conformance check is never removed; it may be added. A new check ships with a fake update in the
  same change." Adding a MUST check therefore changes what every existing provider is held to, the
  moment it merges, with no way for a provider to say "I meet the contract as it was" and no way
  to retire a check that turned out wrong. That same property is also a protection worth keeping:
  a check that closes a security gap binds everyone at once.
- **The first large change is already queued.** ADR-0040 decision 6 adds `export` and `import_`
  to every stateful capability's protocol and a MUST round trip to each suite, and calls each "a
  contract minor version (ADR-0041)". Without versions that change either lands as one red wall
  across every provider, or waits.
- **Schemas have exactly the machinery contracts lack.** Every schema carries `MAJOR.MINOR` in its
  `$id`; a version names one contract; frozen copies under `schemas/_frozen/` are append-only; and
  `tools/schema_check.py` refuses a change that is not additive within a major, or any non-doc
  change without a new minor (ADR-0001 decision 4). A capability contract is behaviour as well as
  shape, so it needs the same idea applied to operations and checks, not a copy of the schema rule.
- **A check's behaviour is wider than its module.** Every suite imports `conformance/suites/_util.py`;
  the lake suites import `_lake.py`; `orchestration_features.py` imports helpers from the
  `orchestration` suite; suites import their fakes and mutants from `conformance/fakes/`; and
  `lake_query.py` imports `homelabnext.lake.ceiling.CeilingReader` and `homelabnext.tlp.Label`, so
  the lake-query suite's TLP-ceiling checks mean whatever those modules say. Any version stamp that
  hashes only the suite file misses a change to a control.
- **The overlap rule exists, for one case.** ADR-0026's amendment staged the controller's wire
  renames over "one release ... as `CHANGELOG.md` records it": both names accepted for that
  release, the old one dropped no earlier than the next, and only once a check finds no consumer.
  That is the rule a breaking contract change needs, stated for field names only. No release has
  been cut since 0.1.0 (the tech-debt audit, section 7); ADR-0046 decision 9 makes the cadence a
  nightly-checked obligation (a release once the newest section is over 28 days old or
  `[Unreleased]` holds over 100 entries).
- **Seven suites have no contract page.** The 18 core capabilities each have a generated page under
  `docs/capabilities/`; the extended suites (`backup`, `dns`, `edge`, `log-pipeline`, `migration`,
  `broker-tokens`, `orchestration-features`) have none, because the generator
  (`homelabnext/sop/capabilities.py`, `collect`) iterates `CAPABILITIES` only (tech-debt audit,
  section 5). Three of them back slots the slot registry marks `required_in_core` (`dns`, `edge`,
  `backup`), and `edge` is a privileged trust root, so a module author choosing a provider for the
  front door has no page to read.

## Decision

1. **Every suite carries a semantic version, and the contract version is its first two parts.**
   `Suite` gains `version: "MAJOR.MINOR.PATCH"`. `MAJOR.MINOR` is the **contract version**: what a
   manifest's `requires` or `prefers` names, what a provider claims and what a report states.
   `PATCH` is the suite's own revision within that contract. The meaning of each part:
   - **PATCH**: the suite's import closure (decision 2) changed outside documentation (docstrings,
     comments) while the contract surface did not: a flake is fixed, an assertion message changes,
     a helper is refactored, or an existing check is tightened **only up to what its own summary
     already states**. Anything that makes a check assert more than its summary says is a MINOR
     (a new check, or the old one with a new summary at a new `since`), or a retroactive check
     (decision 11). A patch is further constrained by decision 9.
   - **MINOR**: the surface grew and nothing in it narrowed for a consumer at an older minor: a
     new check, a new operation, a new optional parameter with a default, a new field with a
     default on a contract data type, a new feature name, or a check's severity raised from SHOULD
     to MUST. Two kinds of growth reach consumers that require an older minor, so they are MINOR
     only under a condition:
     - a **new contract exception** must subclass an existing contract exception of the same
       operation, so a dependant written against the older minor already catches it;
     - a **new enum member** is MINOR when it is a value providers return (consumers must already
       tolerate unknown members, `docs/interfaces.md` section 6); a member a consumer may *send*
       is MINOR only if the contract already required providers at older minors to refuse unknown
       members, which a check at those minors proves. Otherwise it is MAJOR.

     Everything new is tagged with the minor it arrived in (decision 3).
   - **MAJOR**: anything else: a check, operation, field, feature or enum member removed or
     renamed; a signature changed incompatibly; a check's required features or skippability
     changed; a severity lowered; or a schema the contract exchanges moving to a new major
     (decision 8).

   New behaviour of an existing capability is added as minors of that capability's contract, so
   its providers can claim it; it is not a second protocol and suite for the same slot. Every suite
   starts at `1.0.0` with every current check and operation in `1.0`, which is what every in-tree
   `requires` already names, so the first step changes no claim.
2. **The contract surface is extracted, not written, and each version is frozen in a lock.**
   - The surface of a version is what `homelabnext.sop.capabilities` already introspects for the
     capability pages: the suite's checks (id, severity, required features, skippability, the
     `since` and `until` of each), the Protocol members and their signatures, the contract's data
     types, enums, constants and exceptions, the feature vocabulary, and the schemas the suite
     declares (decision 8), by `$id` name and major.
   - `suite_digest` is computed over the suite module's **transitive in-repository import
     closure** (the suite, its protocol, sibling suites and helpers such as `_util` and `_lake`,
     the fakes and mutants it imports, and any `homelabnext` module it reaches), excluding
     `homelabnext.conform` itself and the standard library and third-party packages, with
     documentation stripped from each syntax tree. The lock records the closure's module names
     beside the digest, so a helper edit is attributed to every suite that imports it.
   - A new command, `hnx conform versions freeze <cap>`, writes `conformance/versions/<cap>.json`
     to a new draft schema `conform/contract_versions` 1.0, with examples and negatives (ADR-0001
     decision 4). The lock holds one entry per `MAJOR.MINOR`, carrying that version's surface, its
     status and a `patches` list of `{patch, suite_digest, closure, date, retroactive}` records
     (decision 11 for `retroactive`). A patch therefore appends one short record, not a copy of
     the surface.
   - Entries and patch records are append-only: neither changes once written, and a version's
     status moves only forward, `live` to `deprecated` to `removed` (decision 6).
   - `Suite.version` must equal the newest entry and patch of the live major in the lock; a
     mismatch is refused (decision 9). The lock is the history; `Suite.version` is the one line
     the harness needs before the lock is read, and the gate keeps the two equal (ADR-0028).
3. **What is new is tagged with the minor it arrived in, and what a major removes with the major
   that removes it.**
   - `Suite.check` gains `since=` (default `"1.0"`) and `until=` (default none). A raised severity
     is written `severity_since={"should": "1.0", "must": "1.3"}`. A protocol member, field or
     parameter is tagged in the protocol module with `SINCE` and `UNTIL` maps of qualified name to
     version.
   - The harness runs a suite **at a contract version**: `hnx conform run <cap>
     --contract-version 1.2` runs exactly the checks whose `since` is at most `1.2` and whose
     `until`, if any, is above `1.2`, each at the severity it has at `1.2`; and the protocol check
     (`isinstance` against the runtime Protocol) admits a subject lacking a member whose `since`
     is above `1.2` and does not require one whose `until` is at most `1.2`.
   - Because a minor only adds (decision 1), running a major at a minor covers every lower minor
     of it: the same checks or more, severities the same or higher, a protocol at least as strict.
     So a binding is run **once per claimed major, at its claimed minor**. With no
     `--contract-version`, the harness runs at each version the target binding claims
     (decision 4), and with no claim at the newest live version.
   - A version the lock does not hold, or holds as `removed`, exits 2, like any other
     misconfiguration. The JSON result and the report gain `contract_version`, `suite_version` and
     `suite_digest` per capability, as optional fields of `homelabnext.conform.report/1`.
4. **Providers and adapters declare the versions they satisfy, in one place each.**
   - A conformance target file's binding gains `versions: ["1.0", ...]` (target schema
     `conform/target` 1.1, an additive optional property), listing **at most one minor per major,
     the highest it meets**: claiming `1.3` claims `1.0` to `1.3`. A lint in
     `contract_check.py` under `tools/` refuses an in-tree target file (`conformance/targets/`,
     `compose/*/targets/`, a module's `conformance/target.yml`) whose binding omits it, so the
     schema stays additive and the repository's own claims are always explicit.
   - Two binding forms are handled specially. `builtin: fake` claims, per non-removed major, that
     major's highest minor, and must pass each (decision 5); `fake: true`, the older alias, is
     treated as `builtin: fake`. `builtin: broken[:...]` bindings exist to fail; they carry no
     `versions`, are exempt from the lint, and claim nothing.
   - A provider module's `provides.slots.<slot>` gains `contract_versions`, required whenever the
     entry has a `conformance` target, and equal to that target's `versions`. This is checked by
     the loader, which gains it together with the features-equality rule its schema already
     describes but nothing enforces. A `provisional` entry (no `conformance`) claims no version.
     The manifest schema is a draft (ADR-0027), so this is a field added, not a version bump.
   - The Go gateway and controller stand-ins are bound through target files like any other
     adapter, so they declare there; nothing Go-specific is added.
5. **CI runs every in-tree implementation against every version it claims.** A new command,
   `hnx conform matrix`, enumerates every (target binding, capability, claimed version) the tree
   claims, from the target files and the provider manifests. Each is assigned to exactly one CI
   job by the target file's location: in-process bindings (the fake, reference services, recorded
   fakes) in the existing conformance step, lab-in-a-box bindings in the lab-in-a-box job, the Go
   gateway in `gateway-conformance` (`tools/gateway_conformance.sh`). Each job runs its entries
   and fails on any MUST failure at any claimed version, and a static test fails when a claimed
   entry is assigned to no job or to two. `tests/conform/test_conform_suites.py` alone
   parametrises the fake and the protocol check over **every** non-removed minor, which is what
   proves the `since`/`until` filtering; mutants run at every non-removed minor of the live major,
   so a weakened check at an older minor is caught too. Invariant X-10 and
   `tools/conform_coverage.py` keep their meaning (every blocking capability has a passing suite)
   and now run each capability at the versions its target claims, so a deployed lab's X-10 says
   which version passed.
6. **A breaking change ships with an overlap release and a deprecation window.** The rule is
   ADR-0026's amendment, generalised from wire names to contracts, with "one release" meaning the
   same thing (a release of this repository as `CHANGELOG.md` records it):
   - **Overlap, in one live suite.** Major N+1 lands in the same suite and protocol modules. A
     check, Protocol member or field that the major removes stays in the live suite and protocol
     tagged `until="N+1.0"` (protocol `UNTIL` map): the harness running at `N.x` includes it, at
     `N+1.x` excludes it. A signature change at a major is written as a new member (`since="N+1.0"`)
     plus an `until="N+1.0"` on the old one. No module is copied, so every import keeps resolving
     to the one live tree, and the harness that runs N is the harness that runs N+1. In the pull
     request that lands N+1, every in-tree provider either claims both majors or the pull request
     says, in the provider's own manifest change, why it cannot yet.
   - **Deprecation.** In the release that first ships N+1, N's lock entries move to
     `deprecated` with `deprecated_in: <release>`. Running at a deprecated version passes or fails
     as before and adds a `deprecated` note to the report; the module loader warns on a
     `requires`, `prefers` or claim that names one, so an overlay sees it when it validates at its
     pin.
   - **Removal.** N may be marked `removed`, and its `until`-tagged code deleted, only when all
     three hold, checked by `contract_check.py` under `tools/`: a later release than `deprecated_in`
     exists in `CHANGELOG.md`; at least the deprecation window has passed since `deprecated_in`'s
     date (30 days, the same for every slot, privileged ones included: **decided 2026-11-08,
     operator**, so the window is at least one later release plus 30 days); and `hnx conform
     versions consumers <cap> --major N` finds no in-tree `requires`, `prefers`, claim or
     core-module requirement naming major N. With ADR-0046 decision 9's release at least every 28
     days, the two clocks agree: the 30-day window closes before or at the second release after the
     deprecation, so removal waits at most two release cycles. An overlay is not visible to this
     repository's CI, so it is protected the other way: after removal the loader refuses a
     `requires`, `prefers` or claim naming a removed version, and the overlay's checks fail on the
     pin move that crosses the removal until it has migrated.
7. **Dependants are matched against claims, and claims against evidence.** A new rule beside
   `rules.dependants` in `homelabnext.modules.rules`, run at selection and re-run at a swap's
   cutover against the incoming provider:
   - **Requirements.** For every selected module's `requires.capabilities[]` entry
     `{cap, version: X.Y}` (core modules included), the provider bound to that slot instance claims
     `X.Z` with `Z >= Y`, and `X.Y` is in that capability's lock and not `removed`. A `provisional`
     provider claims nothing, so it fails the match whenever any dependant names a version.
   - **Preferences.** A `prefers.capabilities[]` entry whose version the bound provider does not
     claim (a `provisional` provider included) is treated as the slot being absent: its declared
     `fallback` applies, and the selection reports it. A preference never silently gets a provider
     at a lower minor.
   - **Evidence.** A claim is the provider vouching for itself, and this repository's CI runs only
     in-tree claims (decision 5). So at swap cutover, and in `hnx modules check --site` when
     `--reports` is given, a claim is honoured only with a conformance report for that binding at
     each required version whose `suite_digest` matches a patch record of that version in the lock
     and which has no MUST failure. A claim without such a report is refused at cutover and warned
     at selection. That report is the artifact ADR-0040's replace protocol, step 3 (conformance at
     the version every dependant requires), and ADR-0043's cutover rows cite.
   - This removes the "not re-checked" exception from `docs/modules/swap-flow.md`.
8. **Schema versions and contract versions are related by major, and only by major.**
   - A schema is a data shape, versioned by `$id` and governed by ADR-0001; a contract is operations
     plus behaviour, versioned by this ADR. A suite declares the schemas its contract exchanges as
     `SCHEMAS = {name: major}`, and the lock entry records them. The declaration is checked, not
     trusted: plan step 3's test runs each suite against its fake with schema loading recorded, and
     fails if a loaded `$id` is not declared, so a schema reached through a helper (for example
     `homelabnext.lake.load_schemas`) is not missed.
   - A schema **minor** never forces a contract bump. Within a major a schema only grows, and the
     contract's consumers already tolerate what they do not know. If a provider must start filling
     or honouring a new optional field, that obligation is a new check, so a contract **minor**.
   - A schema **major** that a live contract declares is a contract **major**, because the shape
     the operations exchange broke. `contract_check.py` under `tools/` refuses a change where a declared
     schema's live major differs from the lock's for the live contract version without a contract
     major bump.
   - ADR-0001 decision 3 is unchanged: the runtime schema registry loads only the live major and
     stored documents are migrated, never dual-read. During a contract overlap the harness, not the
     runtime, validates the `until`-tagged checks of major N against the schema's frozen copy,
     which `tools/schema_check.py` already resolves by `$id`. A provider that serves both contract
     majors at once translates between the two shapes itself, and both majors' checks test that
     translation.
9. **One gate classifies every change.** `contract_check.py` under `tools/` (an `hnx-script` check in the
   schemas CI job, beside `tools/conform_coverage.py`, run with `--base` the way
   `tools/schema_check.py --ci-base` is) compares, for every non-removed version, the surface
   extracted at that version with its lock entry, and each suite's `suite_digest` with its newest
   patch record. It refuses:
   - a surface or digest change with no new version or patch record, or with a bump smaller than
     decision 1 requires (a removed check without a major; a new check tagged with an already
     frozen `since` unless it is retroactive, decision 11);
   - a `since` or `until` naming no version, or a minor that skips one;
   - any lock entry or patch record at `--base` that is changed or missing at HEAD, except a
     forward status move that decision 6 allows;
   - `Suite.version` differing from the newest entry and patch of the live major;
   - an in-tree target binding (other than `builtin: broken`) without `versions`, or a claim of a
     version that is not in the lock or is `removed`.

   A patch is held to two further rules, because a digest cannot tell a check that probes harder
   from one that stopped asserting its control:
   - **Every existing mutant stays killed**, at every non-removed minor of the live major
     (decision 5); a patch that lets one survive is refused.
   - **A patch to the closure of a privileged slot's suite** (`secrets`, `idp`, `edge`, `broker`,
     `broker-tokens`, `orchestration`, `orchestration-features`, `records`) is operator review
     tier, like a schema change: `conformance/versions/` and those suites' closures are listed in
     `.github/review-tiers.yml` (ADR-0046 decision 3).

   During an overlap, a digest change records a patch on every non-removed major, since one module
   serves them all. A bump larger than needed is allowed and reported, since it costs every
   consumer an overlap. `docs/interfaces.md` section 6's rule becomes "a conformance check is never
   removed within a major"; the rest of that section stands.
10. **Every suite has a contract page, with its version history.** `hnx docs capabilities
    generate` renders a page for every suite in `names(include_extended=True)`, so the seven
    extended suites get pages under `docs/capabilities/` from the same introspection as the core
    eighteen. The index gains an "Extended suites" table, and the `broker-tokens` and
    `orchestration-features` pages say which core protocol they extend (both are optional-feature
    Protocols of `conformance/protocols/broker.py` and `conformance/protocols/orchestration.py`).
    Every page, core and extended, gains a versions table read from the lock (version, status,
    `deprecated_in`, retroactive checks) and `since` and `until` columns on its checks and
    operations. `hnx docs capabilities check` (already a CI step) fails when any suite lacks a
    page, and the read-only MCP server answers from the same `contract_data`, so a page and a tool
    answer cannot disagree.
11. **A security fix binds every version of its major.** Versioning must not let a provider opt
    out of a control by claiming an older minor. A check that closes a vulnerability or restores a
    control (a token-scope refusal in `broker-tokens`, an auth bypass in `edge`, a release ceiling
    in `secrets`, `idp` or `lake-query`) may be tagged `retroactive="<reason>"`. It applies at
    every live version of its major regardless of `since`, is classified as a PATCH, is listed in
    the patch record's `retroactive` list and under `Security` in `CHANGELOG.md`, and is operator
    review tier whatever suite it is in. A provider claiming any version of that major must pass it,
    so CI, X-10 and the cutover evidence (decision 7) all hold it. A retroactive check is never
    removed except at a major, like any other.

### Out of scope

- The schema version policy (ADR-0001), the Python API's SemVer (`docs/interfaces.md` section 6),
  product version pins, and the module manifest's own `manifest_version`.
- Inter-module `interfaces`. They have no suite or lock: their versions are defined by the one
  module (or the core) that owns each id, and the loader already matches a requirement to a
  defined `(id, version)` pair exactly. Moving them to `contract_version` range matching is a
  change to ADR-0027's interface rules, not to capability contracts.
- Making the extended suites blocking (part of the X-10 set), and which product is primary for a
  capability (ADR-0039).
- The export and import operations themselves (ADR-0040 decision 6); this ADR only provides the
  minor versions they arrive in.
- When releases are cut: ADR-0046 decision 9 sets that cadence; decision 6 here only relies on it.
- Running suites against the operator's lab, and adapters for the capabilities that have none
  (cases, idp, records, detections, Code Mode); the lab's cutover rows (ADR-0043) cite the
  reports decision 7 requires, but the runs are theirs.
- Go-native suites. The Go implementations stay tested by the Python suites through adapters.
- `platform/capability` descriptors and the slot registry: they keep naming the protocol, and the
  lock is the one source of a contract's versions (ADR-0028).

## Consequences

- "Which contract did this provider pass?" has an answer in the report, and a dependant's
  `requires` or `prefers` version finally means something: a selection or a swap that cannot meet
  it is refused, or falls back, and a claim needs a matching report at cutover.
- A contract can grow without breaking its providers: a new MUST check is held against providers
  that claim the new minor, and the others keep passing the version they claim. A security fix is
  the exception and binds every version of its major at once (decision 11). ADR-0040's
  export/import rollout becomes one minor per stateful capability at the time it starts, landed
  one capability at a time.
- A wrong check can be retired, at a major, with a window, instead of living forever.
- The cost is a lock to keep, with entries that concurrent pull requests can collide on (resolved
  by a rebase and a re-freeze, as schema minors already are); a patch record for every non-doc
  change to anything a suite imports, which is small but frequent; a mutant run at every live minor;
  and more CI time once anything claims two versions. Today every claim is `1.0`, so the matrix adds
  no runs until the first minor.
- During an overlap the live suite carries the old major's checks under `until` tags until
  removal; there is no second copy to keep in step.
- Edits to helpers shared by many suites (`_util`, the fakes, `homelabnext.tlp`) now show up as
  patches of every suite that imports them. That is the point: a TLP-ceiling check cannot change
  meaning unseen.
- The overlap rule cannot finish until releases are cut. ADR-0046 decision 9 pages when they are
  not; until the first release, a major can land and deprecate, but nothing can be removed.
- An overlay learns of a deprecation as a loader warning at its pin, and of a removal as a failure
  on the pin move, never as a silent change.

### Implementation plan

Each step is one pull request, in this order; ADR-0040 decision 6 starts after step 6, once the
matrix can exercise the first `1.1` claims in the conformance step, the lab-in-a-box job and
`gateway-conformance`.

1. **This ADR** (`docs:`), with the index row. Tests: the ADR log lint and the summary stamp.
2. **Versions in the harness.** `Suite.version`, `check(since=, until=, severity_since=)`, the
   protocol `SINCE` and `UNTIL` maps, `--contract-version`, and the report fields; every suite set
   to `1.0.0`. Tests: a fixture suite with a check since `1.1` is not run at `1.0` and is run at
   `1.1`; a check `until="2.0"` runs at `1.1` and not at `2.0`; a severity raised at `1.1` is
   SHOULD at `1.0` and MUST at `1.1`; a subject without a member added at `1.1` passes the protocol
   check at `1.0` and fails it at `1.1`; a version above `Suite.version`, or a minor that no
   `since` names, exits 2 (the lock lookup replaces this in step 3); the report carries all three
   fields; every existing suite still passes against its fake at `1.0`.
3. **The lock and its gate.** `conform/contract_versions` 1.0 (draft) with examples and negatives,
   the import-closure digest, `SCHEMAS` on every suite, `hnx conform versions freeze` and `list`,
   `contract_check.py` under `tools/` with `--base`, the `1.0` entry and `1.0.0` patch record for every
   suite in the tree at the time, the version lookup in the harness, the review-tier listing, and
   `docs/interfaces.md` section 6 rewritten. Tests: one fixture change per class is classified
   right (a docstring edit needs nothing, a body edit a patch, an edit to a shared helper a patch
   on every importing suite, a new check a minor, a removed check or a changed signature a major,
   a schema major a contract major); an undersized bump, a new check tagged with a frozen `since`,
   an edited or deleted entry or patch record, a backward status move, and a `Suite.version`
   that differs from the lock are each refused; a patch that lets a mutant survive at an older
   minor is refused; a `retroactive` check tagged with a frozen `since` is accepted, runs at every
   live minor of its major, and fails a fixture provider that claims only `1.0`; a suite whose run
   loads an undeclared schema `$id` fails; an unknown version exits 2 from the lock.
4. **Contract pages for the extended suites.** The generator over all suites, the index's extended
   table, the companion notes, versions tables and `since`/`until` columns, and the MCP answers.
   Tests: `hnx docs capabilities check` fails with a page removed; each of the seven pages exists
   and is deterministic across two runs; an MCP `contract_data` answer equals its page's data.
5. **Claims, matching and evidence.** Target schema `conform/target` 1.1 with `versions`, the
   draft manifest's `contract_versions`, the loader's features-equality and versions-equality
   rules, the version rule beside `rules.dependants` for requirements and preferences, the report
   evidence check at cutover and in `hnx modules check --site --reports`, and the swap cutover
   re-check; every in-tree target and example manifest claims `["1.0"]`; the "not re-checked"
   sentence leaves `docs/modules/swap-flow.md`. Tests: a target without `versions` fails the lint,
   a `builtin: broken` binding without it passes, `fake: true` is treated as `builtin: fake`; a
   manifest whose target's features differ from the entry's is refused; a manifest whose claim
   differs from its target's is refused; a dependant requiring `1.1` against a provider claiming
   `1.0` is refused, `1.2` satisfies it, `2.0` does not; a `provisional` provider fails any
   versioned requirement; a preference at `1.1` against a `1.0` provider takes its fallback and is
   reported; a requirement naming a version not in the lock is refused; a swap whose incoming
   provider misses a dependant's version, or has no report, or a report with a stale
   `suite_digest` or a MUST failure, is blocked at cutover.
6. **The CI matrix.** `hnx conform matrix`, the job assignment, the per-version runs in the
   conformance step, the lab-in-a-box job and `gateway-conformance`, mutants at every live minor,
   and X-10 and `conform_coverage.py` at claimed versions. Tests: a claimed entry assigned to no
   job, or two, fails the static test; a binding that fails at one claimed version fails its job;
   a binding claiming `1.2` is run once, at `1.2`; the fake is parametrised over every non-removed
   minor in `tests/conform/test_conform_suites.py`.
7. **Majors, deprecation and removal.** `until` across a major, the `deprecated` and `removed`
   statuses, `hnx conform versions consumers`, the loader's warning and refusal, and the removal
   conditions in `contract_check.py` under `tools/`, proven end to end on a fixture capability in tests, not
   on a real one. Tests: a fixture contract goes 1 to 2 in one live suite with both majors
   runnable and both claimed; a signature change written as a new member plus an `until` passes
   the protocol check at each major; removal before a later release, before the window, or with a
   consumer left is refused, and succeeds when all three hold and deletes the `until`-tagged code;
   a removed version in a `requires` or `prefers` is refused by the loader.

## Alternatives

- **No versions; keep "a check is never removed, it may be added".** The status quo. It cannot
  retire a wrong check, it applies every new MUST to every provider at once, and it leaves the
  manifests' required `version` as decoration. Its one virtue, that a security check binds
  everyone, is kept by decision 11.
- **One version for the whole conformance package** (the distribution version). Any change to any
  suite would bump every contract, and a provider could not say which contract it meets.
- **Pin each provider to the suite at a git commit.** It answers "which suite" but not "is this
  compatible with what a dependant needs": commits have no order of compatibility, and running an
  old commit's suite needs that commit's harness, so CI would need a checkout per pin.
- **Copy the old major's suite and protocol under `_major/`.** A byte-for-byte copy still imports
  the live protocol, fakes and helpers, so it does not run the old contract; rewriting its imports
  breaks the frozen digest, and copying the whole import closure duplicates fakes and helpers for
  one operator to keep in step. The `until` tag keeps one tree.
- **A full-surface lock entry per patch.** Simpler to read, but every flake fix would append a copy
  of the surface and collide with every concurrent suite edit; patch records carry only what a
  patch changes.
- **The schema rule as is: bump in place, no overlap** (ADR-0001 decision 3). Right for stored
  documents, which are migrated; wrong for a contract with independent providers, which cannot all
  move in the same pull request, least of all in an overlay this repository's CI cannot see.
- **Consumer-driven contract testing with an external tool.** A new dependency and a second
  description of each contract, beside protocols and suites that already exist and already run.
- **Hand-written version files.** A surface typed by hand drifts from the code it describes; the
  lock is extracted, so it can be checked (ADR-0028).

### Operator decisions (2026-11-08)

The operator answered this ADR's open questions on 2026-11-08 ("use defaults"). The ADR stays
proposed; the answers are applied in decision 6.

- **The deprecation window.** Decided: at least one later release plus 30 days, counted the same
  way for every slot; privileged slots (secrets, idp, edge, broker, orchestration, records) get no
  longer window.
- **An in-tree provider behind a new major.** Decided: as decision 6 says. It may stay on the old
  major through the window, with the reason stated in its own manifest change; it need not claim
  both majors in the pull request that lands the new one.
