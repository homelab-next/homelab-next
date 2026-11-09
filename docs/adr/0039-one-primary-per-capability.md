---
summary: Each capability has one primary product; other rows are eval, retiring or legacy with nothing bound to them; the registry refuses a second primary.
summary_of: outline:sha256:30267d991007fea5
---
# ADR-0039: Give each capability one primary product

- **Status:** proposed
- **Date:** 2026-11-07
- **Related:** ADR-0002 (the registry and capability aliases), ADR-0005 (the swap procedure),
  ADR-0007 (model-role aliases), ADR-0011 (private inventory stays private), ADR-0020
  (projects), ADR-0022 and ADR-0038 (the LLM gateway), ADR-0023 (model serving), ADR-0026 (the
  orchestrator in this repository), ADR-0027 (slots, providers, the selection), ADR-0028 (one
  source of truth), ADR-0033 (egress and the enrichment-analyzer maximums), ADR-0034 (single
  sign-on); this batch: ADR-0040 (modules are replaceable by construction), ADR-0041 (versioned
  capability contracts), ADR-0042 (tested restores and cold start), ADR-0043 (the cutover
  ledger), ADR-0044 (the broker carries the vault's lifecycle), ADR-0045 (per-principal,
  short-lived credentials), ADR-0046 (repository governance), ADR-0049 (the SOC data plane moves
  as modules) and the ADR-0026 amendment (placing what the split left unplaced);
  `homelabnext/registry/model.py`, `homelabnext/registry/models.py`,
  `schemas/platform/service.json`, `examples/modules/slots.yml`,
  `homelabnext/agent/tool_classes.yml`
- **Depends-on:** ADR-0002, ADR-0027
- **Amends:** ADR-0002, ADR-0005

## Context

The registry already holds one row per capability: `semantic_problems` refuses a second row with
the same `capability` (`capability ... already provided by ...`), and `Registry.by_capability`,
the resolver, the DNS zone generator and the endpoint environment variable all assume it. That
rule has not given a lab one product per capability. It has pushed a second product into a
second capability *name*. A read-only audit of `main` and of a private overlay's registry
(2026-11-07) found these patterns:

- **Tier lives in the name.** Old products are kept under capabilities with a `-legacy` suffix,
  resolver replicas under `-secondary` and `-tertiary`, model engines under placement suffixes.
  Nothing reads the suffix, so nothing stops a consumer from binding to a legacy row, and nothing
  tells a replica (fine) from a second product (not fine).
- **Several products serve one need, none marked primary.** An overlay can hold two IdPs, two
  LLM gateways, two case managers, several task stores, several things called automation or
  orchestration, and model engines that an ADR has already retired, with nothing saying which
  one consumers use.
- **One name, two meanings.**
  - `orchestration` is this repository's agent-orchestrator contract
    (`conformance/protocols/orchestration.py`, `cap:orchestration` in `tool_classes.yml`). An
    overlay can use the same capability for a SOAR product. A workflow pack whose step targets
    `svc:orchestration` (`workflows/packs/agent-job-retry.yml`), deployed against such a
    registry, would send `agent.job.submit` to the SOAR. The example lab topology
    (`examples/lab-topology/services.yml`) makes the same mistake with a fictional SOAR, and the
    product-name vocabulary calls StackStorm "the orchestration controller's reference product"
    (`tools/product_names.yml`) where it is the `automation` slot's.
  - `agent-runtime` is the agent-runner slot (ADR-0026 decision 5, `slots.yml`, contract
    `null`). `examples/services.yml` uses it for the *controller* (`impl: orchestrator`, its queue
    summary as a status source), and `hnx agent access` finds the runner host through it
    (`homelabnext/agent/access.py`, `_runs_on`), so against a registry with no such row it needs
    `--runs-on`.
  - Guests: a guest record holds exactly one capability, which must be "known" to the class
    table or the conformance harness (`homelabnext/compute/validate.py`). Guests whose service is
    neither are forced onto a known capability as a catch-all, and `cap:orchestration` is the one
    in use, so the field answers no redundancy or blast-radius question.
- **A model-role binding resolves through the capability, not the row.** `ModelResolver` maps a
  binding's `svc:<row>` to that row's capability and resolves the capability
  (`homelabnext/registry/models.py`, `_capability_of`). Once two rows share a capability, a
  binding naming the second row would silently reach the first.

The operator's decisions (2026-11-07): Keycloak is the single sign-on and Authentik retires; the
old SOAR product and the old case manager were never meant to be part of this repository; the old
case manager's analyzer engine (also named Cortex) has been removed from the lab; Synapse with its
own Cortex and IntelOwl both stay, because their enrichment differs, and if Synapse is ever
replaced, IntelOwl stays and Synapse goes with its Cortex. Projects and tasks live in OpenProject
only (operator decision of 2026-10-31, `docs/projects.md`).

**Are we still relying on both IdPs?** This repository is not. Platform code depends on OIDC only
(ADR-0034 decision 1). The only realm it renders is Keycloak's. Authentik is left in two places:
product-specific defaults in the `sssd_ldap` role, and a stale product-vocabulary entry. **The
old lab still is**: its sign-on, and its applications' SSO clients, are in Authentik, and today
the realm generator would render Keycloak's format for whatever row holds `idp`. That reliance
ends at the IdP's ledger row (ADR-0043), which this ADR makes checkable.

## Decision

1. **Each registry row has a standing; at most one row per capability is `primary`.** The
   service registry's next minor version (2.9, `schemas/platform/service.json`; the batch numbers
   its service-schema minors in the merge order ADR-0039, ADR-0045, ADR-0042, so ADR-0045's
   `credentials` is 2.10 and ADR-0042's `recovery` block 2.11) adds an
   optional `standing` object: `{tier, until, why}`. `tier` is one of the following:
   - `primary`: the product consumers of the capability use. This is the default when `standing`
     is absent, so every existing registry keeps validating (ADR-0001: additive). Because
     absence promotes, adding a row or deleting `standing` is reviewed (decision 8).
   - `eval`: a candidate under test (conformance target, shadow lane, canary). Nothing consumes
     it.
   - `retiring`: a former primary that this repository deploys, in its rollback window
     (ADR-0005 decision 2: stopped, not destroyed). Nothing consumes it, and it is kept
     restorable.
   - `legacy`: a product of the old lab that this repository neither deploys nor models. Its row
     exists only so the cutover ledger (ADR-0043), the decommission and the credential
     revocation (ADR-0045) can enumerate it. An old-lab incumbent stays `primary` while
     consumers still reach it and goes straight to `legacy` at its switch: its rollback window
     is the ledger's, held by the old lab, and no generator of this repository renders for it.

   A non-primary row needs `until` (a date) and `why` (one line). `until` is not authored at the
   switch: `plan_promote` (decision 6) computes it from the ledger row's `rollback_days`
   (ADR-0043, the one source of the window), so the swap record of ADR-0040 step 7 and this field
   are both derived from it.

   The field is named `standing`, not `tier`, because `tier` already means a model role's size
   class (`model_roles.json`) and an agent's access tier (`tool_classes.yml`). This ADR exists to
   stop one name meaning two things, so it does not add a third meaning.
   `semantic_problems` replaces its uniqueness rule with *at most one `primary` per capability*
   (`capability X has two primaries: A, B`). Non-primary rows share the capability name of the
   primary they compete with or replace. They no longer invent a capability name for their tier.

   An `eval` or `retiring` row of an egress capability declares its own `tlp_ceiling`, never
   higher than the primary's. Shadow and conformance traffic to it is admitted under that row's
   ceiling and the ADR-0033 enrichment-analyzer maximums, not the primary's. Feeding real
   observables to a candidate enrichment row is an ADR-0033 egress like any other.

   A reference implementation gets a row only when a site runs it as the product, and then it
   is a product like any other: this repository's context store is the `context` primary (ADR-0026
   amendment, decision 11). A reference that exists only as a conformance target has no row and
   no tier.
2. **Only a primary answers for its capability.**
   - `Registry.by_capability` returns the primary or `None`, never another tier.
   - The capability alias `<capability>.<svc_label>.<domain>` (ADR-0002 decision 2), its SRV and
     TXT records, and the default endpoint variable `HNX_ENDPOINT_<CAPABILITY>` belong to the
     primary alone.
   - An `eval` or `retiring` row gets a record under its own row name (`<row>.<svc_label>.<domain>`)
     and the variable `HNX_ENDPOINT_<ROW>`. Conformance targets and the shadow lane address it by
     that name. `semantic_problems`' environment-variable uniqueness check covers the row-named
     variables and the row-named DNS records too, so a row named like another capability is
     refused. An `eval` or `retiring` row's name is no capability of the registry (any tier) and
     none the platform knows, it declares no `env_var`, and every capability's default variable
     stays its primary's even when the primary declares its own `env_var`.
   - A `legacy` row gets no record: the old lab serves its own name until the ledger retires it.
   - "A capability is provided" means "it has a primary". `semantic_problems`' `auth=idp but no
     service provides capability 'idp'` becomes *no primary provides `idp`*, and the edge's
     auth-proxy presence check becomes *no primary `auth-proxy`*: a capability whose only rows
     are non-primary fails closed.

   The generators follow the same rule:
   - **realm:** the realm is rendered for the `idp` row whose `impl` is the realm format's
     product, primary or eval. With none, it renders no realm (asked for by name, it refuses).
     It never renders for a retiring or legacy row. Its clients are for `auth: idp` rows that are primary or eval;
   - **edge site:** `public_hostname` is allowed on primary rows only and refused on eval,
     retiring and legacy rows (ADR-0040 step 2: a shadowed candidate has no public route);
   - **uptime and metrics targets:** primary and eval rows only;
   - **backup membership:** primary and retiring rows (a rollback needs the data);
   - **keyring rows:** primary and eval rows only.

   A golden test renders a registry holding every tier and fails on any artefact a tier may not
   have (`tests/generators/test_gen_golden.py`).
3. **Consumers bind only to a primary; observation is not a binding.** A *binding* is a
   reference that makes a consumer call a service. The bindings are:
   - a row's `upstreams` (by capability);
   - a model-role binding's `backend: svc:<name>` (`model_roles.json`);
   - a workflow pack step's `target: svc:<name>` (`workflows/packs/*.yml`);
   - a module's `requires` resolved through the site selection.

   A `svc:` target may name a row or a capability, as `_capability_of` already accepts both; a
   capability name means its primary. Agent lanes (`real`/`shadow`) name an executor, not a
   registry row, and are not bindings. ADR-0040 step 2 keeps a candidate on `shadow` lanes.

   A new check, `bindings.py` under `homelabnext/registry/`, is run as `hnx registry bindings` over a
   registry plus the role table, the packs and the selection. It refuses each of these:
   - an upstream to a capability with no primary (the registry's own rule since step 2, which
     the check reuses);
   - a role binding or pack target naming a non-primary row;
   - a `svc:` target or event source in a pack or its fixtures that names neither a registry
     row, nor a capability, nor a declared platform source. The platform sources are a list in
     `bindings.py`, each entry with a `why`: `svc:broker` (the action broker, which is part of
     the platform and not a capability), and the controller's old event source for the length
     of its overlap (ADR-0026 amendment, decision 16), removed by the change that drops that
     source at cutover+1. This closes the audit's finding that broker targets and event sources
     are held to the registry nowhere.

   Two exceptions are declared, not inferred. The evaluation report's `canary` bindings
   (`model_roles.eval.json`, read from the base commit as the swap gate reads it) may name an
   eval row. A conformance target file may name any non-legacy row. Status sources, the census,
   `hnx decommission` and the ledger read every tier: watching a row is not depending on it.

   At run time, `ModelResolver.resolve` raises on a binding naming a non-primary row, so the
   silent reroute above cannot happen. `resolve_binding` reaches an eval row only when the egress
   canary runner passes `allow_eval=True`, and then resolves that row by its row name (decision
   2), never through the capability. No file name or call path grants the exception. CI runs the
   check over `examples/` (`make check`). The overlay's `checks.yml` template runs it over `lab/`.
4. **Replicas are not tiers.** A row that serves the same data as a primary from a second place
   (a resolver secondary fed by zone transfer) keeps a capability of its own and declares
   `replica_of: <capability>`. The check requires that capability to have a primary with the same
   `impl`. Clients that list several resolvers bind to each replica row's own capability, which is
   primary. DNS primary and secondaries stay as they are, with the relation now stated.
5. **A capability name carries no tier.** The registry refuses a capability ending in `-legacy`,
   `-old`, `-new`, `-next`, `-eval`, `-test`, `-candidate` or `-v<N>`. It refuses one ending in
   `-secondary`, `-tertiary` or `-replica` without `replica_of`. Standing is a field (decision 1),
   never a spelling. A suffix list cannot catch every invented name; review does (decision 8).
6. **The decided primaries, and how a switch changes them.** The switch step of the replace
   protocol (ADR-0040 decision 5, step 6) is owned by ADR-0040 and is two changes in one
   reviewed diff: the selection diff applied by `apply_selection_diff`, and the standing
   promotion computed by this ADR's `plan_promote` (`homelabnext/swap/flip.py`), which ADR-0040
   calls. It is recorded in that service's ledger row (ADR-0043). `plan_flip` remains only for
   moving the same product (host, port, version) and refuses an `impl` change once a capability
   has a non-primary row; ADR-0005 decision 2 ("cutover by changing the registry `impl:`") is
   amended accordingly. ADR-0040's `status: retired, replaced_by:` is the module's record; this
   ADR's `standing` is the row's.

   The tier is not changed before the switch, because decision 3 must hold on the live registry
   every day. Until then the decided primary is an `eval` row and the incumbent stays `primary`.

   | Capability | Decided primary | Every other product, and its tier | What moves it |
   |---|---|---|---|
   | `idp` | Keycloak, on the lab's IdP host (ADR-0034) | Authentik: `legacy` at the switch (an old-lab incumbent, decision 1); its hand-made SSO clients go on the revocation ledger (ADR-0043 decision 8). The old task tool's sign-in through an edge access provider's OIDC client, a third IdP in neither registry: `legacy`, retires with the task tool; its client goes on the revocation ledger (ADR-0043 decision 8) | the IdP's ledger row; when it closes, this repository's Authentik-specific defaults in `sssd_ldap` and its vocabulary entry go. ADR-0034 is unchanged: its decision 7 stands, and the role stays for a lab whose IdP has an LDAP outpost; only this repository's Authentik-specific defaults go |
   | `auth-proxy` | oauth2-proxy (ADR-0034 decision 3) | none | — |
   | `llm-gateway` | the own gateway, `orchestrator/cmd/gateway` (ADR-0038, ADR-0026) | LiteLLM: `legacy` at the switch, once the own gateway passes the gateway suite against the lab (ADR-0038 decision 7). The isolated range's gateway is a row of a separate capability, `range-llm-gateway`, because the range is its own trust zone and its consumers must not reach the production gateway; its product follows the same switch on its own ledger row. **Decided 2026-11-08 (operator):** the range keeps its own model gateway, so `range-llm-gateway` stays a capability of its own | the gateway's ledger row; `render_litellm` and its lab-in-a-box targets are deleted at that row's close (ADR-0022, as amended by ADR-0038) |
   | `orchestration` (the agent-orchestrator contract) | the controller in `orchestrator/`, row name `orchestrator` | the private controller and its LLM queue: `legacy` at the controller cutover after stage 3 (ADR-0026 amendment) | the ADR-0026 amendment's placement of the controller |
   | `automation` | StackStorm (**decided 2026-11-08, operator**). It is `experimental` here (`tools/experimental.yml`) until a lab host runs it. Its row enters the overlay registry as `eval` in the overlay pull request that places StackStorm on a lab host (not in step 9's pass, which adds no row for a product nothing runs), and is promoted at its switch; until then the overlay's only `automation` row is the old SOAR's `legacy` one, and nothing in the lab may bind to `automation` | the old SOAR product: `legacy` | the `automation` ledger row. Its switch needs: `hnx workflows st2 check` (the repository's drift check: the rendered pack is committed and current) as a prerequisite; the live observable of step 9a, `hnx workflows st2 check --live`, passing against the lab host (the installed pack's digest equals the rendered one, and the event bridge shows deliveries); at least 7 days of shadow runs (the shadow window `st2-live` already requires, and ADR-0044's shadow days); and one live A03 run of a person-approved request through the broker |
   | `cases` | DFIR-IRIS | the old case manager: `legacy`, kept read-only until its ledger row closes. Its analyzer engine has been removed, so its guest record is deleted in the overlay. **Decided 2026-11-08 (operator):** the removed Cortex is that analyzer engine, not the one tied to Synapse | ADR-0049 brings IRIS in as a provider module with a real `cases` adapter (none exists today) |
   | `cti-graph` | Synapse, together with its own Cortex (Synapse's storage core, not the removed analyzer engine of the same name). One row, so they retire together. If Synapse is ever replaced, IntelOwl stays. | none | — |
   | `ioc-enrichment` | IntelOwl: on-demand analysis of single observables through its analyzers | none | — |
   | `projects` (tasks too) | OpenProject (ADR-0020). Recorded as the operator's 2026-10-31 decision; the operator may object here | the old task tool: `legacy`. This repository's Markdown store is the contract's frozen conformance reference, not a product any site runs, so it has no row and no tier (decision 1) | the task tool's ledger row |
   | `context` | this repository's reference store, `homelabnext.context.ContextStore` (ADR-0026 amendment, decision 11) | the Go store: retired by that decision, no row | — |
   | `dns` | one resolver product; its secondaries are replicas (decision 4) | none | — |
   | `inference` (production engine) | vLLM (ADR-0023 decision 3) | the desktop engine retired by ADR-0023 decision 7: `legacy`. A GGUF engine (decision 4 there) is a row of its own capability, named for what it serves | — |

   No homelab-next example, adapter, conformance target, fake or vocabulary entry names the old
   SOAR product or the old case manager. Their `legacy` rows exist only in the overlay registry.

   `cti-graph` and `ioc-enrichment` stay two capabilities, each with one primary, because they
   are two contracts. One is a graph that holds and enriches threat-intel knowledge in place. The
   other analyses a single observable on demand against external services, and its egress is
   bounded by ADR-0033's enrichment-analyzer maximums. Metrics, uptime and the status hub are
   likewise three capabilities, not three products for one.
   Model engines are backends, not capabilities consumers address: consumers name roles
   (ADR-0007), and only the gateway maps a role to a row. So "one primary" applies to each engine
   row's capability, and decision 3's role-binding check is what keeps a role off a retired
   engine.
7. **The overloaded names are fixed in this repository.** This ADR settles the vocabulary; the
   ADR-0026 amendment's PR 2.7 (decision 16 there) owns the wire names and the controller's
   example row.
   - **`orchestration` means the agent-orchestrator contract only.** The controller's example row
     becomes `orchestrator`, with capability `orchestration`, matching its event source
     `svc:orchestrator` (`orchestrator/internal/events`). Per the amendment, the packs' broker
     target moves to it at once, without an overlap (the old target names no controller in any
     registry), and only the event source keeps the one-release overlap.
     `examples/lab-topology/services.yml`'s fictional SOAR moves to `automation`, and the
     StackStorm vocabulary entry is reworded to the `automation` slot.
   - **`agent-runtime` means the runner slot only.** No service row carries it. `hnx agent
     access` finds the runner host by host role (`hosts.<name>.role: agent-runtime`) or the
     selection's placement, and refuses an ambiguous answer, as `provider_for` does.
   - **A guest's capability is one the registry places on it.** `hnx guests validate` gains
     `--registry`. With it, a guest's `capability` must be the capability of a row hosted on the
     registry host of the same name, so `cap:orchestration` fits only the guest that runs the
     controller. The current rule (known to the class table or the harness) is what forced the
     catch-all, and the new rule replaces it when a registry is given. Several capabilities per
     guest stay ADR-0027's follow-up.
8. **Standing is reviewed, and it expires loudly.** A change that adds or removes a row, adds,
   changes or removes `standing`, or changes `capability` or `replica_of` is human-approve in
   `hnx site review-tier`, because it moves what every consumer reaches; deleting `standing`
   promotes a row, and a new row under an invented capability name becomes a primary with its
   IdP client, keyring rows and backups. In the overlay, that change is a pull request the
   operator merges (ADR-0046). Validation stays free of the clock (`tools/hermetic_lint.py`). A
   new criterion in the Modularity pillar of `docs/checklist.md`, X-12 *"No non-primary registry
   row is past its `until`"* (ADR-0043's ledger row takes X-13), runs `hnx registry standing
   --overdue` and fails on any row past its date, so an `eval` that never ends or a `retiring`
   row nobody removed turns red instead of lingering.

### Out of scope

- How a candidate is proven and switched: the shadow, conformance, compare and rollback steps
  (ADR-0040); which contract version a candidate must satisfy (ADR-0041).
- Consolidating the search and index engines a lab runs under several products (ADR-0040 state
  classes, ADR-0049); the order a cold start brings primaries up (ADR-0042).
- Per-service cutover mechanics and dates (ADR-0043); revoking a retired product's credentials
  (ADR-0045); who may change a tier, and with which identity (ADR-0046).
- The agents' tasking queue and proposals: a broker lifecycle (ADR-0044), not the `projects`
  capability, so moving them is not a task-tool decision.
- The controller's wire names, example row and unit (ADR-0026 amendment, PR 2.7).
- Renaming the lab's agent keys; several capabilities per guest.

## Consequences

- "Which one do we use?" has one answer per capability, in one field of one file (ADR-0028). A
  second product can be tried without inventing a capability name, and it cannot be depended on
  by accident.
- The registry's uniqueness rule changes meaning, not strength: two primaries are refused as two
  rows were. Every reader of `by_capability` keeps its contract, now "the primary".
- The lab registry needs one reviewed pass, an overlay pull request the operator merges. It tags
  the rows in decision 6, moves the `-legacy` rows onto their real capability with a standing,
  declares the replicas, drops the removed analyzer's guest record (the operator confirmed on
  2026-11-08 that it is the case manager's Cortex), replaces the catch-all guest
  capabilities, registers the edge access provider's OIDC client as `legacy`, and adds the
  Keycloak and own-gateway rows as `eval`. That pass bumps the overlay's pin past the steps
  below, because decision 5 refuses names the lab uses today.
- Until StackStorm's `automation` row is promoted to primary, the workflow packs cannot be
  deployed against the lab registry. That is the intended effect: today one of them would aim at
  the SOAR.
- Legacy rows are inventory, not deployments. A reader that needs one (the decommission audit,
  the ledger) reads every tier on purpose. A generator that renders one is a defect, and the
  golden test fails on it.
- The number 0039 was briefly used on an unmerged branch for what became ADR-0026. That branch is
  stale and has no bearing on this ADR.

### Implementation plan

Each step is one pull request, merged green after a design review and a security audit.

1. **This ADR** (`docs:`), with its index row and summary stamp. Tests: the ADR log test
   (headings, `Depends-on`, the reciprocal `Amended-by` lines added to ADR-0002 and ADR-0005).
2. **Registry 2.9: `standing` and `replica_of`.** This step covers the
   schema, `Service` fields, the frozen copy of the previous minor, and the new rules in
   `semantic_problems`: one primary; `until` and `why` on non-primaries; `replica_of` naming a
   primary of the same `impl`; the suffix rule; `public_hostname` on primary rows only; a
   non-primary egress row's `tlp_ceiling` present and not above the primary's; "provided" meaning
   "has a primary" for `auth: idp`; row-named variables and records in the uniqueness check. It
   adds `replica_of: dns` to `examples/four-box-lab/services.yml`'s `dns-secondary` row, so the
   examples validate with one added `replica_of`. Tests: one case per rule in
   `tests/registry/test_registry_model.py`, each failing on the parent, including an eval
   enrichment row whose ceiling is above the primary's (refused), an eval row with a
   `public_hostname` (refused), and an `auth: idp` row whose only `idp` row is `eval` (refused).
   Schema negatives under `schemas/platform/negative/`.
   - **Also in this step:** an upstream to a capability with no primary is refused by
     `semantic_problems` (after the self-upstream check), the one binding the registry holds
     itself; step 5's `hnx registry bindings` reuses the rule. A public `auth: idp` row needs a
     primary `auth-proxy`. A non-primary egress row's declared `tlp_ceiling`, legacy included,
     is not above the primary's. An explicit `env_var` stays unique whatever the row's tier.
     `until` and `why` are refused on a primary. A replica capability is named
     `<replica_of>-<suffix>`.
   - **Consumers see primaries only.** Until step 3, `build_registry` holds every non-primary
     row back from consumers (`Registry.services` is the primaries; the rest are in
     `Registry.non_primary`). `by_capability` returns the primary or nothing, and a non-primary
     row's default endpoint variable is its row name's. So no generator, resolver or reader
     sees an `eval`, `retiring` or `legacy` row before step 3 widens each one by tier.
   - **The ceiling test uses `notify`.** An enrichment candidate is bounded by ADR-0033's
     enrichment-analyzer maximums, not by a registry `tlp_ceiling`: the egress capabilities
     that carry one are `notify`, `events`, `backup` and `webhook`, so the ceiling test is
     written against `notify`.
3. **Resolution and generators by tier.** Step 2 hides every non-primary row from consumers.
   This step widens them by tier: `by_capability` (primary only, as today), `Resolver`, the
   endpoint variables, the DNS zone, the realm, edge, uptime, metrics, keyring and backup
   generators, and the edge's auth-proxy presence check. Each reads `Registry.non_primary`
   for the tiers decision 2 gives it. The realm is rendered for the `idp` row
   whose `impl` is the realm format's product, primary or eval, and renders no realm with none. Tests: a
   golden render of an all-tiers registry; a resolver test showing an eval row is reachable by
   row name and never by the capability alias; a realm rendered for a Keycloak eval row beside a
   different primary; no realm when the only matching row is retiring.
4. **The names** (decision 7, vocabulary only): the lab-topology SOAR moved to `automation`, the
   StackStorm vocabulary wording, and `_runs_on` by host role. Tests: `hnx agent access`
   resolves the runner with no `agent-runtime` row and refuses two candidate hosts.
5. **`hnx registry bindings`** (`bindings.py` under `homelabnext/registry/`) over upstreams, role
   bindings, pack targets and event sources, and `requires`, with the declared platform sources
   and the two declared exceptions. `ModelResolver.resolve` raises on a non-primary row;
   `resolve_binding` takes `allow_eval`, which only the egress canary runner passes. The check
   runs in `make check` and the overlay template's `checks.yml`, and passes over the current
   examples (a `svc:` capability target means its primary; the old event source is a declared
   overlap source). It must merge before the ADR-0026 amendment's PR 2.7, whose tests use it.
   Tests: each binding site pointed at each non-primary tier is refused; a pack naming an
   unregistered `svc:` is refused; an agent lane naming the controller is not checked;
   `resolve_binding` on an eval row without `allow_eval` raises; the evaluation report's canary
   binding naming an eval row passes, and the same binding in `model_roles.json` is refused.
6. **Guests against the registry**: `hnx guests validate --registry`. Tests: a fixture guest
   declaring a capability no row on its host has is refused, and the example guests pass.
7. **Promotion as one change.** `homelabnext/swap/flip.py` gains `plan_promote(doc, capability,
   row, switched_on, rollback_days)`: the candidate moves `eval → primary`, and the incumbent
   moves `primary → retiring` (or `legacy` for an old-lab incumbent) with `until` computed from
   the date and `rollback_days`, as one diff with an exact inverse. `plan_flip` refuses an
   `impl` change on a capability with a non-primary row. ADR-0040's switch step calls
   `plan_promote` beside `apply_selection_diff`. Tests: promote, then inverse, is byte-identical.
   A promote that would leave two primaries or none is refused. `plan_flip` changing `impl` beside
   an eval row is refused.
8. **Expiry and review.** This step adds checklist row X-12 and its criterion (`hnx registry
   standing --overdue`), and adds row additions and removals, `standing`, `capability` and
   `replica_of` to the human-approve fields of `hnx site review-tier`. Tests: the example
   register runs the criterion green. A fixture row past its `until` fails it. A standing change
   is classed human-approve; deleting `standing` is classed human-approve; adding a row is
   classed human-approve.
9. **The overlay pass** (overlay pull request, operator merges), as listed under Consequences,
   validated with this repository's CLI at the bumped pin and clean under
   `private_leak_check.py private`.
   - **9a. The live StackStorm check**: `hnx workflows st2 check --live --host <svc:automation
     row>`, a read-only observable for the `automation` switch. It reads the installed pack's digest
     from the StackStorm host (the pack API, as a StackStorm user whose only RBAC grant is to view
     packs) and fails unless it equals the digest of the pack rendered at the pinned commit; and it
     reads the event bridge's status source and fails unless the bridge has delivered at least one
     event within its window and has nothing dead-lettered. Tests: against recorded API fixtures, a
     matching digest with recent deliveries passes; a drifted digest, no deliveries in the window,
     and a dead-lettered event each fail with their own reason; an unreachable host exits as not
     measured, never as a pass.
10. **The switches**, one per ledger row (ADR-0043): `idp`, `llm-gateway`, `orchestration`, and
    `automation` once StackStorm's `eval` row exists (it enters with the overlay pull request that
    places StackStorm on a lab host). Each is ADR-0040's switch step, carrying a `plan_promote` once
    its candidate passes its suite against the lab. `automation` has no suite; its switch takes
    the evidence the decision 6 table lists: `hnx workflows st2 check` as a prerequisite, step 9a's
    `--live` check passing, at least 7 days of shadow runs, and one live A03 run of an approved
    request through the broker. At each close, the non-primary row is removed with the
    support code only it used.

## Alternatives

- **Keep one row per capability and put the tier in the name** (today). Cheap, but the suffix is
  read by nothing, a legacy row can be bound like any other, and a replica cannot be told from a
  rival product.
- **A separate decisions file listing each capability's primary.** It would be a second source
  beside the registry (ADR-0028), and the two would drift on the first swap.
- **Allow several primaries with weights or priorities.** That is load balancing or failover,
  which the gateway's ordered deployments and the resolver replicas already express where they
  are wanted. For everything else it only postpones the choice this ADR makes.
- **Delete non-primary rows instead of tiering them.** Then a candidate under test, a rollback
  target and an old product awaiting retirement are invisible to the census, the decommission
  audit and the ledger, which are the readers that most need them.

### Operator decisions (2026-11-08)

The operator answered this ADR's open questions on 2026-11-08 ("use defaults"). The ADR stays
proposed; the answers are applied in decision 6 and the Consequences above.

1. **Which Cortex was removed?** Decided: as this ADR read it. The removed Cortex is the old case
   manager's analyzer engine; Synapse's own storage core stays with Synapse in the `cti-graph`
   row, and the overlay pass deletes the analyzer engine's guest record.
2. **`automation`.** Decided: StackStorm is the `automation` primary. Its row enters the overlay
   registry as `eval` with the overlay pull request that places it on a lab host, and is promoted
   at its switch (decision 6).
3. **The isolated range's gateway.** Decided: the range keeps its own model gateway, so the
   `range-llm-gateway` capability stays.

### Amendments (2026-11-08)

Made while ADR-0039 is proposed, in the pull request for step 3 after its design review and
security audit:

1. **The realm renders nothing without its product's row**, instead of refusing. Refusing made
   `hnx registry generate` fail for every lab whose IdP is another product. A full generate
   prunes a stale realm; `--only idp_realm` still refuses.
2. **A non-primary row's name and variable claim no capability.** A consumer with no registry
   cannot tell a row name from a capability, so decision 2's uniqueness rule is widened: an
   `eval` or `retiring` row may not be named like any capability (of the registry, any tier, or
   the platform's), may not declare `env_var`, and no row but a capability's primary may take
   its default variable.

### Amendments (2026-11-09)

Made while ADR-0039 is proposed, in the pull request for step 5 after its design review and
security audit:

1. **Step 4 places the runner by host role only.** An agent session's access block (`hnx
   agent pack --profile`) finds the runner as the one host whose role is `agent-runtime`;
   decision 7's second source, the selection's placement, is deferred because no caller of the
   access block holds a selection. Follow-up: read the selection's `agent-runtime` placement
   once a caller passes one, and refuse a host role that disagrees with it.
2. **A pack may name an unplaced capability only by declaration.** A pack is checked against a
   registry that may place no row of a capability it names (the controller's row reaches the
   examples only with the ADR-0026 amendment's PR 2.7c). Such a name is a note, not a problem,
   only where `bindings.UNPLACED` declares it for that pack, each entry with its reason and the
   change that removes it; any other name with no row is refused. A registry that holds any row
   of the capability judges it by decision 3 as usual.
3. **The overlay checks the packs that are deployed.** `make check` judges every pack in this
   repository; the overlay's `checks.yml` judges only the packs the pinned commit's deploy
   manifest pins (`--deployed`), since those are the packs that run against the lab.
