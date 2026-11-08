---
summary: Every guest has a backup policy and every datastore a consistent dump; drills restore into an isolated zone; boot and UPS order come from the dependency graph.
summary_of: outline:sha256:e2ac09ceaad99c52
---
# ADR-0042: Restores are tested and the lab can cold-start

- **Status:** proposed
- **Date:** 2026-11-07
- **Related:** ADR-0004 (role hooks), ADR-0005 (swap procedure), ADR-0012 (the hypervisor is
  substrate), ADR-0016 (control `backup-verify`), ADR-0018 (generated maps), ADR-0021 (keys stay
  offline), ADR-0027 (modules, `requires`, `data:` datasets, egress slots), ADR-0033 (labels,
  reader ceilings, the backups and off-site egress point); this batch: ADR-0039, ADR-0040,
  ADR-0041, ADR-0043, ADR-0044, ADR-0045, ADR-0046, ADR-0047, ADR-0048, ADR-0049, and ADR-0026's
  amendment; [checklist](../checklist.md) rows F-09, F-10, F-13, F-14, F-20, X-02, X-07;
  [role interface](../role-interface.md); [four-box lab](../four-box-lab.md);
  `ansible/roles/restore_drill/`, `homelabnext/compute/gen/backup_jobs.py`,
  `homelabnext/status/nut.py`, `homelabnext/power.py`, `conformance/protocols/backup.py`
- **Amends:** ADR-0008
- **Amended:** 2026-11-07 by ADR-0047 (decision 13): decision 9's UPS plan first creates, on each
  host it feeds, the local stop file of every fleet-stop point on that host, needing no network
  credential, in place of a call to `hnx fleet stop`
- **Amended-by:** ADR-0047

## Context

A backup that has never been restored is a hope, and a lab that has never been switched off and on
again does not know its own start order. The repository has the pieces of a recovery story but not
the story:

- **Backups are guest images only.** The guest model names a backup policy per guest
  (`backup.policy`, rendered by the `backup_jobs` generator into one job per policy), and the
  hypervisor takes an image of the whole guest. Nothing takes an application-consistent copy of a
  running database. The `compose_app` role's `backup` hook writes a list of bind-mount paths
  (`backup-manifest.json`), a cold file copy of whatever the database had on disk at that moment;
  its `export` hook is a `tar.gz` of the data directory (ADR-0008's status note already says
  decision 1 is not met). The role interface records two unverified gaps of the same hook: the
  manifest may omit `./` bind sources, and a restore may not keep file ownership
  ([role interface](../role-interface.md), "Developer follow-ups"). The one consistent dump in the
  tree is the controller store's `BackupForMigration` (`VACUUM INTO`, verified, mode 0600;
  `orchestrator/internal/store/backup.go`), and it runs only before a schema migration.
- **Opting out is silent.** A guest with no `backup` block reads as `policy: none`
  (`Guest.backup_policy`), and `hnx guests validate` checks only that a named policy exists. A
  real lab read for the audit of 2026-11-07 shows what that allows: about a third of its guests
  and hosts declare no policy, including hosts that carry stateful services, and none of its
  datastores, across a dozen engine kinds, has a dump of its own. The specifics are the overlay's.
- **The drill checks bytes, not service.** The `restore_drill` role (control `backup-verify`,
  ADR-0016) runs the backup product's command per guest, which restores the latest image to
  scratch space and compares it with the backup's own checksum; it records the result per guest
  (`drills.json`, keyed by guest) and fails health after 90 days. It never starts the restored
  guest, never asks whether the service inside answers, and never runs the capability's
  conformance suite against it. Checklist rows F-09 (3-2-1 with an immutable copy), F-10
  (restores are proven), F-13 (break-glass exercised), F-14 (recovery targets defined and met)
  and X-07 (export hooks exercised) are `SERVER` rows with no observable code behind them.
- **No copy leaves the building.** A lab's backup target usually sits beside its hypervisors.
  [Egress](../modules/egress.md) lists "backups and off-site copies" as an egress point whose
  content check is "not yet".
- **The keys to the secret store have no written procedure.** ADR-0021 decision 4 keeps OpenBao's
  unseal keys and the initial root token offline, in a password manager and on paper, and the
  [four-box lab](../four-box-lab.md) warns that the password manager is itself a guest of the lab.
  Lab-in-a-box runs OpenBao in dev mode, "starts unsealed", so no test has ever unsealed one.
- **The start order is nowhere.** The registry records what each service calls (`upstreams`, a
  list of capabilities), the knowledge graph turns that into `depends_on` edges (`hnx graph`), and
  module manifests declare `requires.capabilities` (ADR-0027). Nothing orders a start from them,
  and nothing finds the loops a homelab grows: the resolver reads its config from the secret store,
  the secret store's storage is on a host named through the resolver, the IdP's client secrets come
  from the secret store, the edge asks the IdP, the IdP is reached through the edge. The guest model
  has only `lifecycle.on_boot`. Lab-in-a-box's `depends_on` lines are written by hand.
- **Power is watched, not acted on.** `poll-nut` reads each UPS, `homelabnext.power` knows what
  every UPS feeds (a guest inherits its hypervisor's power), and the hub pages "on battery" and "low
  battery" naming the guests at risk (F-20). Nothing shuts anything down, in any order, and nothing
  brings it back, and no role configures NUT.
- **A restore may not run the code that wrote the data.** Nothing stops a stateful service from
  running a `:latest` image, so a restore next month can start different code from the code that
  wrote the data, and nothing flags a datastore whose engine major is past its end of life.
  Where the real lab stands on either is overlay data.

## Decision

1. **Every guest and host has a backup policy, said out loud.** Guest schema 1.7 (additive; no
   other ADR of this batch changes the guest schema) adds `backup.reason`; the schema keeps `backup`
   optional, so the frozen baselines and the existing fixtures stay valid (ADR-0001's additive
   rule, `tools/schema_check.py`). The requirement is a semantic rule in `hnx guests validate`,
   as `homelabnext.power` already does for `ups: none`: it fails a guest with no `backup` block,
   and a `policy: none` without a `reason`. A guest with `status: retired` is exempt; a `planned`
   guest is not, so its policy is reviewed before it is built. A hypervisor's `none` reason is
   ADR-0012's ("rebuilt from its configuration"), and is accepted only if no stateful service row
   (decision 2) is placed on it; a datastore on a hypervisor is backed up by its dump, whatever
   the host's image policy. This is a standing invariant, a new checklist row (`F-25`,
   `PUBLIC-NOW`): `hnx guests validate DIR` exits 0 and every non-retired guest's backup policy
   is a defined policy or a reasoned `none`. It extends `homelabnext/compute/validate.py` and the
   `backup_jobs` generator, which now also renders the reasoned opt-outs so the job list is the
   whole fleet.

2. **Every datastore has an application-consistent dump beside the image, with recovery
   targets.** A row is **stateful** when its module's state class is `private` (ADR-0040
   decision 1), or, for a role that is not yet a module, when it declares a `data:` dataset or
   its `compose_app` spec mounts a named volume or a bind source. A `platform` module keeps no
   private datastore and needs no dump: its data is backed up by the stateful providers of the
   slots it writes to. A stateful row carries a `recovery` block on its registry row (service
   schema 2.11, additive: the batch numbers its service-schema minors in the merge order ADR-0039
   (2.9), ADR-0045 (2.10), this ADR), the one declaration site that ADR-0040's dataset
   `recovery: <entry>` reference points at: one entry per datastore, `{engine, method, schedule,
   retain, rto, rpo}`. `method` is a closed vocabulary, one entry per engine kind, each
   implemented once as a task file in `compose_app` (and callable by any role):
   - `pg-dump` (`pg_dump -Fc` per database plus `pg_dumpall --globals-only`);
   - `mysql-dump` (`--single-transaction`);
   - `sqlite-backup` (the online backup API or `VACUUM INTO`, as the controller store does);
   - `search-snapshot` (an OpenSearch/Elasticsearch snapshot repository);
   - `kv-snapshot` (the secret store's raft snapshot, decision 6);
   - `lake-snapshot` (the catalog's metadata plus the object store's data prefix, taken after a
     catalog-wide commit point);
   - `record-tree` (an online copy of an append-only tree of one file per fact under one
     writer, such as ADR-0044's broker records: files are copied in name order up to a recorded
     high-water mark, which is consistent because a record is never rewritten);
   - `quiesced-files` (stop, copy, start: only for an engine with no online method, with the
     reason recorded).

   ADR-0040's `recovery: rebuild` for a rebuildable view stays a dataset declaration there, not a
   method here. `rto` and `rpo` are durations: validation refuses a `schedule` whose interval is
   longer than the entry's `rpo`, and a service drill (decision 3) fails when its `duration`
   exceeds the row's `rto`. The `backup` hook's contract changes from "write a list of paths" to
   "write the dumps into the backup path and a manifest naming each dump, its sha256, the engine
   version and the image digest that wrote it"; the image backup then carries a consistent copy.
   The hook also closes the two follow-ups: `./` bind sources resolve against the compose
   directory, and the manifest records owner, group and mode so a restore can set them. ADR-0040
   adds its clause to this one contract (the manifest names every named volume and bind source)
   and calls the hook from `lifecycle.backup`. Enforced by a new role-lint rule, `RL015` (a
   `compose_app` spec whose services run a known database image must have a `recovery` entry),
   and by X-02, whose "every registry row has backup" becomes "every stateful row has a `recovery`
   block with `rto` and `rpo`" (an automated criterion over the registry, the live half staying
   `SERVER`). F-14 becomes automated over the same block and the drill records (decision 4). This
   amends ADR-0008: the dump is for restoring the same product; the export (ADR-0008 decision 1)
   is for leaving it, and stays a separate, open-format hook.

3. **A restore drill restores a service, not a file, inside a zone that cannot touch the live
   lab.** `restore_drill` gains a second kind, `service`, beside today's `image` kind. A service
   drill restores the guest image or the dumps into a fresh instance inside a **restore zone**
   through the role's `restore` hook (role interface 1.1, ADR-0040 decision 1), starts the
   service, runs the role's `health` hook and the capability's conformance suite against the
   restored instance (a target file rendered for it, `hnx conform run`), compares a per-dataset
   fingerprint recorded at dump time (row counts per table, document counts per index, the lake's
   snapshot ids), checks `duration` against the row's `rto`, and tears the instance down.
   - **The zone.** It is a site-model zone with `purpose: restore` (site schema 1.8,
     additive, after ADR-0045's 1.7 in the batch's merge order). The network generators render it
     with no route to any other zone and no egress (a test of the firewall and router renderers
     holds this). The drill runs from an ephemeral runner placed inside the restore zone. The only
     flow into the zone is generated: the backup host pushes the restore set and pulls the drill
     record, and no other flow is allowed in either direction.
   - **Its dependencies are its own.** The restored service's dependencies come from inside the
     zone: a throw-away resolver, a throw-away IdP realm and a drill-only secret store seeded with
     fresh values. A restored service never resolves a `secret:` against the live store, and its
     registry view is the live row re-pointed at the drill instance and the drill store, never a
     live address. Its restored credentials (API tokens, password hashes, OIDC client secrets) are
     treated as compromised-if-leaked. A drill target file naming a live address or a live
     `secret:` path is refused before the drill starts.
   - **Its storage is red and temporary.** The zone's storage takes label `red` (ADR-0033: the
     strictest label of its content) and is wiped at teardown, and a teardown that fails fails the
     drill.
   - **Its credential is per run.** The drill runner's hypervisor credential is a per-run,
     short-lived credential scoped to the restore zone's pool (ADR-0045), never a standing API
     token.
   - **Cadence.** Every stateful row is drilled at least every `restore_drill_interval_days`
     (default 30), round-robin; a row may override the interval (`restore_drill_interval_days` on
     its `recovery` block) with a reason. The old lake's read-only archive (ADR-0043 decision 7) is
     the first override: it is drilled once in full at freeze, verified on the default interval
     against its `object-tree` manifest, and restored in full every 365 days.
   - **The record.** `drills.json` keeps its `guests` mapping for the `image` kind and gains a
     `services` mapping keyed by registry row beside it, each holding the last record per kind:
     `{kind, snapshot, verified, suite, fingerprint_match, duration}`. A record never carries
     dumped content. The role's restore task accepts both shapes, so old records still restore.
     ADR-0008 decision 2 (restore one product from its export) runs through the same kind, with
     `source: export`, and that is X-07's observable; ADR-0040's slot round-trip MUST is the suite
     half of it and does not redefine the row.

4. **Drill results are status, and a failure pages once.** The drill records are a `poll-file`
   status source generated for the backup host (one item per stateful row: ok when the last
   service drill passed within the interval, warn when it is overdue, fail when the last one
   failed or is older than `restore_drill_max_age_days`). The records reach the hub through the
   results transport ADR-0049 decision 7 builds for results and last-run records, so this step
   depends on it. A newly failed or newly overdue drill pages through the shared notifier,
   state-diffed like the UPS notice. F-10, F-14 and X-07 become automated criteria of the
   invariants register with an observable a stranger can run (`hnx recovery drills check
   --records drills.json --max-age 90d`, which also fails a row whose last drill exceeded its
   `rto`), so the hourly invariants run sees a stale drill the way it sees any other drift. The
   criteria are contributed with a cadence and a `positive_control` as ADR-0049 decision 7
   requires, by these modules: the core `recovery` module (F-10, F-14, X-07 and the cold-start
   criterion of decision 8), the guest validator in the core (F-25), the `backup` slot's off-site
   provider (F-09), and the `ups` module of decision 9 (F-20 and the UPS shutdown criterion).

5. **There is an off-site, encrypted, immutable copy (3-2-1), and the provider is the operator's
   choice.** The backup set is copied off site on a schedule (at least weekly, F-09's seven days)
   by a provider module filling the `backup` slot's off-site role (ADR-0027; ADR-0039: one primary
   off-site provider). The contract, not the product, is fixed here:
   - **Encrypted before it leaves**, with a key the provider never holds.
   - **Immutable for the retention window.** The lock is compliance-mode (or the provider's
     equivalent, which no account can bypass within the window). The automation credential may
     only put and read objects: it cannot change retention, lifecycle, versioning or the bucket
     policy. The provider's account/admin credential is held only in break-glass custody
     (decision 6), never in the secret store the automation reads.
   - **Tested.** A drill restores at least one service a quarter from the off-site copy, not the
     local one. The extended `backup` suite (ADR-0041 versions it) gains `copy_offsite`,
     `verify_offsite`, `delete_must_fail`, `shorten_retention_must_fail`,
     `disable_versioning_must_fail` and `restore_from_offsite`, with a fake object store that
     enforces a compliance lock and refuses retention and versioning changes from the automation
     identity; F-09's "a delete attempt with the automation identity fails" is these steps.
   - **The egress point is checked.** The off-site point in [egress](../modules/egress.md)
     becomes checked: the off-site module is refused unless its manifest declares client-side
     encryption. For this egress point, ADR-0033 decision 13's content check is replaced by a
     ciphertext-only check, because a whole-store encrypted copy cannot be filtered per item and
     contains `red` data: the egress refuses any object that is not encrypted under the off-site
     key, and the provider is a reader with ceiling `clear` that only ever holds ciphertext.
   - **Local dumps are red by default.** A dump on the backup host takes the strictest label of
     the datastore it copies (`red` when unknown), is written mode 0600 by the backup principal,
     and is readable by no agent principal. A drill record or status item never carries dumped
     content, only the fields of decision 3.

   The encryption key is held in the secret store **and** in break-glass custody (decision 6),
   since a copy whose only key lives in the lab is lost with the lab.

   **Decided 2026-11-08 (operator):** no off-site provider is chosen yet; the provider stays the
   operator's choice. No compliance-lock retention is set on any off-site store until the operator
   has picked both the provider and the retention window, because a compliance lock cannot be
   shortened or lifted by anyone inside its window, so a retention mistake cannot be undone until
   the window ends. Until then the lab has no off-site copy, and F-09's off-site half is not met.

6. **Break-glass is a written, tested procedure.** The secret store runs in server mode with
   integrated storage; initialisation produces Shamir unseal shares at a threshold the operator
   sets, and the initial root token is revoked after bootstrap. **Decided 2026-11-08 (operator):**
   unseal is by Shamir key shares, not auto-unseal, so the root of trust is never a key the lab
   must reach at boot.
   - **Custody.** Each share is held offline by its holder, on paper and in a password manager
     that is not hosted by the lab, with at least the threshold held away from the lab's
     premises. The off-site encryption key, the off-site provider's admin credential, the site's
     break-glass SSH key (ADR-0045 decision 8) and the overlay's age identity sit in the same
     custody (ADR-0021 decision 4).
   - **The procedure** (`docs/recovery.md`, generic; the lab's holders and places in the overlay)
     covers unseal after a cold start, generating a root token from the shares for a repair and
     revoking it after, rekeying when a holder changes, restoring a raft snapshot, and using the
     break-glass SSH key and the off-site credentials. Shares are entered at a console, never
     through an agent, the broker or a CI path.
   - **The dump principal.** `kv-snapshot` runs as a principal whose policy covers the raft
     snapshot path only, issued as a short-lived credential (ADR-0045).
   - **Tested twice.** In CI, a lab-in-a-box profile runs OpenBao in server mode with throw-away
     shares, and a nightly rehearsal initialises, seals, unseals at threshold, fails below
     threshold, generates and revokes a root token and restores a snapshot. In the lab, F-13's
     observable is the criterion (a manual criterion of the invariants register, `last_checked`
     at most 180 days old, no new parallel criterion): each break-glass procedure, including the
     operator unsealing a restored snapshot in the restore zone with the real shares, was
     exercised. That instance is destroyed afterwards, and any root token generated is revoked
     before teardown.
   - Agents never hold a share, a root token or any break-glass material (ADR-0045 short-lived
     credentials; ADR-0046: agents are not the operator).

7. **The cold-start order is derived from the dependency graph, never written by hand.**
   `homelabnext.recovery` builds one directed graph from what the tree already declares: registry
   `upstreams` (each resolved to the service row that provides the capability), module
   `requires.capabilities`, the implicit edges every row has (to `secrets` for any `secret:`
   reference, to `idp` and `auth-proxy` for `auth: idp`, to `dns` for every row, to its host for
   its placement, a guest to its hypervisor), and the substrate (router, switches, storage)
   first. It finds every strongly connected component (Tarjan); **a cycle fails generation**
   unless one edge of it is declared `start_without` on the row (`{capability, reason,
   degraded}`, in the same additive service schema minor as decision 2). `degraded` is a closed
   vocabulary: `serves-static` (for example a resolver serving its zone file before it can read
   the secret store), `queues` (accepts writes and replays them) or `refuses-until-ready`. A row
   with `auth: idp`, the `auth-proxy` row itself, and any edge to `secrets` from a row that serves
   secrets-gated content may declare only `refuses-until-ready`, and validation refuses any other
   value. The output is a generated `boot-order.json` (ADR-0018): tiers by longest path, each
   tier's members and the health check that admits the next tier, and the manual gates (the
   unseal of decision 6 is one; the order says who must act and where). `hnx recovery order`
   writes it; the hypervisor generator renders each guest's start order and delay from it
   (`terraform_proxmox`, ADR-0012); a test refuses a lab-in-a-box `depends_on` that disagrees with
   the graph. A property test holds that every edge points to an earlier tier or is a declared
   `start_without`; the cycle negatives (DNS, IdP, secrets and storage loops) and an auth proxy
   that declares `serves-static` on its `idp` edge are fixtures.

8. **The cold start is tested periodically.** A nightly lab-in-a-box job stops the whole stack,
   starts it tier by tier in the generated order, waits for each tier's health before the next,
   and runs the smoke checks; a second variant kills every container without a clean stop and
   starts again from the dirty state (the power-cut case). Either failing fails the nightly
   report. In the lab, the cold start is a manual criterion (at most a year old) performed in a
   maintenance window with the order as its checklist.

9. **The UPS shutdown and startup follow the same graph, and each host acts only on itself.**
   A plan generator reads the site's `power` section and `boot-order.json` and writes, per UPS,
   the hosts that UPS feeds (`homelabnext.power`) in reverse tier order, the host that runs the
   UPS's monitor last.
   - **The fleet stops first.** Every plan's first step, on each host the UPS feeds, creates the
     local stop file of every fleet-stop point on that host (ADR-0047 decisions 11 and 13), before
     any service the agents use is stopped. It needs no network credential and never calls `hnx
     fleet stop`.
   - **Each host shuts down only its own guests, locally**, through the hypervisor's own reverse
     start order, which decision 7 already renders into each guest's start order: applications
     first, then data engines, identity, secrets and DNS. Cross-host order comes from tier waits
     announced through NUT's own primary/secondary protocol, not from a remote power credential,
     so the plan generator orders only hosts.
   - **Triggers are authenticated and debounced.** upsd is reached over TLS with a per-host
     upsmon user (`secret:` references, as the recorded `tls.txt` transcript shows). A trigger is
     one of the NUT states the hub already reads (on battery past a set time, a runtime below a
     threshold, or low battery, whichever comes first) and must hold for two consecutive polls; a
     return to line power before the plan completes stops it.
   - **Startup** after power returns is the boot order of decision 7, behind each guest's
     `on_boot`.

   A new role configures the NUT client and its scheduler on each host from the plan, as the `ups`
   module that contributes this decision's criteria (decision 4). Tested by replaying the recorded
   upsd transcripts already in `tests/status/fixtures/nut/` (the on-battery and online transcripts,
   the latter including a low-battery UPS) into the plan runner in dry-run, asserting the order, the
   local stop files first, the two-poll debounce and the abort; and by a unit test per UPS that
   nothing a UPS does not feed is touched. A lab needs a `power` section before this can run (F-20).

10. **A restore runs the code that wrote the data.** Every image a stateful row runs is pinned by
    tag and sha256 digest (role-lint RL009 for roles, `compose_app`'s validate for specs, and a
    new overlay CI check over the overlay's own specs that refuses `:latest` and a missing
    digest); each dump's manifest records the digest that wrote it, and a service drill restores
    with that digest, then with the current pin when they differ, so an upgrade's restore path is
    proven before the upgrade. A stateful engine past its end of life is drift: an automated
    criterion reads the pin-freshness report and an end-of-life table and fails on any. An
    end-of-life major is upgraded by a dump from the old major and a restore into the current
    one, done as a service drill (decision 3) before the row's cutover (ADR-0043). The operator
    confirmed ADR-0043 decision 7's fresh lake on 2026-11-08, so the new lake's query engine and
    catalog are pinned from the first deploy and dumped with `lake-snapshot`.

## Consequences

- Restores are rehearsed by the conformance suite the service was accepted with, so "the backup
  verified" and "the service came back" stop being the same claim, and every stateful row states
  how long it may be down (`rto`) and how much it may lose (`rpo`), checked at every drill.
- Opting a guest out of backup becomes a reviewed sentence rather than a missing block, and the
  backup job list covers the whole fleet. A lab's undeclared guests and hosts each need a policy
  or a reason before its overlay validates.
- The lab gains a restore zone (with its own throw-away resolver, IdP realm and secret store),
  more disk on the backup target for dumps beside images, and a drill workload that runs every
  night on the backup host; drills of the large engines (a SIEM's search engine, the lake) are
  long and are scheduled for one a night at most.
- An off-site provider is a recurring cost and an external dependency, chosen by the operator
  and not chosen yet (decision 5). Its automation credential is put-and-read only under a
  compliance lock, so pruning off-site copies happens only by retention expiry, and a retention
  mistake cannot be undone inside the window; that is why no retention is set before the provider
  and the window are both chosen.
- A cold start needs a human at the unseal gate: the operator chose Shamir shares over
  auto-unseal (decision 6). The order makes that gate visible instead of discovering it during an
  outage.
- Every new service row with `upstreams`, every `secret:` reference and every module `requires`
  now changes the boot order; a change that forms a cycle fails generation and must name its
  `start_without` with a reason and a degraded mode the validator accepts.
- Cross-batch obligations:
  - ADR-0039's single primary per capability is the product the drill targets.
  - ADR-0040's state class decides which rows are stateful; its dataset `recovery` reference
    points at decision 2's block, and its `restore` hook is what decision 3 drives.
  - ADR-0041 versions the extended `backup` suite and the `recovery` block.
  - ADR-0043: a passing service drill of the new home is the restore evidence this ADR offers the
    `new-shadow` to `new-primary` gate of a stateful row; it is a gate only once ADR-0043's
    evidence table lists it. The old lab's data arrives by a restore, not a copy of files.
  - ADR-0044's broker records are a stateful row with a `record-tree` dump from day one, and the
    controller store of ADR-0026's stage 2 with a `sqlite-backup` dump.
  - ADR-0045: the break-glass material of decision 6 is outside the agents' reach and is tracked
    by ADR-0045 decision 11 as standing exceptions with no expiry, exercised under F-13. A
    restored service's credentials are rotated by ADR-0045's drills.
  - ADR-0047: an agent-dispatched drill is a broker action at the approval tier for
    state-changing actions, traced like any other; its result to the agent is the drill record
    only.
  - ADR-0048's fuzzing and shared vectors cover the graph builder and the cycle detector.
  - ADR-0049's results transport carries the drill records to the hub, and the modules named in
    decision 4 own the backup, restore and power checks of its ownership table.
  - The old lake's archive (ADR-0043 decision 7) is drilled at freeze, then verified against its
    manifest on the drill interval and restored in full yearly, not drilled in full every month.

### Out of scope

- The choice of the backup product and of the off-site provider (the operator's; decision 5 fixes
  only the contract).
- High availability, replication and a warm second site: this ADR is about getting back, not
  staying up.
- Backup of workstations and of data outside the lab's guests (a laptop, a phone).
- Moving the old lab's data into new services and the lake's history (ADR-0043).
- Rotating the credentials a restore brings back (ADR-0045); a restored service's credentials are
  rotated by that ADR's drills, not here.
- Consolidating a lab's search and column engines: a candidate under ADR-0039, not a recovery
  question.

### Implementation plan

Each step is one pull request; the tests named are what it proves. Data loss is the larger risk,
so the dumps, drills and off-site copies come before the boot order.

1. **Backup policy invariant.** Guest schema 1.7 (`backup.reason`, additive), the `hnx guests
   validate` rule (retired guests exempt), `backup_jobs` renders opt-outs, examples and fixtures
   updated, checklist row F-25 and its criterion. Tests: negatives for a missing block and a
   reasonless `none`; a retired guest with no block passes; a hypervisor `none` refused when a
   stateful row is placed on it; the generator golden lists every guest; `schema_check` passes
   against the frozen baselines.
2. **Consistent dumps** (was step 5). The `recovery` block with `rto` and `rpo`, the `backup`
   hook's new contract, `compose_app` dump task files per method, the manifest with digests,
   ownership and `./` sources, `RL015`, X-02's automated half, the `schedule`-versus-`rpo` rule.
   ADR-0040 step 2 (its dataset `recovery` reference) lands with or after this step, and
   ADR-0040 step 3 adds its named-volume clause to this step's manifest rather than rewriting the
   hook. Tests: in lab-in-a-box, a Postgres and a SQLite dump taken under a concurrent writer
   restore with matching fingerprints; a `record-tree` copy taken during appends restores every
   record up to its high-water mark; the lint refuses a database image with no entry; a schedule
   looser than the `rpo` is refused; manifest fixtures for `./` sources and ownership.
3. **Service drills in a restore zone** (was step 6). `purpose: restore` in the site model and
   the network renderers, the in-zone ephemeral runner, the drill-only resolver, IdP realm and
   secret store, the `service` kind of `restore_drill`, the drill target file, fingerprints, the
   `services` mapping of `drills.json`, the per-run hypervisor credential, the per-row interval
   override. Tests: firewall and router goldens show the restore zone isolated in both directions
   except the generated push and pull; a drill target naming a live address or a live `secret:`
   path is refused; a lab-in-a-box drill restores the lake catalog's Postgres and passes the
   `lake-catalog` suite; a corrupted dump fails the fingerprint; a drill longer than its `rto`
   fails; a failed teardown fails the drill; an old guest-only `drills.json` still restores.
4. **Drill status and paging** (was step 7). Needs ADR-0049's results transport. The generated
   `poll-file` source, the state-diffed notice, `hnx recovery drills check`, F-10, F-14 and X-07
   as automated criteria with their positive controls. Tests: hub fixtures for ok, overdue and
   failed; the notifier pages once per change; the criterion fails on a stale record and on an
   `rto` miss.
5. **OpenBao break-glass** (was step 9), so `kv-snapshot` exists before off-site copies. The
   server-mode lab-in-a-box profile, the nightly unseal rehearsal, `kv-snapshot` dumps under a
   snapshot-only short-lived principal, `docs/recovery.md` (shares, root token, break-glass SSH
   key, off-site credentials), F-13's manual criterion. Tests: the rehearsal unseals at
   threshold, refuses below it, revokes the generated root token (a later call with it fails), and
   restores a snapshot whose secrets read back; the dump principal is refused a non-snapshot path.
6. **Off-site copies** (was step 8). Needs ADR-0041's suite versioning. The `backup` suite's six
   new steps and a compliance-locking fake object store, the ciphertext-only egress check for the
   off-site point, a reference provider module. Tests: the suite passes against the fake;
   `delete_must_fail`, `shorten_retention_must_fail` and `disable_versioning_must_fail` each fail
   against a fake without the matching protection; the egress check refuses plaintext and an
   object encrypted under another key.
7. **The recovery graph and the boot order** (was step 2). `homelabnext.recovery` (graph,
   implicit edges, Tarjan components, `start_without` with its closed `degraded` vocabulary in the
   service schema), `hnx recovery order`, a `boot-order.json` golden for the examples. Tests: each
   cycle fixture (DNS, IdP, secrets, storage) fails with the cycle named; a declared
   `start_without` breaks it; an auth proxy declaring `serves-static` on its `idp` edge is
   refused; a property test over generated registries that every edge points earlier; the golden.
8. **The order reaches the hypervisor and lab-in-a-box** (was step 3). `terraform_proxmox`
   renders start order and delay from the tiers; a test compares lab-in-a-box's `depends_on` with
   the graph. Tests: the generator golden; the comparison fails on a hand-made drift fixture.
9. **The cold-start rehearsal** (was step 4). `smoke.sh --cold-start` (tiered start) and
   `--power-cut` (kill, restart dirty) in the nightly workflow. Tests: the nightly job passes; a
   deliberately unhealthy tier-1 fake stops the tiers after it and fails the report.
10. **Ordered UPS shutdown and startup.** The host-order plan generator, the NUT client role over
    TLS with per-host users, the dry-run runner, the local stop files as the first step
    (ADR-0047 decision 13). Tests: replaying the recorded on-battery and online transcripts (the
    latter with a low-battery UPS) yields the expected order, the local stop files first and the
    abort; a single-poll trigger does not
    fire; per-UPS tests that nothing outside a UPS's load is touched; the monitoring host is last;
    no plan step uses a credential for another host.
11. **Pins and end of life.** The overlay's pin check (an overlay pull request, merged by the
    operator), the end-of-life criterion, drills that restore with the writing digest. Tests: the
    check refuses a `:latest` and a digest-less fixture; the criterion fails on an engine fixture
    past its end of life. The lab's own pins and upgrades are overlay and stand-up work recorded
    in `TODO.md`.

## Alternatives

- **Keep image backups only.** They restore a guest, and an image of a running database restores
  whatever was on disk mid-write. Engines usually recover from that, which is exactly the claim
  nobody has tested.
- **Dumps instead of images.** A dump is smaller and portable but leaves out everything around the
  engine (configuration, certificates, local state); keeping both costs disk and buys a restore
  that does not depend on either alone.
- **Declare the dump on the module's dataset instead of the registry row.** It sits closer to the
  data, but roles that are not yet modules have no dataset, and ADR-0040 already points its
  dataset reference at this block; two declaration sites would drift.
- **A hand-written boot order in the overlay.** It is quicker to write and wrong the first time a
  service gains an upstream; the graph already exists, and only a generated order stays in step
  with it.
- **A central UPS runner that powers off every host.** One place to read, and it needs a
  standing credential to every hypervisor; local shutdown with NUT's own primary/secondary
  signalling needs none.
- **Auto-unseal by default.** It removes the human from the cold start, and moves the root of
  trust to a key the lab must reach at boot (a cloud KMS, or a second secret store that is itself
  in the boot order). Rejected: the operator chose Shamir shares on 2026-11-08 (decision 6).
- **Drills against the live network or the live secret store.** Cheaper than a restore zone with
  its own dependencies, and a restored copy of a service that pages, writes to the bus, answers on
  the live address or authenticates as the live service is an incident of its own.
- **Name an off-site provider here.** The cost, the jurisdiction and the trust are the operator's,
  who has not chosen one yet (decision 5); the contract (client-side encryption, a compliance
  lock, a tested restore) is what this repository can check.
