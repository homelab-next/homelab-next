---
summary: The SIEM manager, log pipeline, lake writer, sensors and case and intel adapters become modules; native rules are tested; each lab check is an owned criterion.
summary_of: outline:sha256:22e0606aa622a9b3
---
# ADR-0049: The SOC data plane and the lab's checks move as modules

- **Status:** proposed
- **Date:** 2026-11-07
- **Related:** ADR-0006 (detections as code), ADR-0008 (export hooks), ADR-0009 (the bus at the
  reaction seam), ADR-0011 (real detections stay private), ADR-0013 (the status hub), ADR-0017
  (approval-gated actions), ADR-0021 (the private overlay), ADR-0027 (feature and provider
  modules), ADR-0030 (the broker), ADR-0033 (TLP), ADR-0036 (novelty baselines); this batch:
  ADR-0039 (one primary per capability), ADR-0040 (modules are replaceable by construction),
  ADR-0041 (versioned capability contracts), ADR-0042 (tested restores and cold start), ADR-0043
  (the cutover ledger), ADR-0044 (the broker carries the vault's lifecycle), ADR-0045
  (per-principal, short-lived credentials), ADR-0046 (repository governance), ADR-0047 (agent runs
  traced, budgeted and evaluated), ADR-0048 (verification beyond one reviewer) and the ADR-0026
  amendment (placing what the split left unplaced);
  [detections](../detections.md), [log pipeline](../log-pipeline.md), [status hub](../status.md),
  [scripts](../scripts.md), [modules](../modules.md), [contributions](../modules/contributes.md),
  [slots](../modules/slots.md), `homelabnext/invariants/runner.py`,
  `homelabnext/generators/fleet_units.py`, `homelabnext/lake/checkpoint.py`,
  `homelabnext/detections/backends/wazuh.py`, `homelabnext/modules/review_tier.py`
- **Depends-on:** ADR-0006, ADR-0027, ADR-0039, ADR-0040, ADR-0043
- **Amends:** ADR-0006

## Context

The read-only parity audit of 2026-11-07 ranked what the lab would lose if it cut over today. After
the agent fleet (ADR-0026), the next two losses are these:

- **The SOC data plane.** The old lab runs a SIEM manager with an indexer and dashboard, the lab's
  own native rule files, Python writers that turn the manager's stream into OCSF tables in the
  lake, a log pipeline with a committer timer, network sensors (an IDS and a network monitor), an
  endpoint forensics server, a case store, a threat-intel platform, a CTI graph and an enrichment
  service. homelab-next has the contracts and libraries for most of these (the Sigma toolchain,
  the `log-pipeline` and `cases` suites, `homelabnext.lake` with commit-then-checkpoint writes,
  pinned OCSF subsets, the runtime and TLP labels), and roles for the SIEM agent
  (`ansible/roles/wazuh_agent`) and sensor enrolment (`ansible/roles/suricata_enroll`). It has no
  manager role, no pipeline role, no ported writer, no network-monitor or forensics module, and no
  real adapter for cases, threat intel, the graph or enrichment. Every module under
  `examples/modules/` is fictional, and there is no top-level `modules/` directory yet.
- **Well over a hundred detector and collector timers**, from a scheduler role and from other
  roles and scripts. They include a daily ingest audit, which compares every log source with its
  own cadence and clusters manager errors into ongoing and recovered bursts, and a fleet health
  check that pages on stuck and fleet-wide deferrals. The audit sorts the rest into families:
  agent dispatch, fleet and agent health, governance hygiene, repository drift, invariants, SOC and
  lake health, host and network health, identity collectors, and generated pages. homelab-next has
  one generic unit renderer (`fleet_units`), last-run records for role timers (`job-last-run`,
  checklist O-10), an invariants runner that pages newly red criteria only (`page_changes`, L-03),
  and catalogued `kind: check` scripts (`hnx scripts`, M-01 to M-04). It has none of the checks.
  The audit calls the result the loss of "every silent-failure detector the lessons register was
  built on".

Five facts in this repository shape the answer:

- **Detections are Sigma only in practice.** ADR-0006 decision 4 allows a native rule "with a
  stated reason", and says the native-rule location and its lint are not implemented. Today
  `compile` names each rule a backend cannot express, leaves it out of the bundle and exits 1. The
  engine stub (`backends/wazuh.py`) expresses a conjunction of single-alternative selections. A
  manager's frequency and timeframe rules, parent-rule chains, list lookups and the level overrides
  that silence its stock rules have no Sigma form here. Translating them would lose them.
- **Modules can already contribute what a check needs, but the schema lags the docs.**
  `contributes:` has `scheduler_jobs` (a `fleet_units` spec), `invariants`, `status_sources`,
  `notify_pairs`, `lake_tables` and `detections`. [Contributions](../modules/contributes.md) and
  the loader cite criterion ids `<module>/<slug>` under "registers/invariant 1.1", but
  `schemas/registers/invariant.schema.json` on main is still 1.0, whose id pattern accepts only
  the central register's `X-NN` form. Nothing yet assembles the selected modules' criteria into a
  register that runs, and nothing schedules a criterion.
- **Criteria are owner tier, fleet units are human tier.** `homelabnext/modules/review_tier.py`
  gives `invariants` and `detections` to the owner, and `scheduler_jobs`, `roles` and
  `entry_points` to a human. An invariant's observable is an executed command whose register is
  trusted input (the runner's docstring). A design that turns a criterion into a scheduled unit
  must not let an owner-tier change create code execution on a host.
- **A timer may not run a check directly.** `hnx scripts runner-lint` (M-04) refuses it: a
  `kind: check` script runs under an invariants criterion, so its exit codes (0 pass, 1 to 99 fail,
  100 or more could not measure) mean one thing everywhere. `hnx scripts` has `catalog`,
  `reality`, `runner-lint` and `list`, and no way to run a catalogued script by id.
- **Several old checks read a product's private storage.** The tech-debt audit lists checks that
  open the controller's database, the notifier's cache file and the IdP's database. ADR-0040
  decision 2 forbids that for modules.

The operator's decisions bound the product set. The old SOAR product and the old case manager are
not part of homelab-next. The old case manager's analyzer engine has been removed. The CTI graph
and its own storage layer stay, and so does the enrichment service: they enrich differently
(ADR-0039 decision 6). The lake starts fresh at the cut, with the old lake kept as a read-only
archive (ADR-0043 decision 7; confirmed by the operator on 2026-11-08), so this ADR builds on
`fresh` and says where a `migrate` stamp would change it.
Single sign-on is Keycloak; the old IdP retires (ADR-0039).

## Decision

1. **Each SOC product is one provider module, and each lab check is a criterion its owner module
   contributes.** Public modules live under a new top-level `modules/<id>/`, beside `orchestrator/`.
   The lab's own content and lab-only checks live in overlay modules,
   `<overlay>/lab/modules/<id>/`, which the loader already reads. Every module passes `hnx modules
   check` (the loader's rules, in `make gates` and in the overlay's deploy workflow) and declares
   its state class (ADR-0040 decision 1). The product-name lint (X-11) keeps product names inside
   their own module directories, so the core and core modules name only slots. The core paths
   that carry product names today (`ansible/roles/wazuh_agent`, `ansible/roles/suricata_enroll`,
   `homelabnext/detections/backends/wazuh.py`) move into their modules, and their entries leave
   `tools/product_names.baseline.json` in the same pull request (plan steps 6a and 10).

   **Identifiers.** A provider module's id is its product's name. Under ADR-0040 decision 4's
   provider-namespace exemption, the names that exist only inside that namespace (its
   `secret:<id>/...` references, its bound fleet units, its own criterion ids such as
   `wazuh/rule-drift`, its private tables) carry the product name and go with the module. A name
   another module or a person addresses does not: the OCSF tables are named by capability, the
   indicator table is `threat_intel.indicators`, and the hunt results table that the novelty
   analyzer reads is `endpoint_forensics.hunts`. The identifier lint holds for those.

   | Module (kind) | Fills | State class | Notes |
   |---|---|---|---|
   | `wazuh` (provider) | `siem-source`, `detections`, `hot-index` | private: the indexer is `view_of` the lake's alert dataset (ADR-0040 decision 7) | decision 2; absorbs `wazuh_agent` for enrolment |
   | `vector` (provider) | `log-pipeline` | none | decision 3; a pass-through pipeline is refused while any selected source needs a label set in transit |
   | `lake-writer` (core) | the OCSF tables, by `lake_tables` | platform | decision 3; names no product |
   | `suricata`, `zeek` (provider) | `network-sensor` (new, stage 1) | none: their local logs are rotating buffers that the pipeline ships, not datasets | decision 4; `suricata` absorbs `suricata_enroll` |
   | `velociraptor` (provider) | `endpoint-forensics` (new, stage 1) | private; hunt results go to the lake | decision 4; **privileged**: the server is an authority (`remote-admin` class), and its manifest is human-approve |
   | `alert-intake` (core) | consumes `events`, writes to `cases` | none | decision 5; replaces the old SOAR flow |
   | `dfir-iris` (provider) | `cases` | private: case narratives are the app's authority | decision 5 |
   | `misp` (provider) | `threat-intel` (new, stage 9) | private, export `stix` | decision 6 |
   | `synapse` (provider) | `cti-graph` (new, stage 9), with its own storage layer | private, export `stix` | decision 6; one row, so both retire together |
   | `intelowl` (provider) | `ioc-enrichment` (new, stage 5) | private: job history and results, with backup and restore, export `jsonl` | decision 6; an egress slot |
   | `source-census` (core) | criteria over `lake-query` | none | decision 9 |

   The new slots go into `examples/modules/slots.yml` with a stage, formats and `stateful`.
   `threat-intel`, `cti-graph` and `ioc-enrichment` are `stateful: true` and join ADR-0040
   decision 6's export and import scope, and this ADR adds `stix` (STIX 2.1 bundles) to the
   registry's export-format vocabulary when it registers them. `endpoint-forensics` is
   `privileged` in the slot registry. Each new slot is provisional (`contract: null`) until its
   contract ships, and then it starts at contract 1.0 (ADR-0041 decision 1). ADR-0039's standing
   applies to every row these modules create: one primary per capability, and nothing binds to
   the old SOAR product (`legacy`) or the old case manager (`legacy`, read-only until its ledger
   row closes).

2. **The SIEM manager is a provider module, and its native rules are module content with tests.**
   - The `wazuh` module ships the manager, indexer and dashboard role, a reference by name to the
     enrolment template credential in the module's own namespace, and the engine adapter. The
     adapter moves the stub's compile and `evaluate` into the module and adds `load(bundle)`,
     `test_native(rule, line)` and `deployed_digest()`. It maps the engine's level to the OCSF
     `severity_id`, which implements ADR-0006 decision 3 for this engine.
   - **The manager acts on no host.** Active response is disabled on the manager and on the
     agents, and remote commands from centralized configuration stay off (`remote_commands` 0 in
     the agent role). A response that changes a host is a `remote-admin` broker action (ADR-0017,
     ADR-0030). A role test asserts both settings.
   - **This amends ADR-0006 decision 4.** A rule is native only when Sigma cannot carry it. The
     module's `contributes.detections` entries take a `format` (`sigma` or `native`). A native
     entry names its `det:` id, its engine and a `native_reason` from a closed list:
     `engine-correlation` (frequency, timeframe, same-field or parent-rule chains), `decoder`
     (it reads a field only the engine's own decoder produces), `list-lookup` (an engine-side
     list) or `stock-override` (it changes the level of, or silences, a rule the product ships).
     Any other reason is a lint error. The location is `detections/native/<slug>.<ext>` in the
     engine's module. For the lab's own rules, the location is the overlay module of the same id,
     because real detections stay private (ADR-0011). The lab's own Sigma rules (including
     ADR-0047's honeytoken canary-hostname rule, whose canary zone is overlay data) sit in an
     overlay detection-content module, `lab-detections`.
   - **A `stock-override` is the riskiest native class, so it is reviewed as one.** An entry with
     that reason is human-approve under `homelabnext.modules.review_tier`, although other
     detection entries are owner tier. It needs a `must_not_fire` fixture for the case it
     silences, and a `must_fire` fixture on which the overridden stock rule still fires for a
     non-benign variant. Overrides count in their own ratchet baseline, apart from the other
     native rules.
   - **A native rule is tested as a Sigma rule is.** Its fixtures sit in
     `fixtures/<slug>/{must_fire,must_not_fire}/` as raw engine input, one event per file, with an
     optional `evasion/` of the same meaning as ADR-0006 decision 1's. The public lint,
     `python -m homelabnext.detections lint --native`, fails on a native rule without both
     required fixture kinds, without a reason, with a `det:` id that a Sigma rule also has, or
     with an engine rule number outside the module's reserved range. The engine run, `python -m
     homelabnext.detections run --native --target <target>`, sends each fixture through
     `test_native` (the engine's own rule tester, in the lab-in-a-box manager container) and fails
     on a missed must-fire or a fired must-not-fire. `det_map.yml` covers native rules too, so
     `map --check` and the raw-number lint (ADR-0006 decision 2) hold for both kinds.
   - **Sigma first, made visible.** The enforcing control is the ratchet: the count of native rules
     per module is a baseline (`detections/native.baseline.json`), listed in `tools/ratchets.yml`,
     that only a reviewed change may raise (ADR-0048). The closed reason list and the fixtures make
     each native rule's case reviewable. A Sigma drafter that converts a native rule is a project
     of its own, so it is not in this plan and does not gate admission.
   - **Coverage stays honest.** `attack_coverage.json` keeps counting Sigma rules from the
     reference runner. Native rules count only in the engine's own `backends` entry, from the
     engine run.
   - **Deploys are safe and checked.** The role loads the compiled bundle and the native files,
     runs the manager's configuration test before it restarts, and restores the previous rule set
     when the test fails (checklist D-03). The module's criterion `wazuh/rule-drift` compares
     `deployed_digest()` with the bundle's digest (D-01).

3. **One log pipeline and one writer per table, with the labels set on the way.**
   - The `vector` module renders its configuration from the registry and the guests. It loads
     `runtime-labels.json` (`hnx guests render --target runtime-labels`) and reloads it when the
     guests change. It sets `hnx_tlp` from each route's declaration and never from the event
     ([log pipeline](../log-pipeline.md); ADR-0033 decision 5). The loader refuses a pass-through
     pipeline while any selected source needs a label set in transit, because `lake-writer` would
     then refuse every unlabelled event. The module must pass the `log-pipeline` suite with
     `--strict` before its ledger row leaves `old` (ADR-0043 decision 3). Its remaps from the
     manager's archive and alert streams, and from the sensors, to the pinned OCSF classes are
     golden fixtures: raw input in, OCSF rows out, checked against `schemas/ocsf/`.
   - **One writer per table, enforced by the loader.** The pipeline stages batches to the object
     store. `lake-writer` owns the OCSF tables and commits them through `LakeClient.write_batch`
     with an idempotency key and the commit-then-checkpoint rule of
     `homelabnext/lake/checkpoint.py`. It contributes every OCSF table as a `platform/lake_table`
     record, with a `tlp` column from the first row. Another module may own its own tables (the
     indicator table of decision 6, the hunt table of decision 4) through the same library and the
     same idempotency rule; the loader refuses a second writer for any table. The old lab's Python
     stream writers and its separate committer are not carried. They are `replace` rows on the
     ledger, because two writers for one table are two primaries (ADR-0039).
   - Writer code is written fresh against `homelabnext.lake`. The old writers are reference for
     behaviour only (ADR-0011 decision 1).
   - **No backfill path, while the lake row is `fresh`.** On a fresh lake there is nothing to
     backfill. Were the lake row ever restamped `migrate`, the old lake would be copied as
     ADR-0043 decision 7 describes, after the TLP backfill, and this decision would gain a
     backfill path; the other decisions would not change. The writer is tested with the recorded crash-and-replay case
     of `checkpoint.py`: a replay after a crash adds no row.

4. **Sensors and endpoint forensics are modules at stage 1, and acting on endpoints goes through
   the broker.**
   - `suricata` and `zeek` fill the new `network-sensor` slot (out: OCSF `network_activity` and
     `detection_finding`). Each renders `HOME_NET` and the capture interfaces from the site model,
     extra addresses and IPv6 subnets included, as `suricata_enroll` does today. Upstream rule
     feeds are product content, updated by the module's job. The lab's own sensor rules are native
     rules under decision 2's rules, in the overlay module.
   - Each sensor module owns its capture-health criteria (decision 8): capture running, drops
     under a bound, event output growing.
   - **The forensics server is an authority, and the module's own principal only collects.** A
     hunt is not read-only by construction: an artifact can run commands and write files, and
     whoever may define artifacts can define one that runs a shell, so the server is in effect a
     fleet-wide root agent. The hunt principal the module uses holds only collect rights over an
     allow-listed artifact set, catalogued in the module and human-approve, with no EXECVE,
     FILESYSTEM_WRITE, artifact-writer or server-admin permission. Any artifact that needs one of
     those, and any action that changes an endpoint (a quarantine, a file removal, a process
     kill), is a `remote-admin` broker action behind approval (ADR-0017). That acting credential
     is held by the broker's handler and never by an agent (ADR-0030, ADR-0045). A test proves the
     hunt principal is refused an EXECVE artifact and an artifact upload.
   - Baseline hunts write to `endpoint_forensics.hunts`, which the module owns (decision 3) and
     which the novelty analyzer reads (ADR-0036).
   - **A retired network-forensics suite is not carried.** Its ledger row is `drop`. Offline
     packet-capture analysis is a later job of the `zeek` module, run on an isolated host role
     (`exposure: isolated`). It has its own ledger row and is out of this ADR's plan.

5. **Alerts reach cases through the bus, not through a SOAR product.**
   - The `wazuh` module's integration publishes each alert at or above a threshold as one
     `homelabnext.alert.created` 1.2 event (ADR-0009), with the `det:` id and the event's
     `severity`, mapped from the OCSF `severity_id` (ADR-0006 decision 3). The envelope's `tlp` is
     set from the SIEM source's declaration (`red` by default), never from the event. The schema
     does not change: `alert-intake` derives the dedup key from `detection` and the sorted
     `entities`.
   - **Only the SIEM may raise an alert.** Only the bus user of the selected `siem-source` and
     `detections` provider (the `wazuh` module) may publish `<prefix>.homelabnext.alert.>`, as
     only `hnx-broker` may publish `decision.>` (P-12). `alert-intake` also refuses an event whose
     `source` is not that provider's. It holds the `cases` credential, so without both rules any
     bus client could open cases and drive promotion.
   - The `alert-intake` core module consumes the event and calls the `cases` contract:
     `create_alert`, then `promote` per the overlay's promotion policy. Its consumer is durable and
     idempotent by event id. A repeat with the same dedup key collapses into the open alert's
     `count`, as the contract already requires.
   - `dfir-iris` is the first real `cases` adapter. It must pass the `cases` suite with `--strict`
     against the lab-in-a-box product container. It also needs an `export` that round-trips
     (`jsonl`, `markdown-tree`; ADR-0040 decision 6), restore-tested under ADR-0042.
   - **The observable is checklist E-01**, a criterion of `alert-intake` whose positive control is
     the canary itself: a daily canary goes to a closed case within 5 minutes. In plan step 9 the
     canary starts at a SIEM agent log line; plan step 10 extends it to start at the sensor.
     Canary alerts carry `det:` canary ids. `alert-intake` closes them itself, and they never
     page.

6. **Threat intel, the CTI graph and enrichment get adapters behind three contracts.**
   - `threat-intel` (`misp`): look up an indicator, list indicators changed since a mark, and
     export STIX 2.1. Read-only from the platform: no adapter method writes events.
   - `cti-graph` (`synapse`): a bounded query and a STIX export. The graph's own storage layer is
     part of the same module and row.
   - `ioc-enrichment` (`intelowl`): analyse one observable at a given TLP. The adapter refuses an
     observable above the analyzer maximums that ADR-0033 already sets, and the slot is on the
     egress list (O-12).
   - Each contract ships with a fake, a suite, a version and a contract page, like the existing
     ones. Indicators reach `threat_intel.indicators` through a `misp` scheduler job (layer 9,
     typed indicators), written through `homelabnext.lake` by the `misp` module, which owns the
     table (decision 3).
   - **Labels follow ADR-0033 decision 3.** An indicator record takes the `misp` data
     declaration's `tlp` (`red` by default). An event's own tag counts only when it is stricter,
     unless the declaration sets `honour_item_labels` (a human-approve field). A lab sighting makes
     the record `red` (ADR-0033 decision 4). The same rule labels `cti-graph` STIX exports and
     `ioc-enrichment` results, from the analyzer's declared label.

7. **A criterion carries its schedule, its owner and its proof.**
   - **Schema.** `registers/invariant` 1.1 (additive) admits the module form of id
     (`<module>/<slug>`) that [contributions](../modules/contributes.md) already cites, beside the
     central `X-NN` form, and gains:
     - `cadence`: a calendar expression in the `fleet_units` grammar, with an explicit `UTC` and
       no shorthand. A criterion without one runs only when someone asks for it;
     - `runs_on`: a host role among its module's host roles. A core module with none runs on the
       site's checks role (the overlay's `site.yml`);
     - `positive_control`: either `{fixture: <path>}`, an input on which the check must exit 1 to
       99, or `{seeded: <procedure>}`, a lab procedure by which a seeded instance is caught. A
       seeded run's evidence holds lab data, so it is recorded on the overlay ledger row by
       digest, and a public module never carries a seeded `evidence` path;
     - `evidence_tlp`: the label of the check's evidence text, `red` by default. A value below
       `red` is a human-approve field, valid only where the evidence comes from a fixed template
       that cannot echo data (ADR-0033 decisions 2 and 7).
   - **An observable runs only its own module's code.** A contributed criterion's observable is
     exactly `hnx scripts run <own module>/<script id> [args]` (a new `hnx scripts` subcommand that
     runs a catalogued script by id) or a plugin from the module's own entry points; the loader
     refuses any other form. `cadence`, `runs_on` and `observable` are human-approve fields under
     `homelabnext.modules.review_tier`, like `scheduler_jobs`, so an owner-tier criterion change
     cannot create scheduled execution on a host.
   - **Fixture controls are injected, not assumed.** A `kind: check` script whose criterion uses a
     fixture control declares `fixture_arg` in its header (for example `--input PATH`). `hnx
     invariants controls` runs the observable with that argument, and M-04 refuses a fixture
     control on a script that does not declare one.
   - **Assembly and units.** `hnx modules render` gains one output: the **assembled register**,
     every selected module's criteria in one file, sorted by id. It also writes one `fleet_units`
     entry per (module, cadence, `runs_on`), whose `exec` is `hnx invariants run <assembled>
     --module <id> --cadence <name> --state <state dir>/<module>.<cadence>.json --notify-cmd <site
     channel> --notify-ceiling <the site's declared ceiling for that channel>`. The ceiling is read
     from the site's notify channel declaration (ADR-0033 decision 6), never from a module; a unit
     with no declared channel ceiling is not rendered. The runner gains the `--module` and
     `--cadence` selectors. A timer still never runs a check directly, so M-04 holds unchanged.
   - **A rendered unit is least-privilege.** It runs as the module's own service principal
     (`fleet_units` `user:`, or `DynamicUser`), never `root`, with the `HARDENING` set; the
     renderer refuses `run_as_root` for criterion units. It runs the shared last-run writer on
     start and stop (O-10), so ADR-0043's timer proof (three consecutive successful runs in the
     hub's `job-last-run` records) applies unchanged.
   - **Results.** Each unit writes `invariants/<module>.<cadence>.json` under the status root, and
     keeps its state diff in `<state dir>/<module>.<cadence>.json`, so two cadences never
     overwrite each other or diff across each other. The module contributes a `poll-file` status
     source, with the existing `invariants-results` mapping, that globs the module's files, so each
     criterion is one item on the hub.
   - **The results transport.** The results reach the hub the way last-run records do: a hub pull,
     the transport that `docs/status.md` lists as still to build. The hub's pull account is an
     OpenBao-issued, short-lived SSH certificate whose principal is valid only for a forced
     command, which streams the host's results and last-run directories read-only. The hub files
     what it receives under the host it connected to, never under a name the stream supplies. This
     ADR builds it once for every per-host status file: criterion results, last-run records,
     ADR-0042's drill records (`drills.json`) and ADR-0043's cutover records (`cutover.json`),
     which those ADRs declare as their dependency.
   - **Shadow does not page.** While a module's ledger row is `new-shadow`, its units run with
     `--no-notify`. At the switch to `new-primary`, the first run uses `--baseline`, so the
     standing reds are recorded and only newly red criteria page afterwards (L-03). The
     `--baseline` run's red set is printed into the `new-primary` transition's evidence, and the
     operator's approval of that transition covers it, so no standing red is accepted silently.
   - `hnx scripts runner-lint` gains one rule: every criterion with a `cadence` has a
     `positive_control`. `hnx invariants controls <assembled>` runs every fixture control and
     fails on a control that exits 0. ADR-0043's timer gate requires the seeded evidence's digest
     before a detector's row becomes `new-primary`: a detector that has never fired is unproven.

8. **The lab's checks become catalogued criteria, each with an owner module, ported in value
   order.**
   - A **check** decides a property and reports through an exit code. It becomes a `kind: check`
     script, run by a criterion of decision 7. A **collector** moves data (a metrics-to-lake
     bridge, an agent-health ingest, a sensor's sample shipping). It is a `scheduler_jobs` unit
     that reports through its last-run record (O-10). The landing freshness of its table is a
     criterion of the same module.
   - **A check reads through a slot's API or a status source, never another module's storage**
     (ADR-0040 decision 2). The old checks that open a product's database are rebuilt on the
     product's API (the controller's queue summary, the notifier's API, the IdP's admin API through
     its module) rather than ported.
   - A generic check goes in its owner's public module, with a fixture control in CI. A check that
     names lab systems (the router, a named host, a lab-only product) goes in an overlay module
     with a seeded control.
   - **The migrated invariants form one overlay module until their family is ported.** ADR-0043
     migrates the old lab's invariants into the overlay. They land as the overlay module
     `lab-invariants`, with criterion ids `lab-invariants/<old id>` and the old ids in
     `aliases.yml`, so every citation still resolves and the register stays per module. Each
     imported check is catalogued in that module, human-approve, and runs under decision 7's
     unit rules. When a family is ported, its criteria move to the owner module and the aliases
     follow them.
   - Ownership by family:

     | Family (the audit's) | Owner module | Notes |
     |---|---|---|
     | SIEM manager health: enrolment, daemons, rule drift, rule-tester smoke, silent-rule divergence, rule volume | `wazuh` | the error-burst half of the ingest audit (decision 9) is here |
     | Source census, all classes dark, freshness, timestamp provenance, detection fidelity | `source-census`, `lake-writer` | decision 9 |
     | Lake reachability, query connector liveness | the `lake-query` and `lake-catalog` providers | through their contracts |
     | Sensor capture and output | `suricata`, `zeek` | |
     | Forensics client health | `velociraptor` | |
     | Fleet and agent health: stuck and fleet-wide deferrals, hollow runs, failed jobs, engine watchdogs | the orchestrator's core module | needs ADR-0026 stage 3 and the controller API; never its database |
     | Governance and vault hygiene | the broker's core module | lands with ADR-0044 |
     | Repository and IaC drift | the core (`hnx decommission`, the registry gates) and ADR-0046's governance check | |
     | Leak-watch liveness (no successful scan for three hours pages) | the overlay's governance module | ADR-0046 decision 8; it names the lab's runner, so it has a seeded control |
     | Alerting delivery heartbeat | the `notify` provider | through the notifier's API |
     | Backups, restore and power | ADR-0042's core `recovery` module, the `backup` provider (its off-site role) and the `ups` module | ADR-0042 decision 4 |
     | Host and network health that names lab gear | overlay modules | seeded controls |
     | Identity collectors | the `idp` provider (Keycloak) | the old IdP's collector is not carried (ADR-0039) |
     | Not yet ported invariants | `lab-invariants` (overlay) | moved family by family |
     | Agent dispatch; generated pages | not checks | ADR-0026 and the status hub |

   - Every old timer is a ledger row of kind `timer` (ADR-0043). Its `new` names a criterion id or
     a unit name, or its disposition is `drop` with a reason. `hnx cutover check` finds a timer
     with neither.
   - **Port order, by value.** Each line starts in shadow when its module's row does:

     | # | What | Why first |
     |---|---|---|
     | 0 | Decision 7's mechanism and the results transport | everything below lands on it |
     | 1 | Log pipeline, lake writer, OCSF tables | the fresh lake warms only from the day it starts writing (ADR-0043 `warm_until`); every later check reads it |
     | 2 | SIEM manager, the Sigma bundle, the native rules, rule drift and manager health | detection is the largest single loss |
     | 3 | Source census and manager error bursts (the ingest audit) | the lab's best single check of whether telemetry flows |
     | 4 | Alert intake and the case adapter (E-01 from a SIEM agent line) | alerts without cases are not triaged |
     | 5 | Sensors, then their health criteria (E-01 from the sensor) | network telemetry and its blind spots |
     | 6 | The remaining lake and SOC health criteria | silent-failure detectors over data that now lands |
     | 7 | Fleet health, after ADR-0026 stage 3 | it needs the controller API |
     | 8 | Governance hygiene, with ADR-0044 | it needs the broker's records |
     | 9 | Threat intel, CTI graph and enrichment adapters | enrichment adds value to alerts that already flow |
     | 10 | Endpoint forensics | hunts are periodic; the old server keeps them until then |
     | 11 | Host, network and identity checks, lab-only last | most have a hub collector or blackbox probe meanwhile |

9. **The ingest audit becomes two generic checks.**
   - `source-census/sources-flowing` runs `hnx lake source-census`. Over a window (8 days by
     default), it groups the event table by its source columns through the `lake-query` contract.
     For each source it learns the source's own cadence from its arrival history, and flags a
     source whose silence exceeds a multiple of that cadence. A flagged source fails unless it is
     on the overlay's acknowledged-quiet list, which carries an owner and an expiry. The query uses
     the portable SQL subset. `homelabnext/lake/dialect.py` gains an hour-bucket expression beside
     its UTC date.
   - **Learning is visible and has a floor.** A source with less history than the window is
     `learning`. A learning source passes (exit 0) with evidence that names it, and the hub shows
     the criterion as `warn`. While learning, a source that has arrived at least 3 times and is
     then silent past an absolute floor (24 hours by default, overlay-settable) fails, so the
     cutover period is not blind. The companion criterion `source-census/all-classes-dark` (no
     event of any class in its window) never learns.
   - `wazuh/manager-errors` clusters error, failure, critical and warning lines in the manager's
     log in time, and collapses each burst to distinct message shapes, with numbers and addresses
     masked. A burst whose last line is older than the quiet period is `RECOVERED` and passes. One
     still running is `ONGOING` and fails. A shape on the module's benign list is dropped. Each
     benign shape carries a reason, and the list is a ratchet baseline in `tools/ratchets.yml`
     that grows only by a reviewed change. The clusterer is a core library,
     `logbursts.py` under `homelabnext/`. The benign shapes are module content. Its fixture control is a
     recorded ongoing burst. A recovered burst and a recurring one are also fixtures: a burst that
     recurs on three days is reported as ongoing, not as three recoveries.

### Out of scope

- The lake's history and the archive (ADR-0043 decision 7). Restore drills and the cold-start
  order of these modules (ADR-0042). The modules' per-host enrolment and API credentials, issuance
  and rotation (ADR-0045).
- The old SOAR product and the old case manager: not carried, `legacy` until their rows close
  (ADR-0039). The `automation` slot's primary is StackStorm (ADR-0039 decision 6), which no
  decision here needs.
- The sandbox, honeypots, red-team range, vulnerability scanner, cloud-posture scanner and runtime
  kernel sensor. Their lake feeders follow decision 8's collector rule when their modules come.
- The agents that read SOC data, and their MCP tools (ADR-0026 stages 3 to 5, ADR-0044, ADR-0047).
- **Not carried, and not owned by any ADR of this batch.** **Decided 2026-11-08 (operator):**
  - the live 24-hour dataflow page is retired: its ledger row is `retire` (ADR-0043), with no
    successor;
  - each of these three gets a future ADR of its own, named as a follow-up in
    [module follow-ups](../modules/follow-ups.md#follow-up-adrs). Until each is written, its
    timers or flows get ledger rows of `undecided` (ADR-0043), so the gap stays visible:
    - the risk-based alerting engine's scoring (ADR-0036's analyzer and the decide cascade cover
      first-seen behaviour; risk scoring is a separate design);
    - the external CTI pipeline and its publishing;
    - the interactive-session runbook gate.

## Consequences

- The SOC moves as a set of swappable parts. Replacing the SIEM engine is a provider module, its
  adapter and a fixture run, not a rewrite of the writers, the case flow or the checks. The case
  flow depends on a contract and an event, not on a SOAR product.
- The lab keeps the rules it cannot express in Sigma, and they gain tests they never had. The
  price is an engine run in lab-in-a-box (a manager container, nightly) and a second fixture
  format. The native ratchet makes the Sigma share visible and keeps it from falling unnoticed;
  stock overrides, which silence product rules, get a human review and a ratchet of their own.
- One writer per table removes the duplicate-row class the old lab learned from, and removes a
  path. The old Python writers' behaviour has to be re-derived into remaps and golden fixtures,
  which is work.
- Every check gets an owner, a schedule, a proof and a place on the hub. A check whose module is
  removed is removed with it, and a check nobody owns cannot exist. Several old checks are rebuilt
  rather than ported, because they read storage they must not. The old timers become one unit per
  module and cadence plus the collectors' own units; dropped timers leave with a reason on the
  ledger.
- A criterion's schedule and command are human-reviewed, its units run unprivileged, and its page
  ceiling comes from the site, so the check plane adds no path to root or to a looser page.
- The forensics server and the SIEM manager are treated as the fleet-wide authorities they are:
  the manager's own response paths are off, and the forensics module collects only an allow-listed
  set, with anything stronger behind the broker.
- Paging gets quieter: one state diff per unit and cadence, no page during shadow, a baseline at
  the switch that the operator sees. The cost is a results transport to build and keep, and a hub
  that shows only what reaches it.
- Retiring the old case manager and the old SOAR product also retires the search and column stores only they used, the
  strongest consolidation candidate in the datastore audit.
- The fresh lake means the census and look-back checks are `learning` for their first window. That
  is the visible form of ADR-0043's warm-up cost, shown as `warn`, with an absolute floor so a
  source that has started and then stops still fails.
- The new contracts (`network-sensor`, `endpoint-forensics`, `threat-intel`, `cti-graph`,
  `ioc-enrichment`) are five more suites to keep versioned under ADR-0041, and three of them are
  stateful slots with export and import to keep.

### Implementation plan

Each step is one pull request, in this repository unless marked, merged green after a design
review and a security audit. Overlay pull requests are merged by the operator.

1. **This ADR** (`docs:`), with its index row, the summary stamp and **Amended-by: ADR-0049** plus
   an amendment note on ADR-0006 decision 4. Tests: the ADR log test (headings, reciprocal pair,
   `Depends-on`).
2. **Criterion schedule and proof.** `registers/invariant` 1.1 (the module id form, `cadence`,
   `runs_on`, `positive_control`, `evidence_tlp`), the runner's `--module` and `--cadence`, `hnx
   scripts run`, the script header's `fixture_arg`, and `hnx invariants controls`. Tests: schema
   negatives (a shorthand cadence, a non-UTC cadence, a control with neither form, a public seeded
   control with an `evidence` path); a fixture control that exits 0 fails `controls`; a fixture
   control on a script without `fixture_arg` fails M-04; the selectors run exactly the named
   module's criteria at that cadence; the runner-lint rule refuses a scheduled criterion without
   a control; an `evidence_tlp` below `red` is classified human.
3. **Assembly and units.** `hnx modules render` writes the assembled register and one fleet unit
   per (module, cadence, `runs_on`). Tests: goldens over the example modules; a criterion whose id
   names another module is refused; a criterion whose observable is not `hnx scripts run
   <own>/...` or an own plugin is refused; a `cadence`, `runs_on` or `observable` change is
   classified human; a unit with no declared channel ceiling is not rendered; a criterion unit
   with `run_as_root` is refused; each unit runs the last-run writer; two cadences of one module
   write distinct results and state files, and the status source globs both; M-04 still passes;
   the shadow flag renders `--no-notify`, and the switch renders one `--baseline` run whose red set
   is printed.
4. **The results transport.** The hub pulls each host's results and last-run directories (and the
   drill and cutover records when ADR-0042 and ADR-0043 write them) with an OpenBao-issued
   short-lived SSH certificate limited to a forced command, under `<status root>/<host>/`. Tests:
   a stream naming another host's path is refused; a certificate used for any other command is
   refused; a record dated ahead is unknown (as for last-run records); the `invariants-results`
   items appear per criterion.
5. **Native rules.** `contributes.detections` gains `format`. The `--native` lint, the native and
   stock-override baselines in `tools/ratchets.yml`, `det_map` over both kinds and the review-tier
   rule for `stock-override` land. Tests: one fixture per lint refusal; an optional `evasion/` is
   accepted and run; a `stock-override` entry is classified human, and fails without its
   silenced-case `must_not_fire` and its still-fires `must_fire`; raising either baseline without
   review fails; a shared `det:` id fails `map --check`.
6. **The `wazuh` module**, in three pull requests:
   - **6a.** The adapter moved from `homelabnext/detections/backends/wazuh.py` into
     `modules/wazuh/`, the severity mapping, `load` and `deployed_digest`; the moved path leaves
     `tools/product_names.baseline.json`. Tests: the `detections` suite against the adapter's
     fake target; severity goldens; the product-name lint passes with the shrunk baseline.
   - **6b.** The lab-in-a-box manager container, `test_native` and the nightly engine run. Tests:
     the `detections` suite with `--strict` against the container; a native fixture that misses
     fails the run.
   - **6c.** The manager, indexer and dashboard role, `wazuh_agent` absorbed into the module (and
     out of the baseline), D-03 rollback and `wazuh/rule-drift`. Tests: a broken native rule is
     rejected and the previous set restored; `rule-drift` fails on a changed deployed file; the
     role test asserts active response disabled and `remote_commands` 0.
7. **The `vector` module and `lake-writer`**, with the OCSF table records, the remap goldens and
   the one-writer-per-table rule. Tests: the `log-pipeline` suite with `--strict`; a label forged in
   the event is dropped; a pass-through pipeline with a source that needs a transit label is
   refused; a crash-and-replay adds no row; a second writer for one table is refused by the loader.
8. **The source census and the burst clusterer** (`hnx lake source-census`,
   `logbursts.py` under `homelabnext/`, the criteria). Tests: a source silent past its cadence fails; an
   acknowledged quiet source passes until its expiry; a young source is `learning`, passes and
   shows `warn`; a learning source that arrived three times and is silent past the floor fails;
   `all-classes-dark` fails during learning; a recovered burst passes, an ongoing one fails, and a
   burst recurring on three days fails; a benign shape without a reason is refused.
9. **`alert-intake` and the `dfir-iris` module.** Tests: the `cases` suite with `--strict` against
   the product container; a duplicate event adds no alert; the promotion policy promotes at its
   threshold and not below; the export round-trips; in lab-in-a-box, a forged `alert.created`
   from another bus user is refused (the `bus-acl` step), and an event with a foreign `source` is
   refused by `alert-intake`; the envelope's `tlp` is the source declaration's; the E-01
   criterion's canary, starting at a SIEM agent log line, reaches a closed case and does not page.
10. **Sensor modules** (`suricata`, absorbing `suricata_enroll`, then `zeek`), the
    `network-sensor` slot and their health criteria; the moved role leaves
    `tools/product_names.baseline.json`. Tests: `HOME_NET` goldens with extra and IPv6
    addresses; a stopped capture fails its criterion; remap goldens to OCSF; E-01's canary now
    starts at the sensor.
11. **The three intel contracts and adapters**, one pull request per contract, each adding its
    slot (`stateful`, with `stix` in the format vocabulary for the first two), contract, fake,
    suite and adapter:
    - **11a.** `threat-intel` and `misp`, with `threat_intel.indicators`. Tests: the suite against
      the fake and a recorded target; no adapter method writes; an untagged or `clear` event is
      labelled `red`, a stricter tag is kept, and a looser one counts only with
      `honour_item_labels`.
    - **11b.** `cti-graph` and `synapse`. Tests: the suite; a query past its bound is refused; the
      STIX export round-trips and takes the declared label.
    - **11c.** `ioc-enrichment` and `intelowl`, with the module's backup and restore. Tests: the
      suite; enrichment above the analyzer maximum is refused; results take the analyzer's
      declared label; the `jsonl` export round-trips.
12. **The `velociraptor` module** and the `endpoint-forensics` slot (`privileged`), with acting
    through a broker handler. Tests: a hunt result lands in `endpoint_forensics.hunts`; the hunt
    principal is refused an EXECVE artifact and an artifact upload; a change to the artifact
    allow-list is classified human; an acting call without approval is refused by the broker; no
    agent profile can hold the acting credential.
13. **Overlay: the lab's content** (operator merges): the overlay modules with the lab's native
    rules and fixtures, `lab-detections` (with ADR-0047's canary-hostname rule), `lab-invariants`,
    the acknowledged-quiet list, the promotion policy, the overlay governance module and the
    lab-only checks. Each old timer's ledger row is given its `new` or `drop`. Tests: `hnx modules
    check` and the native lint over `lab/modules/`; `hnx cutover check` finds no timer row without
    a successor or a reason; every old invariant id resolves through `aliases.yml`;
    `private_leak_check.py private` is clean.
14. **Then, family by family in decision 8's order**, one pull request per family. Each pull
    request moves its checks into their owner module with a control. Each ledger row is promoted
    on ADR-0043's evidence: three runs and a seeded catch.

## Alternatives

- **Translate every native rule to Sigma.** This would keep one format. But the correlation,
  decoder, list and stock-override rules have no form in the subset, and widening the subset to
  carry them would reimplement the engine. ADR-0006 already allowed native rules; the gap was a
  place and a test.
- **Gate native admission on an automatic Sigma draft.** A converter reliable enough to refuse
  rules is a project in itself, and a one-operator lab gains little over the closed reason list,
  the fixtures and the ratchet, which already make every native rule visible and reviewed.
- **Keep the native rules untested in the role.** This is what the old lab does. Drift and silent
  rules are exactly what its checks were catching after the fact.
- **One central check register and one scheduler, as in the old lab.** This is simpler to start.
  But a check survives the removal of what it checks, an unowned check is invisible, and the
  scheduler becomes a monolith of product branches, the shape ADR-0027 removed. The
  `lab-invariants` module is a temporary holding module, not this.
- **Let a criterion carry its own page ceiling.** A module would then set a reader's ceiling,
  which ADR-0033 decision 6 gives to the operator, and could raise it to `red` on its own.
- **Run each check from its own timer.** M-04 refuses it: exit codes would mean different things
  per script, and paging would not be state-diffed.
- **Keep a SOAR product for alert to case.** The flow is one event and one contract call. A
  workflow product adds a datastore and a release stream to carry a single mapping, and the
  operator has ruled the old one out.
- **Port the old Python writers beside the pipeline.** That would make two primaries for one
  table, and the duplicate-on-replay incident shows what two paths cost.
- **Carry the retired network forensics suite.** It was retired in the old lab, and the sensors
  and the lake cover its telemetry.
