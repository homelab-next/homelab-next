---
summary: The orchestrator joins this repository as the Go module orchestrator/, gateway first; lab data goes to the overlay, MCP servers become modules, in stages.
summary_of: outline:sha256:07f8a62fd60cb6e2
---
# ADR-0026: Make the orchestrator and its gateway part of this repository

- **Status:** proposed
- **Date:** 2026-11-07
- **Amended:** 2026-11-07, with the operator's stage-2 decisions: the controller cuts over after
  stage 3, behind a runner seam proven first in the private repository; neutral wire names with a
  migration; no HTTP passthrough; the lessons and runbooks readers on this repository's register
  formats; the module's first third-party dependencies, among them the YAML library, and its
  `go.sum` (see the amendment at the end of Decision); and 2026-11-07 again, with the placement of
  what the split left unplaced (decisions 10 to 21; see the second amendment at the end of
  Decision and its consequences); and 2026-11-07 by ADR-0043 (decision 8): stage 6's archive
  waits for the revocation ledger and the scoped archive gate (decision 19 here), and by ADR-0044
  (decision 13): decision 6's vault, tasking-queue and deconfliction MCP servers are not ported,
  the broker's records actions replace them (decision 20 here)
- **Related:** ADR-0005, ADR-0017, ADR-0021, ADR-0022, ADR-0024, ADR-0027, ADR-0030, ADR-0033,
  ADR-0039 to ADR-0049,
  [LLM gateway](../llm-gateway.md), [the lab's own gateway](../gateway.md),
  [modules](../modules.md), [MCP catalog](../mcp-catalog.md),
  [private overlay](../private-overlay.md), `tools/go_modules.py`, `tools/go_test_policy.py`
- **Depends-on:** ADR-0038
- **Amends:** ADR-0011, ADR-0038
- **Amended-by:** ADR-0043, ADR-0044

## Context

Three pieces decide what an agent does in the lab. The **controller** decides which agent runs, when
and with which grants. The **broker** decides what an agent may do to a system (ADR-0017, ADR-0030).
The **gateway** decides what reaches a model (ADR-0038). They are one control plane: a grant the
controller hands out is checked by the broker, and a TLP label the runtime assembles is checked
again by the gateway. The broker lives here, in Python, beside its contract and conformance suite.
The controller and the gateway live in the operator's private Go repository (`llm-orchestrator`),
which also holds the lab's own data: deploy units with real hosts, agent profiles, MCP catalogs
naming lab systems, the agent runtime's homes and MCP tools written for lab-only systems.

ADR-0038 put the gateway's contract, schema, renderer and suite here and its implementation in the
private repository. The cost of that split showed at once:

- **A contract change is two pull requests in two repositories.** The four security-review
  departures (ADR-0038's amendment, R15 to R18) were made in the private code first and written into
  the contract here afterwards. Until the second pull request merged, the implementation and the
  contract it was judged by disagreed.
- **The acceptance run needs a cross-repository pin.** The private CI checks this repository out at
  a commit pinned in a file (`ci/homelab-next.ref`), installs its suite and runs it against the
  binary. Every change to the suite, the spec or the renderer has to be followed by a pin move
  there, or the run tests last week's contract.
- **The shared test vectors are a copy.** The TLP admission vectors
  (`conformance/fixtures/tlp_admit_vectors.json`) were copied byte for byte into the private
  repository, with the source commit written beside them.

The operator decided on 2026-11-07 to split the private repository: its generic code joins this
repository, and its lab-specific data goes to the private overlay (ADR-0021). The placement this
ADR records is the one recommended and decided with it.

Most of the private repository is generic: the gateway, the controller's queue, admission,
scheduling, grant loading and telemetry, and MCP servers for products anyone might run. What is
lab-specific is data (hosts, addresses, paths, profiles, catalogs, homes) and a few tools for
systems only this lab has. ADR-0011 decision 1 says files are written fresh and never copied from
private sources, so bringing that generic code in needs an amendment to it (decision 4).

## Decision

1. **The orchestrator is a component of this repository.** The controller, the broker and the gateway
   are one control plane, so a contract, its implementation and its conformance land in one pull
   request. The orchestrator's code joins as **one Go module at the top-level directory
   `orchestrator/`**, module path `github.com/homelab-next/homelab-next/orchestrator`, beside the
   Python broker (`homelabnext/broker`). The name names the component. The module is in neither
   Python distribution (`MANIFEST.in` prunes it), CODEOWNERS owns `/orchestrator/`, and its build
   outputs are ignored (`tests/packaging/test_orchestrator_tree.py` holds all three).
2. **The module's layout and rules.**
   - `cmd/gateway` and `internal/gateway` now; the controller's `cmd/` and `internal/` packages
     later (decision 8, stage 2). `internal/` is private to the module, as Go enforces: no other
     module imports it.
   - The `go` line of `orchestrator/go.mod` is the Go of CI's `GO_VERSION` (1.27.3 today), raised
     with it, by hand, to a release past the 14-day cooldown (CONTRIBUTING.md, "Keeping pins
     current"). CI's `go` job installs that version (`GOTOOLCHAIN=local`) and runs with
     `GOFLAGS=-mod=readonly` and `GOWORK=off`.
   - Standard library first. The gateway imports nothing else; the controller's core adds the
     module's first third-party dependencies in stage 2, and with them the module's `go.sum`
     (see the amendment). A third-party Go dependency follows ADR-0011 decision 4 and
     CONTRIBUTING.md rule 8 as a Python one does: permissively licensed, justified in its pull
     request, and listed by module path in the `go` section of `tools/licences.yml`, which `make
     licence-check` reads from every `go.mod`'s requirements. Dependabot watches the module and
     its linters' module (`gomod` entries; `tests/packaging/test_orchestrator_tree.py` fails on a
     discovered module it misses).
   - **Linters.** `orchestrator/tools/go.mod` is the module's linters' module (the
     `tools/go_modules.py` rule): staticcheck and govulncheck pinned as `tool` dependencies, with
     their `go.sum`, at releases past the 14-day cooldown, each module they pull in listed in
     `tools/licences.yml` as a `tool`. CI's `go` job runs both after the tests.
   - Every Go file starts with the SPDX line (CONTRIBUTING.md rule 10). The tests follow
     `tools/go_test_policy.py`: no network beyond loopback (CI runs them in a network namespace),
     every skip registered with a reason, a quarantine or a root-only test listed in
     `orchestrator/skips.yml` (created with its first entry). The TLP admission vectors are read
     in place from `conformance/fixtures/tlp_admit_vectors.json`, never copied.
   - The module holds examples only under `deploy/` (the gateway's systemd unit, which names no
     host). A lab's real units are the overlay's (decision 3).
3. **Core here, lab data in the overlay.** What is generic and public: the gateway, the
   controller's core, the agent-runner contract (decision 5), the conformance suites, generic MCP
   modules once parameterised (decision 6), fictional example configs (`example.internal`, RFC
   5737 addresses) and the docs. What stays private, in the overlay: deploy units and configs with
   real hosts, addresses, listen addresses and paths; agent profiles; MCP catalog records that name
   lab systems (`<overlay>/lab/mcp/`); the agent runtime's homes; MCP tools for lab-only systems
   (decision 6); and the real controller and gateway configs. Credentials are `secret:` references
   everywhere (ADR-0021 decision 3).
4. **Files come in fresh and pass every gate; ADR-0011 decision 1 is amended to allow it.**
   Generic code the operator owns may come in from the private repository: as new files, in a new
   commit, without its history, each read and rewritten for this repository before it lands.
   ADR-0011's rejected alternative, a scrubbed export of the private repository, stays rejected:
   no history and no rename trail comes across. Every file is read and rewritten before it lands:
   import paths take the new module path, private-repository paths and lab names go, real
   addresses become documentation ranges. The move's pull request passes the leak scan on the
   tree, on every added line (`--history`) and on every author (`--check-authors`), the
   raw-endpoint gate (a test listener or a loopback bind default is excused by an allowlist entry
   or an inline marker, each with its reason), the product-name lint, `tools/private_leak_check.py
   public`, and, before its branch is pushed, the operator's own deny-list (`HNX_DENYLIST`). A file
   that cannot be made generic does not come in; it goes to the overlay.
5. **The agent runner is a public contract; Hermes is one provider behind it.** The controller
   needs a small set of things from any agent runner: start a session with a prompt; hand it its
   toolsets and MCP grants; give it a home and config; collect its usage report; cancel it; and
   receive its stall signals. That **agent-runner contract** is public core, with a fake and a
   conformance suite like every other capability. It is the `agent-runtime` slot of ADR-0027, and
   its contract is written as an ADR of its own, which takes the next free number when it is
   written. The Hermes agent runtime is
   one **provider module** behind it (the private repository's `internal/hermesagent` splits along
   that line: the generic runner logic becomes the contract and its fake here, and what is
   Hermes-specific becomes the provider's code), so the runtime can change later without touching
   the controller. This ADR names the decision; the contract and the provider come in a later pull
   request (decision 8, stage 3).
6. **MCP servers are modules, not orchestrator code.** Each MCP server of the private repository
   becomes:
   - a **module** (ADR-0027): a provider module when it wraps a product (a hypervisor's API, a case
     manager, a malware sandbox), a feature module otherwise. Its manifest contributes the server
     (`contributes.mcp_servers`), names its slots, egress and config, and its directory is the only
     place its product's name may appear (the product-name lint);
   - its **catalog record** (ADR-0024), in the module's `mcp/` directory: origin, transport, tools
     and their capability classes, egress, `tlp`, `data_tier` and reviews. A server with an acting
     tool acts through the broker (`acts_via: broker`, ADR-0030) unless a human-reviewed `direct`
     exception names it. Profiles are granted the server by its catalog id.

   Public or private is decided per module. An integration with a product anyone might run becomes
   a public module under `modules/<id>/` once its hard-coded hosts, addresses and paths are module
   `config` keys the site fills from the overlay's registry (`svc:` names) and its credentials are
   `secret:` references. A tool for a system only this lab has (a probe of one specific honeypot,
   the lab's own tooling, the Hermes vault, the tasking queue) becomes an overlay module under
   `<overlay>/lab/modules/<id>/`, with its record under `<overlay>/lab/mcp/`. *Amended by
   ADR-0044 decision 13:* the vault, tasking-queue and deconfliction servers are not ported; the
   broker's records actions replace them (decision 20).
7. **Go code in a module.** A module's Go MCP server lives at `modules/<id>/go/` (in the overlay,
   `<overlay>/lab/modules/<id>/go/`), beside the module's `python/` tree, as **its own Go module**
   with its own `go.mod` (module path `github.com/homelab-next/homelab-next/modules/<id>/go` here).
   `tools/go_modules.py` discovers it and CI's `go` job builds, vets and tests it like any module,
   with its own `skips.yml` and its own Dependabot entry, so one module's dependencies never enter
   another's graph. Its catalog record names it as a first-party origin
   (`{kind: first-party, path: modules/<id>/go}`), and its launch is generated from that origin
   (**specified, not implemented**: the first Go module's pull request adds the launch for a
   first-party Go path). Module code may import **only a small public SDK** for writing MCP
   servers against this platform: a separate Go module at `orchestrator/mcpkit/` with its own
   `go.mod`, which imports nothing from the rest of `orchestrator/`. It never imports the
   controller or `orchestrator/internal/`; the SDK is the one interface module code depends on,
   and it is versioned with the contract.
   - **In this repository**, a module requires the SDK through a relative `replace`, so a module
     and the SDK it was tested with are one commit.
   - **In the overlay**, a module pins the SDK by module version or pseudo-version at the
     homelab-next commit the overlay pins (`HNX_REF`, ADR-0021 decision 7); there is no relative
     `replace` across repositories.

   Follow-ups, **specified, not implemented**: a `modules/<id>/go/` tree gets a manifest rule in
   `homelabnext/modules/rules.py` like `code_tree_problems` for `python/` (only the module's own
   code, no symlink, no other module's tree), and it stays out of both Python distributions, as
   `orchestrator/` does.
8. **The staged order.** Each stage is its own pull request (or series). Stages 1 to 3 run in order,
   each starting once the one before it has merged; stages 4 and 5 may run in parallel once stage 3
   has merged:
   1. **The gateway** (this pull request): `orchestrator/cmd/gateway`, `orchestrator/internal/gateway`,
      its docs and its in-repository conformance job.
   2. **The controller's core**, after scrubbing: the generic packages (queue, admission,
      scheduling, grant loading, telemetry), the lessons and runbooks readers on this repository's
      registers, the internal runner seam, the config and database migrations to neutral names,
      and no HTTP passthrough, with fictional example configs (see the amendment).
   3. **The agent-runner contract** (its own ADR) **and the Hermes provider module** (decision 5).
   4. **The MCP modules, one by one**: each its own module pull request, with its review tier
      (`hnx modules review-tier`), its catalog record and its conformance target where its slot
      has a contract.
   5. **The lab-only modules and the lab's data to the overlay**, through pull requests the
      operator merges there.
   6. **Archive**: once every component has cut over, the private repository is archived
      read-only, never deleted, so its history stays readable. *Amended by ADR-0043 decision 8:*
      the archive waits until the private repository's ledger rows are `old-retired` and their
      revocation records `verified` (decision 19).

   **Each component cuts over as soon as it can run the lab's work: the gateway as soon as it
   lands, the controller after stage 3** (see the amendment), so the lab runs a frozen copy only
   while its replacement cannot yet serve the lab's work. The lab's deployment then builds it from this repository at the commit the overlay
   pins (ADR-0021 decision 7). The gateway cuts over under ADR-0038's rules (its suite green here,
   a period beside LiteLLM, the runtime sending labels). From this pull request on, this
   repository's gateway is the implementation ADR-0038 is judged against, and the private copy is
   frozen. Until a component has cut over, a security fix may be backported to its private copy,
   and each such backport is recorded in the pull request here that carries the same fix. After
   cutover the private copy is removed there, with its own conformance job, by an operator-merged
   pull request.
9. **ADR-0038 decision 7 changes: the conformance run is an in-repository CI job.** CI's
   `gateway-conformance` job builds `orchestrator/cmd/gateway`, renders the conformance gateway
   spec with `--conformance`, starts the fake inference server and the gateway on loopback with
   generated keys, and runs `hnx conform run inference --target
   compose/lab-in-a-box/targets/inference-own-gateway.yml --strict`, failing on anything but a
   pass of every check. It runs on every pull request and every push to `main`, in a network
   namespace with only loopback, and `go-ok`, the Go modules' one stable check, passes only when it
   passed, so a Python-side break of the suite also shows as a red `go-ok`. The cross-repository pin
   (`ci/homelab-next.ref`) goes away: the suite, the spec, the renderer and the binary are one
   commit. ADR-0038's acceptance condition reads "green on this repository's `main`" where it read
   "green on the orchestrator's main branch"; the side-by-side period and the cutover rules are
   unchanged.

### Amendment (2026-11-07): the controller's stage 2, decided

The operator decided how the controller's core comes in before its pull request was written. The
decisions change decision 8's cutover point and decision 2's statement about `go.sum`, and settle
what stage 2 carries:

- **The controller cuts over after stage 3, not after stage 2.** The controller in this
  repository cannot run the lab's agents until it has a runner: the agent-runner contract and the
  Hermes provider module (decision 5) arrive in stage 3. Stage 2 lands the controller's core with
  an **internal runner seam**: an interface under `orchestrator/internal/`, the line along which
  decision 5 splits the private repository's runner code. It is not the public agent-runner
  contract; stage 3's ADR defines that contract and may reshape the seam. Behind the seam stage 2
  ships only a test double, nothing the lab's agents could use. The seam is proven first where the
  code runs today: a refactor pull request in the private repository puts the controller behind
  the seam and merges there, and only then does the code move here.
- **The private controller between stage 2 and stage 3.** From stage 2's merge the private
  controller is frozen and keeps running the lab. Only a security fix is backported to it, and
  each backport is recorded in the pull request here that carries the same fix (decision 8). Every
  other fix is made here only, and reaches the lab at the cutover after stage 3.
- **Wire names become neutral**, so no product name sits in the controller's wire format
  (ADR-0027). The job API's `hermes_session_id` becomes `session_id`; the config keys named after
  the runtime (`hermes_home`, `hermes_local_home`, `hermes_cloud_home`,
  `hermes_local_fallback_home` and the `hermes_agent_*` keys) take neutral names; and the metric
  prefix (`llmorch_`) and the event source (`svc:llm-orchestrator`) do too, under names stage 2's
  pull request sets. The change is staged so that no caller breaks at once:
  - **One release** is a release of this repository as `CHANGELOG.md` records it. The release at
    which the controller cuts over (the first release the lab deploys it from) accepts both field
    names on input and returns both; the old name is dropped no earlier than the next release
    after that, and only once the check below finds no consumer of it. A request that carries both names with different values is
    refused (400). A config that sets both an old key and its new key is refused.
  - The metric prefix and the event source get the same overlap, timed the same way: the controller emits
    both metric names, and for the event source every consumer accepts both sources for one release
    while the controller's source is configured (an event is emitted once: two sources would be two
    event ids for one run). Their consumers (dashboards, alert rules,
    audit queries) are found by a check that stage 2's pull request adds, and moved, before the old
    names go.
  - A config migration and a database migration move the stored names. **Before every run of the
    database migration against a live database**, wherever it runs, the private copy included,
    the database is backed up, the backup is checked restorable first, and it is protected like
    the database itself. A failed migration is a restore of that backup and a return to the
    previous controller, not a repair in place.
  - This repository's controller doc and its conformance stand-in move to the new names in stage
    2's pull request.
- **The controller's HTTP passthrough is not ported.** Every remaining passthrough caller moves to
  the gateway (ADR-0038), which authenticates, admits and records every call, before the
  controller cuts over. With no passthrough, a job naming an unknown `agent_key` is always refused
  (404), with no opt-in flag: `request_body` and `reject_unknown_agent_keys` are not ported. The
  controller's config has no key naming an inference URL other than the gateway's; a probe or
  health URL stays a probe only. [The controller doc](../orchestration-controller.md) is updated
  in stage 2's pull request.
- **The lessons and runbooks readers read this repository's registers.** The controller's lessons
  reader is ported to the lessons register as this repository defines it
  (`schemas/registers/lesson.schema.json`), not to the private format. That schema gains `match`
  in an additive 2.2, as an optional field: a lesson without `match` is never matched, and `match`
  is a bounded matcher, never an arbitrary regular expression. A matched lesson's text that reaches
  a prompt is data, never instructions. The schema change lands with the code that reads it, in
  stage 2's pull request, not with this amendment. The runbooks reader is ported the same way, to
  this repository's runbook register, so the two readers stay consistent.
- **The YAML library is `go.yaml.in/yaml/v3`**, the maintained successor of the archived
  `gopkg.in/yaml.v3`, at a release past the 14-day cooldown (CONTRIBUTING.md, "Keeping pins
  current"). It is one of the module's first third-party dependencies and follows decision 2's
  rule for one: permissively licensed, justified in its pull request, recorded with its SPDX
  expression as `kind: linked` in the `go` section of `tools/licences.yml`, and watched by
  Dependabot.
- **The module gets a `go.sum`.** Stage 2 adds third-party Go dependencies, so `orchestrator/`
  stops being standard library only and its `go.sum` is committed with them, checked by CI's `go`
  job under `GOFLAGS=-mod=readonly`. The gateway's packages stay standard library only, and stage
  2 adds the test that holds them to it: `go list -deps` of the gateway's packages names only the
  standard library and the module's own packages.

### Amendment (2026-11-07): what the split left unplaced

The parity and naming audits of 2026-11-07 listed every piece of the private repository and of this
repository's orchestration code against the stages of decision 8. Most pieces had a stage. Twelve
did not, or had one that contradicts a later ADR: a lock shared with the legacy scheduler; a Go
implementation of the `context` capability; three third-party MCP servers launched from wrapper
scripts; a patch to the agent runtime; the private end-to-end tests and the per-agent profile tests;
the recorded conformance stand-in; four names for the controller, two of which belong to something
else; a loader check that only Go can run; profile-bound grants; the private repository's freeze;
and the vault and tasking-queue MCP servers that decision 6 sent to the overlay while ADR-0044
retires the vault they front. Decisions 10 to 21 place each one. Each names its stage, the check
that holds it and the code it extends. Pull-request numbers such as "PR 2.4" are those of the
controller's stage-2 series in [the controller doc](../orchestration-controller.md); "the cutover
release" is the release at which the controller cuts over, and "cutover+1" the release after it
(decision 8's amendment). The ledger and its rows are ADR-0043's.

| Piece | Where it goes | Decision |
|---|---|---|
| Interlock lock shared with the legacy scheduler | already in the config (PR 2.3b); taken in PR 2.4, honoured in the pool in PR 2.5; replaced by one declared per-engine limit | 10 |
| Go `context` store (`internal/mdctx`, `cmd/ctxstore`) and its private adapter | **retired**; not ported | 11 |
| Third-party MCP servers launched by wrapper scripts | catalog records with pinned origins, stage 4; the IdP's server retires with that IdP | 12 |
| The agent runtime's usage-sizing patch | upstreamed; carried by the stage-3 provider module until a release has it | 13 |
| Private end-to-end and per-agent profile tests | not ported; replaced by loopback CI jobs and overlay checks | 14 |
| The recorded stand-in and its `-recorded` target | retired in PR 2.7 | 15 |
| Four names for the controller | one row name, `orchestrator`, for the event source and the broker target | 16 |
| The Go loader's judgement, for a site without Go | `controller check --config` in PR 2.7 | 17 |
| Profile-bound grants (`binds`) | every lab record binds before the controller's row is `new-primary` | 18 |
| The private repository's freeze | marked and guarded there; backports recorded here | 19 |
| The vault, tasking-queue and deconfliction MCP servers | **not ported** (ADR-0044 decision 13) | 20 |
| Pieces nothing needs (scratch commands, one-off scripts, notes) | not ported; listed on the ledger as `retire` (code) or `archive` (notes) | 21 |

10. **The interlock is honoured from the config that already has it, and one declared limit per
    engine replaces it.** The private controller takes an advisory `flock` on a lock file in the
    legacy scheduler's state directory before each local session, so the legacy dispatcher and the
    controller never run two sessions at once on an engine that serves one. The lock protects a
    property of the engine, not of either dispatcher, and it disappears with the legacy scheduler.
    - **The interlock is already in the configuration (PR 2.3b):** a top-level `lock_path`, a
      per-backend `needs_interlock` (unset is true, resolved by `InterlockRequired()`) and
      `interlock_wait_timeout_seconds`. No second key set is added. `config.Check` already refuses
      a `lock_path` that is not a clean absolute path; it also refuses one under the controller's
      state directory (the store's instance lock owns that) or in a directory writable by group or
      others, whenever any backend requires the interlock.
    - **PR 2.4** (`inference`) takes the `flock` on `lock_path` for a backend whose
      `InterlockRequired()` is true. Its test holds the lock from a second process and proves a
      session waits for it, and that a cancel while waiting releases nothing it did not take (the
      `flock` test registered as root-only where it needs one, in `orchestrator/skips.yml`).
      **PR 2.5** honours it in the backends pool. A backend whose interlock wait times out falls
      over only to a backend its job may use, never to a lane its job forbids (`local-only`).
    - **The engine's concurrency is declared once**, in the gateway spec's backend entry, as an
      additive `max_in_flight` (the spec's schema version bumps under ADR-0001's schema-version
      rule). The gateway counts calls in flight per spec backend, summed over every role and
      deployment bound to it, and refuses a call over the cap with R15's `429
      concurrency_limited`. `hnx gen gateway render --check` with a `controller:` block extends
      `homelabnext/generators/agent_homes.py` `controller_problems`: a backend whose engine
      declares `max_in_flight` must set `max_concurrent` to a value from 1 to `max_in_flight`
      (`0`, today "unmeasured", is refused there, since it would admit without limit), and a
      fixture in `tests/generators/fixtures/controller-backends/fail/` breaks each half of the
      rule once.
    - **`max_concurrent` is a hard admission cap when it is set** (**decided 2026-11-08,
      operator**). The merged PR 2.5 does this much: `Reserve` skips a backend whose load has
      reached its cap, and a test admits one session on a backend with `max_concurrent: 1` and
      holds the second until the first releases, by liveness (ADR-0029). Two parts are stage 2.6
      follow-ups, recorded in the controller doc's "Left to stages 2.6 and 2.7": the attempt
      chain's fallover (`callLocal`) must not overfill a backend at its cap, and the runner classes
      a `concurrency_limited` 429 as a retryable wait on the same backend, never as a backend
      failure, so it never falls over to another backend or to the cloud.
    - **Other callers** cannot exceed the cap where the engine's host admits calls only from the
      gateway (the guest's ingress and egress rules). That holds per site, so the lab check for
      the engine host (ADR-0049) states it and fails when another source can reach the engine.
    - **The interlock is removed from the lab's config when the legacy dispatcher's ledger rows
      are `old-retired`.** The controller row's `new-shadow` to `new-primary` gate (ADR-0043
      decision 3) requires either those rows retired, or `needs_interlock` not false on every
      backend the legacy dispatcher also uses (the overlay overrides what `config.Migrate` wrote
      for the local backend, and says why). `lock_path`, `needs_interlock` and
      `interlock_wait_timeout_seconds` are deleted from the code at cutover+1 if no site sets them.
11. **The Go `context` store is retired; this repository's reference store is the `context`
    primary.** `internal/mdctx` is imported only by `cmd/ctxstore` and by the vault MCP server
    (decision 20), so neither caller survives. `homelabnext.context.ContextStore`, which passes
    `hnx conform run context --target context-reference`, is the capability's one primary
    (ADR-0039), and ADR-0032 holds that context stays authored files, served in levels. The
    private adapter for the Go store (`contrib/hnx_adapter`, with its target file) retires with
    it; no third home for adapter code is created. A Go or product context store may come later
    only as a provider module under ADR-0040's replace protocol, passing the `context` suite at
    the contract version it claims (ADR-0041). Whatever the Go store holds in the lab is a dataset
    row (ADR-0043 decision 7): `in-place` if it is the authored files the reference store reads
    unchanged, otherwise `migrate` or `archive`, decided at stage 5.
    - `tests/packaging/test_orchestrator_tree.py` gains a `NOT_PORTED` list of package
      directories, `orchestrator/cmd/ctxstore` and `orchestrator/internal/mdctx`, and fails when a
      tracked path lies under one. The same test scans `orchestrator/` and `modules/*/` for those
      packages' import paths.
    - The passthrough is held by what it does, not by a file name, since PR 2.4's `inference`
      package may well have a legitimate `client.go`: a Go test fails when any file in
      `orchestrator/internal/inference` registers a passthrough route or defines its handler
      (asserted on the route pattern and the handler symbol).
    - Decision 20's servers would live in the overlay's modules, which this repository cannot
      see, so their guard is in the overlay's checks job (decision 20), by neutral role names here.
12. **Third-party MCP servers become catalog records with pinned origins; the IdP's server retires
    with its IdP.** Decision 6 covered the MCP servers of the private repository. Three more are in
    the lab's catalog and are launched by wrapper shell scripts: a Sigma rule tool, an ATT&CK
    lookup server and a server for the IdP that ADR-0034 and the operator's decision retire.
    - The first two come in at **stage 4**, each as a provider module (ADR-0027) whose record
      (ADR-0024) names a `package`, `image` or `git` origin with an exact version and a digest. The
      launch is rendered from the record by `hnx mcp catalog render`; no wrapper script comes
      across. `hnx mcp catalog check` already fails `kind: unknown`, and `hnx mcp catalog import`
      turns a wrapper-script launch into exactly that, so a record that is still a wrapper cannot
      be granted. Both are read-only (`read` class); neither acts, so neither needs a broker lane.
    - Each record declares `egress: []` at run time. The ATT&CK and Sigma data the servers read is
      a pinned, digest-verified artifact of the module, fetched at build time and never at run
      time, so an agent's query text never leaves with a download. The record's `tlp` admits at
      most what the granting profile's ceiling allows (ADR-0033). A server that needs run-time
      egress is refused at stage 4 until that egress is listed and reviewed.
    - The IdP's server is **not ported**. Its ledger row is `retire`, tied to the IdP's own row:
      it is stopped no later than the IdP it fronts, and its credential is on the revocation
      ledger (ADR-0043 decision 8). No server for the remaining IdP is added by this amendment.
13. **The agent runtime's patch is upstreamed, and carried by the provider module until then.** The
    private repository applies one patch to the agent runtime so that its usage file sizes each
    model call. Dropping it silently changes the usage report the controller reads (ADR-0025's
    job-finished record and ADR-0047 decision 4's trace check, which compares the report's call
    count with the run's model-call spans, depend on it).
    - The patch is offered upstream first, by an operator-owned contribution.
    - Until an upstream release that contains it is past the 14-day cooldown and pinned, the
      **stage-3 provider module** carries it as a file in its own directory, listed in its
      manifest by path and sha256 (an additive field of `module.schema.json`, landing with that
      module). `hnx modules check` refuses a listed patch whose digest differs and a patch file the
      manifest does not list.
    - The agent-runner suite (stage 3's ADR) gains a usage check: a session of two model calls
      reports two sized calls. It fails against the unpatched runtime, so a pin bump that loses
      the fix is red, not silent. When an upstream release carries the fix, the patch file and its
      manifest entry go in the pull request that moves the pin.
14. **The private end-to-end and per-agent profile tests are not ported; what replaces them runs
    on loopback or in the overlay.** This repository's test policy allows no network beyond loopback
    (`tools/go_test_policy.py`, `tests/network_guard.py`, CI's network namespace), and the private
    tests either reach a live lake or pin lab data. Each kind goes to a stated home:
    - **The controller's end-to-end behaviour** is `orchestration-conformance` (PR 2.7): the
      controller built from `orchestrator/cmd/controller`, started on loopback in the namespace
      with the exec runner and the runner body `conformance/fakes/llm_orchestrator_hermes.py`, and
      `hnx conform run orchestration --target orchestration-orchestrator --strict`. `go-ok`
      requires it, as it requires `gateway-conformance`. PR 2.8's fault injection adds the hold
      checks (killed worker, restart reconciles) against the real binary.
    - **The live-lake test** is not ported. The lake reads it exercised are the `lake` suite's,
      against the loopback stand-in this repository already runs; a check against the lab's own
      lake is a lab check under ADR-0049, run where the lake is, never in CI.
    - **The deploy, toolset-home and catalog tests** become checks that already exist or that
      decision 17 adds: `hnx gen gateway render --check` (homes against the gateway spec),
      `hnx gen gateway homes` (invariant A-14), `hnx mcp catalog render --check` and `controller
      check --config`.
    - **The per-agent profile tests** pin facts about the lab's agents, so they are lab data. Each
      one is classified at stage 5: a rule every profile must meet becomes a rule of the profile
      compiler's policy ceiling (`hnx agent verify`), with its test here on fictional profiles; a
      fact about one lab agent becomes an invariant criterion in the overlay's register, run by
      `homelabnext/invariants` and the overlay's checks job (ADR-0049). A test that fits neither
      is recorded on the ledger as dropped, with its reason. The overlay's checks job runs both.
15. **The recorded stand-in retires in PR 2.7.** The stand-in (`llm_orchestrator_api.py` in `conformance/fakes/`, deleted by PR 2.7c)
    models a private commit and cites private `file:line` shapes; once the controller is built
    here it is a second thing to keep true.
    - **PR 2.6** (the API) moves the stand-in to the ported behaviour (no passthrough, an unknown
      agent key always 404), and moves both fakes' cites (`llm_orchestrator_api.py` and
      `llm_orchestrator_hermes.py`) to `orchestrator/` paths, or to the seam's documented
      behaviour where no in-repo file exists yet, as decision 8's amendment requires of stage 2.
    - **PR 2.7** deletes the stand-in, the target `orchestration-llm-orchestrator-recorded.yml`,
      the as-recorded half of `tests/conform/test_conform_orchestration_controller.py` and the
      adapter's `fixes:` machinery (the stage-2 plan put that in PR 2.8; it goes in PR 2.7 because
      the recorded target it served is deleted there, and this amendment wins); renames the adapter to
      `orchestrator.py` in `homelabnext/conform/adapters/` and the target that runs the in-repo binary to
      `orchestration-orchestrator` (targets are `<capability>-<impl>`); and moves the example
      registry's controller version and the pin in `tools/tests/test_pin_consistency.py` from the
      private commit to this repository's. A test in `tests/conform/` fails when any target file's
      name ends in `-recorded` for `orchestration` or when a file under `conformance/` cites
      `internal/hermesagent`. The live target `orchestration-llm-orchestrator.yml`, which measures
      the lab's private controller, stays until the controller's row is `old-retired`, then goes.
    - `conformance/fakes/llm_orchestrator_hermes.py` stays as the runner body until stage 3's
      runner fake replaces it.
16. **The controller has one service name, `orchestrator`, as event source and as broker target.**
    Today it is the broker target `svc:orchestration`, the event source `svc:llm-orchestrator`
    (private) or `svc:orchestrator` (`orchestrator/internal/events`), and the example registry row
    `agent-runtime`; in the lab's registry `orchestration` is a SOAR product and the controller has
    no row. ADR-0039 decision 7 settles the vocabulary; this decision settles the wire names:
    - The registry row is `orchestrator`, capability `orchestration`. The event source is
      `svc:orchestrator`, the default the code already has. The broker target of
      `workflows/packs/agent-job-retry.yml` and `workflows/packs/proposal-validate.yml` becomes
      `svc:orchestrator`, and their pinned renders under `workflows/stackstorm/homelabnext/pinned/`
      are regenerated. The target moves at once, without an overlap: the old target names no
      controller in any registry (in the lab's it names the SOAR product), so nothing could depend
      on it and an overlap would keep a live misdirection. ADR-0039 decision 7 says the same; its
      overlap applies to the event source only. `hnx registry bindings` (ADR-0039 decision 3)
      refuses a pack whose `svc:` target or source names no registry row, capability or declared
      platform source, which holds the rename.
    - The event source keeps decision 8's overlap, worded once: **in the cutover release every
      consumer accepts both `svc:llm-orchestrator` and `svc:orchestrator`**; the old source is
      dropped at cutover+1, and only once PR 2.7's consumer check finds no consumer of it. The
      controller emits under one configured source at a time. For the overlap, `svc:llm-orchestrator`
      is one of ADR-0039 decision 3's declared platform sources (an event source only, never a
      target, with its `why`), so the check that holds the rename also admits the overlap in
      `workflows/packs/agent-job-retry.yml` and its fixtures; the entry is removed by the change
      that drops the old source at cutover+1. PR 2.7's consumer check covers the
      list in [the controller doc](../orchestration-controller.md) ("Neutral names") plus
      `schemas/events/README.md` and the conformance fakes, which the audit found missing from it.
    - `agent-runtime` is the runner slot only (ADR-0039): the runner host is found by host role,
      and stage 3's ADR names the slot's contract.
    - PR 2.7 depends on ADR-0039's `hnx registry bindings` (its implementation step 5), which
      must merge first; ADR-0039's step 4 changes only the vocabulary and the fictional SOAR row,
      and leaves the wire names, the controller's example row and the packs to PR 2.7, so the
      rename is implemented once.
    - The controller's example unit is `orchestrator/deploy/systemd/orchestrator.service` (PR
      2.7), named after the row. The lab's row and unit are added to the overlay at stage 5, apart
      from the SOAR product's row, which ADR-0039 moves out of `orchestration`.
17. **`controller check --config` gives every site the Go loader's judgement (PR 2.7).** PR 2.3a
    removed the Python copy of the grant loader's rules (`clients.orch_accepts`): the Go loader is
    the one judge, and a Go test loads this repository's committed render in place. A site that
    runs only the Python tooling then has `clients.orch_render_problems`, which checks that the
    render is well formed, not that the controller accepts it. PR 2.7 adds `controller check
    --config FILE`:
    - it loads the configuration, the catalog of kinds and every profile the configuration names,
      and renders each profile's two lanes (`Registry.CheckGrants`), without opening the database,
      binding a port or reaching the network;
    - it reads no `tokens_file` or other secret file's contents: it checks only that the path is set
      and is a regular file it is allowed to read;
    - exit `0` clean, `1` one line per problem (no value from a record or a secret in any line,
      the rule `hnx mcp catalog` follows), `2` a usage error or an unreadable file;
    - `make controller-check` runs it on the fictional example in CI's `go` job, and a fixture
      breaks each refusal once;
    - the overlay's checks job builds `orchestrator/cmd/controller` at the commit the overlay pins,
      with `GOTOOLCHAIN=local GOFLAGS=-mod=readonly GOWORK=off` against the pinned `go.sum` as CI's
      `go` job does, and runs the check on the lab's configuration. The binary that a site deploys runs the same
      check, so a site without a Go toolchain uses that binary rather than a Python copy.
18. **Every identity or scope grant binds to its profile before the controller cuts over.** PR
    2.3a added `binds` to the MCP catalog record (record schema 1.4): a parameter that picks an
    identity or a scope binds to the granting profile (`agent_key`, `agent_key_lane`, `lane`,
    `writable`, `readable` or `prefix`), the render writes it into the kind's `profile_scope`, and
    `hnx mcp catalog check` refuses such a parameter that does not bind. That check finds such a
    parameter by its env key's suffix (`_PREFIX…`, `_SCOPE`, `_LIST`, `_AGENT_KEY`, `_BY`), and
    any other parameter is pinned to the union of every rendered profile's values. The lab's
    grants were written for the private controller and pin values across profiles, which would let one profile
    set another's prefix. So:
    - at stage 5 the lab's records under `<overlay>/lab/mcp/` declare `binds` on every identity or
      scope parameter, and the lab's profiles carry the scope key under its public name (the
      private name is refused as an unknown key, never read wrongly);
    - the controller row's `new-shadow` to `new-primary` gate (ADR-0043 decision 3) requires
      `hnx mcp catalog check` and `hnx mcp catalog render --check` clean over the overlay's
      catalog and `controller check --config` (decision 17) clean over the lab's configuration,
      each recorded by digest as the gate's evidence;
    - the gate's evidence also includes the render's cross-profile report, because the suffix rule
      misses an identity or path parameter spelled `_USER`, `_DIR`, `_PATH`, `_ROOT`, `_ID` or
      `_TENANT`: every pinned, non-`enum` parameter whose `allowed_values` holds values from more
      than one profile is listed, and each must either declare `binds` or carry a human-reviewed
      `shared: true` with a reason. A listed parameter with neither fails the gate.
19. **The private repository is marked frozen, and every backport is recorded here.** From the
    merge of each stage here, its packages are frozen in the private repository (decision 8). The
    audit found no marker there. So, by an operator-merged pull request in the private repository
    (it is outside this repository's reach, ADR-0046):
    - its README and each frozen package's doc comment say `FROZEN: moved to homelab-next`, with
      the stage;
    - its CI refuses a commit that touches a frozen path unless the commit's message carries a
      `Cutover-Fix: <ledger uid>` trailer naming the row the fix belongs to and a `Backport-Of:`
      trailer naming the pull request here that carries the same fix, the pair ADR-0043 decision 6
      defines for both frozen repositories, so `carried_fixes` reads one format;
    - that CI resolves the named pull request through the GitHub API and refuses a `Backport-Of:`
      that names no open or merged homelab-next pull request, or one without the `security`
      label (only security fixes are backported, decision 8's amendment);
    - the private gateway, its conformance job, its pin file and its copied vectors are deleted at
      the gateway's cutover, as decision 8 already says.
    Here, a pull request that carries a backported security fix says so in its description, and
    the controller's ledger row lists it in `carried_fixes` (ADR-0043 decision 6). Stage 6's
    archive waits until every ledger row whose `old` names a component of the private repository
    (the controller, the gateway, its MCP servers and decision 21's rows) is `old-retired` and their
    revocation records are `verified`: `hnx cutover check --archive-gate --rows <those uids>`. The
    lab-wide gate (every row of the ledger) would hold the archive on unrelated services such as
    DNS or the lake, which share nothing with this repository; ADR-0043 decision 8 is reworded to
    this scoped gate for stage 6, and its step 6 adds the `--rows` filter.
20. **The vault, tasking-queue and deconfliction MCP servers are not ported.** ADR-0044 decision
    13 owns this (it amends decision 6), including what replaces them and how the vault's history
    comes across. This amendment adds only the guard: the overlay's checks job fails when a module
    or catalog record under the overlay names one of them, and their code is archived with the
    private repository at stage 6. The other lab-only servers of decision 6 keep its plan.
21. **Everything else the audit found without a stage is not ported unless a ledger row says
    otherwise.** A scratch command, the one-off sync and facts scripts and the private design and
    verification notes stay in the private repository's archive (stage 6). Each is a ledger row
    with disposition `retire` or `archive` (ADR-0043), so the ledger's completeness check, not
    memory, shows that nothing was dropped by accident.

**Out of scope for this amendment:** the agent-runner contract itself (stage 3's own ADR), the
broker's records actions and the vault import (ADR-0044), per-agent keys and their lifetimes
(ADR-0045), run traces and budgets (ADR-0047), which product fills the `automation` slot (ADR-0039:
StackStorm, decided 2026-11-08), an MCP server for the remaining IdP, and the conversion of the
lab's agent profiles to compiled profiles (stage 5, with ADR-0043's roster of record).

**Requirements other ADRs put on these stages.** ADR-0045 and ADR-0047 do not amend this ADR, but
their decisions land inside its stages, and each stage's pull request carries them as written
there: controller authentication on by default in stage 2's controller pull request (ADR-0045
decision 9); `Session.Trace` and `Session.RunTokens` on the runner seam and the facts block's
budget in PR 2.4, and the run deadline in PR 2.6 (ADR-0047); per-run agent credentials and trace
propagation in stage 3's agent-runner ADR, which must cite ADR-0045 decision 6 and ADR-0047's
runner requirements.

## Consequences

- A contract change, its implementation and its conformance run are one pull request, reviewed and
  tested together. Nothing waits on a pin move.
- This repository gains a long-running network server and a second language. Go code takes every
  gate Python code takes (leak scan, raw endpoints, product names, SPDX, the test policy), and CI
  builds and tests each Go module in its own job.
- The gateway's code becomes public. Its security does not rest on secrecy: keys are digests in
  memory, the config holds environment names only, and the tests use documentation addresses.
- The operator owns the review of each move: every stage's pull request is read for identifiers
  before it ships, as CONTRIBUTING.md asks of every new top-level directory.
- Until the archive, two repositories hold orchestrator code. A moved package is frozen in the
  private one from the merge of its stage here, and its fixes are made here; a security fix is
  backported only until that component's cutover, and recorded in the matching pull request here.
  For the controller that window runs from stage 2's merge to its cutover after stage 3, and a
  fix that is not a security fix reaches the lab only at that cutover.
- MCP servers move as modules, so each needs a manifest, a catalog record and a review before it
  lands. That is slower than copying a directory, and it is the point: a tool that reaches a lab
  system is granted, classed and reviewed like every other.
- The module SDK (`orchestrator/mcpkit`) becomes an interface this repository must keep stable for
  the modules that import it, in-tree and in the overlay.

### Of the amendment of what the split left unplaced

- Every piece of the private repository now has a stage, a retirement or a ledger row, and each
  placement is held by a check: the orchestrator tree test's `NOT_PORTED` list and passthrough
  test, the overlay's server-name guard, `controller check --config`, `hnx mcp catalog check`, `hnx registry bindings`, `controller_problems` and the
  ledger's gates.
- One engine limit replaces a lock two dispatchers shared. It holds for every caller of the
  gateway, not only the two dispatchers that knew about the lock, at the cost of a gateway config
  field and a schema bump. It holds against other callers only where the engine host admits only
  the gateway, which the lab check states. `max_concurrent` becomes a hard admission cap (decided
  2026-11-08), so a backend that set it as a measured hint now also limits admission.
- Retiring the Go context store and the recorded stand-in removes two copies of code that would
  otherwise have to be kept true beside the real thing; the cost is that the lab's context comes
  only from the reference store until a provider module replaces it.
- The live-lake end-to-end test has no CI successor. Its coverage moves to the `lake` suite on
  loopback and to a lab check that runs at the lab, which CI does not see.
- Carrying a runtime patch makes the stage-3 provider module heavier until upstream takes it; the
  runner suite's usage check is what keeps a pin bump from dropping it silently.
- The overlay's checks job gains a Go build at the pinned commit, so overlay CI takes longer.

**Implementation plan.** Each step is one pull request in this repository unless it says otherwise;
the order follows the stage-2 series it rides on.

1. **This amendment** (`docs:`), with the header lines and the index summary restamped. Proves:
   `tools/tests/test_adr_log.py` (headings, reciprocal **Amends**/**Amended-by**, known ids).
2. **The tree's `NOT_PORTED` list** (`test:`), in `tests/packaging/test_orchestrator_tree.py`.
   Proves: a fixture tree holding a file under `orchestrator/cmd/ctxstore` or
   `orchestrator/internal/mdctx`, or a `modules/*/` file importing either, fails; the real tree
   passes.
3. **PR 2.4 takes the interlock** (decision 10) from the existing `lock_path` and
   `needs_interlock`, with the `config.Check` refusals and the passthrough test of decision 11.
   Proves: a lock held by a second process delays a session on a backend whose
   `InterlockRequired()` is true and not on one set `needs_interlock: false`; a `lock_path` under
   the state directory or in a group-writable directory is refused when any backend requires the
   interlock; a fixture `inference` file registering a passthrough route fails the Go test.
4. **The gateway's per-engine `max_in_flight`** (decision 10), with the spec schema's additive
   bump, the renderer, the gateway's enforcement and the `controller_problems` rule. Proves: a call
   over the cap gets `429 concurrency_limited` before its body is read, with the count summed over
   two roles bound to the same spec backend; `hnx gen gateway render --check` fails a backend whose
   `max_concurrent` exceeds its engine's cap or is `0` (fixtures); the schema's examples and
   negatives pass and fail.
5. **PR 2.5 enforces `max_concurrent`** at admission (`Reserve`) and honours the interlock in the
   backends pool. Proves: with `max_concurrent: 1` a second session waits and is admitted when the
   first is released by liveness. The fallover cap and the retryable `concurrency_limited` 429 are
   stage 2.6 follow-ups (the controller doc's "Left to stages 2.6 and 2.7"). Also proves: an
   interlock timeout on a `local-only` job's backend does not fall over to a cloud backend.
6. **PR 2.6 moves the stand-in to the ported behaviour and both fakes to `orchestrator/` cites**
   (decision 15). Proves: the recorded target refuses an unknown agent key with 404 and has no
   passthrough route; neither fake cites `internal/hermesagent`.
7. **PR 2.7: the controller binary**, after ADR-0039's `hnx registry bindings` has merged, with `controller check --config` (decision 17), the
   `orchestration-conformance` job (decision 14), the stand-in's retirement and the renames
   (decision 15), the one service name and the consumer check (decision 16), and the example
   unit. Proves: `make controller-check` passes on the example and each refusal fixture fails with
   exit 1; `hnx conform run orchestration --target orchestration-orchestrator --strict` passes in
   the namespace and `go-ok` requires it; no `-recorded` orchestration target and no
   `internal/hermesagent` cite under `conformance/` remain; `hnx registry bindings` passes over
   `examples/` with the packs targeting `svc:orchestrator`, and fails a fixture pack targeting an
   unregistered `svc:`, while the overlap source in `agent-job-retry.yml`'s fixtures passes as a
   declared platform source and fails as a target; the consumer check lists every consumer of `svc:llm-orchestrator` named in
   decision 16.
8. **PR 2.8: fault injection** against the real binary. Proves: the hold checks run and pass
   instead of skipping.
9. **The private repository's freeze** (decision 19), an operator-merged pull request there.
   Proves, in its CI: a commit touching a frozen path without `Cutover-Fix:` and `Backport-Of:` is
   refused, and so is one whose `Backport-Of:` names no homelab-next pull request or one without
   the `security` label.
10. **Stage 3: the agent-runner contract and the provider module**, carrying the runtime patch
    (decision 13). Proves: the runner suite's usage check fails on the unpatched runtime and passes
    on the patched one; `hnx modules check` refuses a patch whose digest differs from the manifest.
11. **Stage 4: the two third-party MCP modules** (decision 12), one pull request each, with review
    tier and record. Proves: `hnx mcp catalog check` passes with pinned origins and `egress: []`,
    and fails the imported wrapper-script form (`kind: unknown`) and a record listing run-time
    egress; the module's data artifact is refused when its digest differs.
12. **Stage 5, in the overlay (operator-merged):** the lab's records with `binds` (decision 18),
    the controller's row and unit (decision 16), the per-agent tests classified into compiler
    rules, invariant criteria or dropped rows (decision 14), the checks job running `controller
    check --config` at the pin (decision 17), and the ledger rows for decisions 11, 12, 20 and 21.
    the cross-profile report (decision 18), the server-name guard (decision 20), and the dataset row
    for the Go store's contents (decision 11). Proves: the overlay's checks job is green with all of
    them; a fixture record with an identity parameter named `*_DIR` holding two profiles' values
    fails the gate; `hnx cutover check` shows no piece of the private repository without a row.
13. **The cutover release:** consumers accept both event sources (decision 16); the controller's
    `new-primary` gate holds decision 18's evidence and decision 10's interlock condition.
    **Cutover+1:** the old source and its declared platform-source entry, the old client kind and,
    if no site sets them, `lock_path`, `needs_interlock` and `interlock_wait_timeout_seconds` are
    removed, each after its consumer check finds nothing.

## Alternatives

- **Keep the orchestrator private and pin this repository from its CI** (ADR-0038 as written). This
  is the status quo. It keeps the two-pull-request contract changes, the pin moves and the copied
  vectors described in Context.
- **A third repository, public, for the orchestrator alone.** It removes the privacy problem but
  keeps the cross-repository pin and the split between contract and implementation.
- **Rewrite the gateway and the controller in Python.** The Go code exists, runs in the lab and
  passes the suite; a rewrite would add risk and delay for no change in behaviour, and a
  long-running, concurrent server is not what the Python package is built for.
- **Import the private repository with its history** (a subtree or a filtered history). Rejected:
  the history holds lab identifiers in old revisions, and ADR-0011 decision 1, as amended by
  decision 4, still keeps private history off the public remote.
- **Another top-level name** (`go/`, `cmd/`, `controlplane/`). `go/` and `cmd/` name a language or
  a convention, not a component. `controlplane/` is accurate but would also cover the Python
  broker, which stays where it is. `orchestrator/` names the component.
- **MCP servers inside the orchestrator module.** That would put every product's name in the core
  and grant tools outside the catalog. Modules keep products in provider modules (ADR-0027) and
  every server in the catalog (ADR-0024).
- **Module code importing the orchestrator module directly.** That would tie every MCP module to the
  controller's dependency graph and its internals; a small SDK module is a narrower contract.
