---
summary: The orchestrator joins this repository as the Go module orchestrator/, gateway first; lab data goes to the overlay, MCP servers become modules, in stages.
summary_of: outline:sha256:dd8a0ee78f574512
---
# ADR-0026: Make the orchestrator and its gateway part of this repository

- **Status:** proposed
- **Date:** 2026-11-07
- **Amended:** 2026-11-07, with the operator's stage-2 decisions: the controller cuts over after
  stage 3, behind a runner seam proven first in the private repository; neutral wire names with a
  migration; no HTTP passthrough; the lessons and runbooks readers on this repository's register
  formats; the module's first third-party dependencies, among them the YAML library, and its
  `go.sum` (see the amendment at the end of Decision)
- **Related:** ADR-0005, ADR-0017, ADR-0021, ADR-0022, ADR-0024, ADR-0027, ADR-0030, ADR-0033,
  [LLM gateway](../llm-gateway.md), [the lab's own gateway](../gateway.md),
  [modules](../modules.md), [MCP catalog](../mcp-catalog.md),
  [private overlay](../private-overlay.md), `tools/go_modules.py`, `tools/go_test_policy.py`
- **Depends-on:** ADR-0038
- **Amends:** ADR-0011, ADR-0038

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
   `<overlay>/lab/modules/<id>/`, with its record under `<overlay>/lab/mcp/`.
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
      read-only, never deleted, so its history stays readable.

   **Each component cuts over as soon as it can run the lab's work: the gateway as soon as it
   lands, the controller after stage 3** (see the amendment), so the lab never runs a frozen copy
   for long. The lab's deployment then builds it from this repository at the commit the overlay
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
  - **One release** is a release of this repository as `CHANGELOG.md` records it. The first
    release that carries the controller accepts both field names on input and returns both; the
    next release drops the old name. A request that carries both names with different values is
    refused (400). A config that sets both an old key and its new key is refused.
  - The metric prefix and the event source get the same one-release overlap: the controller emits
    both metric names and an alias of the event source. Their consumers (dashboards, alert rules,
    audit queries) are found by a check, and moved, before the old names go.
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
