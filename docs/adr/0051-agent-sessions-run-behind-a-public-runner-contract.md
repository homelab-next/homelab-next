---
summary: Agent sessions run behind a public runner contract (session spec, usage report, launcher), each in its own unit as its profile user; Hermes is one provider.
summary_of: outline:sha256:ae8dd6a6a3a7f2fd
---
# ADR-0051: Run agent sessions behind a public agent-runner contract

- **Status:** proposed
- **Date:** 2026-11-09
- **Related:** ADR-0013 (agent activity tiers), ADR-0025 (orchestration telemetry), ADR-0029
  (holds released by liveness), ADR-0030 (agents act only through the broker), ADR-0033 (TLP),
  ADR-0038 (the gateway), ADR-0040 (modules are replaceable by construction), ADR-0041 (versioned
  capability contracts), ADR-0043 (the cutover ledger),
  [the controller](../orchestration-controller.md)
  ("The runner seam", "The trust boundary", "Carried past PR 2.7b"), [modules](../modules.md),
  `examples/modules/slots.yml` (`agent-runtime`)
- **Depends-on:** ADR-0026, ADR-0027, ADR-0045, ADR-0047

## Context

ADR-0026 decision 5 makes the agent runner a public contract, the `agent-runtime` slot of
ADR-0027, with the Hermes agent runtime as one provider module behind it, and leaves the contract
to its own ADR at stage 3. Stage 2 is complete: this repository's controller has its core, its
binary, an internal runner seam (`orchestrator/internal/runner`: `Runner.Run(ctx, Session)`, a
`Session` of plain fields, a `Result`, and the failure classes the core decides on) and one
built-in runner kind, `exec`, a generic subprocess runner. The in-repository conformance job
drives the controller with `exec` and a scripted runner body
(`conformance/fakes/llm_orchestrator_hermes.py`). Nothing behind the seam can run a lab agent,
which is why the controller cuts over only after stage 3 (ADR-0026's amendment).

Several requirements are already written down elsewhere and wait for this ADR:

- **Per-run credentials** (ADR-0045 decision 6). A profile's gateway key is delivered per run,
  never through a backend's home. It is sealed at rest to the host, plaintext only to the run's
  uid for the run's life. The launcher cannot run an arbitrary process as an agent uid, and the
  controller never reads an agent's key. A `per-run-credential` check proves it. ADR-0045
  decision 7 runs each compiled profile as its own system user.
- **Trace and run tokens** (ADR-0047 decisions 2, 3, 5 and 7). The trace reaches every model
  call (`traceparent` beside `X-HNX-Tag`) and every call to a local MCP server (`_meta`), and no
  non-local server. The run tokens are delivered per run like the key. The usage report has an
  entry per tool call and `budget_exhausted`. `trace-propagation` proves it against mutants.
- **The runtime patch** (ADR-0026 decision 13). The runtime is patched so that its usage file
  sizes each model call. The provider module carries the patch, listed by path and digest, until
  an upstream release has the fix. A usage check (two model calls report two sized calls) fails
  on the unpatched runtime.
- **What stage 2 left to stage 3.** Every session the `exec` runner starts runs as the
  controller's own user. It can read `controller.db`, the controller's `/proc/<pid>/environ`, and
  other runs' directories and usage reports. A descendant that calls `setsid` escapes the session's
  process group, and lives until the unit stops. The runner reads liveness by scanning `/proc`.
  Each of these is a property of how a session is launched, not of the runtime, so the contract
  has to settle it.

The contract has two sides with different owners. The controller decides which session runs,
with what grants and limits. The runtime decides how to run an agent loop. The contract has to
let either change without the other: a different runtime behind the same controller, and the same
runtime under a different launcher in CI and in production.

## Decision

1. **The agent-runner contract is a process contract, version 1.0.** A provider implements one
   program, its **runner body**. The controller's runner kind `agent` starts it once per attempt,
   through a **launcher** (decision 4). The body reads one **session spec**, runs the session,
   writes one **usage report**, and exits with a status the provider's manifest maps to the
   seam's failure classes. The contract is three files and one process lifecycle, not a library
   and not an RPC. A body may be written in any language, and a runtime that cannot be imported
   into Go needs no wrapper. The `agent-runtime` slot's descriptor names its contract
   (`conformance/protocols/agent_runner.py`). Its suite carries version 1.0 under ADR-0041, and
   every provider declares the versions it satisfies there.

2. **The session spec is a closed document with no secret in it.**
   `schemas/runner/session.schema.json` 1.0 holds:
   - `run_id`, `agent_key`, `lane`;
   - the prompt by path, never inline (it can hold task text; it is read from the run's spool);
   - `toolsets` and `servers`, the profile's rendered MCP grants as `grants.Catalog.Render`
     returns them;
   - `target`: the gateway's base URL, the model role, and whether this is the cloud leg. There
     is never an engine URL (ADR-0038; no passthrough, ADR-0026's amendment);
   - `home`, `limits` (`timeout_s`, `stall_timeout_s`, `max_turns`, `liveness`);
   - `gateway_tag`, `trace` (a `traceparent`), `budgets` (ADR-0047 decision 6, as data);
   - `usage_path`;
   - `credentials`, which holds names, never values: the gateway key and each run token, as file
     names under the run's credentials directory.

   The controller writes the spec into the run's spool directory (decision 4) and nothing else of
   the session reaches the body's argv or environment. The body's environment is the launcher's
   allowlist (`runner.env_allowlist`, as `exec` has it), and the events token is never in it. A
   negative per field shows what the schema refuses: a key value, an engine URL, an inline prompt,
   an unknown key.

3. **The usage report is a closed, names-and-numbers record.**
   `schemas/runner/usage_report.schema.json` 1.0 holds:
   - `session_id`, `turns`;
   - `calls`: one entry per model call, with its role, input, output and cache-read tokens, and
     its span id. A call the runtime could not size is reported as unsized, never left out;
   - `tool_calls`: one entry per tool call, with the tool name, the server's catalog id, start,
     duration, outcome and span id, never arguments or results (ADR-0047 decision 3);
   - `budget_exhausted` when the runtime received a budget refusal (ADR-0047 decision 7);
   - `class`, a self-reported failure class from the seam's names, which the controller trusts
     only where decision 6 says so.

   It never holds a prompt, task text, tool input or output, or model text (ADR-0025 decision 2),
   and its negatives prove it. The controller reads it after the body exits. A report that does
   not validate is `Internal`, never silently empty. An unknown cost is `null`, and the budget
   backstop never treats `null` as zero (ADR-0047 decision 8).

4. **Each session runs in its own unit, as its profile's user.** This is the production launcher,
   and it is ADR-0045 decision 6's shape.
   - **The unit.** The deploy renders one template per compiled profile,
     `hnx-agent-<slug>@.service`. It has a fixed `ExecStart` (the provider's runner body, from
     its manifest) and `User=` the profile's system user (ADR-0045 decision 7). It loads the
     profile's credential with `LoadCredentialEncrypted=`. It sets `PrivateTmp=`,
     `ProtectProc=invisible` and a `RuntimeDirectory=`, and takes `MemoryMax=`, `TasksMax=` and
     `CPUQuota=` from the profile's limits.
   - **Starting a run.** The controller starts a run as an instance of that template (the instance
     name is the run id), allowed by a polkit rule naming those templates and the `start` and
     `stop` verbs only. It chooses no command and no environment. It supplies only the session
     spec and the run tokens it issued, through a per-run spool directory: created by the
     controller, handed to the profile's user, `0700`, removed with the run.
   - **What this closes.** The session cannot read `controller.db`, the controller's environment
     or another profile's runs. That is the separate session user carried from stage 2. Each run
     is its own cgroup, so cancelling a run is stopping its unit, which ends every descendant, a
     `setsid` one included. That is the per-session cgroup carried from stage 2. Liveness `cpu`
     reads the unit's `cpu.stat` instead of scanning `/proc`. Concurrent runs of one profile share
     its uid (ADR-0047 decision 5 bounds what that allows); each still has its own unit, cgroup,
     spool and private `/tmp`.
   - **The development launcher.** A second launcher, `exec`, runs the body directly under the
     controller's user, as stage 2's runner does. It isolates nothing. `controller check` refuses
     it unless `runner.agent.launcher: exec` comes with `runner.agent.unisolated: true`, and
     `serve` notes it on every start. It exists for CI's network namespace and the lab-in-a-box,
     where there is no systemd and no agent users.

5. **The internal seam grows to the contract, and keeps its shape.** `runner.Session` gains
   `Trace`, `RunTokens` (names of the tokens the controller issued, ADR-0047 decision 5),
   `Credentials` (names, never values) and `Budgets`. The class list gains `BudgetExhausted`,
   which is never retried, moved or re-run on cloud. `runner/agent` implements `Runner` on top of
   decisions 1 to 4. `runner/exec` and `runnertest` stay for the core's tests. A provider never
   imports the seam, and the seam may change without a contract version as long as the session
   spec and the usage report do not.

6. **Failure classes come from typed signals, never from text.** The provider's manifest maps
   exit statuses to classes (`exit_classes`, as `runner.exec` has them). The usage report's
   `class` may name only `TurnCap`, `ContextExceeded`, `ToolCallParse`, `ConcurrencyLimited` and
   `BudgetExhausted`, the classes only the runtime can see. `BudgetExhausted` additionally needs
   the gateway's records by trace (ADR-0047 decision 7). `KilledByController`, `Stalled`,
   `TimeoutCeiling` and `KilledExternally` are the launcher's to decide, from how the unit ended.
   No class is inferred from stderr or the model's output.

7. **Hermes is one provider module, in this repository.** The module
   (`modules/agent-runtime-hermes/`) is a provider of the `agent-runtime` slot. Its manifest has:
   - `product` (the runtime, by its upstream name and pinned version);
   - `origin` (the upstream release by version and hash, ADR-0027 decision 10);
   - the runner body, a thin adapter that turns the session spec into the runtime's home, config
     and command line, and the runtime's usage file into the usage report;
   - `exit_classes`;
   - `conformance` naming the `agent-runner` target;
   - `patches` (decision 8).

   What is Hermes-specific lives only there: the home layout, the config keys, the usage file's
   format. The product-name lint holds it there. The runner body sends `X-HNX-Tag` and
   `traceparent` on every model call, reads its key and tokens from the files the spec names, and
   puts `_meta.traceparent` only on calls to MCP servers whose catalog locality is `local`.

8. **The runtime patch is a manifest-listed file, checked by digest and by behaviour.** Module
   schema 1.x gains `patches`, an additive field: a list of
   `{path, sha256, reason, upstream}`, where `upstream` is the offer's state (`offered`,
   `accepted <version>` or `refused`). It lands with the provider module, as ADR-0026 decision 13
   says. `hnx modules check` refuses a listed patch whose digest differs and a patch file under
   the module that the manifest does not list. The suite's usage check (decision 9) is the
   behavioural half: it fails on the unpatched runtime. The pull request that moves the pin to an
   upstream release with the fix removes the patch and its entry.

9. **The `agent-runner` suite proves the contract against a fake runtime and against each
   provider.** It runs on loopback, with a fake gateway (it records every call's headers and
   bearer), a fake local and a fake non-local MCP server, and the launcher a target names. Its MUST
   checks:
   - `session-answers` (a spec in, the answer and a valid report out);
   - `usage-sizes-each-call` (a session of two model calls reports two sized calls; ADR-0026
     decision 13);
   - `cancel-ends-the-whole-session` (a body that forks a `setsid` child; nothing of the run is
     left after cancel);
   - `stall-is-signalled`, `turn-cap-is-a-class` and `exit-status-maps-to-class`;
   - `per-run-credential` (ADR-0045 decision 6: every call carries the run's profile key, never
     another profile's or a backend's; nothing of the key is left after the run);
   - `trace-propagation` (ADR-0047 decision 2);
   - `gateway-tag-on-every-call`;
   - `tool-call-entries` and `budget-exhausted-is-typed`;
   - `spec-carries-no-secret` (the spec, argv and environment the body sees hold no key value);
   - under the unit launcher, `session-cannot-read-controller-state` (as the session, opening a
     file only the controller's user may read fails).

   Mutants prove each check can fail: a body that drops `_meta`, one that sends it to a non-local
   server, a run sent the backend key or another profile's key, a key left after the run, a start
   outside the templates, a report with an unsized call left out, and a launcher that kills only
   the process group. Checks that need root or systemd (the unit launcher's) run in a CI job that
   has them. The rest run in the network namespace like every suite. A check left `untested`
   fails a strict run.

10. **The fake runtime replaces the stage-2 runner body.** `conformance/fakes/agent_runner_body.py`
    is the contract's reference body. It reads the spec, makes the model calls a scripted job
    line asks for against the target's gateway, calls the handler host as the old body did
    (loopback only), and writes a contract usage report. The orchestration conformance job and
    the lab-in-a-box move to `runner.kind: agent` with the `exec` launcher and this body.
    `conformance/fakes/llm_orchestrator_hermes.py` is deleted in the same pull request, as
    ADR-0026 decision 15 foresaw.

11. **The controller cuts over on the contract, through the ledger.** The controller's ledger row
    (ADR-0043) may reach `new-shadow` only when two things hold. First, the provider's
    `agent-runner` target passes strict in CI, the unit launcher's checks included. Second, the
    lab runs the provider under the unit launcher for the shadow lane. It reaches `new-primary`
    with ADR-0026's gates (decisions 10 and 18) and ADR-0045 decision 11's backend-key exception
    expiring that day.

12. **Small follow-ups that ride along.** Each is a line on the stage-3 pull requests, not a
    decision of its own:
    - The lab-in-a-box bind guard recognises the controller by a fifth mark, its build's
      Dockerfile.
    - The controller's API gains a status scope that reads `GET /admin/queue-summary` only, and the
      example status source moves to it from `read`.
    - The facts command's environment, and the session's `HNX_*` names, refuse `events.token_env`.
    - The development launcher names its excluded variables, rather than relying on their order.
    - The conformance harness uses a throwaway token instead of an unauthenticated loopback bind.
    - The lab image moves to a slim or distroless runtime stage, read-only with a `tmpfs` `/tmp`.

## Consequences

- A runtime can be replaced by writing a runner body and passing one suite. The controller does
  not change. The suite, not a review, says whether a provider keeps the key per run, the trace on
  every hop and the usage report sized.
- The controller's trust boundary moves to the unit. A session can no longer read the
  controller's state or another profile's runs, and a cancelled run leaves nothing behind. Runs of
  one profile still share a uid, which ADR-0047 decision 5 already bounds.
- Production needs systemd, polkit, `systemd-creds` and an agent user per profile. CI needs a job
  that has root for the unit launcher's checks. The development launcher keeps CI's namespace and
  the lab-in-a-box working, and is refused anywhere it is not declared unisolated.
- The repository carries a third-party runtime's adapter and, until upstream ships the fix, a
  patch to it. A pin bump is then a module pull request with its review tier and the suite run.
- Two schemas join the contract surface (session spec, usage report), versioned with the suite
  under ADR-0041. A field the runtime needs later is an additive minor.

### Implementation plan

Each step is its own pull request and says what it proves.

1. **This ADR** (docs only): the index row, the summary stamp and the README count. Proves: the ADR
   log test, the docs index and the summaries lint pass.
2. **The contract surface.** This adds the session spec and usage report schemas with examples and
   a negative per refused field, `conformance/protocols/agent_runner.py`, the slot descriptor's
   `contract`, the fake runtime (`agent_runner_body.py`) and the suite's checks against it with the
   development launcher. Proves: every check passes on the fake, and every mutant of decision 9
   that needs no root is caught.
3. **The controller's `agent` runner kind with the development launcher.** This adds the seam's new
   fields and `BudgetExhausted`, `runner/agent`, and `controller check`'s launcher rules.
   `orchestration-conformance` and the lab-in-a-box move to it, and
   `llm_orchestrator_hermes.py` is deleted. Proves: the orchestration suite passes strict with
   `runner.kind: agent`, `check` refuses an undeclared unisolated launcher, and no file names the
   old body.
4. **The unit launcher.** This adds the per-profile template render (`hnx gen agent-units` from the
   compiled profiles), the polkit rule, the per-run spool, sealed credentials (ADR-0045 step 11),
   cgroup cancel and liveness, and the root CI job. Proves, in that job:
   `session-cannot-read-controller-state`, `cancel-ends-the-whole-session` with a `setsid` child,
   and `per-run-credential` with its four mutants (backend key, another profile's key, a key left
   after the run, a start outside the templates).
5. **`patches` in the module schema and `hnx modules check`.** Proves: a listed patch with another
   digest is refused, an unlisted patch file is refused, and a listed one that matches passes.
6. **The Hermes provider module**, with its patch, runner body, `exit_classes` and `agent-runner`
   target, and the suite run strict against it in CI. Proves: `usage-sizes-each-call` fails on the
   unpatched runtime and passes on the patched one, and every MUST check passes on the provider.
7. **Trace, tool-call entries and the budget signal** (ADR-0047 step 7), if they are not already
   complete in steps 2 and 6. Proves: `trace-propagation` passes on the fake and the provider, and
   fails on a body that drops `_meta` and on one that sends it to a non-local server;
   `budget-exhausted-is-typed` fails on a refusal with no typed signal.
8. **The small follow-ups of decision 12**, each with its test.
9. **Overlay (operator-merged):** the lab's agent users, the rendered units, the sealed
   credentials, and the controller's ledger row moved to `new-shadow` under decision 11. Proves:
   the overlay's checks job is green, and `hnx cutover check` accepts the transition's evidence.

### Operator decisions needed

Each has a recommended default; this ADR is written to the default.

1. **Where the Hermes provider module lives.** Default: in this repository, at
   `modules/agent-runtime-hermes/`. The runtime is open source and the adapter holds nothing about
   the lab. The alternative is the overlay, which would keep the runtime's name out of the public
   tree at the cost of no public suite run against a real provider.
2. **The contract's form.** Default: the process contract of decision 1. The alternatives are a
   linked Go interface or an RPC service (see Alternatives).
3. **The production launcher.** Default: a systemd unit per run (decision 4, ADR-0045 decision 6's
   shape). The alternative is a setuid helper with bubblewrap.
4. **Concurrent runs of one profile.** Default: they share the profile's uid, each with its own
   unit, spool and private `/tmp`. The alternative is a uid per run (`DynamicUser=`), which breaks
   the broker's peer-uid identity (ADR-0045 decision 7) unless the broker learns run-scoped uids.
5. **The development launcher outside CI.** Default: allowed only when declared unisolated, refused
   by `controller check` otherwise, and never in the overlay's production config.
6. **CI for the unit launcher.** Default: a CI job with root and systemd (as the real-tools job has
   root) runs the unit launcher's checks on every pull request that touches the runner or the
   provider. The alternative is running them nightly only.
7. **The runtime in CI.** Default: the pinned upstream release is fetched by hash before the
   network namespace, as the Go modules are, and the suite runs both the unpatched and the patched
   runtime, so the usage check's red is proven on every run.
8. **Liveness.** Default: `cpu` from the unit's cgroup and `progress` from the usage report's
   growth, with `stall-is-signalled` covering both. The alternative is a heartbeat file the runtime
   must write, which the runtime does not do today.
9. **Who offers the patch upstream.** Default: the operator, as ADR-0026 decision 13 says, before
   the provider module's pull request. The module records the offer's state in `patches[].upstream`.

## Alternatives

- **An in-process Go interface, with the provider linked into the controller.** It is the
  smallest change from the seam, but every runtime would need a Go wrapper. The controller and the
  runtime would share a process, so a runtime fault could take the controller down, and a
  session's isolation would rest on code instead of the kernel.
- **An RPC runner service (a long-running daemon per host that starts sessions).** It adds a
  privileged daemon that must hold every profile's key, which ADR-0045 decision 6 rules out (the
  launcher must not be able to run an arbitrary process as an agent uid).
- **A setuid helper or bubblewrap instead of systemd units.** Either can switch users and make
  namespaces. Neither gives a per-run cgroup that ends every descendant, sealed credentials
  released on every exit, or accounting the controller can read, without rebuilding what the
  unit already has.
- **Keep sessions under the controller's user and harden the files.** The usage directory showed
  that a layout is not an isolation: the session can read whatever the controller's user can.
