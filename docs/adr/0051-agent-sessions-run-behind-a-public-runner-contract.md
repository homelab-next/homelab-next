---
summary: Agent sessions run behind a public runner contract (session spec, usage report, launcher), each in its own unit as its profile user; Hermes is one provider.
summary_of: outline:sha256:3881cb36345d453b
---
# ADR-0051: Run agent sessions behind a public agent-runner contract

- **Status:** proposed
- **Date:** 2026-11-09
- **Related:** ADR-0013 (agent activity tiers), ADR-0025 (orchestration telemetry), ADR-0029
  (holds released by liveness), ADR-0030 (agents act only through the broker), ADR-0033 (TLP),
  ADR-0038 (the gateway), ADR-0040 (modules are replaceable by construction), ADR-0041 (versioned
  capability contracts), ADR-0043 (the cutover ledger),
  [the controller](../orchestration-controller.md)
  ("The runner seam", "The trust boundary", "Stage 3 (the provider)", "Carried past PR 2.7b"),
  [modules](../modules.md), `examples/modules/slots.yml` (`agent-runtime`)
- **Depends-on:** ADR-0026, ADR-0027, ADR-0045, ADR-0047
- **Amends:** ADR-0026, ADR-0047

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
  ADR-0026's amendment put `Session.Trace` and `Session.RunTokens` on the seam in stage 2's PR 2.4.
  **PR 2.4 did not deliver them:** the seam on `main` has neither field and no `BudgetExhausted`
  class. This ADR gives each piece one owner (decision 5).
- **The runtime patch** (ADR-0026 decision 13). The runtime is patched so that its usage file
  sizes each model call. The provider module carries the patch, listed by path and digest, until
  an upstream release has the fix. A usage check (two model calls report two sized calls) fails
  on the unpatched runtime.
- **What the controller doc leaves to the provider** ("Stage 3 (the provider)"):
  - the runner sends `Session.GatewayTag` as `X-HNX-Tag` on every model call;
  - the provider classifies its own failures, which until now were matched as text: a connection
    or timeout signature is `BackendFault`, and the others are `ContextExceeded`, `ToolCallParse`,
    `Stalled`, `TimeoutCeiling` and `TurnFailed`;
  - output saying nothing serves the backend carries `runner.MarkAbsent`;
  - a clean exit whose answer is a failure report goes through an `AnswerChecker`.
- **What stage 2 left to stage 3.** Every session the `exec` runner starts runs as the
  controller's own user. It can read `controller.db`, the controller's `/proc/<pid>/environ`, and
  other runs' directories and usage reports. A descendant that calls `setsid` escapes the session's
  process group, and lives until the unit stops. The runner reads liveness by scanning `/proc`.
  Each of these is a property of how a session is launched, not of the runtime, so the contract
  has to settle it.

The contract has two sides with different owners. The controller decides which session runs,
with what grants and limits. The runtime decides how to run an agent loop. The contract has to
let either change without the other: a different runtime behind the same controller, and the same
runtime under a different launcher in CI and in production. And whoever can write a session's
inputs must not thereby choose what runs as an agent's uid.

## Decision

### The contract

1. **The agent-runner contract is a process contract, version 1.0.** A provider implements one
   program, its **runner body**. The controller's runner kind `agent` starts it once per attempt,
   through a **launcher** (decisions 7 to 10). The body reads one **session spec**, runs the
   session, appends to one **usage stream**, and exits with a status the provider's manifest maps
   to the seam's failure classes. The contract is files and one process lifecycle, not a library
   and not an RPC. A body may be written in any language, and a runtime that cannot be imported
   into Go needs no wrapper. The `agent-runtime` slot's descriptor names its contract
   (`agent_runner.py` under `conformance/protocols/`). Its suite carries version 1.0 under
   ADR-0041, and every provider declares the versions it satisfies there.

2. **The session spec is closed, holds no secret and names no command.**
   `schemas/runner/session.schema.json` 1.0 holds:
   - `run_id`, `agent_key`, `lane`;
   - the prompt as a credential name (decision 8), never inline;
   - `toolsets`, and `servers` as **server ids only**. A server's command, arguments and
     environment are never in the spec (decision 3);
   - `target`: the gateway's base URL, the model role, and whether this is the cloud leg. There
     is never an engine URL (ADR-0038; no passthrough, ADR-0026's amendment). The URL is a
     consistency check, not a choice: the deploy pins the gateway in the unit template
     (`Environment=HNX_GATEWAY_URL=`; the development launcher sets it the same way), and the
     body sends the run's key, tokens and prompt only there. A spec naming another gateway makes
     no call and ends `Internal`, so whoever writes the spec cannot choose where the key goes
     (ADR-0045 decision 6);
   - `limits` (`timeout_s`, `stall_timeout_s`, `max_turns`, `liveness`);
   - `gateway_tag`, `trace` (a `traceparent`), `budgets` (ADR-0047 decision 6, as data);
   - `credentials`: the names of the gateway key and of each run token, which decision 8 makes
     files under the same directory for both launchers.

   A negative per field shows what the schema refuses: a key value, an engine URL, an inline
   prompt, a server command, an unknown key.

3. **A session's MCP servers come from a deploy-rendered grants file, never from the spec.**
   `hnx gen agent-units`, run as root by the deploy, renders each compiled profile's servers
   (`grants.Catalog.Render`, both lanes) into `/etc/hnx-agent/<slug>/grants.json`, mode `0640`,
   owned `root:hnx-agent-<slug>`, beside the unit template. It refuses a server of a kind the
   profile is not granted. A server's `env` holds no credential and refuses every key the MCP
   catalog refuses (its `DENIED_ENV`: the loader, the interpreters, the proxies, ...); a
   server's `locality: local` is checked against the registry at render time, so a non-local
   server is never given the trace by a wrong label.
   The template pins the file in two ways:
   - **The file's own bytes.** The sha256 of `grants.json` is pinned as
     `Environment=HNX_GRANTS_SHA256=`. That is the integrity check: the runner body refuses a file
     whose bytes do not match.
   - **The compiled profile's digest.** The file also records the digest of the profile it came
     from. That is only a staleness check, so a profile recompiled without a redeploy is refused.

   The body starts only servers whose ids are both in the spec and in the file. An id the file
   does not list is refused, and the session ends `Internal` before any server starts. Whoever
   writes a session's inputs can therefore narrow a run's servers, never add one or change what
   one runs, and the `servers` of the internal seam stop at the launcher. Under the development
   launcher, the controller writes the same file from its own render into the run's directory.

4. **The usage stream is append-only, closed, and names and numbers only.**
   `schemas/runner/usage_record.schema.json` 1.0 defines the records of one JSON Lines file:
   - `call`, one per model call: role, input, output and cache-read tokens, span id. A call the
     runtime could not size is an `unsized` call, never left out;
   - `tool_call`, one per tool call: tool name, the server's catalog id, start, duration, outcome
     and span id, never arguments or results (ADR-0047 decision 3);
   - `signal`, a typed runtime signal (decision 6);
   - `end`, written last: `session_id`, `turns`, `budget_exhausted` when the runtime received a
     budget refusal (ADR-0047 decision 7), and `class` (decision 6).

   Records are written as they happen. A stream is bounded:
   - at most `max_usage_bytes` in all, and each line at most 16 KiB and nested at most 8 deep;
   - the launcher stops a unit whose stream passes the bound, as `ResourceLimit`;
   - a stream over the bound when read is `Internal`;
   - each output root is its own size-limited filesystem or quota (decision 8), so one run cannot
     fill a disk another run needs.

   `progress` liveness (decision 10) counts new `call` records the gateway's records corroborate,
   not raw growth, so a body cannot keep a stalled session alive by writing. A stream with no
   `end` record is a session that did not finish its report. That
   is fine for a killed session, and `Internal` for a clean exit. A record that does not validate
   is `Internal`, never silently skipped. No record holds a prompt, task text, tool input or
   output, or model text (ADR-0025 decision 2), and the negatives prove it.

   **The gateway's records are authoritative for cost and budget.** The controller sums usage by
   trace and tag from the gateway (ADR-0047 decision 8). It flags a stream whose call count or
   tokens disagree with the gateway's as `usage_mismatch` on the job (an invariant, never a
   class). An unknown cost is `null`, never zero.

### The seam

5. **The seam grows to the contract, and each new piece has one owner.**
   - **This ADR's step 3** adds to `runner.Session` the fields `Trace`, `RunTokens` (names of the
     tokens the controller issued), `Credentials` (names, never values) and `Budgets`. It adds the
     classes `BudgetExhausted` and `ResourceLimit` (decision 10) and `runner/agent`, which passes
     the new fields into the spec and the launcher.
   - **ADR-0047's step 6**, landing after this ADR's step 3, mints and stores the trace and issues
     the run tokens. It also runs the budget backstop and adds the `orchestration-features`
     checks. It no longer adds the class.
   - ADR-0026's amendment and ADR-0047's decision 2 table are amended to say so.
   - `runner/exec` and `runnertest` stay for the core's tests.
   - A provider never imports the seam, and the seam may change without a contract version as
     long as the spec and the stream do not.

6. **Failure classes come from typed signals, never from text, and the gateway corroborates what
   it can.** The pool reads only classes (the controller doc's "Stage 3 (the provider)" list), and
   each of them now has a typed source:

   | Class | Source |
   |---|---|
   | `BackendFault` | an exit status the manifest maps to it (`exit_classes`), for a connection or timeout signature the body saw on the gateway |
   | `ContextExceeded`, `ToolCallParse`, `TurnCap` | the `end` record's `class`, on any exit, a clean one included |
   | `ConcurrencyLimited` | the `end` record's `class` or an exit status the manifest maps to it, uncorroborated (see below) |
   | `BudgetExhausted` | the `end` record's `budget_exhausted` (ADR-0047 decision 7) |
   | `Stalled`, `TimeoutCeiling`, `KilledByController`, `KilledExternally`, `ResourceLimit` | the launcher, from how the unit ended (decision 10) |
   | `TurnFailed` | an exit status the manifest maps to it |

   - **The gateway corroborates what it records.**
     - A self-reported `ContextExceeded` counts only when the gateway's usage records for the
       run's tag hold a call with `error_code` `upstream_rejected` and `status` 400, recorded
       later than every call the gateway answered in the run (a refusal followed by answered calls
       is a turn the runtime recovered from, not the reason it stopped). That is the gateway's
       envelope for an upstream 4xx. It proves the upstream refused the call, not that
       the refusal was the context window, because the gateway does not tell those apart.
     - An uncorroborated `ContextExceeded` is `Internal`, which moves nothing. That covers a claim
       with no matching record, records that lag, and a window in which the gateway reported
       `usage_records_dropped > 0`. It is never `TurnFailed`, which would be attributable and move
       the job.
     - **How long the launcher waits.** Before it decides a corroborated class, the launcher waits
       up to `runner.agent.gateway_wait_s` (default 2 seconds) for the gateway's records to cover
       the run's end, polling the usage API. Records still behind after that, or a gateway that
       reports dropped records, leave the claim uncorroborated, so a slow gateway can delay a
       class by that long and never turn it into an attributable one.
     - `ConcurrencyLimited` is **not** corroborated. The gateway refuses `429 concurrency_limited`
       before the model call and writes no usage record for it, so requiring one would turn every
       such refusal into a fault and move the job, which the operator's decision of 2026-11-08
       forbids. A false claim only makes the run wait on its own backend, and the pool bounds the
       waits (`Policy.ConcurrencyWaits`).
     - `BudgetExhausted` needs the gateway's or the broker's records (ADR-0047 decision 7).
   - **Retired text matching.** A `signal` record `backend_absent` (the backend answered that
     nothing serves it) is the typed form of `runner.MarkAbsent`. It prompts the pool's own health
     probe and is never a verdict on its own. The `AnswerChecker`, which read a clean exit's answer
     as a failure report, is retired: a clean exit that failed says so in its `end` record's
     `class`. Its text matching moves nowhere, because the controller doc's rule that a failure's
     text may quote the model holds for the provider too.
   - **The default is non-attributable.** Under `runner.kind: agent`, an exit status the manifest
     does not map is `Internal`, whether the exit was zero or not, and `Internal` moves no job to
     another backend or to the cloud.

### The launchers

7. **Each session runs in its own unit, as its profile's user.** This is the production launcher,
   and it is ADR-0045 decision 6's shape.
   - **The template.** The deploy renders one template per compiled profile,
     `hnx-agent-<slug>@.service`. It has:
     - a fixed `ExecStart` (the provider's runner body, from its manifest) and `User=` the
       profile's system user (ADR-0045 decision 7, whose `agent_users` role is a prerequisite);
     - `LoadCredentialEncrypted=` for the profile's gateway key, and `LoadCredential=` for the
       run's inputs (decision 8);
     - `CollectMode=inactive-or-failed`;
     - `PrivateTmp=yes`, `PrivatePIDs=yes`, `ProtectProc=invisible`, `ProtectSystem=strict`,
       `ProtectHome=yes`, `NoNewPrivileges=yes`, `CapabilityBoundingSet=` (empty) and a
       `SystemCallFilter=`;
     - `IPAddressDeny=any`, with `IPAddressAllow=` the gateway's and each granted network MCP
       server's addresses. They are rendered as addresses at deploy, from the registry. A name that
       does not resolve then fails the render (fail closed). If the body resolves names itself, the
       local resolver's address is allowed too, and nothing else;
     - `MemoryMax=`, `TasksMax=`, `CPUQuota=` and `RuntimeMaxSec=` from the profile's limits, the
       last a backstop a grace past the controller's ceiling.

     The template uses `%i` (the escaped instance name), never `%I`, in every path. The instance
     name is the run id: 32 lower-case hex digits from the operating system's generator, which
     also makes it unguessable.

     `PrivatePIDs=` needs systemd 257 or later. `controller check` under the unit launcher, and the
     overlay's validation of a host that runs it, refuse an older systemd (operator decision 6),
     rather than let the template start without its PID namespace.
   - **The polkit rule is exact.** It returns `YES` only when all of these hold, and everything
     else falls through to the default deny:
     - `action.id == "org.freedesktop.systemd1.manage-units"`;
     - `subject.user` is the controller's user;
     - the `verb` detail is `start` or `stop`;
     - the `unit` detail fully matches `^hnx-agent-[a-z0-9-]+@[0-9a-f]{32}\.service$`.

     That rule lets the controller do nothing else: no transient units (`StartTransientUnit`,
     `systemd-run`), no `SetUnitProperties`, no `restart`, `reload` or `kill`, and nothing for an
     agent's uid.
   - **What it closes.** The session cannot read `controller.db`, the controller's environment or
     another profile's runs. That is the separate session user carried from stage 2. Each run is
     its own cgroup, so cancelling a run is stopping its unit, which ends every descendant, a
     `setsid` one included. That is the per-session cgroup carried from stage 2. Liveness `cpu`
     reads the unit's `cpu.stat` instead of scanning `/proc`.

8. **A run's inputs are credentials and its outputs are a group-shared directory.** Neither needs
   a privilege the controller does not have: its bounding set is empty, so it can chown nothing.
   - **Inputs.** The controller writes the spec, the prompt, the grants under the development
     launcher, and each run token as `0600` files it owns, in
     `/var/lib/orchestrator/runs/<run id>/in/`. The template's `LoadCredential=` lines, such as
     `spec:…/%i/in/spec.json`, one per name the contract defines (`spec`, `prompt`,
     `run-token-gateway`, `run-token-broker`), have the service manager copy them into the run's
     `$CREDENTIALS_DIRECTORY`.
     That directory is readable only by the run's uid, read-only, and gone when the unit stops.
     The agent cannot rewrite its spec after the controller validated it, and never sees another
     run's inputs.
   - **Outputs.** The deploy creates one output root per profile, `/var/lib/hnx-agent/<slug>/`,
     owned `root:hnx-agent-<slug>`, mode `2770` (setgid), on its own size-limited filesystem or
     quota.
     - The profile's user and the controller's user are the group's only members. The deploy
       guarantees that the `hnx-agent-<slug>` groups grant nothing beyond the output roots: no
       other file or directory is group-owned by one.
     - Before it starts the unit, the controller creates the run's `<run id>/` directory and sets
       it to `2770` explicitly. The controller runs under `UMask=0077`, so the mode is a `chmod`,
       never inherited.
     - The body writes the usage stream and its answer there, under `UMask=0007`. The controller
       reads them and removes the directory when the run ends.
     - Removal never follows a link. Go's `os.RemoveAll` walks with `openat` and does not follow
       symbolic links, and the tests hold it to that with a link planted in a run directory.
   - **Sibling runs of one profile.** They share the uid and the group, so each unit sees its own
     run only:
     - `TemporaryFileSystem=` hides the output root and `/run/credentials`;
     - `BindPaths=` maps back the run's own `<run id>/` directory;
     - the unit's own `$CREDENTIALS_DIRECTORY` stays mounted over the hidden `/run/credentials`;
     - `PrivatePIDs=` hides the siblings' processes.

     Two checks of decision 13 hold this together. `sibling-runs-see-only-their-own` proves the
     hiding works. `session-answers`, run under the unit launcher, proves the hiding does not also
     hide the run's own credentials and directory, which a wrong mount order would. ADR-0047
     decision 5 bounds what a sibling could do with a token if it got one.
   - **The home.** The runtime's home is built in the run's own directory, from the backend's
     home, which is a read-only template the deploy installs. No run writes a shared home.
   - **The controller reads defensively.** It opens each output with `O_NOFOLLOW|O_NONBLOCK` (so a
     FIFO planted in place of a file cannot block it), then checks that the open file is regular.
     It reads at most the stream's bound (`max_usage_bytes`) and the answer's
     (`max_response_bytes`).
   - **Facts commands run without the agent groups.** The controller is a member of every
     `hnx-agent-<slug>` group. A facts command it runs (stage 2's facts block) drops those
     supplementary groups first, so a facts command can never read a run's outputs. The controller
     doc's trust boundary says so.
   - **Names for both launchers.** The body finds its inputs under `$CREDENTIALS_DIRECTORY` and
     its output directory under `$HNX_RUN_DIR`, under both launchers. The development launcher
     sets both to directories in the run's own tree.

9. **The development launcher runs the body as the controller's user, and is barred from
   production mechanically.** The `exec` launcher exists for CI's network namespace and the
   lab-in-a-box, where there is no systemd and no agent users. It isolates nothing, and the bar is
   enforced in three places, not left to a reader:
   - `controller check` refuses it unless the configuration also sets
     `runner.agent.unisolated: true`;
   - `serve` refuses it when the API binds beyond loopback, or when any `hnx-agent-*` unit or
     agent user exists on the host;
   - the overlay's validation refuses `unisolated: true` in a production configuration.

   `runner.env_allowlist` applies to this launcher only. The unit launcher's environment is the
   template's, fixed at deploy.

10. **The launcher decides how a unit ended, before the unit is collected.**
    - **Watching.** It subscribes to the service manager's `JobRemoved` and to the unit's
      `PropertiesChanged`. When the unit goes inactive or failed, it reads `Result`,
      `ExecMainCode` and `ExecMainStatus`, then lets `CollectMode=` collect the unit.
    - **Mapping each result to a class:**

      | How the unit ended | Class |
      |---|---|
      | `exit-code` | the manifest's `exit_classes` and the stream (decision 6) |
      | the controller stopped it for a cancel or the run's deadline | `KilledByController` |
      | the controller stopped it at the attempt's ceiling on a session still progressing | `TimeoutCeiling` |
      | `timeout`, the `RuntimeMaxSec=` backstop | `TimeoutCeiling` |
      | the controller stopped it for no progress within `stall_timeout_s` | `Stalled` |
      | `oom-kill` | `ResourceLimit`, never retried, moved or re-run on cloud |
      | `signal` the controller did not send, or `core-dump` | `KilledExternally` |
      | anything else | `Internal` |

    - **Liveness.** `cpu` reads the unit's `cpu.stat`. `progress` counts the stream's new `call`
      records that the gateway corroborates (decision 4). While the gateway's records lag by more
      than the gateway wait, or the gateway reports dropped records, nothing counts as progress:
      the stall timer runs on. The launcher never falls back to CPU time there, because a body
      could flood the gateway into dropping records and then busy-loop to stay alive. A run's
      liveness mode is fixed by its spec, so no mode switch can reset the timer.
    - **`ResourceLimit` end to end.**
      - It comes only from `Result=oom-kill` or the stream bound (decision 4), never from a signal
        kill. A `SIGKILL` the launcher did not cause is `KilledExternally`.
      - In the queue it joins `spentBudget` (`queue/failure.go`), so `mayRetryAttempt` and
        `mayAutoRequeue` refuse it: never retried by `max_attempts`, never requeued, never moved to
        another backend or re-run on cloud.
      - It is stored as failure class `resource-limit` and published as the failed event's
        `reason`. It is not in `RetryableFailureClass`, so a caller's resubmit is refused as for
        `budget` and `turn-cap`. A run under raised limits is a new submit with the new profile
        revision, not a resubmit.
      - `agent-job-retry`'s trigger reasons (capacity, stall, timeout, backend-down) exclude it.
      - The telemetry's `failure_class` enum docs list it (operator decision 10).

### The provider, the patch and the suite

11. **Hermes is one provider module, in this repository.** The module
    (`modules/agent-runtime-hermes/`) is a provider of the `agent-runtime` slot. Its manifest has:
    - `product` (the runtime, by its upstream name and pinned version);
    - `origin` (the upstream release artifact by version and hash, ADR-0027 decision 10);
    - the runner body, a thin adapter that turns the spec into the runtime's home, config and
      command line, and the runtime's usage file into the usage stream;
    - `exit_classes`;
    - `conformance` naming the `agent-runner` target;
    - `patches` (decision 12).

    What is Hermes-specific lives only there: the home layout, the config keys, the usage file's
    format. The product-name lint holds it there. The body:
    - sends `X-HNX-Tag` and `traceparent` on every model call;
    - reads its key, its tokens and its prompt from the credential names the spec gives;
    - puts `_meta.traceparent` only on calls to MCP servers whose catalog locality is `local`;
    - writes `backend_absent` when the runtime reports that nothing serves the backend.

12. **The runtime patch is applied to the hash-verified artifact, and reviewed with the module.**
    Module schema 1.x gains `patches`, an additive field: a list of
    `{path, sha256, applies_to, patched_sha256, reason, upstream}`, where:
    - `applies_to` is the upstream artifact's hash;
    - `patched_sha256` is the patched result's hash;
    - `upstream` is the offer's state (`offered`, `accepted <version>` or `refused`).

    The patch's provenance is the module's review tier (`hnx modules review-tier`): a patch change
    is a module change. The build verifies the artifact against `origin` before unpacking it,
    applies the patch, and checks the result against `patched_sha256`. `hnx modules check` refuses
    a listed patch whose digest differs and a patch file under the module that the manifest does
    not list. The suite's usage check (decision 13) is the behavioural half: it fails on the
    unpatched runtime. The pull request that moves the pin to an upstream release with the fix
    removes the patch and its entry.

13. **The `agent-runner` suite proves the contract against a fake runtime and against each
    provider.** It runs with:
    - a fake gateway that records every call's headers and bearer, and speaks ADR-0047's wire
      formats for run tokens and budget refusals (its steps 3 and 4). The run token travels in
      one header, `X-HNX-Run-Token` (`RUN_TOKEN_HEADER` in `homelabnext/orchestration/trace.py`),
      which every party imports and ADR-0047's step 3 gateway verifies and, like
      `Authorization`, never writes to a log;
    - a fake local and a fake non-local MCP server;
    - a launcher. A provider's target supplies only its runner body's argv and its
      `exit_classes`, and is run under the reference launcher (later the controller's
      `runner/agent`); a launcher is certified by its own target. So the checks of the
      launcher's own rules (exit statuses, stream bounds, what reaches the body) always run,
      with a suite body in place of the provider's, and no target can skip them.

    Its MUST checks:
    - `session-answers`: a spec in, the answer and a valid stream with an `end` record out;
    - `usage-sizes-each-call`: a session of two model calls reports two sized calls (ADR-0026
      decision 13);
    - `cancel-ends-the-whole-session`: a body that forks a `setsid` child leaves nothing of the
      run after cancel;
    - `stall-is-signalled`, `turn-cap-is-a-class` and `exit-status-maps-to-class`;
    - `unreachable-gateway-is-a-backend-fault`: a target gateway that refuses connections
      reaches the pool as `BackendFault`;
    - `unmapped-exit-is-internal`;
    - `self-reported-class-needs-the-gateway`: a `ContextExceeded` the fake gateway never refused
      (no `upstream_rejected`/400 record for the tag) is `Internal`, and a `ConcurrencyLimited`
      with no gateway record still waits on its own backend, never moving;
    - `per-run-credential` (ADR-0045 decision 6): every call carries the run's profile key, never
      another profile's or a backend's, and nothing of the key is left after the run;
    - `trace-propagation` (ADR-0047 decision 2), `gateway-tag-on-every-call`, `tool-call-records`
      and `budget-exhausted-is-typed`;
    - `servers-come-from-the-grants-file`: the spec names a server id the grants file lacks, the
      spec carries a command, or the grants file's bytes differ from `HNX_GRANTS_SHA256`, and
      nothing runs;
    - `usage-stream-is-bounded`: a stream past the bound, a line over 16 KiB or nesting past 8 is
      refused, and records a body writes without model calls do not count as progress;
    - `spec-carries-no-secret`: the spec, argv and environment the body sees hold no key value.

    Under the unit launcher, in a CI job that has systemd and root, these MUST checks are added:
    - `session-answers` again, here because a wrong mount order can hide the run's own
      credentials and directory under the per-unit mounts;
    - `session-cannot-read-controller-state`;
    - `sibling-runs-see-only-their-own`: a session can neither read nor write another run's or
      another profile's directory, and cannot see a sibling's processes. It exists because
      siblings share a uid and group, so only the per-unit mounts and PID namespace keep them
      apart;
    - `outputs-are-read-without-following`: a symbolic link or a FIFO planted in place of the
      stream or the answer is refused without blocking, and removing the run directory leaves the
      link's target untouched;
    - `oom-kill-is-a-resource-limit`;
    - `stop-ends-the-run-as-killed-by-controller`;
    - `polkit-allows-only-start-and-stop-of-run-units`.

    Mutants prove each check can fail:
    - a body that drops `_meta`, and one that sends it to a non-local server;
    - a run sent the backend key, a run sent another profile's key, and a key left after the run;
    - a body that runs a command from the spec, and one that starts an unlisted server id;
    - a stream with an unsized call left out;
    - a launcher that kills only the process group;
    - for the polkit rule: a start or stop by an agent's uid; `StartTransientUnit` (`systemd-run`)
      with a matching name and `ExecStart=` or `User=root`; `SetUnitProperties`; `restart`,
      `reload` or `kill` of a run unit; and a start of an instance that is not a run id.

    A check left `untested` fails a strict run.

14. **The fake runtime replaces the stage-2 runner body.** `agent_runner_body.py` (under
    `conformance/fakes/`) is the contract's reference body. It:
    - reads the spec and the grants file;
    - makes the model calls a scripted job line asks for against the target's gateway;
    - calls the handler host as the old body did (loopback only);
    - appends a contract usage stream.

    The orchestration conformance job and the lab-in-a-box move to `runner.kind: agent` with the
    development launcher and this body, and `conformance/fakes/llm_orchestrator_hermes.py` is
    deleted in the same pull request, as ADR-0026 decision 15 foresaw.

15. **The controller cuts over on the contract, through the ledger.** The controller's ledger row
    (ADR-0043) may reach `new-shadow` only when two things hold. First, the provider's
    `agent-runner` target passes strict in CI, the unit launcher's checks included. Second, the
    lab runs the provider under the unit launcher for the shadow lane. It reaches `new-primary`
    with ADR-0026's gates (decisions 10 and 18) and ADR-0045 decision 11's backend-key exception
    expiring that day.

16. **Small follow-ups that ride along**, each a line on a stage-3 pull request, checked against
    `main` on 2026-11-09:
    - The lab-in-a-box bind guard recognises the controller by a fifth mark, its build's
      Dockerfile.
    - The controller's API gains a status scope that reads `GET /admin/queue-summary` only. Today
      the example status source uses `read`, which also lists job summaries.
    - The conformance harness uses a throwaway token instead of an unauthenticated loopback bind.
    - The lab image moves to a slim or distroless runtime stage, read-only with a `tmpfs` `/tmp`.

    - The gateway emits a distinct `error_code` for a context-window refusal (for example
      `context_length_exceeded`), and `ContextExceeded` is corroborated on it, not on any 400
      `upstream_rejected`.

    Two follow-ups are already on `main` and are not repeated: the `events.token_env` refusals
    (the facts commands' environment, the session's variables and the allowlist), and the `exec`
    runner's named exclusion of its servers-file variable.

### Amendments

17. **ADR-0026 and ADR-0047 are amended.**
    - ADR-0026's amendment ("Requirements other ADRs put on these stages") puts `Session.Trace`
      and `Session.RunTokens` in PR 2.4. They move to this ADR's step 3.
    - ADR-0047's decision 2 table names PR 2.4 for the controller-to-runner hop. It now names this
      ADR's step 3 for the seam fields and ADR-0047's step 6 for the minting.
    - ADR-0047's step 6 lands after this ADR's step 3, and no longer adds `BudgetExhausted`.
    - ADR-0047's step 3 carries the run token in `X-HNX-Run-Token` (decision 13), imports the
      shared constant, and redacts the header from the gateway's access logs.

## Consequences

- A runtime can be replaced by writing a runner body and passing one suite. The controller does
  not change. The suite, not a review, says whether a provider keeps the key per run, the trace on
  every hop and the usage stream sized.
- The controller's trust boundary moves to the unit, and what an agent's uid runs is fixed at
  deploy. Whoever writes a session's inputs can narrow its servers, but cannot choose a command.
  A session can no longer read the controller's state or another profile's runs, and a cancelled
  run leaves nothing behind. Runs of one profile still share a uid, and the per-unit mounts and
  PID namespace keep them apart.
- Production needs systemd with `PrivatePIDs=` (systemd 257 or later), polkit, `systemd-creds`, an
  agent user and group per profile, and the deploy's grants files. CI needs a job with root and
  systemd for the unit launcher's checks. The development launcher keeps CI's namespace and the
  lab-in-a-box working, and is refused in three places anywhere it would matter.
- The repository carries a third-party runtime's adapter and, until upstream ships the fix, a
  patch to it. A pin bump is then a module pull request with its review tier and the suite run.
- Two schemas join the contract surface (the session spec and the usage record), versioned with
  the suite under ADR-0041. A field the runtime needs later is an additive minor.
- `ResourceLimit` is a new seam class, and needs a failure class in the job record (operator
  decision 10).

### Implementation plan

Each step is its own pull request and says what it proves.

1. **This ADR** (docs only), with the **Amended** and **Amended-by** lines on ADR-0026 and
   ADR-0047, the index row, the summary stamp and the README count. Proves: the ADR log test, the
   docs index and the summaries lint pass.
2. **The contract surface.** This adds:
   - the session spec, usage record and grants file schemas, with examples and a negative per
     refused field;
   - the protocol (`agent_runner.py` under `conformance/protocols/`) and the slot descriptor's
     `contract`;
   - the fake runtime and the fake gateway (on ADR-0047 steps 3 and 4's wire formats);
   - the suite's checks that need no systemd, with the development launcher.

   Proves: every one of those checks passes on the fake, and every mutant of decision 13 that
   needs no systemd is caught.
3. **The controller's `agent` runner kind with the development launcher.** This adds the seam's
   new fields, `BudgetExhausted` and `ResourceLimit`, `runner/agent`, and the three bars of
   decision 9. `orchestration-conformance` and the lab-in-a-box move to it, and
   `llm_orchestrator_hermes.py` is deleted. Proves:
   - the orchestration suite passes strict with `runner.kind: agent`;
   - `check` refuses an undeclared unisolated launcher, and `serve` refuses it beyond loopback;
   - an unmapped exit is `Internal`;
   - no file names the old body.
4. **The unit launcher**, after ADR-0045 step 10 (`agent_users`). This adds:
   - the per-profile template and grants-file render (`hnx gen agent-units` from the compiled
     profiles) and the polkit rule;
   - the input credentials, the output roots and the result watcher;
   - sealed keys (ADR-0045 step 11);
   - the CI job with systemd and root.

   Proves, in that job: the unit launcher's MUST checks of decision 13, `per-run-credential` with
   its mutants, and every polkit mutant refused.

   It also requires, each with a check: an agent user has no lingering user manager
   (`loginctl` linger off), is denied `at` and `cron`, and gets nothing on the system bus beyond
   polkit's default deny. `cancel-ends-the-whole-session` gains a variant whose body tries
   `systemd-run --user` to leave a process outside the run's unit.
5. **`patches` in the module schema and `hnx modules check`.** Proves: a listed patch with another
   digest is refused, an unlisted patch file is refused, a patched result that does not match
   `patched_sha256` fails the build, and a listed patch that matches passes.
6. **The Hermes provider module**, with its patch, runner body, `exit_classes` and `agent-runner`
   target. CI fetches the pinned artifact by hash before the network namespace, verifies it
   before unpacking, and builds nothing from a source distribution with the network. The suite
   runs strict against the patched and the unpatched runtime. Proves:
   - every MUST check passes on the patched provider;
   - `usage-sizes-each-call` fails on the unpatched one;
   - `trace-propagation`, `tool-call-records` and `budget-exhausted-is-typed` pass on the provider
     as they do on the fake.
7. **The follow-ups of decision 16**, each with its test.
8. **Overlay (operator-merged):** the lab's agent users, the rendered units and grants files, the
   sealed credentials, and the controller's ledger row moved to `new-shadow` under decision 15.
   Proves: the overlay's checks job is green, it refuses `unisolated: true`, and `hnx cutover
   check` accepts the transition's evidence.

### Operator decisions needed

Each has a recommended default; this ADR is written to the default.

1. **Where the Hermes provider module lives.** Default: in this repository, at
   `modules/agent-runtime-hermes/`. The runtime is open source and the adapter holds nothing about
   the lab. The alternative is the overlay, which would keep the runtime's name out of the public
   tree at the cost of no public suite run against a real provider.
2. **The contract's form.** Default: the process contract of decision 1. The alternatives are a
   linked Go interface or an RPC service (see Alternatives).
3. **The production launcher.** Default: a systemd unit per run with the exact polkit rule
   (decision 7). The alternative is a setuid helper with bubblewrap.
4. **How a run's inputs and outputs cross the uid boundary.** Default: inputs as `LoadCredential=`
   copies of controller-owned `0600` files, and outputs in a per-profile setgid `2770` directory
   whose group holds only the profile's user and the controller's (decision 8). The alternative is
   `RuntimeDirectory=` with `RuntimeDirectoryPreserve=` and a group read bit. That keeps outputs
   in `/run`, but needs the controller to read them before the next start of the same instance
   name, which run ids make moot, and it loses them on reboot.
5. **Sibling runs of one profile.** Default: they share the profile's uid and group, and each unit
   sees only its own run (`TemporaryFileSystem=`, `BindPaths=`, `PrivatePIDs=`). The alternatives:
   - a uid per run (`DynamicUser=`), which breaks the broker's peer-uid identity (ADR-0045
     decision 7) unless the broker learns run-scoped uids;
   - declaring siblings one trust domain and dropping the per-unit mounts, which leaves one run
     able to read another's prompt and answer.
6. **Hosts older than systemd 257** (no `PrivatePIDs=`). Default: not supported for the unit
   launcher. The alternative is `PrivateUsers=` with a PID namespace from a wrapper, which
   reintroduces a helper the template has to trust.
7. **CI for the unit launcher.** Default: a CI job with root and systemd runs the unit launcher's
   checks on every pull request that touches the runner, the provider or the polkit rule. The
   alternative is a nightly run only.
8. **The runtime in CI.** Default: the pinned release artifact is fetched by hash before the
   network namespace and verified before unpacking, and the suite runs both the unpatched and the
   patched runtime, so the usage check's red is proven on every run.
9. **Liveness.** Default: `cpu` from the unit's cgroup and `progress` from the usage stream's
   growth. The alternative is a heartbeat file the runtime must write, which the runtime does not
   do today.
10. **`ResourceLimit` in the job record.** Default: a new failure class `resource-limit`, added to
    `agent.job.failed` and `agent.job.finished` as an additive minor, outcome `failed`. The
    alternative is reporting an OOM kill as `turn-failed`, which would send it to the cloud leg
    under a profile that may use the cloud.
11. **Who offers the patch upstream.** Default: the operator, as ADR-0026 decision 13 says, before
    the provider module's pull request. The module records the offer's state in
    `patches[].upstream`.

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
  released on every exit, or a result the controller can read, without rebuilding what the unit
  already has.
- **Server commands in the spec, checked by the body against the profile.** It keeps one file, but
  whoever writes the spec chooses what runs until the check, and the check lives in every
  provider. A root-owned grants file makes the command a deploy fact that no runtime input can
  change.
- **Keep sessions under the controller's user and harden the files.** The usage directory showed
  that a layout is not an isolation: the session can read whatever the controller's user can.
