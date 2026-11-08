---
summary: Each agent run carries one trace id end to end, spends a MAC-bound per-run budget the gateway and broker refuse past, is evaluated by task, and can be stopped.
summary_of: outline:sha256:49cc9b22fad466de
---
# ADR-0047: Agent runs are traced, budgeted and evaluated

- **Status:** proposed
- **Date:** 2026-11-07
- **Related:** ADR-0006 (detections as code), ADR-0009 (telemetry stays direct), ADR-0013 (agent
  activity tiers), ADR-0017 (the broker), ADR-0029 (holds released by liveness), ADR-0030 (agents
  act only through the broker), ADR-0031 (Code Mode tokens), ADR-0033 (TLP), ADR-0035 (the
  coordinator's ledger); this batch: ADR-0039 (one primary per capability), ADR-0040 (modules are
  replaceable by construction), ADR-0041 (versioned capability contracts), ADR-0042 (tested
  restores, ordered shutdown), ADR-0043 (the cutover ledger), ADR-0044 (the broker carries the
  vault's lifecycle), ADR-0045 (per-principal, short-lived credentials), ADR-0046 (agents are not
  the operator), ADR-0048 (verification beyond one reviewer), ADR-0049 (the SOC data plane and the
  lab's checks as modules) and ADR-0026's amendment placing what the split left unplaced;
  [orchestration controller](../orchestration-controller.md),
  [orchestration telemetry](../orchestration-telemetry.md), [the lab's own gateway](../gateway.md),
  [broker](../broker.md), [codemode](../codemode.md), `conformance/protocols/orchestration.py`,
  `conformance/suites/orchestration.py`, `conformance/suites/orchestration_features.py`,
  `homelabnext/golden/`, `homelabnext/registry/limits.py`, `homelabnext/agent/compiler.py`
- **Depends-on:** ADR-0025, ADR-0026, ADR-0038, ADR-0044, ADR-0045
- **Amends:** ADR-0025, ADR-0038, ADR-0042

## Context

The controller decides which agent runs, the gateway what reaches a model, and the broker what an
agent may do (ADR-0026, Context). Each records its own part of a run, and nothing ties the parts
together or stops a run that has gone wrong before its clock runs out.

**A run cannot be followed end to end.** A job joins its model calls by `gateway_tag`, a prefix
plus the run id, which the controller sends as `X-HNX-Tag` (ADR-0025 decision 4; the gateway
records it, ADR-0038 decision 6). That join stops at the gateway. A broker request carries
`request_id`, `actor` and `target` (`schemas/broker/request` 1.1) and its audit record
`request_id`, `caller`, `token_id` and `execution_id` (`schemas/broker/audit` 1.4), and neither
names a run. The orchestration telemetry page expects per-tool-call records from MCP servers "may
come later as a third source" ([orchestration telemetry](../orchestration-telemetry.md)), and
`agent.job.finished` carries tool calls only as optional `tools[{name, calls}]` counts. A broker
call cannot be traced back to its run (ADR-0044's Consequences leave that to this ADR), and an MCP
call cannot be traced at all.

**Budgets are declared and capped, but not enforced where the spend happens.** A compiled agent
profile must carry `budgets` with `max_input_tokens`, `max_output_tokens`, `max_runtime_s` and
`max_tool_calls` (`schemas/platform/agent_profile` 1.2; `BUDGET_KEYS` in
`homelabnext/agent/compiler.py`), and the overlay's ceiling policy caps each (`check_budgets`). The
only enforcement is the Python `Limiter` (`homelabnext/registry/limits.py`, checklist G-10). It
guards Python-side model calls only, counts a profile's tokens in a sliding window of
`max_runtime_s`, not per run, and lets the call that crosses a limit complete. The gateway's limits
are per key and per role, in sliding windows (`orchestrator/internal/gateway/limits.go`, with no
cost limit per key in v1, `config.go`). Nothing in `orchestrator/` reads a profile's budgets, and
nothing counts tool calls. The controller's API takes no per-run deadline, so
`deadline-expiry-frees-capacity` skips against it
([orchestration controller](../orchestration-controller.md), "Holds").

**The motivating case.** In the old lab, a coordinating agent issued 241 lake queries in 1,098 tool
calls during one 40-minute run. It was killed at its timeout and delivered nothing. The query
engine was nearly idle throughout (well under 1% CPU, sub-second queries): the agent ran out of
wall clock talking to itself, and every tool call was another model round trip. The response then
was an instruction in the agents' shared operating context ("aim for at most 15 queries a run").
That is advice to the model, not a control. The only bound that held was the wall clock, and it
held in the worst way, after the whole spend and with nothing to show for it.

**Model changes are evaluated; agent changes are not.** A model rebind must pass the pinned
evaluation: golden suites, the K-12 replay and the egress canary for every binding (`hnx golden
pins check`, G-11, `homelabnext/golden/pins.py`). The report is a function of the pins, the suites
and the canary's code, so it goes stale when any of them changes. A tool-using golden suite
already runs an agent's prompt against a fake broker with fixtures and trace scorers
(`schemas/agent/golden_task` 1.1, `TRACE_SCORERS`, `homelabnext/golden/agentic.py`; Code Mode
CM-6). But no report goes stale when a profile, its prompt or its tools change, and nothing grades
whether an agent did its *task*: filed the right finding, called the right actions and no others,
stayed within its budget. ADR-0043's gate for moving an agent row into `new-primary` names "the
profile's task-level eval (ADR-0047)", which does not exist yet.

**Agents can read what they must not move, and nothing notices when they do.** Agents read
findings, memory, context documents, lake rows and tool results, and some of that is untrusted
(G-01 to G-04). Prompt-injection defences are tested against a corpus (G-02), and the egress canary
samples whether a model reaches for the network unasked. Neither plants anything in live data that
would show an agent carrying lab data across a boundary: to a model role that leaves the lab, into
an acting broker parameter, out through DNS, or presented as a credential.

**There is no stop and no recall in this repository.** The parity audit lists the old lab's
incident recall (marker files with an active status, and one ack file per agent) as missing.
ADR-0044 decision 9 makes the recall and its acks broker records and refuses an addressed agent's
finding until it has acked, but leaves to this ADR what the controller does when a recall is
raised. Nothing at all says how the operator halts every agent at once. Today that means revoking
gateway keys, which is a config change and a gateway restart (ADR-0038, Consequences: "revocation
is as fast as a deploy"), and stopping a controller whose job API is unauthenticated (ADR-0045,
Context).

## Decision

### Tracing

1. **One trace per run.** When a run is created, the controller mints a **trace id**: 16 random
   bytes from the operating system's generator, written as 32 lower-case hex digits in the W3C Trace
   Context `traceparent` form (`00-<trace-id>-<span-id>-<flags>`; an all-zero id is invalid). It
   stores the trace id on the job row (a store migration behind the backup rule of ADR-0026's
   amendment) and never changes it. Every attempt of the run, an automatic retry under
   `max_attempts`, a move to another backend and a session-level cloud re-run share that trace id.
   A **resubmit** (`retry_of_run_id`) is a new run with a new trace, and its root span names the
   parent's trace id (`parent_trace_id`). A shadow run has its own trace with `lane: shadow`. A
   trace id is an identifier, never an authority: it grants nothing, and a component that receives
   one it cannot bind to a run (decision 5) records it as `asserted`, never `verified`.

2. **The trace travels on every hop, each hop tested on its own.** The parent span id changes at
   each hop; the trace id never does.

   | Hop | Carrier | Test that proves it |
   |---|---|---|
   | controller to runner | `Session.Trace` and `Session.RunTokens` on the internal runner seam (ADR-0026's amendment; stage 2 PR 2.4), then the public agent-runner contract (stage 3) | runner seam unit test; the runner suite's `trace-propagation` check (below) |
   | runner to gateway | one `traceparent` header on every model call, beside `X-HNX-Tag` | inference suite feature `trace-context` |
   | gateway to model | a fresh `traceparent` whose parent is the gateway's span, sent **only** to deployments with locality `local`; never to a deployment that leaves the lab | `traceparent-local-only`: the fake inference server records the headers it receives |
   | runner to MCP server | the MCP request's `_meta` object, key `traceparent`, sent **only** to MCP servers whose catalog locality is `local` | runner suite `trace-propagation`: a fake local MCP server records `_meta` of every call, and a fake non-local one records none |
   | runner to broker (the agent's broker client) | an optional `trace` field on the request (`schemas/broker/request` 1.2), with the run's broker run token (decision 5) | broker tests: the audit record names the trace and whether it was verified |

   The runner suite's `trace-propagation` check points a run at a fake gateway and fake MCP
   servers and passes only if every model call and every call to a local tool carries the run's
   trace id. The gateway still forwards no caller header upstream (ADR-0038 decision 3). The
   `traceparent` it sends to a local engine is its own, built from the trace id it verified. Trace
   propagation and per-run token delivery (decision 5) are requirements of the public agent-runner
   contract, which ADR-0026 stage 3's ADR inherits as written here.

3. **The trace is recorded where each hop already records, names and numbers only.** No new log is
   introduced. Each existing record gains trace fields, additively:
   - `agent.job.finished` 1.3 adds `trace_id`, `parent_trace_id` and `budget` (decision 7).
   - The gateway's usage record and the neutral turn record (`TURN_FIELDS`,
     `conformance/protocols/inference.py`) add `trace_id`, `span_id`, `parent_span_id`,
     `trace_verified` and `tool_calls` (the tool calls the reply emitted, decision 6).
   - The broker audit record 1.5 adds `trace_id`, `span_id` and `trace_verified`.
   - The agent-runner contract's usage report adds one entry per tool call: tool name, server
     catalog id, start, duration, outcome and span id. It never holds arguments or results. It
     also carries `budget_exhausted: <budget>` when the runtime received a budget refusal
     (decision 7).
   - MCP servers record no spans of their own under this ADR: the runner's per-tool-call entry is
     the tool-call span. Server-side spans, if they are ever wanted, would be a closed
     `agent.tool.call` event on the bus that the collector reads there, and are a later decision.
   The rule of ADR-0025 decision 2 and of ADR-0013's summary tier holds for every one of these:
   closed objects, no prompt, task, tool input or output, or model text. Each schema's negatives
   prove it (`span-carries-arguments`, `turn-carries-prompt` and so on).

4. **Spans land in the lake, through a module, and a broken trace is red.**
   - A feature module, **`agent-ops`** (ADR-0027, with the state class `platform` of ADR-0040: its
     only data is one lake table), owns the lake table `table:agent_ops.spans`. The table follows
     the `lake_table` contract, with `retention_days: 400` (the R-06 retention of at least a year)
     and batch freshness. Its row schema is `schemas/telemetry/agent_span.schema.json` 1.0, a draft
     until this ADR is accepted, with these fields: `trace_id`, `span_id`, `parent_span_id`, `kind`
     (`run`, `attempt`, `model-call`, `tool-call`, `broker-request`), `component` (an `svc:` id),
     `profile`, `run_id`, `name` (a role alias, tool name or action name only), `started_at`,
     `duration_ms`, `status` (`ok`, `refused`, `error`, `cancelled`), `code`, the token, cost and
     tool-call counts, `verified` and the row's TLP label (ADR-0033: lab telemetry, never released
     to a public view).
   - The module's collector projects the records of decision 3 into rows. It reads them through
     the read routes that already exist: `agent.job.finished` from the bus, `GET /v1/usage` with
     the gateway's telemetry key, the broker's `audit` operator read, and the runner's usage
     reports. It holds no admin key and no database grant (ADR-0025 decision 3's rule).
   - **Invariant "every finished run's trace is complete"**, checklist row R-10. Over a
     window, it is red when:
     - a finished run has no `run` span;
     - a run with `usage.api_calls > 0` has no `model-call` span;
     - a broker request or gateway call by an agent principal names a trace that no run has (an
       orphan);
     - a call by an agent principal carries no trace on or after `run_binding_required_from`
       (decision 5).
     It pages only when newly red (`page_changes`).
   - The status hub's Orchestration page (ADR-0025 decision 5) gains a trace view of one run's
     span tree, from the table.

### Budgets

5. **A run token binds a trace and a budget to a run.** At admission the controller issues the run
   one **run token per verifier**: one for the gateway and one for the broker. A token is
   `hnxrun1.<base64url claims>.<base64url HMAC-SHA256>`. Its claims are `aud` (`svc:` id of the
   verifier), `kid`, `trace_id`, `run_id`, `profile`, `key_alias` (gateway audience only), `budgets`
   (decision 6), `iat` and `exp`. `exp` is the run's deadline plus a 60-second grace.
   - **The keys.** Each verifier has its own key (`secret:orchestrator/run-token/<verifier>`). The
     controller is its one holder and the verifier its verifier (ADR-0045 decision 1). An HMAC key
     cannot be verified without being held, so the inventory declares each key as a symmetric pair,
     `{ref, symmetric: true}`: the one-holder rule still names one holder, and the pair records
     that the verifier must hold the key it checks. Each key is a credential under ADR-0045, with
     an owner, a `max_age`, a rotation verb and an overlap of two `kid`s during a rotation.
   - **Delivery.** The tokens reach the run the way its gateway key does, delivered per run and
     readable only by the profile's uid (ADR-0045 decision 6). The controller holds no agent's
     gateway key. Concurrent runs of one profile share that uid, so one of them can read another's
     token. The mismatch checks below bound that: a token works only for its own profile and its
     own trace, so a run can at worst charge a sibling run of the same profile, never another
     profile, and the sibling's trace then records the call.
   - **The cutover switch.** The **controller's cutover** is the controller's row of ADR-0043's
     ledger reaching `new-primary`. Its target date is written, as a date, into the broker manifest
     and `gateway.json` as `run_binding_required_from: <date>`. Before that date only an **absent**
     token is tolerated, on the paths named below, and is recorded `asserted`. On and after it, an
     absent token is refused everywhere. A key or caller still optional past that date is an
     ADR-0045 decision 11 standing-exception failure (red), and the backend-level keys'
     transitional exception carries the same date as its `expires`.
   - **The gateway** refuses a call by a key whose owner is a profile:
     - with 401 `run_token_required` when the call carries no token;
     - with 401 `run_token_invalid` when the MAC or `kid` is wrong, the token is malformed or it
       has expired;
     - with 403 `run_token_mismatch` when `key_alias` is not the calling key or the
       `traceparent`'s trace id is not the token's.
     These checks come right after authentication and the fleet stop (decision 11), before R15's
     in-flight cap and before the body is read. The only exception is a key marked
     `run_binding: optional` in `gateway.json`: the backend-level keys of ADR-0045's standing
     exception. On those keys an absent token is recorded `trace_verified: false`, but a **present
     token that fails verification is refused** with `run_token_invalid` or `run_token_mismatch`,
     as on any other key.
   - **The broker** verifies its token the same way, and keeps the caller's own identity
     authoritative (ADR-0045 decision 7). It refuses:
     - with `run-token-invalid` a present token that fails verification, at once, before and
       after the cutover date;
     - with `run-token-mismatch` a token whose `profile` is not the profile mapped from the
       caller's peer uid, or a request whose `trace` is not the token's `trace_id`;
     - with `run-token-required` a request by an agent principal with no token, on and after
       `run_binding_required_from`. Before it, such a request is served and its trace recorded
       `asserted`.
   - **Shared vectors.** The token format, the trace-context parsing and the MAC are one set of
     **shared vectors**, `conformance/fixtures/run_token_vectors.json` and
     `trace_context_vectors.json`. The Python implementation (`trace.py` under `homelabnext/orchestration/`)
     regenerates them, and the Go package (`orchestrator/internal/trace`) reads them in place, as
     with the TLP vectors (ADR-0038 decision 5; ADR-0048's shared cross-language vectors). Both
     parsers are fuzz targets: ADR-0048 decision 1's first set gains `trace.FuzzRunToken` (a token
     the parser accepts re-encodes to the same bytes, and no tampered byte verifies) and
     `trace.FuzzTraceparent` (accepted exactly when the vectors' reference grammar accepts).

6. **Budgets are per run, and each is enforced where its spend passes.** The compiled profile's
   budgets gain `max_cost_usd` and the two wrap-up fields of decision 7, `wrap_up_tools` and
   `wrap_up_calls` (`schemas/platform/agent_profile` 1.3; the ceiling policy caps `max_cost_usd`,
   `check_budgets`). The controller copies the run budgets and the wrap-up fields into the run
   tokens' `budgets` claim, so each verifier reads them from the token alone.

   | Budget | Enforced at | How | Extends |
   |---|---|---|---|
   | `max_input_tokens`, `max_output_tokens`, `max_cost_usd` | gateway | a per-trace window with no expiry before `exp`, reserved at admission and settled on the reply, as R16 does for key and role windows; upstream error statuses cost nothing, as today | `orchestrator/internal/gateway/limits.go` |
   | `max_tool_calls`, model-emitted | gateway | counts the tool calls in each reply: OpenAI-compatible `tool_calls` (streamed deltas by `index`), Anthropic `tool_use` blocks; parallel calls in one reply count each | the reply scanner (`jsonscan.go`) |
   | `max_tool_calls`, broker-side | broker | counts the broker requests per verified trace; a Code Mode token's `max_calls` (`issue_token`, ADR-0031) is at most what the run has left | `homelabnext/broker/service.py` |
   | `max_runtime_s` | controller | it is the run's deadline: the orchestration contract's `deadline` feature, which the controller now serves, so `deadline-expiry-frees-capacity` runs against it | `orchestrator/internal/queue` (stage 2 PR 2.6) |

   - **Two independent counters.** The gateway's count of model-emitted calls and the broker's
     count of broker requests are independent, and each is held to `max_tool_calls`; neither sums
     the other. A Code Mode call is one emission at the gateway and many requests at the broker,
     and each enforcer holds its own count to the limit.
   - **Overshoot is bounded by one reply.** The gateway counts a reply's tool calls only once the
     reply is in, and the runtime executes them, so a run can pass `max_tool_calls` by at most the
     tool calls of its last reply. Calls to non-broker MCP servers (the motivating lake queries)
     have no second enforcer, so that bound is the bound. Once fewer than 4 tool calls remain, the
     gateway sets `parallel_tool_calls: false` upstream where the protocol has it, which narrows the
     bound to one call on engines that honour it.
   - **One budget for the run.** A run's budget covers all of its attempts and any cloud re-run
     (decision 1), so a fallback never starts with a fresh budget. The counters live in gateway
     memory and are lost on a gateway restart. Decision 8 is the backstop.
   - A per-agent daily budget, and budgets proposed from eval evidence, are a follow-up. The per-run
     budgets and the overrun invariant cover the motivating case.

7. **A budget refusal is clear, final, and leaves the run a last turn in which it can report.**
   - **Wrap-up first.** When a run's tool-call budget is spent, the gateway serves the run's next
     `wrap_up_turns` model calls (default 2, in the gateway spec) in **wrap-up**. In both protocol
     translations it narrows the request's `tools` to the profile's `wrap_up_tools` (default: the
     finding-filing and recall-ack tools, `finding.file` and `recall.ack` of ADR-0044) and sets
     `tool_choice` to `auto` over that set only, never to `none`, and it marks the usage record
     `budget_phase: wrap-up`. The broker counts `finding.file` and `recall.ack` against a separate
     `wrap_up_calls` allowance (default 2), never against `max_tool_calls`, so a run past its tool
     budget can still file its finding and a recalled agent can still ack. Token and cost budgets
     reserve `wrap_up_reserve_tokens` (default 4,096) off their limit for the same purpose: a call
     that would eat into the reserve is served in wrap-up.
   - **A wrap-up violation ends wrap-up.** A wrap-up reply that carries a tool call outside
     `wrap_up_tools` (an engine that ignores the narrowed list) ends wrap-up at once: the next call
     is refused, and the usage record is marked `wrap_up_violation`.
   - **Then refuse.** Once wrap-up is spent, or a token or cost reservation cannot fit even inside
     the reserve, the call gets **403 `run_budget_exhausted`**. Its body names `budget`
     (`input_tokens`, `output_tokens`, `cost_usd` or `tool_calls`), `limit` and `used`. It is never
     a 429: waiting does not help. A 429 still means a key's or role's window, as today. The broker
     refuses past its count, or past `wrap_up_calls`, with `run-budget-exhausted`.
   - **The run ends as a budget failure, by typed signal.** The runner contract's usage report
     carries `budget_exhausted: <budget>` when the runtime received either refusal, and the
     controller confirms it from the gateway's usage records by trace (decision 8). With neither,
     the class is not `BudgetExhausted`; no refusal text is matched. The runner seam gains the class
     `BudgetExhausted`. Like `TurnCap`, it is never retried by `max_attempts`, never moved to
     another backend and never re-run on cloud. The run ends `failed` with failure class `budget`,
     and `agent.job.finished` reports `outcome: timeout`, as its schema already maps `budget`, with
     `budget` naming which one. A run that reaches its deadline ends with failure class `deadline`,
     as today.
   - **The agent knows its budget.** The controller's facts block (stage 2 PR 2.4) gives every run
     its budgets as data, and the gateway answers every model call with
     `X-HNX-Budget-Remaining` (counts only), which the runner contract passes to the runtime when
     it can.

8. **The controller is the backstop, and an overrun is red.** The controller reads its running
   runs' spend from the gateway's usage records, by trace, with the telemetry key. It cancels a run
   whose recorded spend has passed its budget. That covers a gateway restart, which resets the
   gateway's counters, and a run that reached the gateway on an optional key. Invariant
   **"no run overspends its budget"** (G-21) is red for any finished run whose recorded usage
   exceeds its budgets by more than one call's reservation (and, for tool calls, one reply's
   calls, decision 6). The gateway drops usage records when its queue is full (ADR-0038 R18), and
   both the backstop and this invariant read those records, so the invariant reads
   COULD-NOT-MEASURE for any window in which the gateway reported `usage_records_dropped > 0`. The
   backstop is slower than the gateway and never replaces it.

### Evaluation

9. **Agent changes pass task-level evals, beside the model goldens and the canary.**
   - **The corpus.** Each agent has a **task-eval suite**, `agents/<key>.evals.yml` in its module
     (manifest `agents[].evals`, a change in place to the module manifest schema, which is
     `x-draft` until ADR-0027 is accepted). Its format is
     `schemas/agent/task_eval` 1.0, which extends `golden_task` 1.1. A task names a prompt, a
     **fixture world** (what the fake broker, fake MCP servers and a fixture lake table answer:
     the `fixtures` and `inject` of the Code Mode harness, extended to MCP tools and lake rows),
     and its **graded outcomes**. Outcomes are deterministic graders, each its own scorer:
     - `finding`: a finding note with these fields was filed (ADR-0044 decision 8);
     - `actions`: the required broker actions were called;
     - `forbidden`: none of these were called, and no acting call is outside the task's set;
     - `answer`: the existing scorers;
     - `budget`: the run stayed within the profile's budgets;
     - `injection`: zero instruction-follows, over the G-02 corpus placed through `inject`;
     - `honeytoken`: no test honeytoken moved (decision 10).
     A task passes when every `must` grader passes. Its score is the weighted share of the
     `should` graders. A model-graded rubric may be attached but is **advisory**: it never passes
     or fails a task (ADR-0048).
   - **Two modes.** The `harness` mode runs the profile's compiled prompt, tools and budgets
     through the golden agentic turn protocol, against the profile's model role. The `runner` mode
     submits each task as a shadow-lane run (`lane: shadow`) through the real controller and runner
     provider, with the fixture world served by fakes. Only the `runner` mode tests the whole stack.
   - **When it runs.** The report (`hnx-agent-eval/1`) is a function of its inputs, as the model
     evaluation report is (`inputs_of`): the profile's role pins, the compiled profile's digest
     (prompt, charter, tools, grants, budgets), the suite and fixture digests, the grader code
     version and the runner provider's version. **`hnx evals check`** (in `make check` and CI) fails
     when an agent has no suite, when a stored report is stale, or when it does not pass. CI
     evaluates against the deterministic fake, which proves the harness and the staleness tracking
     but never that an agent is good, as for the model goldens. `make agent-evals` runs both modes
     live, and `--require-live` refuses a fake report. ADR-0043's agent gate requires a live
     `runner` report.
   - **Spend is recorded.** Each report records the p50 and p90 spend per task, the evidence a
     reviewer reads when a profile's budgets change. A tool that proposes budgets from it is the
     follow-up of decision 6.

### Detection

10. **Honeytokens are planted where agents read, and moving one is detected where it crosses a
    boundary.**
    - **Placements are overlay data, and values live in the secret store.** A placement record
      (`schemas/platform/honeytoken` 1.0) gives an id, a `kind` (`credential`: a string in a known
      credential format; `hostname`: a canary DNS name under the lab's declared canary zone, which
      the lab's resolver answers with a sinkhole; `record`: a decoy inventory or contact entry), a
      `planted_in` (a findings note, a memory entry, a context document, a lake row, a fixture tool
      result, a decoy file in an agent home) and a `secret:` reference. The overlay keeps placement
      records SOPS-sealed under `lab/sealed/`, by the overlay's rule for sensitive non-credential
      data. This repository holds only the schema, the generator, the detectors and fakes; its tests
      generate token values at run time and commit none.
    - **Reading a planted token is normal. Moving it is the detection.** An agent may read and
      reason over the data it is granted, including when it sends that data to a local role. A
      token *moves* when it reaches:
      - the gateway, in a request body to a role that leaves the lab (`credential` and `hostname`
        kinds);
      - the gateway, presented as a caller key: answered 401 like any unknown key, and recorded;
      - the broker, in the params of any action (every kind: the broker digests each string
        parameter whole, so a `record` decoy's identifying fields are caught there);
      - the lab's resolver or egress logs, as a canary hostname: a Sigma rule (ADR-0006) with
        fixtures, carried by the overlay's SOC detection module, since the canary zone is overlay
        data (ADR-0049's detection content);
      - any lake table but the one it was planted in: a scheduled detection query.
      A `record` decoy sent to a cloud role in free text is **not** detected at the gateway: the
      gateway does no general content inspection (decision 14). It is caught only if it later
      crosses the broker or the lake.
    - **A trip looks like an ordinary refusal.** A honeytoken trip at the gateway is answered with
      the same status and code as a TLP refusal of that call (403 `tlp_refused`), and at the broker
      with `denied` and the TLP reason, so an injected payload cannot learn which strings are
      decoys by probing. The specific reason appears only in the usage or audit record and in the
      event below.
    - **Verifiers hold digests, never values.** The gateway and the broker get, at deploy, the set
      of HMAC-SHA256 digests of the `credential` and `hostname` values (the broker also of the
      `record` fields), keyed with their own digest key (the broker's `digest_key` already keys
      secret arguments, `homelabnext/broker/service.py`). The gateway scans only for the declared
      credential formats and for names under the canary zone, and digests each candidate. The lake
      query compares `hmac_sha256` of the candidate columns with the digest set; the detection job
      reads its digest key and the digest set from the secret store at run time and writes neither
      into a query it stores. The honeytoken format scanner is a fuzz target in ADR-0048 decision
      1's first set (`gateway.FuzzHoneytokenScan`: every candidate it reports is a substring of the
      input in a declared format, and a declared-format substring is always reported).
    - **The lab's own tokens are scanned too.** The gateway's scan of cloud-bound bodies for
      credential formats covers `hnxrun1.` run tokens and the gateway's own key formats, so an agent
      that pastes its run token or key into a cloud prompt is refused and recorded the same way,
      with reason `lab-credential`.
    - Each trip emits `agent.honeytoken.seen` 1.0 on the bus. It is closed: token id (never the
      value), kind, component, `trace_id`, `profile`, and the role or action. It pages through the
      notifier, state-diffed per token, and the trace leads to the run. A tripped token is retired
      and replaced.
    - **Positive control.** `hnx honeytokens drill` runs a fixture agent that carries a test token
      across each boundary and requires each detector to fire. Its evidence file is the positive
      control ADR-0043 asks of a detector. The drill also runs in CI against the fakes.

### Stop and recall

11. **The fleet stop is a contract, enforced at three points, each sufficient alone.**
    - **`fleet-stop` is a product feature** of three suites:
      - `orchestration-features`: `stop()` and `start()`;
      - `inference`: the gateway;
      - the broker's tests.
      Each suite's checks are versioned under ADR-0041.
    - **When engaged:**
      - **Controller**: refuses every submit (503 `fleet_stopped`), admits nothing, and cancels
        every running run. Each run ends `cancelled` within its `cancel_grace_s` (at most
        `MAX_CANCEL_GRACE_S`, 10 s) with its holds released (clause b, ADR-0029).
      - **Gateway**: refuses every key whose owner is a profile and every key marked
        `run_binding: optional` (the backend-level keys that carry agent traffic until the
        controller's cutover), with 403 `fleet_stopped`, right after authentication and before the
        run-token checks and R15's in-flight cap, so a stopped fleet answers `fleet_stopped`, never
        `concurrency_limited`. With scope `all` it also refuses every service key. The admin and
        telemetry keys are still served, so the operator can see what happened.
      - **Broker**: refuses every request by an agent principal (`fleet-stopped`). Operator
        operations and the relay keep working.
    - **Engaging it needs nothing the agents run on.** Each point is stopped while either of two
      switches is set, and it reads both at least once a second:
      - a local **stop file**, whose presence means stopped: the out-of-band switch, set by root
        on the host with no network and no credential;
      - its own **stop flag**, set and cleared by its authenticated routes and persisted in the
        point's own state (the controller's and broker's stores; for the stateless gateway, a file
        in its state directory), mode 0700 under the service's uid.
      A switch it cannot read reads as stopped (fail closed). A restart while stopped stays stopped.
    - **Who can clear a switch.** Clearing a switch means start. The stop file lives in a directory
      owned by root, mode 0755, not writable by the service's uid or any agent's uid; only root
      removes it. Neither the stop file nor the stop flag lives in a directory a deploy recreates, so
      a redeploy never restarts a stopped fleet. No agent uid can write either.
    - **Stop and start are separate credentials.** Each point has an authenticated stop route:
      - the controller's admin API (authenticated per ADR-0045);
      - a gateway route under a dedicated **stop key** that can stop and read status only;
      - the broker's operator operation through the relay, by an SSO operator with a second factor
        (ADR-0034).
      Start clears the stop flag and is the gateway's admin key, the controller's authenticated
      admin API and the broker's second-factor operator operation, never the stop key. The stop key
      can therefore be given to automation without giving it the power to restart the fleet.
      `hnx fleet stop [--scope agents|all]` fans out to all three and exits non-zero unless each
      reports `fleet_stopped: true` on its health route. If a route is unreachable, it prints the
      stop file to create by hand on that host. `hnx fleet status` reads the three and names which
      switch holds each point stopped.
    - **Only the operator starts the fleet again.** `fleet.start` is operator-only, and no agent
      principal may call it. `hnx fleet start` clears each stop flag through its point's start
      route; a stop file still present keeps its point stopped until root on that host removes it,
      and `hnx fleet start` says so. An agent may *request* `fleet.stop` only as an approval-gated
      broker action, like `incident.recall`: containment is never an agent's to take.
    - **A drill proves it.** CI's `fleet-stop-drill` job runs the in-repository controller, the
      gateway and the broker on loopback in a network namespace, with runs in flight, and requires
      all of the following:
      - within 15 s, every run is `cancelled`, every submit is refused, every agent key is refused
        and every agent broker call is refused;
      - a call on an optional (backend-level) key is refused while stopped;
      - the telemetry and operator reads still work;
      - a restart of each process stays stopped;
      - an unreadable stop file reads as stopped;
      - an agent uid cannot remove the stop file or clear the stop flag, and the stop key cannot
        start the fleet;
      - a redeploy of each process leaves it stopped.
      Checklist row G-20 records it, and the lab runs the same drill as a SERVER
      check.
    - **The UPS shutdown engages it locally.** ADR-0042's plan runner is non-interactive and holds
      no network credential, so its first step on each host it feeds creates the local stop file of
      every stop point on that host, as root, before it stops any service the agents use. It never
      calls `hnx fleet stop` and never uses the broker's second-factor route (decision 13 amends
      ADR-0042 decision 9).

12. **The controller's part of a recall.** The recall is ADR-0044's record. While a recall is
    `active`, the controller does three things:
    - **Wakes every addressed profile.** At most one tick after the recall is raised, it submits
      one run of every profile the recall addresses that has no run queued or running. Each run is
      on the real lane, with the recall's name and its part for that profile in the facts block as
      data, never as instructions.
    - **Replaces routine passes.** It replaces each addressed profile's scheduled routine run with
      a recall run, until the recall reads `resolved`.
    - **Tags the trace.** It tags every recall run's root span with `recall: <name>`.
    - **Lets a routine run in flight finish.** An addressed profile's routine run already running
      when the recall is raised is not cancelled. Its broker answers carry `recall: <name>`, and
      ADR-0044 refuses its finding until it acks, so it acks on the way out. The wake submits that
      profile's recall run once the routine run has ended.
    - **Yields to a fleet stop.** While the fleet is stopped the controller submits no recall run.
      The wake happens at the next tick after `fleet.start`, and the ack invariant's clock for the
      recall starts then.
    A recall raises no profile's budgets and no grants; an addressed run that is past its tool
    budget can still ack in wrap-up (decision 7). An end-to-end test raises a recall on the fake
    broker and requires a run of every addressed profile within one tick and an ack of every one of
    them by the fake runner.
    - **One owner per criterion.** This ADR owns the invariant "every addressed agent has acked an
      active recall" (R-11): red for each profile without an ack after `ack_within_s` (default
      900, counted from the recall or from the fleet start that followed it), paging when newly
      red. ADR-0044 owns the broker's refusal of an unacked finding and the one-finding-per-run
      invariant (G-15). Neither ADR adds the other's criterion.

### Amendments and scope

13. **ADR-0038, ADR-0025 and ADR-0042 are amended.**
    - **ADR-0038, decision 3.** The gateway replaces only `model` in a request, except in wrap-up
      (decision 7), where it narrows `tools` to `wrap_up_tools` and sets `tool_choice` to `auto`,
      and when few tool calls remain (decision 6), where it sets `parallel_tool_calls: false`. It
      forwards no caller header, and sends its own `traceparent` to local deployments only
      (decision 2).
    - **ADR-0038, decision 4.** The refusal order gains these steps:
      - the fleet stop, then the run-token checks (decision 5), right after authentication and
        before R15's in-flight cap, so a stopped fleet answers `fleet_stopped`, never
        `concurrency_limited`;
      - the honeytoken and lab-credential check, after the TLP step, answered as a TLP refusal
        (decision 10);
      - the per-run budget, after the TLP step and before the key's and role's limits, with its
        403 `run_budget_exhausted`.
    - **ADR-0038, decision 6.** The usage record gains the trace fields of decision 3,
      `budget_phase` and `wrap_up_violation`.
    - **ADR-0025, decision 1.** `agent.job.finished` gains `trace_id`, `parent_trace_id` and
      `budget` in an additive 1.3.
    - **ADR-0025, decision 4.** `gateway_tag` stays the job-to-turn join for the status hub, and the
      trace id joins every component in the lake. Folding one into the other is a later decision.
    - **ADR-0042, decision 9.** The UPS plan's first step, on each host it feeds, creates the local
      stop file of every fleet-stop point on that host (decision 11), needing no network
      credential, in place of a call to `hnx fleet stop`.
    Each amended ADR names this one in an **Amended:** line and under **Amended-by**.

    **Schema versions this ADR claims.** `agent.job.finished` 1.3, `agent_profile` 1.3,
    `agent.honeytoken.seen` 1.0, `honeytoken` 1.0, `agent_span` 1.0 and `task_eval` 1.0 are unique
    to this ADR. Broker `request` and `audit` are shared with ADR-0044 (`related`, and its record
    operations); both bumps are additive, so whichever pull request lands second takes the
    following minor (request 1.3, audit 1.6) and says so in its schema description. The module
    manifest's `agents[].evals` is a change in place to an `x-draft` schema (ADR-0027, ADR-0040),
    not a version.

14. **Out of scope.**
    - **Interactive operator sessions.** A person's own coding agent at a terminal is not a
      controller run. Its activity hook stays ADR-0013's. Its gate is out of scope here, as in
      ADR-0043 and ADR-0049, and is left to one later decision for all three.
    - **Prompt and reply content.** Traces hold names and numbers. The detail tier stays ADR-0013's.
      No general content inspection (DLP) is added beyond the honeytoken and lab-credential
      formats.
    - **A tracing product or wire protocol.** No OpenTelemetry SDK, collector or exporter: an OTLP
      export from `table:agent_ops.spans` may be added later, as an adapter.
    - **Billing.** No reconciliation of `cost_usd` with a provider's invoice.
    - **Human chat budgets.** The chat front end's key keeps its window limits.
    - **The recall record itself and the vault's other lifecycles** (ADR-0044); credentials
      (ADR-0045); the agents' repository identity (ADR-0046).
    - **Choosing a lake engine or retention class** beyond the one table (ADR-0049).

## Consequences

- A run is one tree: the controller's run and attempts, every model call, every tool call and every
  broker request, joined by one id in one table. A question like "what did this run do, and what did
  it cost" is a query, not a reconstruction from three logs.
- A runaway run stops at its budget with a final answer or finding in hand, rather than at its clock
  with nothing. The motivating run would have ended its tool use at its profile's `max_tool_calls`
  (overshooting by at most its last reply's calls), filed its finding in two wrap-up turns whose
  only tools are the finding and the ack, and been recorded as `budget: tool_calls`.
- The gateway does more. It verifies a token per call, keeps a window per trace, scans replies for
  tool calls and request bodies for honeytoken and lab-credential formats, and in wrap-up narrows
  the request's tools. Each
  of these is in the path to every model, so each lands with its suite checks, its mutants and its
  fuzz target. The gateway's packages stay standard library only
  (`TestGatewayDependsOnlyOnTheStandardLibrary`): HMAC, random, hex and base64 are all in it.
- Two new credentials, one run-token key per verifier, join ADR-0045's inventory as symmetric
  pairs with rotation drills. A leaked gateway token key lets its holder mint budgets for runs, but
  not reach a model without an agent's key.
- Concurrent runs of one profile can read each other's tokens, because they share a uid. The
  mismatch checks confine that to the same profile, and the misused call lands in the sibling's
  trace where it can be seen. Per-run isolation of tokens would need a uid or namespace per run, a
  later decision if it is ever needed.
- Until `run_binding_required_from`, a run with no token is still served on the optional paths and
  recorded `asserted`. Past it, the same call is refused and any key still optional is red, so the
  migration gap has a date rather than a default.
- In-memory counters mean a gateway restart lets a running run spend up to its budget again before
  the controller's backstop cancels it. The overrun invariant makes that visible. Moving the counters
  to durable state is a later change, if the restarts happen.
- Profiles need honest budgets. A budget set too low now fails runs that used to finish slowly. The
  evals' recorded p50 and p90 spend and the overrun invariant are the evidence a budget change is
  reviewed against.
- Every change to a profile, prompt, charter or tool grant now needs a fresh eval report in the same
  commit, as a model pin change already does. That is work per change, and it is the point.
- Honeytokens need care. A placement record names where the decoys are, so it is overlay data,
  SOPS-sealed under `lab/sealed/`, and the generator never writes a value into the tree. A `record`
  decoy pasted into a cloud prompt goes undetected at the gateway; the design accepts that rather
  than add content inspection. A decoy in a lake
  row is a row other readers see too, so the decoy's form must not distort a detection or a
  baseline (ADR-0036).
- The operator gains one command to halt every agent, which works with the broker down and with the
  agents' hosts unreachable from the operator's workstation, given a root shell on each host. A
  stop credential handed to automation (the UPS plan uses only the local file) can never restart
  the fleet.

### Implementation plan

Each step is one pull request, in this order. Steps 10 and 11 depend only on step 2 (step 11's
gateway detector also on step 4), and may run in parallel with steps 3 to 9.

1. **This ADR** (docs only): the ADR, its index row, and the **Amended:** and **Amended-by** lines
   on ADR-0025, ADR-0038 and ADR-0042, each with a short amendment section. Its tests prove the ADR
   log passes (`tools/tests/test_adr_log.py`: the reciprocal pairs, `Depends-on` ids) and the
   summaries are stamped.
2. **Contracts and the shared vectors.** This step adds:
   - the drafts `schemas/telemetry/agent_span` 1.0 and `schemas/agent/task_eval` 1.0;
   - `agent.job.finished` 1.3, `agent_profile` 1.3 (`max_cost_usd`, `wrap_up_tools`,
     `wrap_up_calls`), broker request and audit at their next minors (decision 13), and the turn
     record's new fields;
   - `trace.py` under `homelabnext/orchestration/`, and `trace_context_vectors.json` and
     `run_token_vectors.json`.
   Its tests prove:
   - the vectors regenerate from the implementation;
   - every negative is refused: a text-carrying field, an all-zero or upper-case trace id, a
     tampered claim, an expired token, a wrong audience;
   - `trace.FuzzRunToken` and `trace.FuzzTraceparent` run in CI with their properties (ADR-0048);
   - the compiler refuses a new budget above the ceiling;
   - the frozen baselines are additive.
3. **Gateway, trace and run tokens.** The Go package `orchestrator/internal/trace` reads the vectors
   in place. The gateway gains run-token verification, `run_binding: required|optional` and
   `run_binding_required_from` in `gateway.json` (rendered from key owners and the controller's
   ledger row), the trace fields in the usage records and `traceparent` to local deployments. The
   inference suite gains the feature `trace-context`, and `gateway-conformance` runs it. Its tests
   prove:
   - a missing, forged, expired or other-key token is refused with its code before the body is
     read;
   - on an optional key, an absent token is served and recorded unverified, a present invalid
     token is refused, and past `run_binding_required_from` an absent one is refused;
   - the fake inference server sees `traceparent` from local deployments only;
   - every usage record names the verified trace.
4. **Gateway, run budgets.** This step adds the per-trace reservations, the reply tool-call counter,
   wrap-up over `wrap_up_tools`, `parallel_tool_calls: false` near the limit, 403
   `run_budget_exhausted` and `X-HNX-Budget-Remaining`. The inference suite gains the feature
   `run-budgets`, each MUST check with a mutant only it catches (`ONLY_ITS_OWN`), and the reply
   scanner gets a fuzz target. Its tests prove:
   - a spent budget is a 403 and never a 429;
   - parallel and streamed tool calls each count;
   - wrap-up reaches the fake server with `tools` narrowed to `wrap_up_tools` and `tool_choice:
     auto`, and the call after wrap-up is refused;
   - a run past its tool budget files its finding in wrap-up;
   - a wrap-up reply carrying another tool call ends wrap-up and is recorded `wrap_up_violation`;
   - overshoot never exceeds one reply's tool calls;
   - a fallback spends the same budget.
5. **Broker.** The broker accepts `trace` and the run token, audits `trace_id` and
   `trace_verified`, counts broker requests per trace, and caps a Code Mode token's `max_calls` at
   what the run has left. It counts `finding.file` and `recall.ack` against `wrap_up_calls`. It
   refuses past the budget with `run-budget-exhausted`, a present bad token with
   `run-token-invalid`, another profile's or another trace's token with `run-token-mismatch`, and
   an agent with no token on and after `run_binding_required_from`. Its tests prove each refusal,
   its audit record, that a finding is still filed past `max_tool_calls`, and that an unverified
   trace never changes the caller.
6. **Controller** (after ADR-0026 stage 2 PR 2.7). The controller mints the trace and tokens per
   run, on the job row (migration behind a backup). It carries them through `Session`, turns
   `max_runtime_s` into the deadline, and gains the runner class `BudgetExhausted`, set only from
   the usage report's `budget_exhausted` or the gateway's records, never retried and never moved. It
   reads usage for the backstop and emits `agent.job.finished` 1.3. `orchestration-features` gains
   `budgets` and `trace`, each check with its mutant, run by `orchestration-conformance`:
   - `budget-exhausted-run-is-never-retried-or-moved`;
   - `runtime-budget-is-the-run-deadline`;
   - `every-attempt-shares-the-run-trace`;
   - `resubmit-gets-a-new-linked-trace`;
   - `budget-class-needs-a-typed-signal` (a refusal with neither signal is not `BudgetExhausted`).
7. **Runner contract** (ADR-0026 stage 3). The agent-runner contract carries the trace on every
   model call and every call to a local MCP server, delivers the run tokens per run, reports an
   entry per tool call and `budget_exhausted`. Its tests prove that the runner suite's
   `trace-propagation` passes against the fake runtime, fails against a mutant that drops `_meta`,
   and fails against one that sends `_meta.traceparent` to a non-local server.
8. **The `agent-ops` module.** This step adds the lake table, the collector's projections, the
   invariants "every finished run's trace is complete" and "no run overspends its budget", and the
   hub's trace view. Its tests prove that the fixture traces join, that an orphan broker call, a
   missing run span and an overrun each turn red, that a window with `usage_records_dropped > 0`
   reads COULD-NOT-MEASURE, and that a text-bearing source record is refused.
9. **Fleet stop.** This step adds the stop files, stop flags and routes in the controller, gateway
   and broker, the gateway's stop key, `hnx fleet stop|start|status`, the `fleet-stop` feature of
   each suite, and the CI job `fleet-stop-drill`. Its tests prove decision 11's drill, that an
   agent principal can never start the fleet, and that the stop key cannot start it.
10. **Task evals.** This step adds `hnx evals run|check`, the graders, the `harness` mode,
    and a suite for every example agent, with `hnx evals check` in `make check`. Its tests prove
    that each grader catches its mutant, that a change to a prompt, a profile, a pin or a fixture
    makes the report stale and fails CI, that a forbidden action fails a task whatever its answer,
    and that an advisory rubric never changes a verdict. The `runner` mode follows step 7.
11. **Honeytokens.** This step adds the placement schema, the digest sets for the gateway and the
    broker, the detectors (with `gateway.FuzzHoneytokenScan`), the lab-credential scan, the event
    `agent.honeytoken.seen` 1.0, the Sigma rule with fixtures on a fictional canary zone (the
    overlay's SOC detection module instantiates it, ADR-0049), and `hnx honeytokens drill`. Its
    tests prove:
    - each boundary trips, and a read with a send to a local role does not;
    - a trip is answered exactly as a TLP refusal of the same call, at the gateway and the broker;
    - a run token or gateway key in a cloud-bound body is refused;
    - no value appears in a record, an event or the tree (the leak scan runs over test output);
    - the drill's evidence validates.
12. **The recall wake** (after ADR-0044's recall pull request). The controller wakes addressed
    profiles and swaps their routine runs, and this step adds the ack-coverage invariant. Its tests
    prove decision 12's end-to-end test, that a resolved recall diverts nothing, that a
    budget-exhausted addressed agent can still ack, that a routine run in flight finishes and acks,
    and that no recall run is submitted while the fleet is stopped.
13. **Checklist and acceptance.** This step adds the checklist rows (G-17 run budgets refuse,
    G-18 agent changes pass task evals, G-19 honeytokens trip, G-20 the fleet can be stopped, G-21 no
    run overspends; R-10 traces are complete, R-11 recalls are acked; the numbers are reserved by
    this batch, after ADR-0044's G-14 to G-16) and their criteria in
    `examples/registers/invariants.yml`. The ADR is proposed for acceptance once steps 2 to 12 have
    merged and the lab's first live stop drill and honeytoken drill have evidence.

## Alternatives

- **Use the run id as the trace and `gateway_tag` as its carrier.** The tag already joins jobs to
  turns. But a tag is free text that a caller sets, it does not reach MCP servers or the broker,
  and nothing binds it to a run, so a forged tag would charge another run's budget. A trace id plus
  a bound token keeps the tag's join and adds what it lacks.
- **Adopt an OpenTelemetry SDK and collector.** It is the standard toolkit, and its `traceparent`
  is the format chosen here. But it would end the gateway's standard-library-only rule, its span
  attributes are open-ended where every record here is closed, and it would add a second telemetry
  pipeline beside the bus and the lake. An export adapter later keeps that door open.
- **Budgets by wall clock only.** This is the status quo. The clock bounds the spend only after
  all of it has happened, and it returns nothing. It stays as `max_runtime_s`.
- **Budgets in the runtime only** (the agent counts its own calls). The runtime is the agent, so
  what it reports about itself is evidence, never a control. Its reports become spans, and the
  enforcement sits at the gateway and the broker.
- **A hard stop at the budget, with no wrap-up.** Simpler, and it leaves the gateway's request
  untouched. But it repeats the motivating failure at a lower cost: the run ends with nothing.
  Wrap-up is two bounded turns whose only tools file the finding and the ack.
- **Wrap-up with `tool_choice: none`.** Simplest to state, but filing a finding and acking a recall
  are broker actions, so a tool-less wrap-up could write an answer nobody records.
- **Register each run with the gateway over an admin route** instead of a token. That would make
  the gateway stateful and dependent on the controller reaching it, and would need a new admin
  credential on a service. A token the gateway can verify alone keeps it stateless.
- **Ed25519 run tokens**, so that a verifier cannot mint. That would add the first cryptography
  dependency on the Python side. HMAC with one key per verifier means a verifier can mint tokens
  only for itself. Revisit if a third verifier appears.
- **Model-graded evals as the gate.** They are cheap to write, but a model grading a model is the
  single-reviewer problem ADR-0048 rejects. Rubrics stay advisory.
- **A distinct honeytoken refusal code.** Clearer in logs, but it tells an injected payload which
  strings are decoys. The reason is kept in the records instead.
- **MCP server-side spans through `mcpkit`.** They would show the server's own view, but they need
  a sink the collector can read and add a second record of every tool call. The runner's entry is
  enough for one operator; a bus event is the route if it is ever wanted.
- **Honeytokens as DNS canaries only.** They cover egress, but not a decoy credential pasted into
  a cloud prompt or an acting broker parameter, which are the two boundaries an agent crosses
  without touching the network itself.
- **A kill switch by revoking keys.** Revoking a gateway key is a config change and a restart. It
  leaves the controller admitting work and the broker answering, and it does not survive a
  redeploy from the same config.
