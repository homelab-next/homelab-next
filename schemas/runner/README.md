# schemas/runner

The agent-runner contract's files (ADR-0051, proposed; the `agent-runtime` slot, whose suite is
`conformance/suites/agent_runner.py`). A launcher starts a provider's runner body once per attempt.
The body reads the session spec and the run's inputs from `$CREDENTIALS_DIRECTORY`, starts only the
MCP servers the grants file lists, appends its usage stream to `$HNX_RUN_DIR/usage.jsonl`, and
writes its answer to `$HNX_RUN_DIR/answer`. All three schemas are **drafts** (`x-draft`): not
frozen, and free to change until the ADR is accepted.

| Schema | What it is |
|---|---|
| `session` | one attempt's session, as the controller hands it over: run id, agent key, lane, the prompt as a credential name (never inline), toolsets, MCP server **ids** only, the gateway target (never an engine URL), limits (`timeout_s`, `stall_timeout_s`, `max_turns`, `liveness`), the gateway tag, the run's `traceparent`, budgets as data, and the names of the credential files (`gateway-key`, `run-token-gateway`, `run-token-broker`); closed, with no secret value |
| `usage_record` | one line of the usage stream: a `call` per model call (sized with its tokens, or `unsized`, never left out), a `tool_call` per tool call (server id, tool name, start, duration, outcome; never arguments or results), a `signal` (`backend_absent`), and one `end` (session id, turns, `budget_exhausted`, and a `class` only the runtime can see: `ContextExceeded`, `ToolCallParse`, `TurnCap`, `ConcurrencyLimited`); names and numbers only |
| `grants` | a compiled profile's MCP servers as the deploy renders them beside the unit template (`/etc/hnx-agent/<slug>/grants.json`): per server id its kind, transport (`stdio` with an absolute command, or `http` with a URL), locality (`local` gets `_meta.traceparent`, `non-local` never does), and the compiled profile's digest; the template pins the file's own sha256 (`$HNX_GRANTS_SHA256`). The file is `0640 root:hnx-agent-<slug>`, and a server's `env` holds no credential and refuses every key the MCP catalog's `DENIED_ENV` refuses |

**The gateway.** The spec's `target.gateway_url` must be exactly the gateway the deploy pins in
the template (`$HNX_GATEWAY_URL`). A body sends the run's key, tokens and prompt nowhere else, and a
spec naming another gateway makes no call and ends `Internal`.

**Contract version.** `cap:agent-runtime` 1.0, which `examples/modules/slots.yml` names, tracks
these drafts until they freeze with ADR-0051's acceptance.

**Bounds.** A stream is at most `max_usage_bytes` (1 MiB in the reference launcher), each line at
most 16 KiB and nested at most 8 deep. A stream past its bound while the run is going is
`ResourceLimit`. One over its bound when read, or holding a line that breaks a bound or does not
validate, is `Internal`.

**Classes.** The launcher decides a run's class from these, never from text (ADR-0051 decisions 6
and 10):
- why it stopped the run, and how the body exited, through the provider's `exit_classes` (an
  unmapped status is `Internal`);
- the `end` record's claims, which the gateway's records corroborate:
  - a `ContextExceeded` needs a 400 `upstream_rejected` record later than every answered call of
    the run;
  - `BudgetExhausted` needs a 403 `run_budget_exhausted`;
  - `ConcurrencyLimited` is never corroborated, since the gateway records no 429.

  The launcher waits up to its gateway wait (2 seconds in the reference) for the records to cover
  the run's end. Records that still lag, or records the gateway dropped since the run started
  (its `usage_records_dropped` is cumulative), leave the claim uncorroborated (`Internal`).

**Timeouts.** A `stall_timeout_s` other than 0 must be at least twice the launcher's gateway wait
plus one poll interval, and a launcher refuses a shorter one. While the gateway's records cannot be
judged, the stall timer is frozen and only `timeout_s` bounds the run.
