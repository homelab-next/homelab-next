<!-- SPDX-License-Identifier: Apache-2.0 -->
# Code Mode build plan

The order in which [ADR-0031](adr/0031-code-mode-through-the-broker.md) (proposed) is built.
CM-1, CM-2, CM-3, CM-4, CM-5a and CM-5b have landed (described below); nothing else here is built yet. Steps
tagged **PUBLIC-NOW** are provable in CI with fakes, like the [build order](build-order.md)'s P
phases; steps tagged **SERVER** need the lab and are documented, not run, here.

The rule from the build order holds: **contracts before services.** The executor and runner
contracts, with their reference fakes and mutants, land before any real sandbox does, and the
real executor goes live only when the same suite passes against it.

```
CM-1 ADR + plan --> CM-2 schemas --> CM-3 generator --+--> CM-5a tokens --> CM-5b runner --> CM-6 golden suites
                                  \-> CM-4 executor contract -/                                |
CM-7 sandbox spike (SERVER) --> CM-8 real executor (SERVER) --> CM-9 one role live (SERVER)
```

## Phase 1: read-only, one PR per step

| Step | Tag | What lands | Done when |
|---|---|---|---|
| CM-1 | PUBLIC-NOW | ADR-0031 (proposed) and this plan | the ADR log and doc-fact tests pass |
| CM-2 | PUBLIC-NOW | **Landed.** Schemas under `schemas/codemode/` (drafts): execution request and result (`status` ok, paused, denied, error, limit), capability token claims, step-journal record; examples and negatives (drafts, frozen when the ADR is accepted) | `make schemas` passes; every negative is refused for its stated reason |
| CM-3 | PUBLIC-NOW | **Landed.** `hnx codemode gen [--check]` in `homelabnext/codemode/`: reads the broker manifest (its grants, actions and handler documents) and writes, per agent profile, synchronous typed stubs and the search index, from each action's argument spec; generated marker; goldens from `examples/` in `examples/codemode/<profile>/`. Exec result types come from the handler document's optional `result_schema`; the MCP catalog arrives with CM-5 | `--check` fails on a hand edit and on a manifest change; a profile's output names only its granted actions; wired into `make gates` |
| CM-4 | PUBLIC-NOW, **landed** | The `codemode-executor` capability: protocol, a reference fake (test-only, not a boundary), a suite with the five MUST checks (no network but the broker, no credentials, limits enforced, disposable, result bounded) and one registered mutant per check | the fake passes; `hnx conform mutants all` catches every new mutant; capability pages regenerated |
| CM-5a | PUBLIC-NOW, **landed** | Capability tokens issued, held and enforced by the broker ([broker](broker.md#code-mode-capability-tokens)): `codemode.execute`'s params checked as an execution request and the request in flight, bound to its runner (the registered one, else the one the manifest action names in `runner:`, required with several runners), while its handler runs; `issue_token` for that runner only, claims from the request, actions narrowed to what `decide()` admits for the actor, lifetime and live tokens capped by the manifest's `codemode` block, the call cap per execution (a resume inherits what is left); execution ids per actor; the secret kept as a digest; every token call checked in order (invalid, sandbox both ways, expired, spent, paused, action, cap) and counted broker-side before `decide()`; answers and post-admission refusals naming the request; a call needing approval, or a submit, stores the request and pauses the token in one step; spend with an outcome (`finished`, `paused`), resume of a paused execution only, `token_run` of the paused request; a crash sweep and retention; audit 1.3 `token_id`/`execution_id` and `token-pause`/`token-spend`; the `runner` and `sandbox` socket peers, the runner exempt from the refusal limit. The `broker` contract's feature `codemode-tokens`, proved by the extended suite `broker-tokens` | the thirteen MUST checks pass on the fake and the reference broker; each of the fourteen mutants is caught by its own check only |
| CM-5b | PUBLIC-NOW, **landed** | The runner, `codemode.execute`'s handler ([below](#cm-5b-the-runner); `homelabnext/codemode/runner.py`): the execution request checked, the run's token from `issue_token` as the bound runner (the actor's granted actions, never `codemode.*`, the cap and lifetime from the budget), the program, the token and the run's endpoint (the CM-4 wire, served by the runner's relay) handed to a `CodeExecutor`, and an `execution_result` back (status, calls, logs, pending, value and `truncated`, held to the schema); every program call a broker request with the token (`call` is `token_call`, `submit` is `token_submit`, the paused step on a resume `token_run`), over the socket as the runner and sandbox peers with the bearer line; an exec envelope unwrapped to `output` (JSON or text) and the cases that are not that success defined (`output-truncated`, `handler-failed`, `result-schema-mismatch` against the index's result schema, `result-too-large`, each data); a broker refusal a denied call the program catches as `broker.Denied`, with the request ids once the broker built the request; the step journal (`journal_step`, local, append-only, `0700`, one file per record, a keyed fingerprint per call, retention 7 days finished and 30 paused); a submit or a call needing approval pausing the run (`pending`); a resume reading `token_status`'s `paused_by_state` (never polling `token_run`), pausing again unissued while it waits, else answering journalled steps from the journal (`replayed`), `token_run` of the paused request and only the later calls new, a different call refused `replay-mismatch`; the broker's `call-cap-reached` ending the run `limit` (`calls`). The tool class `codemode` (read-only, reader-forbidden, not broker-only), `platform/mcp_server` 1.2, the record `hnx-codemode` (`codemode_search`, `codemode_describe` over the generator's index, narrowed to the broker's grant; execute stays `broker_call` of `codemode.execute` on `hnx-broker`), `cap:codemode-runner` classed `exec`. The `codemode-runner` capability, the eighteenth | the six MUST checks pass on the fake broker and the reference service; each of the six mutants is caught by its own check only; G-13 and `make mcp-check` green |
| CM-6 | PUBLIC-NOW | Golden suites `codemode-<role>` against the fakes, with the same tasks in classic MCP mode as the baseline; scorers for the answer, the broker call count, denied calls and ungranted actions; the G-02 corpus placed inside tool results a program reads | both modes run in CI against the fake inference server; the report shows accuracy and turns per mode |
| CM-7 | SERVER | Sandbox spike on the sandbox host: OpenShell against gVisor, judged against ADR-0031 decision 5; cold start, per-run cost with a warm pool, syscall overhead, real handler latency; the stubs are synchronous, so a TypeScript executor must offer a blocking host call to the broker (`Atomics.wait` on a worker, or a sync bridge): check it before choosing | a short decision note picks the executor and records the numbers |
| CM-8 | SERVER | The real executor adapter and an Ansible role for the sandbox host: a warm pool with a fresh child or isolate per run, egress only to the broker (host firewall), no credentials | the CM-4 suite, after the egress-probe fixes from phase 2, passes against the real executor on staging |
| CM-9 | SERVER | One role enabled in the private overlay with read actions only (DNS and DHCP lookups, hypervisor nodes and guests, network clients and devices, one lake query) | the correlation task passes on the lab; the live golden run beats MCP mode for that role, or the role stays on MCP mode and the result is recorded |

CM-4 as landed: the contract is `conformance/protocols/codemode_executor.py`, in the vocabulary of
`schemas/codemode` (PR #64): `CodeExecutor.run` returns status `ok`, `paused`, `denied`, `error`
or `limit`, an error as `{kind, message}` (one line, at most 2000 characters), the cap that ended
a run, a value cut to a `truncated` prefix of its pinned JSON, the printed output and the pending
call of a paused run. The broker is an endpoint the harness serves where the executor declares
(`broker_bind`) and a token scoped to the run, never an environment variable; the executor owns
the transport, and its broker client caps calls (`max_calls`, refused as `call-cap-reached`).
The suite `conformance/suites/codemode_executor.py` has fifteen MUST checks: the five above plus
a broker round trip, errors, denials, a denial's reason, a pause the program cannot swallow,
broker errors, the call cap, and oversized, unencodable and unknown-language programs refused.
The client-side pause and call cap are behaviour, not enforcement: the broker's refusal on a
paused or over-cap token is, and has landed with CM-5a (the `broker-tokens` checks
`paused-token-refused` and `call-cap-enforced-by-the-broker`, at the broker's API). Its mutants are
`open-egress`, `env-leak`, `no-timeout`, `reused-state`, `unbounded-result`, `no-call-cap` and
`pause-catchable`, and the reference page is
[capabilities/codemode-executor](capabilities/codemode-executor.md). Each check holds its
programs per language, and a declared language a check has no program for fails it as
untested. The reference fake forks each program from a warm Python process that never runs one
itself (the warm-pool shape of ADR-0031 decision 5) and puts it behind an audit hook: it is
test-only and **not an isolation boundary**. The programs are Python only, so the TypeScript
executor CM-7 may choose (built in CM-8) needs them written for it.

Phase 1 is done when CM-9 is, both contracts are green with every mutant caught, and at least
one role has a recorded adoption decision.

### CM-3: the generator

```bash
hnx codemode gen            # examples/broker/manifest.yml -> examples/codemode/<profile>/
hnx codemode gen --check    # writes nothing; exit 1 on drift (make gates, CI)
hnx codemode gen --manifest path/to/manifest.yml --out build/codemode   # another manifest
```

Per profile the manifest grants actions to, `<out>/<profile>/` gets three files from one model
(`homelabnext/codemode/model.py`):

- `types.d.ts`: a `declare namespace` per action prefix, one function per action taking the
  params as one object;
- `stubs.pyi`: a class per namespace bound to a module-level name, keyword-only parameters;
- `search.json`, for `codemode_search` and `codemode_describe`: per action `name`, `call` (what a
  program writes), `summary`, `tier`, `needs_approval`, `kind` (exec or lane), `params` (the exact
  JSON Schema), `result` (type name and schema, or null) and `signatures` (one line per language).

**Calls are synchronous** in both languages (`def method(...)`, `function method(args): R`, no
`Promise`): a call returns its result, and a call that needs approval pauses the whole run until
it is decided (ADR-0031 decision 7).

Which actions a profile sees is asked of `homelabnext.broker.decide` with one shadow probe per
granted action, as `hnx broker actions` lists them, so an ungranted action, one above the grant's
`max_tier` or one with no handler never appears, and `needs-approval` becomes
`needs_approval: true`. `codemode.*` actions never appear: a program cannot start a program. An
exec action's parameters are its handler's `params_schema`; a lane action's are the lane's
(`{name, content}`, or `{note, body?, slug?}` for a records inbox) and its result is `LaneWrite`
(`{path, bytes, digest}`). A parameter's description, `pattern` and bounds are in its note. Where
the stubs are wider than a schema (a nested object in Python, `allOf`, `$ref`) the module
docstring of `homelabnext/codemode/render.py` lists it; the index keeps the exact schema.

**An exec call returns the handler's `output`.** The broker answers an exec call with an envelope
(`{exit_code, output, truncated, stderr_bytes}`); the runner (CM-5b) unwraps it, so a program gets
`output`, the handler's stdout parsed as JSON when it is JSON, else its text. A handler document may
declare a `result_schema` (`schemas/broker/handler` 1.2, additive): a JSON Schema object for that
decoded `output`. The generator renders the stub's return type from it with the mapping the
parameters use (a named interface/`TypedDict` for an object with properties, else an inline type),
puts it in `search.json`'s `result`, and holds every string in it to the same checks as a params
schema. A handler without one keeps `unknown`/`Any`. It describes only the success case (exit 0, not truncated, stdout valid JSON); text output, a
truncated output and a non-zero exit are defined by the runner ([CM-5b](#cm-5b-the-runner): text
is the value, the other two are `broker.Error`), and the stub type does not cover them. A schema the generator cannot render faithfully (a `required` name declared only
inside `allOf`, say) leaves that method's result `unknown`/`Any`; a refused character or `*/` in
it still fails generation. A `$ref` is local or a shared id and is never dereferenced by the
generator. An object result whose property names are not plain identifiers (`exit-code`, `class`)
is typed inline with quoted keys (`dict[str, Any]` in Python). The broker only validates the schema when it
loads the document; it does **not** check an output against it at call time, so it is a statement of
intent, not a guarantee. The runner checks it: an output that does not match reaches the program
as `broker.Error` (`result-schema-mismatch`), while the call record keeps the broker's `ok`.

Names and inputs are refused rather than guessed: a keyword or a name that would shadow a builtin
the stub's annotations use gets a trailing `_` (`list` becomes `list_`); two actions landing on one
method, a parameter that is not an identifier or is `self` (or `params` beside `**params`), a
`required` name the spec does not declare, a name with a trailing newline or a control character,
and a description or pattern holding a control, bidi or zero-width character, `*/` or `"""` stop
the generator (exit 2). The MCP catalog is not read yet; the `codemode` tool class and its catalog
record (`hnx-codemode`) arrived with the runner ([CM-5b](#cm-5b-the-runner)), reading this index.

`--check` fails (exit 1) on a file that differs (a hand edit; a manifest or handler change), one
that is missing or a symlink, and a marked `<slug>/<file>` no profile renders any more; it exits
100 when it cannot read the output directory. `gen` writes each file through a temporary file and
`os.replace`, refuses a symlinked profile directory or file, and deletes only those stale marked
files, checked again just before each unlink.

### CM-5b: the runner

`homelabnext.codemode.runner.Runner(broker, executor, state_dir, ...)` is `codemode.execute`'s
handler: `broker.register_runner(runner.runner_id, runner.handle)` in process; over the socket
the manifest's `codemode.execute` handler is the runner's client (CM-8). One run:

1. the params are an execution request (`schemas/codemode/execution_request`); a language the
   executor does not run is an `error` result (`sandbox`), never a crash;
2. a resume (`resume: true`) needs the runner's journal of a **paused** execution of the same
   actor and code digest (else `error`, kind `token`: `execution-not-resumable`,
   `resume-code-mismatch`), and reads `token_status` of the run that paused for
   `paused_by_state`: `pending` or `expired` ends the run `paused` again at once, with no token
   issued and nothing sent (a resumed run that ended unpaused would finish the execution, and
   `token_run` counts against the cap, [broker](broker.md#code-mode-capability-tokens));
   `approved` and `denied` run;
3. `issue_token` as the bound runner, listing the actor's granted actions (from the search index,
   or a callable the embedder passes; never `codemode.*`): the broker narrows them, and the call
   cap and lifetime come from the request's budget;
4. the runner serves the run's endpoint (the CM-4 wire, one JSON line per call, at the executor's
   `broker_bind`) and the executor runs the program with it and the token. The program's view is
   CM-4's plus `broker.submit(action, args)` and a `target=` keyword (the wire's optional `op`
   and `target`);
5. the token is spent `paused` when the run ended on a pause, else `finished`, and the result is
   held to `schemas/codemode/execution_result` before it is returned (a result that fails is a
   runner bug, `RunnerError`, which the broker reports `handler-failed`).

**Calls.** Every call is a broker request with the run's token, so `call` is `token_call`, `submit`
is `token_submit`, and on a resume the step that paused is `token_run` of its request. Over the
socket the runner speaks as its `codemode.runners` peer (`SocketRunnerBroker`) and its relay as a
`codemode.sandboxes` peer (`SocketSandboxBroker`: `BrokerClient`'s bearer-line path), so in a
deployment the relay's connection comes from the sandbox user its tokens are bound to. A call
with another token than the run's is refused at the relay (`token-invalid`) and never forwarded.

| The broker answers | The call record | The program gets |
|---|---|---|
| `{result}`, not an exec envelope | `ok`, request ids | the result |
| `{result}`, an exec envelope (`{exit_code, output, truncated, stderr_bytes}` exactly) | `ok` | `output`: JSON decoded when it was JSON, else the text |
| an envelope with `truncated` | `ok` | `broker.Error`, reason `output-truncated` (a prefix is never handed over as if whole) |
| an output not matching the action's `result` schema in the index | `ok` | `broker.Error`, reason `result-schema-mismatch` |
| a result over the journal's `max_result_bytes` (256 KiB) | `ok` (journalled as `result: null` and the real digest) | `broker.Error`, reason `result-too-large` |
| a non-zero exit | the broker refuses it, `handler-failed`: `error`, request ids | `broker.Error`, reason `handler-failed` |
| `{state: pending}` (a submit, or a call needing approval) | `pending` | the pause: the run ends `paused`, `pending` names the call |
| `Denied`, or `InvalidArguments` (`invalid-params`) | `denied`, the broker's reason, request ids when the broker built the request | `broker.Denied` with that reason: a value it can catch and go on |
| a token refusal (`TOKEN_REFUSALS`) | `denied`, no request ids, not journalled | `broker.Denied` |
| any other `BrokerError`; a transport failure | `error` (`broker-unreachable` for the transport) | `broker.Error` |

The call record and the journal always keep the broker's own outcome; the reply is what the
program may use. `calls`, `pending` and the journal are the runner's; `value`, `logs` (the printed
output as single lines, unsafe characters replaced, at most 100 of 1000 characters) and
`error.message` are program output.

**Status.** A run with a pending call is `paused`, whatever the program did after; a cap the
executor reports is `limit`; a replay mismatch is `error` (`runtime`); a call refused
`call-cap-reached` ends the run `limit` with `limit: calls` (the broker's count is the
enforcement, so the executor's client is given one call more than the token's cap); otherwise the
executor's status stands.

**The journal** (`homelabnext/codemode/journal.py`), under `<state>/journal/`, by the broker's
state-dir conventions: one directory per execution (`execution_key` of the actor and the id,
so ids are each actor's own), `meta.json` (actor, id, code digest, state, the run's tokens),
and one file per record (`<step>-<seq>.json`, created exclusively, `0600`; `seq` 1 only for a
pending step that settles), each a `journal_step` record and the call's fingerprint: an
HMAC-SHA256 under the runner's `journal.key` of `{op:action, target, args}`, since the request
digest is the broker's and cannot be computed for a call not yet sent. A resume serves a step
only when its action and fingerprint match; a different call is refused `replay-mismatch`, every
later call too, and the run ends `error`: the journal is never replayed into another program. At
most 200 steps, two records each; executions are swept 7 days after they finished and 30 after
they paused or stopped running (a resume of a swept one is refused like an unknown one).

**Search and describe.** `hnx codemode mcp --index DIR --socket PATH` serves
`codemode_search(query, limit)` and `codemode_describe(name)` (`homelabnext/codemode/mcp_tools.py`,
catalog record `examples/mcp/hnx-codemode.yml`, tool class `codemode`): the calling profile's
`<index>/<profile>/search.json`, narrowed to the actions the broker's `actions` answer grants that
process now, so an agent names no profile and sees no action its grant dropped. Execute is not a
tool here: it is `broker_call` of `codemode.execute` on `hnx-broker`. The class `codemode` is in
`reader_forbidden` and not in `broker_only` (`homelabnext/agent/tool_classes.yml` says why: its
tools only read, and what runs code is the broker action, already `exec` and broker-only);
`cap:codemode-runner` is classed `exec`, so no profile is granted it other than as that action.

**The contract.** `codemode-runner` (`conformance/protocols/codemode_runner.py`, the eighteenth
capability): the suite (`conformance/suites/codemode_runner.py`) asks the broker, as an agent, to
run real programs and judges the result, the broker's state and the journal, with six MUST checks,
`result-matches-the-schema`, `denied-call-is-a-value`, `every-call-is-journalled`,
`submit-pauses-the-run`, `resume-without-replay` and `call-cap-ends-the-run`, and one mutant each
(`raw-logs-unchecked-result`, `denial-as-error`, `refusals-unjournalled`, `pause-hidden`,
`resume-resends`, `cap-hidden`), caught by its own check only. The subject is the reference runner
over the fake broker (`fake`) or the reference service (`hnx conform run codemode-runner --target
broker-reference`), with the forking test executor (`conformance/fakes/codemode_runner.py`). A call
needing approval cannot be reached through the contract's API (an in-process command never needs
one), so that path, `paused_by_state` waits, exec envelopes and the socket roles are proved by
`tests/codemode/test_runner.py` against the example manifest. Reference page:
[capabilities/codemode-runner](capabilities/codemode-runner.md).

## Later phases

Each is planned as steps like the ones above when phase 1 closes.

2. **Hardening.** An adversarial sandbox suite (escape attempts, egress probes, resource
   exhaustion); the injection-in-results corpus against real models; the live golden and
   injection evals on a timer with a page on regression. The isolation checks deferred from the
   CM-4 review, pending operator authorization:
   - *before CM-8*, because today's egress probes can pass a sandbox that has egress: the
     name-lookup probe resolves `localhost`, which is answered from `/etc/hosts` without a
     resolver (it should look up a random name and treat any resolver answer as reached), and
     the UDP probe trusts a successful `sendto` (it should be judged by what the decoy
     received);
   - post-cap calls: a capped program must not reach the broker after `run` returns;
   - a tamper check: a program resetting its client state or calling the broker directly
     cannot exceed the cap or continue past a pause (the broker's refusal on the token is the
     enforcement, landed with CM-5a and proved at the broker's API; the sandbox-side probe
     remains);
   - an environment allowlist and canaries set before the executor is constructed, and the
     canary absent from the output as well as the environment;
   - well-known credential paths in the sandbox's filesystem;
   - more egress families and destinations: IPv6, `AF_UNIX`, ICMP, and addresses other than
     the harness's;
   - the harness's own `/proc` environment unreadable, and a pid namespace of the sandbox's own;
   - non-root, no capabilities, no-new-privileges, a read-only root, and process-count and
     scratch-size limits;
   - the output cap applied to stderr as well as stdout;
   - the token's absence beyond the environment;
   - more disposable locations.
3. **Rule approvals.** `rule` as an approver kind in the broker's approval check; a standing-rule
   schema, lint and register in the overlay; checks that a call outside a rule's shape escalates,
   a top tier is never rule-approved, an expired rule approves nothing and rule approvals are
   rate-limited; proposals of a rule after N matching human approvals. First low-risk writes:
   DNS records, graceful guest start and stop.
4. **Discovery** over the full catalog, plus reviewed reusable snippets.
5. **Durable workflows:** alert-driven investigations through the orchestration contract,
   whose holds already stay with a run between attempts.

## Open questions

- OpenShell or gVisor (the CM-7 spike), and so the language inside the sandbox (Python or TypeScript; the
  stubs are generated for both from the same argument specs, synchronous in both).
- Whether a read-only `codemode.execute` variant, whose token reaches only read actions, should
  exist for reader profiles.
- N for rule proposals, and how long a standing rule lives.
- Whether to pin `@cloudflare/codemode` or take only its ideas and the type generation.
