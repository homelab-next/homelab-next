<!-- SPDX-License-Identifier: Apache-2.0 -->
# Code Mode build plan

The order in which [ADR-0031](adr/0031-code-mode-through-the-broker.md) (proposed) is built.
CM-1, CM-3 and CM-4 have landed (both described below); nothing else here is built yet. Steps
tagged **PUBLIC-NOW** are provable in CI with fakes, like the [build order](build-order.md)'s P
phases; steps tagged **SERVER** need the lab and are documented, not run, here.

The rule from the build order holds: **contracts before services.** The executor and runner
contracts, with their reference fakes and mutants, land before any real sandbox does, and the
real executor goes live only when the same suite passes against it.

```
CM-1 ADR + plan --> CM-2 schemas --> CM-3 generator --+--> CM-5 runner contract --> CM-6 golden suites
                                  \-> CM-4 executor contract -/                          |
CM-7 sandbox spike (SERVER) --> CM-8 real executor (SERVER) --> CM-9 one role live (SERVER)
```

## Phase 1: read-only, one PR per step

| Step | Tag | What lands | Done when |
|---|---|---|---|
| CM-1 | PUBLIC-NOW | ADR-0031 (proposed) and this plan | the ADR log and doc-fact tests pass |
| CM-2 | PUBLIC-NOW | **Landed.** Schemas under `schemas/codemode/` (drafts): execution request and result (`status` ok, paused, denied, error, limit), capability token claims, step-journal record; examples and negatives (drafts, frozen when the ADR is accepted) | `make schemas` passes; every negative is refused for its stated reason |
| CM-3 | PUBLIC-NOW | **Landed.** `hnx codemode gen [--check]` in `homelabnext/codemode/`: reads the broker manifest (its grants, actions and handler documents) and writes, per agent profile, synchronous typed stubs and the search index, from each action's argument spec; generated marker; goldens from `examples/` in `examples/codemode/<profile>/`. Exec result types come from the handler document's optional `result_schema`; the MCP catalog arrives with CM-5 | `--check` fails on a hand edit and on a manifest change; a profile's output names only its granted actions; wired into `make gates` |
| CM-4 | PUBLIC-NOW, **landed** | The `codemode-executor` capability: protocol, a reference fake (test-only, not a boundary), a suite with the five MUST checks (no network but the broker, no credentials, limits enforced, disposable, result bounded) and one registered mutant per check | the fake passes; `hnx conform mutants all` catches every new mutant; capability pages regenerated |
| CM-5 | PUBLIC-NOW | The runner and the `codemode-runner` capability: `codemode.execute` as a broker action whose handler is the runner; the `codemode` tool class and catalog record for search and describe; token issue through the broker; step journal; pause on `submit`, resume without replay; denied calls as values; the broker refuses calls on a paused or over-cap token (codemode-runner check). Suite with the five MUST checks and mutants | suite green against the fake broker (`conformance/fakes/`); G-13 stays green with the new action and record; mutants caught |
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
paused or over-cap token is (CM-5). Its mutants are
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
(`{exit_code, output, truncated, stderr_bytes}`); the runner (CM-5) unwraps it, so a program gets
`output`, the handler's stdout parsed as JSON when it is JSON, else its text. A handler document may
declare a `result_schema` (`schemas/broker/handler` 1.2, additive): a JSON Schema object for that
decoded `output`. The generator renders the stub's return type from it with the mapping the
parameters use (a named interface/`TypedDict` for an object with properties, else an inline type),
puts it in `search.json`'s `result`, and holds every string in it to the same checks as a params
schema. A handler without one keeps `unknown`/`Any`. It describes only the success case (exit 0, not truncated, stdout valid JSON); text output, a
truncated output and a non-zero exit are the CM-5 runner's to define, and the stub type does not
cover them yet. A schema the generator cannot render faithfully (a `required` name declared only
inside `allOf`, say) leaves that method's result `unknown`/`Any`; a refused character or `*/` in
it still fails generation. A `$ref` is local or a shared id and is never dereferenced by the
generator. An object result whose property names are not plain identifiers (`exit-code`, `class`)
is typed inline with quoted keys (`dict[str, Any]` in Python). The broker only validates the schema when it
loads the document; it does **not** check an output against it at call time, so it is a statement of
intent, not a guarantee. Checking belongs to the CM-5 runner, which may refuse or flag an output
that does not match.

Names and inputs are refused rather than guessed: a keyword or a name that would shadow a builtin
the stub's annotations use gets a trailing `_` (`list` becomes `list_`); two actions landing on one
method, a parameter that is not an identifier or is `self` (or `params` beside `**params`), a
`required` name the spec does not declare, a name with a trailing newline or a control character,
and a description or pattern holding a control, bidi or zero-width character, `*/` or `"""` stop
the generator (exit 2). The MCP catalog is not read yet: the `codemode` tool class and its catalog
record arrive with the runner (CM-5).

`--check` fails (exit 1) on a file that differs (a hand edit; a manifest or handler change), one
that is missing or a symlink, and a marked `<slug>/<file>` no profile renders any more; it exits
100 when it cannot read the output directory. `gen` writes each file through a temporary file and
`os.replace`, refuses a symlinked profile directory or file, and deletes only those stale marked
files, checked again just before each unlink.

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
     enforcement, CM-5);
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
