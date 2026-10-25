<!-- SPDX-License-Identifier: Apache-2.0 -->
# Code Mode build plan

The order in which [ADR-0031](adr/0031-code-mode-through-the-broker.md) (proposed) is built.
CM-4 has landed; nothing else here is built yet. Steps tagged **PUBLIC-NOW** are provable in CI with fakes, like the
[build order](build-order.md)'s P phases; steps tagged **SERVER** need the lab and are
documented, not run, here.

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
| CM-2 | PUBLIC-NOW | Schemas under `schemas/codemode/`: execution request and result (`status` ok, paused, denied, error, limit), capability token claims, step-journal record; examples, negatives, frozen baselines | `make schemas` passes; every negative is refused for its stated reason |
| CM-3 | PUBLIC-NOW | `hnx codemode gen [--check]` in `homelabnext/codemode/`: reads the MCP catalog and the broker manifest and writes, per agent profile, the typed stubs and the search index, from each action's argument spec and result schema; generated marker; goldens from `examples/` | `--check` fails on a hand edit and on a manifest change; a profile's output names only its granted actions; wired into `make gates` |
| CM-4 | PUBLIC-NOW, **landed** | The `codemode-executor` capability: protocol, a reference fake (test-only, not a boundary), a suite with the five MUST checks (no network but the broker, no credentials, limits enforced, disposable, result bounded) and one registered mutant per check | the fake passes; `hnx conform mutants all` catches every new mutant; capability pages regenerated |
| CM-5 | PUBLIC-NOW | The runner and the `codemode-runner` capability: `codemode.execute` as a broker action whose handler is the runner; the `codemode` tool class and catalog record for search and describe; token issue through the broker; step journal; pause on `submit`, resume without replay; denied calls as values; the broker refuses calls on a paused or over-cap token (codemode-runner check). Suite with the five MUST checks and mutants | suite green against the fake broker (`conformance/fakes/`); G-13 stays green with the new action and record; mutants caught |
| CM-6 | PUBLIC-NOW | Golden suites `codemode-<role>` against the fakes, with the same tasks in classic MCP mode as the baseline; scorers for the answer, the broker call count, denied calls and ungranted actions; the G-02 corpus placed inside tool results a program reads | both modes run in CI against the fake inference server; the report shows accuracy and turns per mode |
| CM-7 | SERVER | Sandbox spike on the sandbox host: OpenShell against gVisor, judged against ADR-0031 decision 5; cold start, per-run cost with a warm pool, syscall overhead, real handler latency; a TypeScript executor needs a blocking host call (`Atomics.wait` or a sync bridge) behind the synchronous stubs | a short decision note picks the executor and records the numbers |
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
  stubs can be generated for either from the same argument specs).
- Whether a read-only `codemode.execute` variant, whose token reaches only read actions, should
  exist for reader profiles.
- N for rule proposals, and how long a standing rule lives.
- Whether to pin `@cloudflare/codemode` or take only its ideas and the type generation.
