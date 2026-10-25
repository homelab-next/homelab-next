---
summary: Agents may compose broker actions as short programs in a credential-free sandbox that reaches only the broker.
---
# ADR-0031: Agents may compose broker actions as sandboxed programs (Code Mode)

- **Status:** proposed
- **Date:** 2026-10-25
- **Related:** ADR-0017 (broker service), ADR-0022 (LLM gateway), ADR-0024 (MCP catalog),
  ADR-0027 (modules), ADR-0028 (Veritas), ADR-0030 (agents act only through the broker),
  [Code Mode build plan](../codemode.md), [broker](../broker.md), [agent profiles](../agent.md),
  [checklist](../checklist.md) G-02, G-03, G-11, G-13

## Context

Agents reach lab systems through MCP tools, one tool per operation. That has three costs, and
all three fall hardest on the small local models the lab runs:

- **Context.** Wide APIs (the hypervisor, the network controller, DNS and DHCP, the lake, the
  SIEM) put hundreds of tool schemas into every agent's context. Small contexts and weak tool
  selection fail first on a wide tool list.
- **Round trips.** A multi-step investigation (resolve a name, find its lease, find the guest,
  read its state) is a chain of model turns. Every intermediate result passes through the model,
  which costs tokens, turns and, on local models, wall-clock time.
- **No composition.** Filtering, joining and aggregating happen in the model's head, which is
  where small models make mistakes.

"Code Mode" (Cloudflare's `@cloudflare/codemode`, MIT) inverts this. The model sees a few tools
(search, describe, execute) and writes a short program against typed namespaces. The program runs
in a sandbox, and only its reduced result returns to the model. Claude's programmatic tool calling
is the same idea, but it is vendor-only, runs in the vendor's container and does not take MCP
tools, so it does not fit a local-first lab.

The constraint that shapes the design is ADR-0030: every agent action goes through the broker.
A program is an agent action that hides which tools it uses, so the program cannot be the unit
of policy.

Overhead was measured on 2026-10-24 (4 vCPU, runc, a stand-in broker that answers instantly, a
program of 5 broker calls): 1.6 ms with no sandbox, 239-331 ms for a new container per run,
3.7 ms (p95 4.3) for a warm sandbox forking a fresh child per run, and 0.46 ms for a QuickJS
isolate per run. One warm sandbox with 4 clients ran about 270 programs/s. A local model turn
takes seconds, so the sandbox is not the cost, provided it is warm. gVisor, Firecracker and
OpenShell could not be measured there.

## Decision

1. **Code Mode is a module** (ADR-0027) that contributes one capability, `cap:codemode`, and a
   runner service. It is not a second broker, a new datastore or a new repository.
2. **Every call a program makes is an ordinary broker request** from the agent that ran it:
   `call` for allowed actions, `submit` for actions that need approval. The allowlist, argument
   specs, redaction, request digests, approvals, expiry and audit apply per call. Policy is
   enforced per broker call, never per program.
3. **The model-facing API is three operations.** `codemode_search` and `codemode_describe` are
   `read` tools on the runner's MCP server, in a new `codemode` tool class, and list only the
   actions the calling profile is granted. Execution is the broker action `codemode.execute`,
   reached through the broker's own MCP front like every other action (ADR-0030), whose handler
   is the runner. No new direct acting grant exists. As built (CM-5b) the two read tools live on
   a server of their own, `hnx-codemode` (`hnx codemode mcp`, catalog record
   `examples/mcp/hnx-codemode.yml`), separate from the runner service, and read the generator's
   index for the profile the broker socket maps the caller to; the `codemode` class is
   reader-forbidden and not broker-only, since its tools only read.
4. **The namespaces are generated** (ADR-0028) from the MCP catalog and the broker manifest, one
   set per agent profile, from each action's argument spec and result schema (the generator reads
   the manifest first, CM-3; handler result schemas landed with CM-3 and the catalog record with
   CM-5b). `hnx
   codemode gen --check` fails on drift in CI. Nothing is hand-written, and no raw API is ingested: the
   connectors are the curated broker actions.
5. **The sandbox holds nothing and reaches nothing but the broker.** It has no credentials in its
   environment or image, a read-only root with tmpfs only, a non-root user with all capabilities
   dropped, CPU, memory, PID, wall-clock and output limits, and egress only to the broker
   endpoint. Each run gets a fresh child process or isolate inside a long-lived, hardened sandbox
   from a small pool; a container per run is not required. The executor is a capability with a
   contract, so gVisor and OpenShell are swappable; the first is chosen by a spike against these
   requirements.
6. **A run carries a capability token** from the broker, bound to the caller, the execution id,
   its allowed actions and a call cap, and short-lived. It works for no other execution.
7. **A call that needs approval pauses the run.** The runner returns the pending request ids; on
   approval the run resumes, and a step journal keyed by execution id and step replays completed
   steps instead of re-running them. A denied call is an error value to the program, never a
   runner crash and never a leak of the denied action's details.
8. **Approvals stay deterministic and off the GPU.** Besides humans, an approval may come from a
   reviewed standing rule in the private overlay (agent, action, argument shape, tier), audited
   with the rule id, expiring and rate-limited; its approver kind is `rule`. The top tiers (host
   `exec`, `credential`, `send` outside the lab, anything destructive) are never rule-approvable.
   A model may summarise and order pending requests or draft rules; it never approves.
9. **Adoption is per role and measured.** A golden suite per role runs the same tasks in Code
   Mode and in classic MCP mode against the fakes; a role adopts Code Mode only when it is at
   least as accurate in fewer turns. The G-02 injection corpus is also placed inside tool results
   a program reads.
10. **Two contracts with reference fakes and registered mutants:** `codemode-executor`
    (no network but the broker, no credentials, limits enforced, disposable, result bounded) and
    `codemode-runner` (calls are broker requests, search shows only granted actions, approval
    pauses and resumes without repeating steps, the token is scoped, a denied call is data).

## Consequences

- Agents get a short tool list and multi-step work in one turn. The program does the joins, and
  the model reads only the reduced result.
- Nothing is weaker than today: the broker refuses an ungranted call however it was composed,
  and the audit attributes each call to the agent.
- New things to maintain: the generator and its drift check, the runner, an executor and its
  sandbox host, two contracts with their mutants, the standing-rule schema and lint, and the
  codemode golden suites.
- Small local models may write programs worse than they pick tools. Item 9 decides this per role
  instead of assuming it.
- `codemode.execute` is an acting broker action, so a reader profile (G-03) cannot be granted
  it. Whether a read-only variant whose token reaches only read actions is worth adding is left
  open.
- The build is phased (read-only first, then hardening, rule approvals with low-risk writes,
  discovery over the full catalog, durable workflows); [the build plan](../codemode.md) gives the
  PR order and the checks for each step.

## Alternatives

- **Keep one MCP tool per operation.** Simple, but it carries all three costs above, worst on
  local models.
- **The vendor's programmatic tool calling.** It is vendor-only, runs off-site and does not take
  MCP tools.
- **Run programs in-process (Node `vm`, Python `exec`).** Not an isolation boundary; rejected.
- **A container per execute.** Simple lifecycle, but 0.25-0.35 s per run before gVisor, against
  milliseconds for a warm pool with a fresh child or isolate per run.
- **Firecracker microVMs.** Strongest isolation, heaviest to run, and it needs KVM on the
  sandbox host; kept as a later executor behind the same contract.
- **A model approver.** It needs VRAM or a cloud call per approval, and the small local models
  answered poorly. Rules and humans cover the need; a model may only assist.
- **Treat the program as the unit of policy** (approve or deny a whole program). One `execute`
  hides which actions run, so this would let a program do what its reviewer did not see.
