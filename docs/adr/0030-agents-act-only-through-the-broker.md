# ADR-0030: Agents act only through the broker

- **Status:** proposed
- **Date:** 2026-10-23
- **Related:** ADR-0017 (broker service), ADR-0024 (MCP catalog), ADR-0027 (modules),
  `homelabnext/agent/tool_classes.yml`, `schemas/platform/mcp_server.schema.json` 1.1,
  [agent profiles](../agent.md), [MCP server](../mcp.md), [MCP catalog](../mcp-catalog.md),
  [broker](../broker.md), [checklist](../checklist.md) G-03, G-04, G-13

## Context

The broker (ADR-0017) is where an agent's action is allowlisted, approved, bound to its request
and audited. But nothing required an agent to use it. The reader rule (G-03) kept acting grants
away from profiles that read untrusted content and left every other profile free: an actor
profile could hold a shell, SSH, Ansible or Kubernetes MCP server, the hypervisor or secrets
capability and the `privileged` tier, and the compiler, `verify`, `hnx agent lint`, the catalog
check and the client render all accepted it, because the ceiling policy allowed it. Such an
agent acts with the server's own credential, outside the allowlist, without an approval the
broker can bind and without an audit record. A gap analysis showed the shape: a profile granted
`ssh`, `shell`, `ansible`, `kubernetes` and `cap:hypervisor` passed every gate.

Three smaller holes came with it. A catalog tool's `approval: true` was described as an approval
"through the broker or the client", so a client's own confirmation prompt read as a control. The
orchestrator's tool server offered `submit_job`, a second way onto the controller's queue beside
the broker action `agent.job.submit` that `docs/stackstorm.md` names as the only one. And three
deprecated duplicate shell servers (`bash`, `exec`, `terminal`) were still grantable. G-04's
observable ran one test file, so none of this could turn it red.

## Decision

1. **Every agent action goes through the broker.** `tool_classes.yml` lists the acting classes,
   `broker_only: [exec, file-write, credential]`. A table passed with `--classes` may list more,
   never fewer (the loader refuses one that drops a listed class, as for `reader_forbidden`), and
   an empty list is refused.
2. **The rule `actors-act-via-broker` applies to every profile, reader or not**
   (`homelabnext.agent.readers.broker_problems`, beside the reader rule):
   - a granted MCP server with a tool in a `broker_only` class is refused unless its catalog
     record says **`acts_via: broker`** (each acting tool is a broker call: the broker's own MCP
     front, `hnx-broker`);
   - or it is a **direct exception**: the record says `acts_via: direct` with a `direct_reason`,
     carries a current human `approve` review (a review of an earlier content does not count),
     and the ceiling policy's entry for that profile lists the server in **`direct_mcp`**. The
     policy owner makes the exception per profile and server, like `internet_mcp`; a spec's own
     ceiling cannot (without a policy no direct server is allowed);
   - a capability in a `broker_only` class other than `cap:broker` is refused, with no exception
     (`cap:hypervisor`, `cap:secrets`, `cap:idp`, `cap:orchestration`, `cap:object-store`);
   - a tier whose classes are `broker_only` (`execute`, `privileged`) needs `cap:broker`.
3. It is enforced where the reader rule is: `compile_profile` (`BrokerViolation`),
   `verify_profile` (with the policy's `direct_mcp`), `hnx agent lint` (`--rule` picks one of the
   two rules, `--policy` supplies `direct_mcp`), `hnx mcp catalog check` (which lints the grants),
   the client render (compiled and lean profiles) and the module rules (Decision 7). A context
   manifest's tools obey it too, with no exception (a manifest is bound to a persona, not a
   profile).
4. **`platform/mcp_server` 1.1** (additive; 1.0 stays frozen) adds `acts_via: broker|direct` and
   `direct_reason` (required with `direct`, allowed only with it). `hnx mcp catalog check`
   requires every active or deprecated server with an acting tool to declare `acts_via` (R3.3),
   and refuses `approval: true` on an acting tool unless the server is `acts_via: broker` (R3.2):
   only the broker grants an approval, a client's prompt is not one, so a server that acts
   directly says `false`. The schema's description of `approval` says so.
5. **The shipped catalog.** `hnx-broker` is `acts_via: broker`. `ssh`, `shell`, `ansible`,
   `kubernetes`, `vault`, `filesystem`, `git`, `github` and `gitlab` are `acts_via: direct` with
   a reason and no shipped profile holds them (a record cannot express confining `filesystem` or
   `git` to an agent's own workspace, so they are not exempted either). `bash`, `exec` and
   `terminal` are retired (replaced by `hnx-broker`). `agent-runtime` keeps only its read-only
   `queue_summary`: a job is submitted through the broker action `agent.job.submit`. The
   llm-orchestrator catalog renders a kind for a server that acts other than through the broker
   only when a rendered profile is granted it, so the controller refuses any other grant of it.
6. **The invariants.** G-13 "Agents act only through the broker" runs
   `hnx agent lint --rule actors-act-via-broker`; G-03 runs `--rule readers-cannot-act`, so a red
   says which; G-04's observable runs the broker rule over every profile before its tests.
7. **Modules** (ADR-0027) contribute no authority: a contributed MCP record with an acting tool
   says `acts_via: broker` (a direct exception is only ever the overlay's own catalog record and
   ceiling policy), a contributed agent's spec obeys the rule, and an agent's `tools` entry naming
   an acting tool of the module's own record needs that record to act through the broker.

## Consequences

- An agent that needs to change something asks the broker for a named action; the allowlist,
  approvals bound to the request digest and the audit trail now cover every agent action, not
  only the ones that happened to use the broker.
- Upgrading: an overlay whose profiles or render specs grant a direct acting server (a shell,
  SSH, Ansible, Kubernetes, a secret store, a file or repository writer) now fails `hnx agent
  lint`, `verify`, compile and render, and its records fail the catalog check until each acting
  server declares `acts_via` and drops `approval: true` unless it is the broker. Replace the grant
  with `hnx-broker`, `cap:broker` and a broker action, or make a reviewed exception (the record's
  `acts_via: direct` and `direct_reason`, a human approve review, the policy's `direct_mcp`).
- Changing a record's `acts_via` changes its digest, so its reviews go stale and an active record
  needs them again: claiming `broker` is reviewed like any other change.
- A capability the table does not classify (a conformance or overlay capability such as
  `cap:backup`) is not judged by the broker rule; the reader rule still refuses it to a reader.
  Classing it brings it under the rule.
- The broker becomes the one path for effects, so its availability matters more; a failed broker
  stops agent actions rather than letting them fall back to a direct tool.

## Alternatives

- **Keep the rule to readers (G-03 only).** That is the gap: an actor's acting tools were never
  bounded by anything but the ceiling policy, which says how much, not by which path.
- **Mark the third-party acting servers `acts_via: broker`.** Untrue for a server that runs
  commands with its own key, and it would have made them grantable; they are `direct` and the
  exception is per profile, reviewed and listed by the policy owner.
- **Retire every direct server.** It would remove the escape hatch an operator may need (a lab
  without a broker action for some task yet); the exception keeps it explicit, reviewed and
  narrow instead.
- **Enforce the pairing and the approval rule in JSON Schema only.** The acting classes are the
  class table's data, not the schema's; the schema carries the shape (`acts_via`,
  `direct_reason` together), the catalog check the rules that read the table.
