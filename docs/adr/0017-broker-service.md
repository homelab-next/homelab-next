# ADR-0017: Broker service

- **Status:** proposed
- **Date:** 2026-10-20
- **Related:** ADR-0010, ADR-0014, `docs/broker.md`, `docs/agent.md`, `schemas/broker/`,
  `homelabnext/broker/`, `conformance/protocols/broker.py`

## Context

Agents need a few kinds of effect: limited writes to specific places (their own memory, their
findings, a proposal for a person to decide), reads of system state, and occasionally an action
that changes a system. The pattern this replaces gave each agent a shell and broad read access,
fenced by a guard hook that inspected commands before they ran, plus a vault in which agents could
write only into a `proposed/` zone; a person approved in a dashboard and a sync job applied or moved
the result. In operation that pattern showed its seams: the guard had to parse arbitrary shell to
decide what a command touched, so reads were blocked or allowed by command shape rather than by
intent; the writable zone was a directory, so a path, a symlink or a filename convention was the
whole control; and approval was a file move with no binding to the exact content approved.

The repository already had the pieces of a better shape: a default-deny decision evaluator over a
manifest with approvals bound to a request digest (`homelabnext.broker.decide`), the `broker`
capability contract (allowlisted commands, validated arguments, a redacted audit trail,
caller-bound requests), conflict-free file writes (ADR-0014) and the records inbox (ADR-0010).
What was missing was a service that runs actions, keeps durable state and can be adopted.

## Decision

1. **Agents ask for named actions; they never get a shell or a writable directory.** The broker
   service (`homelabnext/broker/service.py`) implements the `broker` contract on top of `decide()`
   and a manifest (`schemas/broker/manifest` 1.2) and passes the conformance suite
   (`conformance/targets/broker-reference.yml`). Default deny: an action that is not listed, a
   caller without a grant, a tier above the grant, or a missing handler is refused.
2. **Writes go through lanes.** The built-in lane handler writes one file into a declared lane:
   kind `files` (an agent's own `memory.write` / `finding.write` directory, per-actor
   subdirectories by default) or `records-inbox` (`proposal.file`, a records note validated by
   the records schema with `requesting_agent` bound to the caller). The lane fixes the root, the
   filename pattern, the size cap, the format and an optional content schema. Every write is
   validated before a byte is written, resolved one directory at a time with `O_NOFOLLOW` (no
   `..`, no absolute names, no symlink escape and no check-then-write window), created
   exclusively unless the lane says `overwrite: true`, and written atomically. Every refusal has
   a machine reason (`lane-name-invalid`, `lane-path-escape`, `lane-symlink`, `lane-exists`,
   `lane-too-large`, `lane-content-invalid`, `lane-identity-mismatch`, `lane-actor-invalid`).
3. **Everything else runs a pinned handler.** A handler document (`schemas/broker/handler` 1.1)
   pins the file's sha256; the broker reads the file once, verifies the digest before *every*
   run, and executes those verified bytes from the run's private directory, with a fixed argv
   (never a shell), the validated params as JSON on stdin, a scrubbed environment, an enforced
   timeout that kills the process group, and size-capped stdout/stderr. Secrets are named in the
   handler document and resolved at run time for that process only; they never appear in a
   request, an approval or the audit trail, and are redacted from captured output.
4. **Approvals are bound to the request digest and single use.** An action that requires approval
   (always for execute and privileged tiers) is submitted, stored `pending` and announced with a
   `decision.requested` event (through the events bus when one is configured, an outbox
   directory otherwise) and an optional state-diffed notification. An approver from the
   manifest's `approvers` approves or denies it; the approval names the request digest, so a
   request edited after approval no longer matches. Self-approval and unlisted or agent approvers
   are refused by the same `decide()` rules, for a denial as well as an approval. Running
   consumes the approval through a durable store (an exclusive-create marker per approval id),
   so it is single use across processes and restarts. A `decision.returned` event records the
   approver's verdict.
5. **State is files, one per fact, created exclusively** (ADR-0014): requests, the single claim
   that moves a request out of `pending` (run, cancel or deny: of any racing pair exactly one
   wins), results, approvals, consumed-approval markers and the audit trail, one record per file,
   each validating against `schemas/broker/audit`. No lock and no database: any number of broker
   processes can share one state directory.
6. **Every outcome is audited**: ok, denied, invalid, error and shadow, with the machine reason,
   the request id and digest, and the arguments with secret ones redacted and large ones reduced
   to a size and digest. In `shadow` mode the broker decides and audits but runs nothing.
7. **`hnx broker`** validates a manifest (schema, handler digests, lanes) and drives the service
   locally: `submit`, `status`, `run`, `cancel`, `approve`, `deny`, `pending`, `audit`. The CLI's
   `--as` is an asserted identity; it is the local and development path.

Stage 1 (this record) is the engine. **Stage 2** adds what an agent fleet needs to use it
remotely, and is deliberately not here: a transport (a unix-socket or HTTP API whose caller
identity is authenticated, e.g. peer credentials or a front-door token, instead of asserted), an
MCP tool server exposing the granted actions to agents, approvals through the front door with SSO
identities, an "Approvals" page on the status hub (pending, approve, deny, audit tail), and a
migration path from a vault `proposed/` lane: map each current writable zone to a lane, each
approval-gated job to an action with a pinned handler, run the broker in `shadow` beside the
guard hook to compare decisions, then cut over.

## Consequences

- An agent's power is the manifest: a reviewer reads one file to know what each profile can do,
  and a change to it is a reviewed change. A handler edit without a digest update fails
  `hnx broker validate` and is refused at run time.
- The escape attempts the old pattern defended by command parsing (`..`, absolute paths,
  symlinks, clobbering, oversized writes) are refused structurally and tested one by one.
- Approvals no longer depend on a file being in the right directory; they name what they approve
  and are consumed exactly once.
- Until stage 2, callers are named rather than authenticated: the broker is a policy engine for
  a process that already knows who is calling (an embedding program, an operator's shell).
  Deployments must not expose the CLI to agents as a substitute for the transport.
- Exec handlers are single self-contained files run from the state directory, which must not be
  mounted `noexec`. Lane writes and handler runs leave files the operator owns; retention of the
  state directory (audit, runs) is an operator decision.

## Alternatives

- **Keep the guard hook and the writable zone**: rejected; deciding by parsing shell is
  incomplete by construction, and a directory boundary does not bind an approval to content.
- **Run actions through the workflow executor only**: workflows already use the broker decision
  as a step; they need the same engine underneath, not a second one.
- **A database for state**: correct but heavier than the problem; exclusive-create files give
  the same single-winner guarantees, survive restarts, and stay readable with ordinary tools.
- **Let agents write files directly and audit afterwards**: detection after the fact cannot undo
  a write outside the lane; the lane refuses before writing.
