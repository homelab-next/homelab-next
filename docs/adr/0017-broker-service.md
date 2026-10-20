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
   and a manifest (`schemas/broker/manifest` 1.2; 1.3 since stage 2a) and passes the conformance
   suite (`conformance/targets/broker-reference.yml`). Default deny: an action that is not listed, a
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

### Stage 2a: authenticated callers (amendment, 2026-10-20)

8. **The transport says who is calling; the request never does.** `hnx broker serve` runs the
   service on a Unix-domain socket (`homelabnext/broker/server.py`, stdlib only) and reads the
   connecting process's uid from the kernel (`SO_PEERCRED`). Manifest 1.3 maps it: `callers`
   (`uid` or `user` -> the one `profile` it acts as) and `approval_relays` (`uid` or `user` ->
   the `issuer` whose humans it vouches for). A peer is listed once, as a caller or a relay, never
   both. An unmapped peer is refused (`unknown-caller`) before a byte of its request is read; a
   body that names an actor (`actor`, `caller`, `as`, `profile`, `uid`, ...) is refused
   (`actor-in-body`). Every audit record written while serving a socket request carries the peer
   as `via` (audit 1.1); refusals made by the transport itself are audited as operation `connect`.
   Platforms without `SO_PEERCRED` (macOS, the BSDs) are unsupported: the server refuses to start
   rather than fall back to asserted identity.
9. **One small protocol, one request per connection.** A JSON object terminated by a newline (or
   the client's end of stream), at most 1 MiB, read within 10 s; one JSON answer; close. A thread
   per connection with a cap (excess connections are answered `busy`); the state directory
   already makes runs, cancels, denials and approval consumption exactly-once.
   `homelabnext/broker/client.py` (`BrokerClient`) is the one client: the CLI's `--socket` mode,
   the MCP server and the hub (stage 2b) use it.
10. **Approvals arrive through a relay, and the relay is not trusted with policy.** `approve` and
   `deny` are accepted only from an approval relay, carrying `approver: {issuer, subject}`, the
   human the relay authenticated; the issuer must be the relay's own. The manifest's approver
   rules then judge that human exactly as before (allowlist, no self-approval, no agent approver).
   Stage 2b's hub page behind the SSO front door is such a relay and needs only the client.
11. **Agents get MCP tools, not a CLI.** `hnx broker mcp --socket PATH` is a stdio MCP server
   (registered as `hnx-broker`, classes `record-write` and `exec`, so the reader rule keeps it
   from profiles that read untrusted content) whose tools are thin requests to the socket:
   `broker_actions` (what this caller may do, derived from `decide()` itself), `broker_call`,
   `broker_submit`, `broker_status`, `broker_run`, `broker_cancel`, `broker_pending`,
   `memory_write`, `finding_write`, `proposal_file`. No tool takes an identity; it is the MCP
   process's uid.
12. **Asserted identity is a development mode.** The CLI's `--as` against the state directory is
   accepted only when the manifest sets `dev_identity: true` (absent means false).

Remote agents do not get a network listener in 2a (nor in 2b). They reach the broker through an
SSH-forwarded socket (`ssh -L LOCAL.sock:/run/hnx-broker/broker.sock`),
where the peer the broker sees is the forwarding `sshd` session's user on the broker host, so
each remote agent logs in as its own system user.

### Stage 2b: people approve through the front door (amendment, 2026-10-20)

13. **The status hub's Approvals page is the approval relay.** `hnx status serve` with an
   `approvals:` block in `agents.yml` (`schemas/status/agents` 1.1: the broker socket, the SSO
   issuer, the approver group) serves `/approvals` (`homelabnext/status/approvals.py`): pending
   requests (action, actor, target, params, created, digest, age), the recent decisions, and
   approve/deny. It speaks to the broker with `BrokerClient` as its own system user, listed in
   `approval_relays`; the approver it names is the configured issuer and the front door's
   username, never anything from the form. The broker judges that person by the manifest's
   approver rules, unchanged.
14. **Same front door, separate grant.** The page reuses the private tier's door
   (`homelabnext/status/agents/auth.py`: trusted proxy address, shared front-door secret header,
   forward-auth identity header) and adds an **approver group** that must differ from the viewer
   group. Viewers may read the queue (its params are as sensitive as the private tier they already
   read); only the approver group may decide.
15. **The hub's one write is guarded as one.** `POST /approvals/decide` only (every other `POST`
   stays `405`); the console's Host/Origin guard, then a same-origin `Origin` (or `Referer`) and no
   cross-site `Sec-Fetch-Site`; a closed form of five fields; a CSRF token, an HMAC over its
   issue time, the request id, the digest shown and the approver, valid 30 minutes, under the key
   `approvals.csrf_key` names in the secret store (agents 1.2: at least 32 characters, not the
   front door's secret; without it a per-process key and a startup warning); and the **digest the person saw** must equal the broker's current digest for the
   request, or the hub refuses. A repeated decision by the same person files nothing ("already",
   from the broker's audit trail). Every attempt is appended to the hub's access log. The generated
   Caddy site already covers every path of the hub's hostname, so the new route needed no edge
   change.
16. **Notifications link the page.** With `--approvals-url` (`HNX_BROKER_APPROVALS_URL`) the broker
   adds `link` (`<url>?request=<id>`) to `decision.requested` and to its notification (ntfy
   `Click`).
17. **A migration path off the vault pattern.** `hnx broker import-proposals DIR` reads a directory
   of proposal Markdown files and files each through the broker as a `proposal.file` lane record
   (dry run unless `--apply`), mapping fields generically and reporting what it could not map;
   `requesting_agent` is bound to the importing caller, the original requester kept as provenance.
   `docs/broker.md` maps the rest: writable zones to lanes, dashboard approval to the hub page, the
   sync job to broker runs, `completion-request` to a records-lifecycle transition.

The page has a menu entry, `panel: approvals` in the private group (views 1.4), listed only
when approvals are configured and only to the private tier's viewers.

Limits of 2b: one form-token key at a time (rotating it invalidates the forms already shown, at
most 30 minutes of them); an approver outside the viewer group sees no private menu group and
reaches the page by its URL or the notification link; and no network listener for remote agents,
who still use an SSH-forwarded socket.

## Consequences

- An agent's power is the manifest: a reviewer reads one file to know what each profile can do,
  and a change to it is a reviewed change. A handler edit without a digest update fails
  `hnx broker validate` and is refused at run time.
- The escape attempts the old pattern defended by command parsing (`..`, absolute paths,
  symlinks, clobbering, oversized writes) are refused structurally and tested one by one.
- Approvals no longer depend on a file being in the right directory; they name what they approve
  and are consumed exactly once.
- Before stage 2a, callers were named rather than authenticated. Since 2a a deployment gives
  each agent its own system user, maps it in `callers` and serves the socket; the CLI's asserted
  identity is refused unless the manifest opts into `dev_identity`. An embedding program that
  calls the service in-process still names its caller and is trusted to.
- Identity is per uid: two agents sharing a system user are one caller. Unknown local peers can
  write audit records (each refusal is one); the socket's mode and group bound who can reach it.
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
- **Approvals in the broker's own web UI**: rejected; the hub already sits behind the SSO front
  door with an access log, and a second authenticated web surface would be a second thing to
  harden. The hub holds no broker state and decides nothing: the broker re-checks everything.
- **An HTTP listener with bearer tokens in 2a**: deferred. A token is a secret every agent must
  hold and could leak; a socket peer credential cannot be copied. People reach the broker through
  the front door (2b), which already authenticates them; remote agents through a forwarded socket.
- **The caller named in the request, checked against a token**: rejected; the body is what an
  injected prompt controls, so it must carry nothing that decides identity.
