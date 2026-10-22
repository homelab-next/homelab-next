<!-- SPDX-License-Identifier: Apache-2.0 -->
# Broker service

Agents do not get a shell or a writable directory. They ask the broker for a **named action**; the
broker decides (`allow`, `deny` or `needs-approval`) against a manifest, runs a pinned handler, and
writes one audit record for every outcome. Decision record: [ADR-0017](adr/0017-broker-service.md)
([[adr/0017-broker-service|ADR-0017]]). Contracts: `schemas/broker/`; code: `homelabnext/broker/`;
command: `hnx broker`; capability page: [broker](capabilities/broker.md)
([[capabilities/broker|broker]]).

Stage 1 is the engine; stage 2a (this page's [Running the service](#running-the-service)) puts it
on a Unix socket where the caller is *authenticated* by its peer credentials, gives agents MCP
tools, and takes approvals from a relay. Stage 2b puts people's approvals behind the front door:
the status hub's [Approvals page](#front-door-approvals) is that relay, and
[`import-proposals`](#migrating-from-a-vault-proposal-queue) moves a vault-style proposal queue
onto the broker. The CLI's asserted `--as` is the development path, accepted only when the
manifest says `dev_identity: true`.

## What an action can be

| Kind | Declared by | Runs |
|---|---|---|
| lane write | `handler: builtin/lane`, `lane: NAME`, tier `write` | the built-in lane writer: one file into the lane |
| exec | a handler document in `handler_docs` (`schemas/broker/handler` 1.1) | the pinned handler file, digest-checked before every run |
| in-process | `BrokerService.register(command, fn, args)` + `allow(caller, [command])` | a Python function in the embedding program (the capability contract's API) |

Every call goes through `homelabnext.broker.decide` first: the action is listed, the caller has a
grant naming it, its tier is within the grant's `max_tier`, a handler is declared, and an approval
is present when required (always for `execute` and `privileged`). Anything else is refused.

## Lanes: the limited writes

```yaml
lanes:
  - name: memory                 # memory.write -> <data-root>/memory/<profile>/<name>
    kind: files
    root: memory
    per_actor: true              # the caller's own profile slug; default for files
    filename_pattern: '^[a-z0-9][a-z0-9-]{0,62}\.md$'
    max_bytes: 65536
    format: text                 # or json, with an optional content_schema: <dir>/<name>
  - name: proposals              # proposal.file -> <data-root>/records/inbox/<date>-<agent>-<slug>.md
    kind: records-inbox
    root: records
    per_actor: false
    max_bytes: 65536
    note_types: [proposal]
```

Params: a `files` lane takes `{name, content}`; a `records-inbox` lane takes
`{note, body?, slug?}` where `note` is the records frontmatter. The broker binds
`requesting_agent` to the caller, fills `created`, validates the note against
`schemas/records/note` and names the file by the records convention, so an agent cannot file a
note as someone else or under someone else's name. A filed proposal emits `proposal.created`.

What a lane refuses, each with its audit reason: a name that is not one plain segment or does not
match the pattern (`lane-name-invalid`), a symlinked or non-directory component on the way
(`lane-path-escape`), a target that is a symlink (`lane-symlink`), an existing file when the lane
does not say `overwrite: true` (`lane-exists`), content over `max_bytes` (`lane-too-large`),
content of the wrong shape or failing its schema (`lane-content-invalid`), a note naming another
agent (`lane-identity-mismatch`) and a per-actor lane with a caller that is not `profile:<slug>`
(`lane-actor-invalid`). Lane roots live under the broker's **data root** (`--data-root`, default
`<state>/lanes`); point it at the directory the agents' memory, findings and records live in.

## Exec handlers

A handler document pins the file and says how to run it:

```json
{"action": "service.restart", "handler": "handlers/service-restart.sh",
 "handler_digest": "sha256:...", "tier": "execute", "requires_approval": true,
 "params_schema": {"type": "object", "properties": {"grace_s": {"type": "integer"}}},
 "timeout_s": 30, "argv": [], "secrets": ["DEMO_API_TOKEN"], "max_output_bytes": 65536,
 "description": "...", "idempotent": true, "audit": true}
```

The broker validates `params` against `params_schema`, reads the handler once, checks its sha256
against `handler_digest` (refusing with `handler-digest-mismatch`), and runs exactly those bytes
from `<state>/runs/<request id>/` as `[handler, *argv]`, with the params as JSON on stdin, an
environment of only `PATH`, `LANG`, `HOME`/`TMPDIR` (the run directory), `HNX_BROKER_ACTION`,
`HNX_BROKER_REQUEST_ID`, `HNX_BROKER_ACTOR`, `HNX_BROKER_TARGET` and the declared secrets. The
timeout kills the handler's process group; stdout and stderr are kept up to the cap in the run
directory. A non-zero exit is `handler-failed`, a timeout `handler-timeout`; the caller gets the
reason, never the handler's own error text. JSON on stdout is the action's result.

**Secrets** are named, never passed. The default resolver reads `HNX_BROKER_SECRET_<NAME>` from the
*broker's* environment and hands the value to that one handler as `<NAME>`; an embedding program
can pass `resolve_secret=` (for example a lookup in the secrets capability). A value never appears
in a request, an approval or the audit trail, and is replaced by `<redacted>` in captured output.

After editing a handler, update its digest:

```sh
python -c "from homelabnext.broker.execute import file_digest as d; print(d('examples/broker/handlers/service-status.sh'))"
hnx broker validate examples/broker/manifest.yml
```

## Approvals

1. `submit` of an action that needs approval stores the request `pending` and emits
   `decision.requested` (to the events bus when one is configured, else to `<state>/outbox/`), plus
   an optional notification through the state-diffed notifier. With `--approvals-url URL` (or
   `HNX_BROKER_APPROVALS_URL`; an `http(s)` page URL without credentials, query or fragment, e.g.
   `https://status.lab.example/approvals`) the event carries `link` = `URL?request=<id>` and the
   notification ends with `Review: <link>` (ntfy also gets it as `Click`).
2. An approver listed in the manifest's `approvers` runs `approve` or `deny`. The approval document
   (`schemas/broker/approval`) names the request digest and expires after `approval_ttl_s`
   (default 900 s). Self-approval, an unlisted approver and an agent approver (unless
   `allow_agent_approvers`) are refused by the same rules for a denial as for an approval.
   `decision.returned` records the verdict.

   The allowlist is matched **exactly** on `(issuer, subject)`: write each entry as the approver's
   canonical subject (lower-case, the approval schema's `^[a-z][a-z0-9._-]{0,63}$`), exactly as
   the relay sends it. `operator_one`, `operator.one` and `operator-one` are three different
   accounts at an IdP, and only the one named is accepted. Spellings are folded (case, `.`, `_`
   and whitespace to `-`) only where that refuses more: an approver whose folded subject is the
   requesting profile's name is self-approval, and one whose folded subject names a granted
   profile is an agent.
3. The owner runs it. The broker re-decides with the approval, takes the request's claim, and
   only then consumes the approval (an exclusive-create marker, so single use across processes and
   restarts) and runs once: a run refused on the way (arguments that no longer validate, a lost
   race) leaves the approval unused. An expired approval leaves the request pending for a fresh
   one; a denied request can never run; a request edited after approval no longer matches its
   digest.

`pending` (for a relay) and `pending --mine` report each request's `approval_state`, judged by the
same decision a run gets: `none`, `valid` (it can run now), `expired` (past the TTL: file a fresh
approval), `consumed`, `denied`, `invalid` (no longer matches the request or the approver rules),
or `not-required` (an allowed request, in `pending --mine` only). `approved` is kept as
`approval_state == "valid"`.

A request's digest binds its action, actor, target and params. An argument an in-process command
marks `secret` enters the request (and the digest, which is persisted, audited and sent with
`decision.requested`) as `hmac-sha256:<hex>`, keyed with the state directory's `digest.key`, so
the digest still changes with the value but cannot be used to guess a short secret offline.

## State

One directory, one file per fact, every file created exclusively (ADR-0014), so several broker
processes share it without locks: `requests/`, `open/` (an index of the requests still pending,
so listing them reads only those; rebuilt once for an older state directory), `claims/` (the one
transition out of `pending`: run, cancel or deny), `results/`, `approvals/<request>/`,
`consumed/`, `audit/` (one record per file, `schemas/broker/audit`; a tail is read newest first),
`outbox/`, `runs/<request>/` and `digest.key`. Keep it `0700` and owned by the
broker's user; agents get no access to it.

## Running the service

`hnx broker serve` runs the broker on a Unix-domain socket. Who is calling is the **peer's uid**,
read from the kernel (`SO_PEERCRED`, Linux), and mapped through the manifest
(`schemas/broker/manifest` 1.3; example: `examples/broker/manifest.production.yml`):

```yaml
dev_identity: false                       # the CLI's asserted --as is refused (absent = false)
callers:                                  # an agent's system user -> the one profile it acts as
  - {user: hnx-agent-triage, profile: profile:triage}
  - {uid: 2002, profile: profile:reader}
approval_relays:                          # a process that authenticated a person, for one issuer
  - {user: hnx-hub, issuer: sso}
```

A peer is listed once, as a caller *or* a relay (`hnx broker validate` refuses a peer in both);
user names are resolved when the service starts, and an unknown one stops it. Linux only: macOS
and the BSDs have `getpeereid` instead, which Python does not expose portably, so the server
refuses to start there rather than accept an unauthenticated caller.

- **An unmapped peer** is answered `unknown-caller` before its request is read, and audited
  (`operation: connect`, `caller: uid:<n>`); the server drops only what already arrived, without
  waiting or parsing, and closes.
- **The body never names the actor.** A top-level `actor`, `caller`, `as`, `who`, `profile`,
  `identity`, `uid` or `user` is refused (`actor-in-body`); so is any field the operation does not
  take (`request-invalid`). The broker binds everything to the peer's profile, including the
  `requesting_agent` of a filed proposal.
- **Only a relay approves or denies**, for the human it names; an agent's peer gets
  `not-an-approval-relay`, a relay asking to act gets `not-a-caller`.
- **Every audit record carries the peer** as `via: uid:<n>`.

```sh
hnx broker serve --manifest /etc/hnx-broker/manifest.yml --state /var/lib/hnx-broker/state \
  --data-root /srv/agents --socket /run/hnx-broker/broker.sock \
  --socket-mode 660 --socket-group hnx-broker-clients
```

The socket is created `0600` (or `--socket-mode`, which may grant nothing to others) and owned by
the service user, `--socket-group` its group; its directory is created `0750` (`0700` without a
group) and the server refuses a directory owned by another user (other than root), one that is
group-writable or open to others, and a file at the socket path that is not a stale socket.
Bounds: one request per connection, at most 1 MiB (`--max-request-bytes`) read within 10 s
(`--timeout`, for the whole request, not each read); 32 connections at once for callers, plus 4
kept for approval relays so agents cannot crowd out the hub; more get `busy`.

### A systemd unit

A dedicated user owns the state; each agent runs as its own user in `hnx-broker-clients`; the hub
runs as `hnx-hub`, also in that group.

```ini
# /etc/systemd/system/hnx-broker.service
[Unit]
Description=homelab-next broker (named actions for agents)
After=network.target

[Service]
User=hnx-broker
Group=hnx-broker
SupplementaryGroups=hnx-broker-clients
RuntimeDirectory=hnx-broker
RuntimeDirectoryMode=0750
StateDirectory=hnx-broker
StateDirectoryMode=0700
ExecStartPre=+/bin/chgrp hnx-broker-clients /run/hnx-broker
ExecStart=/opt/hnx/bin/hnx broker serve --manifest /etc/hnx-broker/manifest.yml \
  --state /var/lib/hnx-broker/state --data-root /srv/agents \
  --socket /run/hnx-broker/broker.sock --socket-mode 660 --socket-group hnx-broker-clients
EnvironmentFile=-/etc/hnx-broker/secrets.env
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/var/lib/hnx-broker /srv/agents
ProtectHome=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
```

`/srv/agents` (the lanes' data root) is writable by `hnx-broker` only; agents read their own
memory there if the operator grants it, never write. Handler secrets come from
`HNX_BROKER_SECRET_<NAME>` in the service's environment (here an environment file readable by
root and the service user only).

### Agents: the MCP tools

`hnx broker mcp --socket PATH` (extra `homelabnext[mcp]`) is a stdio MCP server for one agent. It
connects to the socket as its own process, so the agent acts as the profile its system user maps
to and **no tool takes an identity**. Tools: `broker_actions` (what you may do: each action's tier,
kind, parameters and whether it needs approval, derived from the manifest by `decide()` itself),
`broker_call`, `broker_submit`, `broker_status`, `broker_run`, `broker_cancel`, `broker_pending`
(your own pending requests), and the lane shortcuts `memory_write`, `finding_write` and
`proposal_file`. A refusal is a tool error `refused (REASON): MESSAGE`.

An agent's MCP client configuration, started under the agent's own user:

```json
{"mcpServers": {"hnx-broker": {"command": "hnx",
  "args": ["broker", "mcp", "--socket", "/run/hnx-broker/broker.sock"]}}}
```

A compiled agent profile grants it as `hnx-broker` in `grants.mcp`;
`homelabnext/agent/tool_classes.yml` classifies it `record-write` and `exec` (the worst a broker
action can be), so a reader profile cannot hold it. What the agent may actually do is still the
broker manifest's grant for its profile. See also [MCP server](mcp.md) ([[mcp]]).

### The CLI against a running broker

Every request command takes `--socket PATH` (or `$HNX_BROKER_SOCKET`) and then asks the running
broker instead of opening the state: `actions`, `call`, `submit`, `status`, `run`, `cancel` and
`pending --mine` act as this process's mapped profile (`--as` is a usage error), `approve`/`deny`
`--as ISSUER:SUBJECT` need this process to be a relay, and `pending` and `audit` list for a relay.

### Approval relays: the protocol

The hub's Approvals page (behind the SSO front door, [below](#front-door-approvals)) is a relay:
it authenticates a person, then speaks to the socket with `BrokerClient`
(`homelabnext/broker/client.py`). The wire format, for a client in another language:

- connect to the socket as the relay's user; write one JSON object and a newline (or close the
  write side); read one JSON object and a newline; the server closes;
- request `{"v": 1, "op": OP, ...}` with these relay operations:

| op | fields | result |
|---|---|---|
| `pending` | - | `{"requests": [{request_id, action, actor, target, params, created, digest, approved, approval_state}]}` |
| `approve` | `request_id`, `approver: {issuer, subject}`, `note` (optional, at most 2000 chars) | the approval document (`schemas/broker/approval`) |
| `deny` | as `approve` | the denial document |
| `audit` | optional filters `action`, `caller`, `outcome`, `operation`, `request_id`; `tail` (default 50, 0-500) | `{"records": [...]}` (`schemas/broker/audit`) |

- response `{"ok": true, "result": ...}` or `{"ok": false, "error": REASON, "kind": "Denied" |
  "InvalidArguments" | "BrokerError", "message": TEXT}`.

A `pending` row's `approval_state` is what a relay shows and acts on: `none` (show approve and
deny), `valid` (approved, the owner may run it now: no form), `expired` or `consumed` (the earlier
approval can no longer be used: show the form again, a fresh approval is accepted), `invalid`
(the approval no longer matches: show the form). `approved` is `true` exactly when the state is
`valid`; a relay written against the older field keeps working and stops hiding an expired one.

`approver.issuer` must be the relay's own `issuer`, exactly (else `relay-issuer-mismatch`);
`subject` is the person's SSO subject. The broker then applies the manifest's rules to that person:
`approval-approver-not-allowed`, `approval-self-approved`, `approval-agent-approver`. A relay
never runs, submits or reads a request for itself (`not-a-caller`).

### Front-door approvals

`hnx status serve` with an `approvals:` block in its `agents.yml` serves `/approvals`: the requests
awaiting an approver (action, actor, target, params, created, digest, age) and the recent
decisions, with approve and deny for people in the hub's **approver group**. Setup and the full
list of refusals: [status hub](status.md#the-approvals-page-broker-stage-2b) ([[status]]). In
short:

- the hub runs as its own user (`hnx-hub`), listed once in `approval_relays` with the issuer its
  front door authenticates (`sso`); the people who may approve are in the manifest's `approvers`;
- the page reuses the private tier's front door (trusted proxy, shared secret header, identity
  header), then requires the approver group (distinct from the viewer group) to decide;
- the approver sent to the broker is `{issuer: <configured>, subject: <the front door's
  username>}`, never a form field. The username is sent **unchanged**: Authentik's usernames are
  case-sensitive (`Bob` and `bob` may be two accounts), so the hub does not lower-case them, and a
  username that is not already canonical (lower-case, as the approver allowlist names it) cannot
  decide. Name approvers in Authentik in lower case. A username can be renamed by an IdP admin;
  pinning the approver to the IdP's immutable id (Authentik's `X-Authentik-Uid`, passed by the
  front door next to the username) is a recommended follow-up: the hub does not receive that
  header today;
- the form carries the request id **and the digest shown**; the hub refuses (`409`) when the
  broker's current digest differs, so a person approves exactly what they read, and the broker
  binds the approval to that digest again;
- `POST` only, same-origin `Origin`/`Referer`, an HMAC token bound to the request, the digest and
  the approver; a re-submit is answered "already" and files nothing; every attempt is logged.

### Remote agents

There is no network listener. An agent on another host reaches the broker through an
SSH-forwarded socket, logging in as its own user on the broker host:

```sh
ssh -N -L /run/user/1000/hnx-broker.sock:/run/hnx-broker/broker.sock hnx-agent-triage@broker-host
hnx broker mcp --socket /run/user/1000/hnx-broker.sock
```

The peer the broker sees is the forwarding `sshd` process, which runs as the logged-in user, so the
mapping is the same as for a local agent. Restrict that user's SSH key to the forward
(`restrict,port-forwarding,command="/bin/false"` in `authorized_keys`).

## Walkthrough

From a checkout, with the example manifest (`examples/broker/`: one agent profile `triage`, three
lanes, a read-only `service.status` and an approval-gated `service.restart` stand-in). It sets
`dev_identity: true`, so the CLI's asserted `--as` drives it directly:

```sh
export HNX_BROKER_MANIFEST=examples/broker/manifest.yml
export HNX_BROKER_STATE=runs/broker-demo/state HNX_BROKER_DATA_ROOT=runs/broker-demo/data
hnx broker validate "$HNX_BROKER_MANIFEST"

# a lane write: the agent's own memory
R=$(hnx broker submit memory.write --as profile:triage --params '{"name":"queue-notes.md","content":"drains slowly\n"}')
hnx broker run "$R" --as profile:triage          # -> runs/broker-demo/data/memory/triage/queue-notes.md
hnx broker submit memory.write --as profile:triage --params '{"name":"../../x.md","content":"x"}'
                                                  # refused (lane-name-invalid), exit 1

# a read-only handler
S=$(hnx broker submit service.status --as profile:reader --target svc:queue)
hnx broker run "$S" --as profile:reader

# an approval-gated action
P=$(hnx broker submit service.restart --as profile:triage --target svc:queue --params '{"grace_s":30}' | cut -d' ' -f1)
hnx broker run "$P" --as profile:triage          # refused (approval-required)
hnx broker pending
hnx broker approve "$P" --as sso:triage          # refused (approval-self-approved)
hnx broker approve "$P" --as sso:operator-one
HNX_BROKER_SECRET_DEMO_API_TOKEN=fake-demo-token hnx broker run "$P" --as profile:triage

# a proposal into the records inbox
N=$(hnx broker submit proposal.file --as profile:triage --params \
  '{"note":{"title":"Raise the queue drain timeout","risk":"low","rollback":"set it back"},"body":"Seen twice."}')
hnx broker run "$N" --as profile:triage

hnx broker audit --tail 20                        # every outcome above, refusals included
```

`--json` on any command prints machine-readable output; exit status is 0 ok, 1 refused (the reason
is printed), 2 usage error or invalid manifest. `tests/broker/test_broker_cli.py` runs this walkthrough.

## Migrating from a vault proposal queue

The pattern the broker replaces (ADR-0017, "Context") is common enough to have a path off it: a
vault directory where agents may write only into a `proposed/` zone (a guard hook enforcing it), a
dashboard in which a person approves or denies, which moves the file into an `approved/` or
`denied/` directory, a sync job that acts on what was approved, and a `completion-request` note
whose `related:` list closes approved items into `completed/`.

| Vault pattern | Broker |
|---|---|
| a writable zone per agent (guard hook allows writes under `proposed/`, `findings/`, ...) | a **lane** per zone: `proposal.file` (kind `records-inbox`) for `proposed/`, `finding.write` / `memory.write` (kind `files`, per actor) for the others; the guard's allow rules become the manifest's `grants` |
| the dashboard's approve / deny (a file move) | the hub's **Approvals page** (`/approvals`) for actions that need approval: approve/deny bound to the request digest, by a person the front door authenticated |
| the sync job that applies approved items | a **broker run**: each change the job made becomes an action with a pinned handler, `requires_approval: true`; the owner (or a scheduler acting as that profile) runs it once approved, and the approval is consumed exactly once |
| reviewing a proposal note (`proposed/` -> `approved/`) | the records lifecycle ([ADR-0010](adr/0010-records-lifecycle-as-an-api.md)): `homelabnext.records.decider` moves inbox notes into `decided/approved` / `decided/denied` (run it as a different OS user from the broker's lanes) |
| `completion-request` with `related:` | a **records-lifecycle transition**: an agent files a `completion-request` note (its own lane, `note_types: [completion-request]`) and the decider's `complete` moves every `related:` item `decided/approved` -> `decided/completed` |
| the guard's audit / the vault's git history | the broker's audit trail: one record per outcome, refusals included, each with the authenticated peer (`via`) |

**Move the existing queue** with `hnx broker import-proposals DIR`. It reads every `*.md` directly
in `DIR` (front-matter + body), maps each proposal to a `proposal.file` lane record and reports
the rest; it is a dry run unless `--apply`:

```sh
hnx broker import-proposals /path/to/old-vault/proposed                 # dry run: what would be filed
hnx broker import-proposals /path/to/old-vault/proposed --default-rollback "revert the change"
hnx broker import-proposals /path/to/old-vault/proposed --apply --socket /run/hnx-broker/broker.sock
```

| records note | taken from | if absent |
|---|---|---|
| `title` | `title`, `summary`, `subject`; else the body's first `# heading` | not imported |
| `risk` | `risk`, `risk_level`, `severity` (`low`, `medium`, `high`; `med`/`moderate` -> `medium`, `critical` -> `high`) | `--default-risk`, else not imported |
| `rollback` | `rollback`, `rollback_plan`, `backout` | `--default-rollback`, else not imported |
| `created` | `created`, `date` (a bare date is midnight UTC) | the filename's leading date, else the file's mtime |
| `affects`, `related` | the same keys, when valid | dropped and reported |
| `provenance` | `inputs`: `imported-from:<file>`, `requested-by:<original agent>`; `source`: the importing caller | - |
| slug | the original agent's name, then the filename after its date (and that name) | the agent's name, then the title |

`requesting_agent` is never carried over: the broker binds it to the caller doing the import (with
`--socket`, the importer's mapped profile; without it, `--as`, only under `dev_identity`), so an
import cannot file a note as another agent; the original requester survives as provenance.
`status` is dropped (the broker keeps state). A `completion-request` or any other non-proposal
`type` is skipped and reported (close those with the records lifecycle). Every other key is listed
as unmapped. Filenames come from `created` and the slug, so a second `--apply` reports
`lane-exists` and adds nothing; the slug keeps the original agent's name, so two agents' proposals
with the same date and title get two files, and two source files that would still share one name
are a `conflict` (the second is not filed). Exit status 1 when any file could not be mapped or
filed, or conflicts. A
suggested order: run the broker in `shadow` beside the guard hook, import the queue, point the
agents at the MCP tools, then remove the agents' write access to the old directory.

## Testing

| Layer | What runs | Where |
|---|---|---|
| unit | the engine, lanes, exec handlers, the socket server (peer map, refusals, modes), the CLI, the MCP tools in memory and over stdio, the hub's Approvals page against a real `hnx broker serve` | `tests/broker/`, `tests/status/test_approvals.py` (`pytest`, every pull request) |
| scenario, local processes | `compose/lab-in-a-box/broker_e2e.py`'s scenario against a broker socket, a hub subprocess, the agent's `hnx broker mcp` behind a real MCP stdio client and `hnx broker` CLI calls, all as the test's uid (the broker maps each process to a distinct uid by the role it was started with) | `tests/compose/test_lab_broker_e2e.py` (every pull request, with the `mcp` extra) |
| end to end, real uids | the same scenario in the lab-in-a-box: the broker (`hnx-broker`, no network, `manifest.production.yml`), the hub (`hnx-hub`, the relay) and the edge in three containers sharing the socket volume | the nightly smoke's `broker` check; locally `make lab-broker` (or `make lab-smoke` for the whole lab) |

The scenario's steps, each a line of the report (`broker_e2e.py run --json`, and the smoke's
`broker` check detail):

1. `mcp-tools`: the agent's MCP server lists its tools; `broker_actions` names the profile the
   peer's uid maps to;
2. `memory-write`: `memory_write` lands in `<data-root>/memory/<profile>/`, mode `600`, owned by
   the broker, not the agent;
3. `proposal-file`: `proposal_file` files `records/inbox/<date>-<agent>-<slug>.md`, named after the
   peer's profile;
4. `submit`, `run-before-approval`: an approval-gated `service.restart` is pending and
   `broker_run` is refused (`approval-required`);
5. `unknown-caller`: `hnx broker actions` from an unmapped uid is refused before its request is
   read;
6. `agent-cannot-approve`: `hnx broker approve` from the agent's uid is refused
   (`not-an-approval-relay`);
7. `hub-front-door`: `/approvals` without the front-door secret is `403`;
8. `hub-approve`: the edge (the hub's one trusted proxy) reads `/approvals?request=ID` with the
   front-door secret and the approver's identity and groups, takes the form's digest and CSRF
   token, and posts `decision=approve` to `/approvals/decide` with a same-origin `Origin`; `200`;
9. `run-once`, `second-run-refused`: the agent runs it once; a second run is refused
   (`not-pending`);
10. `audit`: the relay's `hnx broker audit` holds a record of every step, each with the peer's
    `via: uid:<n>` (agent, unmapped uid and relay).

## Embedding

```python
from homelabnext.broker.service import BrokerService

broker = BrokerService.from_manifest(
    "manifest.yml",
    "/var/lib/hnx-broker/state",
    data_root="/srv/agents",
    bus=event_bus,
    notifier=notifier,
)
broker.call("profile:triage", "memory.write", {"name": "notes.md", "content": "..."})
rid = broker.submit("profile:triage", "service.restart", {"grace_s": 30}, target="svc:queue")
broker.approve(rid, "sso:operator-one")
broker.run("profile:triage", rid)
```

`hnx conform run broker --target broker-reference` runs the capability suite against it.
