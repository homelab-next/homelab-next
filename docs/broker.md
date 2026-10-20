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
tools, and takes approvals from a relay. Approvals through the front door and a hub approvals page
are stage 2b (see the ADR). The CLI's asserted `--as` is the development path, accepted only when
the manifest says `dev_identity: true`.

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
   an optional notification through the state-diffed notifier.
2. An approver listed in the manifest's `approvers` runs `approve` or `deny`. The approval document
   (`schemas/broker/approval`) names the request digest and expires after `approval_ttl_s`
   (default 900 s). Self-approval, an unlisted approver and an agent approver (unless
   `allow_agent_approvers`) are refused by the same rules for a denial as for an approval.
   `decision.returned` records the verdict.
3. The owner runs it. The broker re-decides with the approval, consumes it (an exclusive-create
   marker, so single use across processes and restarts) and runs once. An expired approval leaves
   the request pending for a fresh one; a denied request can never run; a request edited after
   approval no longer matches its digest.

## State

One directory, one file per fact, every file created exclusively (ADR-0014), so several broker
processes share it without locks: `requests/`, `claims/` (the one transition out of `pending`:
run, cancel or deny), `results/`, `approvals/<request>/`, `consumed/`, `audit/` (one record per
file, `schemas/broker/audit`), `outbox/` and `runs/<request>/`. Keep it `0700` and owned by the
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
  (`operation: connect`, `caller: uid:<n>`).
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
group) and the server refuses a directory that is group-writable or open to others, and a file at
the socket path that is not a stale socket. Bounds: one request per connection, at most 1 MiB
(`--max-request-bytes`) read within 10 s (`--timeout`); 32 connections at once, more get `busy`.

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

Stage 2b's hub page (behind the SSO front door) is a relay: it authenticates a person, then
speaks to the socket with `BrokerClient` (`homelabnext/broker/client.py`). The wire format, for a
client in another language:

- connect to the socket as the relay's user; write one JSON object and a newline (or close the
  write side); read one JSON object and a newline; the server closes;
- request `{"v": 1, "op": OP, ...}` with these relay operations:

| op | fields | result |
|---|---|---|
| `pending` | - | `{"requests": [{request_id, action, actor, target, params, created, digest, approved}]}` |
| `approve` | `request_id`, `approver: {issuer, subject}`, `note` (optional, at most 2000 chars) | the approval document (`schemas/broker/approval`) |
| `deny` | as `approve` | the denial document |
| `audit` | optional filters `action`, `caller`, `outcome`, `operation`, `request_id`; `tail` (default 50, 0-500) | `{"records": [...]}` (`schemas/broker/audit`) |

- response `{"ok": true, "result": ...}` or `{"ok": false, "error": REASON, "kind": "Denied" |
  "InvalidArguments" | "BrokerError", "message": TEXT}`.

`approver.issuer` must be the relay's own `issuer` (else `relay-issuer-mismatch`); `subject` is the
person's SSO subject. The broker then applies the manifest's rules to that person:
`approval-approver-not-allowed`, `approval-self-approved`, `approval-agent-approver`. A relay
never runs, submits or reads a request for itself (`not-a-caller`).

### Remote agents

There is no network listener. An agent on another host reaches the broker through the front door
(stage 2b) or an SSH-forwarded socket, logging in as its own user on the broker host:

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
