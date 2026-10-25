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
| exec | a handler document in `handler_docs` (`schemas/broker/handler` 1.2) | the pinned handler file, digest-checked before every run |
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
  - name: proposals              # proposal.file -> <data-root>/records/inbox/<date>-<agent>-<slug>-<tag>.md
    kind: records-inbox
    root: records
    per_actor: false
    max_bytes: 65536
    note_types: [proposal]
```

Params: a `files` lane takes `{name, content}`; a `records-inbox` lane takes
`{note, body?, slug?}` where `note` is the records frontmatter. The broker binds
`requesting_agent` to the caller, sets `created` from its own clock (a note that names its own
`created` is refused: `lane-created-set`), validates the note against `schemas/records/note` and
names the file by the records convention, so an agent cannot file a note as someone else or under
someone else's name. The name is `<date>-<agent>-<slug>-<tag>.md`: `tag` is 8 hex characters of a
keyed hash (under the broker-held key in the state directory) of the caller, the date and the
slug. Profile slugs can prefix each other (`triage`, `triage-lead`), so without it `triage` could
file `<date>-triage-lead-weekly-report.md` first and leave `triage-lead`'s own proposal
`lane-exists`; with it, every agent's names are its own, and the same caller filing the same slug
the same day gets the same name again (`lane-exists`), so a retry files nothing twice. A caller's
`slug` is at most 51 characters (the tag takes the rest of the records convention's 60). A filed
proposal emits `proposal.created`, best effort: the note is filed first, and an event that
cannot be queued is audited `outbox-failed` (operation `notify`) without failing the call.

What a lane refuses, each with its audit reason: a name that is not one plain segment or does not
match the pattern (`lane-name-invalid`), a symlinked or non-directory component on the way
(`lane-path-escape`), a target that is a symlink (`lane-symlink`), an existing file when the lane
does not say `overwrite: true` (`lane-exists`), content over `max_bytes` (`lane-too-large`),
content of the wrong shape or failing its schema (`lane-content-invalid`), a note naming another
agent (`lane-identity-mismatch`) or its own `created` (`lane-created-set`) and a per-actor lane with a caller that is not `profile:<slug>`
(`lane-actor-invalid`). Lane roots live under the broker's **data root** (`--data-root`, default
`<state>/lanes`); point it at the directory the agents' memory, findings and records live in.
Run **one broker process, on one host, per data root and state directory.** The lane quotas, the
shares and the write rates are counted under a `flock` on the lane directory, and on NFS or CIFS
a `flock` is a local lock that other hosts never see (it does not fail; it just is not shared),
so two brokers on two hosts over one data root can overshoot a quota together. Within one host,
the pending-quota check and the open-page state are kept per process as well (the page state is
also read from the notifier's store), so a second process over the same state directory (a `serve`
plus an in-process CLI) can exceed `pending_per_actor` by one and page twice; it never loses a
page or runs a request twice, since claims and approvals are exclusive files.

Each lane directory has a quota (manifest 1.5): `max_files` (default 4096) and `max_total_bytes`
(default 64 MiB, the new file included) for the directory a write lands in, the agent's own for a
`per_actor` lane and the shared one otherwise. A write past either is refused
`lane-quota-exceeded` (a replaced file of an `overwrite` lane counts once). The count and the
write happen under an exclusive `flock` on the directory, so concurrent writers cannot overshoot
it together. Without the quota an agent could add uniquely named files until the disk, by default
the audit trail's disk, was full.

A shared lane (`per_actor: false`, such as the proposals inbox every agent files into) also gives
each actor a share of it (manifest 1.6): `max_files_per_actor` and `max_bytes_per_actor`, default
an eighth of the lane's quotas. A records-inbox file is an actor's by its name, whose agent segment
and broker-keyed tag only that actor's writes produce; a shared `files` lane keeps who wrote each
name in an owner index. And a lane bounds each actor's writes in time: `max_writes_per_hour`
(default 120 on a shared lane, none on a per-actor one), refused `lane-rate-exceeded`. The owner
index and the write times live in `<state>/lanes-ledger/`, never in a lane directory, and are
read and written under the lane directory's `flock`. Two lanes whose roots are one directory, or one inside the other, are
refused by `hnx broker validate`: each would keep its own quota, share and rate over the same
files.

**Append-only lanes.** A lane nothing ever deletes from, such as `findings` (one note per run,
even when clean), outgrows any file cap: 4096 files last about 22 months at 6 runs a day and under
six for an hourly agent, and then every `finding.write` is refused, which under the Hermes rules
reads exactly like a failed run. Give such a lane `max_files: null` (no file cap, manifest 1.6), a
generous `max_total_bytes` and a `max_writes_per_hour`; `examples/broker/manifest.production.yml`
sets `findings` so. Before pointing `--data-root` at an existing tree, look at what is already
there: `hnx broker validate MANIFEST --data-root DIR` prints each lane directory's files and bytes
against its quota and warns at 80%, and `hnx broker serve` logs the same at start. When a write
is refused `lane-quota-exceeded`, the operator is notified once per actor and lane (through the
broker's notifier: "Broker lane quota reached"), and "cleared" once that actor's directory is
back under 80% of its quotas (its share, in a shared lane) -- not on the next small write that
fits -- with at least 15 minutes between two notices for one actor and lane, so a lane at its
edge cannot flap. The usage rows of a shared lane also show each actor against its share
(`validate` attributes an inbox's files by the agent their names carry; `serve` verifies each
name's tag; `validate --state DIR` reads a shared files lane's owner index). Without
the share, one looping agent filled the inbox's quota in under a minute and every other agent's
proposal was refused `lane-quota-exceeded` until someone moved notes out.

## Exec handlers

A handler document pins the file and says how to run it:

```json
{"action": "service.restart", "handler": "handlers/service-restart.sh",
 "handler_digest": "sha256:...", "tier": "execute", "requires_approval": true,
 "params_schema": {"type": "object", "properties": {"grace_s": {"type": "integer"}}},
 "timeout_s": 30, "argv": [], "secrets": ["DEMO_API_TOKEN"], "max_output_bytes": 65536,
 "description": "...", "idempotent": true, "audit": true}
```

A handler document (1.2) may also carry `result_schema`: a JSON Schema object describing the
handler's `output` once decoded as JSON. The broker checks only that it is a valid 2020-12 schema
when it loads the document (a malformed one refuses the manifest, naming the file); it does **not**
enforce it at call time, and an output that does not match is returned unchanged. It describes only the success case (exit 0,
not truncated, stdout valid JSON); text output, truncation and a non-zero exit are the CM-5 runner's
to define, and the generated type does not cover them yet. Runtime checking
belongs to the CM-5 runner (`docs/codemode.md`). `hnx codemode gen` types the method's result from it.

The broker validates `params` against `params_schema`, reads the handler once, checks its sha256
against `handler_digest` (refusing with `handler-digest-mismatch`), and runs exactly those bytes
from `<state>/runs/<request id>/` as `[handler, *argv]`, with the params as JSON on stdin, an
environment of only `PATH`, `LANG`, `HOME`/`TMPDIR` (the run directory), `HNX_BROKER_ACTION`,
`HNX_BROKER_REQUEST_ID`, `HNX_BROKER_ACTOR`, `HNX_BROKER_TARGET` and the declared secrets. The
timeout kills the handler's process group; stdout and stderr are kept up to the cap in the run
directory. A non-zero exit is `handler-failed`, a timeout `handler-timeout`, and an I/O error on
the way (the run directory, the private copy, the kept output: a full disk, a descriptor limit)
`handler-io-error`; each is the run's outcome record and its result, so an approved run never
reads `running` after it has ended. The caller gets the reason, never the handler's own error
text. JSON on stdout is the action's result.

**Secrets** are named, never passed. The default resolver reads `HNX_BROKER_SECRET_<NAME>` from the
*broker's* environment and hands the value to that one handler as `<NAME>`; an embedding program
can pass `resolve_secret=` (for example a lookup in the secrets capability). A value never appears
in a request, an approval or the audit trail, and is replaced by `<redacted>` in captured output,
as are its trivially derived forms: JSON-escaped (with and without `\uXXXX` escapes),
percent-encoded and base64. That redaction is a backstop: **a handler must never print a
secret**, because any other transformation of it (a substring, a hash, another encoding) is not
recognised.

After editing a handler, update its digest:

```sh
python -c "from homelabnext.broker.execute import file_digest as d; print(d('examples/broker/handlers/service-status.sh'))"
hnx broker validate examples/broker/manifest.yml
```

## Approvals

1. `submit` of an action that needs approval stores the request `pending` and emits
   `decision.requested` (to `<state>/outbox/`, which `hnx broker relay` publishes to the bus:
   [Publishing events](#publishing-events-the-outbox-relay); an embedded broker given a `bus`
   publishes directly), plus
   an optional notification through the state-diffed notifier. With `--approvals-url URL` (or
   `HNX_BROKER_APPROVALS_URL`; an `http(s)` page URL without credentials, query or fragment, e.g.
   `https://status.lab.example/approvals`) the event carries `link` = `URL?request=<id>` and the
   notification ends with `Review: <link>` (ntfy also gets it as `Click`).

   Accepted work is bounded per agent (manifest 1.5 `quotas`): an actor may have at most
   `pending_per_actor` requests pending at once (default 20; a `submit` past it is refused
   `too-many-pending`, audited, and counts as a refusal for the rate limit), and its approval
   requests page the approver only while the actor has no open page, and at most once per
   `notify_window_s` (default 300 s; 0: no floor). A page is open once the notifier has sent it
   (a failed send opens nothing) and until its request settles; it is for the actor's oldest
   request awaiting approval and names every one of them, so a request filed while a page is
   open is named on the next page (it is on the Approvals page and in its event at once). What is
   due is derived from state, not remembered: every agent with a request awaiting approval and
   no open page is paged as soon as its floor allows, checked at start (a restart loses no page),
   by a timer, and on every submit, settle and pending listing. A page whose send failed, or
   that the agent's budget held back, is tried again a minute later. An approval or a denial closes the page with a settled
   message saying how many still wait, and the oldest of those is paged next; a cancel by the
   owner closes it quietly. An approval that expires unused puts its request back to waiting and
   pages it again. Every message about an agent draws on that agent's own notifier budget, so
   one agent cannot spend the pages of every other. A looping agent can therefore neither flood
   the approver's phone (a submit/cancel loop pages once per floor) nor bury one malicious
   request among hundreds, nor make one page-silent.
2. An approver listed in the manifest's `approvers` runs `approve` or `deny`. The approval document
   (`schemas/broker/approval`) names the request digest and expires after `approval_ttl_s`
   (default 900 s). Self-approval, an unlisted approver and an agent approver (unless
   `allow_agent_approvers`) are refused by the same rules for a denial as for an approval.
   `decision.returned` records the verdict and who decided: `tier_used: human` for a person,
   `agent` for an approver of kind agent (or one naming a granted profile) under
   `allow_agent_approvers`, so a consumer that acts on a person's approval (StackStorm's A03) can
   tell them apart.

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
`decisions/` (an index of the trail's filed approvals and denials, so the hub's recent-decisions
read never walks the refusals; rebuilt once for an older state directory),
`outbox/` (the events still to publish, each with its place in emit order from the
`flock`-guarded counter `outbox.seq`; the broker removes one once the relay is done with it),
`relay/` (the relay's own: `delivered/`, `undeliverable/`, `quarantine/`, `relay.lock`,
`initialized`; [Publishing events](#publishing-events-the-outbox-relay)), `runs/<request>/` and
`digest.key`.

**Audit before execute.** An action that executes (a `call`, an approved `run`) first writes an
`outcome: started` record (audit 1.2), and the broker refuses to execute it, answering
`audit-unavailable`, when that record cannot be written (a full disk, an unwritable `audit/`): an
action never runs without a record of it. For a `run` the record is written before the claim, so
the request stays `pending` and its approval unused, to run once the trail can take it. The
operation's own record (`ok`, `denied`, `error`) completes it; when that one cannot be written
the caller gets `audit-incomplete` and the `started` record is the evidence that the action ran.
A run then ends `error` (reason `audit-incomplete`); when not even its result can be written it
reads `interrupted`, as does a run whose claiming process (the claim's `pid`) is gone. An
interrupted request never runs again (its approval was consumed with the claim): check the target
and the trail, and submit a new request if the action is still needed. `hnx broker audit
--outcome started` lists the intents; the contract's `audit()` view lists outcomes only.

Keep it owned by the broker's user, `0700`, or `0710` with the outbox relay's group when the relay
runs as its own user ([Publishing events](#publishing-events-the-outbox-relay)): then `outbox/` is
`2750` in that group (its files are `0640`) and `relay/` belongs to the relay; every other
subdirectory and file stays `0700`/`0600`, the broker's only. Agents get no access to it.

## Running the service

`hnx broker serve` runs the broker on a Unix-domain socket. Who is calling is the **peer's uid**,
read from the kernel (`SO_PEERCRED`, Linux), and mapped through the manifest
(`schemas/broker/manifest` 1.5; example: `examples/broker/manifest.production.yml`):

```yaml
dev_identity: false                       # the CLI's asserted --as is refused (absent = false)
callers:                                  # an agent's system user -> the one profile it acts as
  - {user: hnx-agent-triage, profile: profile:triage}
  - {uid: 2002, profile: profile:reader}
approval_relays:                          # a process that authenticated a person, for one issuer
  - {user: hnx-hub, issuer: sso}
refusal_limit: {max: 60, window_s: 60}    # refused requests per peer per window (the default)
quotas: {pending_per_actor: 20, notify_window_s: 300}   # accepted work per agent (the defaults)
```

**Notifications from `serve`.** `hnx broker serve` pages approval requests (see
[Approvals](#approvals)) and the lane-quota notices through ntfy when it has a topic:
`$HNX_BROKER_NOTIFY_TOPIC`, `--notify-topic-file FILE` (or `$HNX_BROKER_NOTIFY_TOPIC_FILE`), or
`--notify-topic TOPIC`, which is visible to every user in `ps` (if the ntfy server lets anonymous
readers subscribe, the topic is a secret: use the file or the environment). The endpoint is the
`notify` capability (`--registry services.yml`, else `HNX_ENDPOINT_NOTIFY`), never a literal. The
access token is a secret reference, `--notify-token` (or `HNX_BROKER_NOTIFY_TOKEN`) naming
`secret:broker/ntfy-token`, whose value is read at send time from the environment variable it
names (`HNX_SECRET_BROKER_NTFY_TOKEN`, from a systemd credential or env file); a literal token is
refused. `serve` resolves the endpoint and checks the variable at start, and refuses a plaintext
`http` endpoint to another host when a token would cross it, so a notifier that could never send
stops it instead of failing every page; a send that fails later is logged at WARNING (at most
every five minutes) and audited `notify-failed`. State lives in `<state>/notify.json` (a settled
request's page is dropped from it); each agent may send 20 messages an hour on its own budget,
and all agents together 60 an hour. Without a topic there are no notifications, and a lane-quota
refusal is logged at WARNING once per agent and lane instead.

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

Refusals are rate limited per peer: a caller or an unknown peer with more than
`refusal_limit.max` refused requests (any answer but `ok`, whatever its kind: an unknown action,
a malformed request, `unknown-caller`, `not-pending`, `too-many-pending`, a failed handler, ...;
only the broker's own faults are not counted: `internal-error`, `busy`, `audit-unavailable`,
`audit-incomplete`, `secret-unavailable`, `handler-spawn-failed`, `handler-timeout`,
`handler-io-error` and `lane-io-error`, so a secret-store outage or a full disk never
rate-limits a healthy agent) within `refusal_limit.window_s` seconds (manifest 1.4;
default 60 per 60 s) is answered `rate-limited` for the rest of the window, without its request
being parsed. The limit is audited **once per peer and window** (`operation: connect`,
`reason: rate-limited`) and the number of requests it suppressed is logged when the window ends,
so a looping or hostile agent can fill neither the audit trail nor the disk. Approval relays are
exempt, as they are from the connection cap.

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
StateDirectoryMode=0710
ExecStartPre=+/bin/chgrp hnx-broker-clients /run/hnx-broker
ExecStartPre=+/bin/chgrp hnx-broker-relay /var/lib/hnx-broker
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

### Publishing events: the outbox relay

The broker never talks to the bus while it decides. Every event it emits (`decision.requested`,
`decision.returned`, `proposal.created`; source `svc:broker`, `BROKER_SOURCE` in
`homelabnext.broker.relay`) is written to `<state>/outbox/<event id>.json` with its place in emit
order, and `hnx broker relay`, a second process under **its own user**, publishes it
(`homelabnext.broker.relay`). A bus outage therefore delays events and never blocks or fails a
decision, and `hnx broker serve` keeps needing no network at all.

* **In order, at least once.** Each pass publishes the oldest undelivered events (at most
  `--batch`, default 100) one after another, as `<prefix>.<event type>` with the event id as the
  JetStream message id (`Nats-Msg-Id`). Emit order is `queued`, the next value of the persisted
  counter `<state>/outbox.seq`, taken and the outbox file linked under one `flock`: an event
  becomes visible only after every earlier one did, and no clock is involved. An event is marked
  delivered (`relay/delivered/<event id>.json`, a copy of the event with its stream sequence) only
  after the PubAck; a failure that can pass ends the pass, so nothing overtakes an event that
  failed. One relay per state directory (`flock` on `relay/relay.lock`; a second one exits 2).
* **The relay reads `outbox/` and writes only `relay/`.** The broker removes an outbox file once
  `relay/` holds a marker for it (at start and at most once a minute while emitting), so `outbox/`
  holds what is pending and a pass costs O(pending), not O(history); the marker is the copy.
  Delivered markers older than `--retain-days` (default 30) are removed once their outbox file is
  gone. Event ids are unique per emission (the broker's dedupe key names the request or the
  approval), so a removed marker is never needed again; an outbox file written later under a
  removed id would be published again as a new message.
* **Poison never stalls it.** An outbox file that is not an event (not JSON, no id or not its
  file name, no type, a bad `queued`) is quarantined: a record in `relay/quarantine/` (file name,
  reason, time; never its content) and a log line, then skipped; so is a file the relay cannot
  read (`unreadable`: a permission, a directory). A publish the bus refuses for the event itself
  (a permission violation, an invalid subject, a body over `max_payload`) is retried with backoff;
  after `--max-attempts` (default 5; counted in `relay/attempts.json`, so `--once` on a timer
  counts across runs) the event goes to `relay/undeliverable/` and the events after it are
  published. **That breaks per-stream order for
  that event, on purpose**: it will never be delivered, and holding every later decision behind it
  forever turns one bad event into an outage; consumers see a gap, never a reordering of the
  events they do get. If three events in a row end up undeliverable with nothing published in
  between, the bus refuses everything (its ACL or stream is wrong, not the events): the relay
  stops skipping and holds, `state` `fail`. The hold is recorded (`relay/holding`), so a restart
  keeps holding instead of giving up another three events; the first event published clears it. A
  transport failure (no connection, no PubAck, no responders: JetStream restarting or electing a
  leader answers nothing for a while) never makes an event undeliverable.
  `hnx broker relay --state DIR --skip <event id>` marks one by hand (no bus needed; it takes the
  relay lock, so stop the relay first, then start it again). Quarantined and undeliverable records keep `state` at `fail` until the operator
  deletes them (after the broker has pruned the outbox file).
* **The first start supersedes history.** Outbox files from before `queued` (the bare event,
  written by a broker that had no relay) would replay old decisions. A first start (no
  `relay/initialized`) with such files refuses (exit 2) without `--since TIME`: older ones are
  marked `superseded` in `relay/delivered/` and never published, newer ones are published in
  order (before every current event: by `time`, whole seconds, then id).
  `--since 1970-01-01T00:00:00Z` publishes them all.
* **A crash is a duplicate, not a loss.** A relay that dies between the PubAck and the marker
  republishes the same id on restart, and the stream's `duplicate_window` answers with the
  original sequence. Past that window the bus stores it twice; consumers dedupe by event id anyway
  (the StackStorm runtime's `admit` remembers ids for a day). Make the window at least as long as
  you expect a relay to stay down after a crash. The window is the stream's (set when it is
  provisioned); the target's `duplicate_window` is what the relay requires of it, and a stream
  whose window is shorter is refused at start (exit 2), never silently weaker.
* **Backoff.** A refused connection or a missing PubAck drops the connection and waits 1 s,
  doubling to `--backoff-max` (60 s), before retrying the same event.
* **Nothing secret logged.** Logs and the `--stats-file` (written atomically, a `poll-file` status
  source: `pending` (counted by name, nothing parsed), `published`, `undeliverable`,
  `quarantined`, `holding`, `consecutive_failures`, `last_error`, `state` `ok`/`warn`/`fail`)
  name event ids, types and exception classes only, never a body, an endpoint or a credential.
* `--once` publishes what is pending and exits 0, or 1 when something is still pending (the bus is
  down). A batch that was all quarantined does not end it early. Exit 2 is a configuration error (the target file, the adapter, the lock).

The bus comes from a **target file** binding the `events` capability, the same files
`hnx conform run` uses (`compose/lab-in-a-box/broker/events-relay.yml` is the lab's); `--stream` and
`--subject-prefix` name the standing stream (never a scratch one), the endpoint is
`HNX_ENDPOINT_EVENTS` (`nats://` or `tls://`), and the bus credential is a secret *name*. The
password goes only over `tls://` (verified against the system CAs, or `ca_file`) or to a loopback
`nats://`; any other `nats://` endpoint is refused unless the target sets `allow_plaintext: true`
(the lab-in-a-box does, on its own network). A `tls://` client does the TLS handshake before it
reads anything (nats-py's `tls_handshake_first`; nats-py 2.7 or later): a client that waits for
the server's `INFO` to ask for TLS sends its `CONNECT`, password included, in clear to a server (or
a man in the middle) that does not ask. So the server's `tls` block needs `handshake_first: true`
(nats-server 2.10.3 or later), or no `tls://` client can connect:

```text
# nats-server.conf (excerpt)
tls {
  cert_file: "/etc/nats/server.pem"
  key_file: "/etc/nats/server-key.pem"
  handshake_first: true
}
```

The target file:

```yaml
# /etc/hnx-broker-relay/events-target.yml
name: broker-events
capabilities:
  events:
    adapter: homelabnext.conform.adapters.nats_jetstream:make
    config:
      user: hnx-broker
      password_secret: secret:events/broker   # read from HNX_SECRET_EVENTS_BROKER when connecting
      ca_file: /etc/hnx-broker-relay/events-ca.pem  # the bus's CA (tls:// endpoint)
      client_name: hnx-broker-relay
      duplicate_window: 86400.0
```

**The relay is its own user.** It holds a network connection and a bus credential, so it gets
nothing else of the broker's: it may traverse the state directory and *read* `outbox/` (through
its group), and it owns `relay/`. It never sees `approvals/`, `claims/`, the audit trail or
`digest.key`, cannot write an outbox file, and publishes an outbox event only if it passes its
envelope and type schema, carries source `svc:broker` and is a `decision.*` or `proposal.*` type
(anything else is quarantined), so a compromised relay is a compromised bus credential, not a
compromised broker. Once, as root:

```sh
useradd --system --no-create-home --shell /usr/sbin/nologin hnx-broker-relay
install -d -o hnx-broker -g hnx-broker-relay -m 0710 /var/lib/hnx-broker/state
install -d -o hnx-broker -g hnx-broker-relay -m 2750 /var/lib/hnx-broker/state/outbox
install -d -o hnx-broker-relay -g hnx-broker -m 2750 /var/lib/hnx-broker/state/relay
# an outbox from an older broker: its files were 0600
chgrp hnx-broker-relay /var/lib/hnx-broker/state/outbox/*.json
chmod 0640 /var/lib/hnx-broker/state/outbox/*.json
```

(`outbox/` is setgid, so the broker's new files get the relay's group; `relay/` is setgid in the
broker's group, which only needs to *see* the relay's markers to remove the outbox files the
relay is done with.)

```ini
# /etc/systemd/system/hnx-broker-relay.service
[Unit]
Description=homelab-next broker outbox relay (outbox -> event bus)
After=network-online.target hnx-broker.service
Wants=network-online.target

[Service]
User=hnx-broker-relay
Group=hnx-broker-relay
StateDirectory=hnx-broker-relay
Environment=HNX_ENDPOINT_EVENTS=tls://events.lab.example
EnvironmentFile=/etc/hnx-broker-relay/relay.env   # HNX_SECRET_EVENTS_BROKER=...
ExecStart=/opt/hnx/bin/hnx broker relay --state /var/lib/hnx-broker/state \
  --events-target /etc/hnx-broker-relay/events-target.yml \
  --stream HOMELABNEXT --subject-prefix lab \
  --stats-file /var/lib/hnx-broker-relay/stats.json
Restart=on-failure
RestartSec=5
NoNewPrivileges=yes
ProtectSystem=strict
ReadOnlyPaths=/var/lib/hnx-broker/state/outbox
ReadWritePaths=/var/lib/hnx-broker/state/relay
InaccessiblePaths=/srv/agents /run/hnx-broker
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6

[Install]
WantedBy=multi-user.target
```

It needs the `nats` extra (`pip install 'homelabnext[nats]'`). The relay's environment holds only
the bus credential; the broker's handler secrets stay in `hnx-broker.service`. A first start over
an outbox from before the relay needs `--since` once (see above).

**The bus ACL is what makes the source mean something.** A consumer that pins `source:
svc:broker` (the StackStorm bridge, A03's approved-run rule, A01) trusts a field the publisher
writes. Only the broker's NATS user may publish `<prefix>.homelabnext.decision.>` and
`<prefix>.homelabnext.proposal.>`; no other user may, or any process on the bus can forge an
approval for A03 to act on. The lab-in-a-box enforces exactly this
([`compose/lab-in-a-box/config/nats/nats.conf`](../compose/lab-in-a-box/config/nats/nats.conf),
stream `HNXLAB_BROKER`, prefix `hnxlab`; for production substitute your stream, prefix and
passwords, ideally bcrypt hashes from `nats server passwd`), and its broker scenario proves it
(the `bus-acl` step). Every user has an allow-list and nothing else: no `$JS.API.>` wildcard (so
no `STREAM.PURGE`, `STREAM.UPDATE`, `STREAM.DELETE` or `MSG.DELETE`), no `STREAM.CREATE` for the
relay or the bridge (an operator provisions both streams with limits; the relay connects with
`provision=False` and refuses a missing or unbounded stream), and replies on the user's own inbox
prefix (`_INBOX.<user>`, the adapter's default for a `user`), never a shared `_INBOX.>` where one
client could read another's replies. The broker's relay and the bridge, verbatim from the lab
(`tests/compose` fails when this excerpt and the lab drift apart):

```text
# compose/lab-in-a-box/config/nats/nats.conf (excerpt: account HNX, the relay and the bridge)
[
{"user": "hnx-broker", "password": $LAB_EVENTS_BROKER_PASSWORD,
 "permissions": {
   "publish": {"allow": ["hnxlab.homelabnext.decision.>", "hnxlab.homelabnext.proposal.>",
                         "$JS.API.STREAM.INFO.HNXLAB_BROKER",
                         "$JS.API.STREAM.INFO.HNXLAB_BROKER_DLQ"]},
   "subscribe": {"allow": ["_INBOX.hnx-broker.>"]}}},
{"user": "hnx-st2-bridge", "password": $LAB_EVENTS_ST2_BRIDGE_PASSWORD,
 "permissions": {
   "publish": {"allow": ["$JS.API.STREAM.INFO.HNXLAB_BROKER",
                         "$JS.API.STREAM.INFO.HNXLAB_BROKER_DLQ",
                         "$JS.API.CONSUMER.INFO.HNXLAB_BROKER.st2-agent-job-failed",
                         "$JS.API.CONSUMER.CREATE.HNXLAB_BROKER.st2-agent-job-failed.hnxlab.homelabnext.agent.job.failed",
                         "$JS.API.CONSUMER.MSG.NEXT.HNXLAB_BROKER.st2-agent-job-failed",
                         "$JS.ACK.HNXLAB_BROKER.st2-agent-job-failed.>",
                         "$JS.API.CONSUMER.INFO.HNXLAB_BROKER.st2-decision-returned",
                         "$JS.API.CONSUMER.CREATE.HNXLAB_BROKER.st2-decision-returned.hnxlab.homelabnext.decision.returned",
                         "$JS.API.CONSUMER.MSG.NEXT.HNXLAB_BROKER.st2-decision-returned",
                         "$JS.ACK.HNXLAB_BROKER.st2-decision-returned.>",
                         "$JS.API.CONSUMER.INFO.HNXLAB_BROKER.st2-proposal-created",
                         "$JS.API.CONSUMER.CREATE.HNXLAB_BROKER.st2-proposal-created.hnxlab.homelabnext.proposal.created",
                         "$JS.API.CONSUMER.MSG.NEXT.HNXLAB_BROKER.st2-proposal-created",
                         "$JS.ACK.HNXLAB_BROKER.st2-proposal-created.>"]},
   "subscribe": {"allow": ["_INBOX.hnx-st2-bridge.>"]}}}
]
```

The lab's other users: `hnx-lab-admin` (the operator: `STREAM.INFO`/`STREAM.CREATE` of the stream
and its DLQ, `STREAM.MSG.GET` of the stream; it provisions them, with
`homelabnext.conform.adapters.nats_jetstream.provision_streams`, and reads back what the relay
published), and `hnx-conformance` in an account of its own (`CONFORM`), where `hnx conform run
events` creates and deletes its scratch streams without any way to reach the `HNX` account's
subjects or streams. No client connects without a user.

### Agents: the MCP tools

`hnx broker mcp --socket PATH` (extra `homelabnext[mcp]`) is a stdio MCP server for one agent. It
connects to the socket as its own process, so the agent acts as the profile its system user maps
to and **no tool takes an identity**. Tools: `broker_actions` (what you may do: each action's tier,
kind, parameters and whether it needs approval, derived from the manifest by `decide()` itself),
`broker_call`, `broker_submit`, `broker_status`, `broker_run`, `broker_cancel`, `broker_pending`
(your own pending requests), and the lane shortcuts `memory_write`, `finding_write` and
`proposal_file`. A refusal is a tool error `refused (REASON): MESSAGE`.

An agent's MCP client configuration, started under the agent's own user, is generated from the
[MCP catalog](mcp-catalog.md) ([[mcp-catalog]]), never written by hand:
`hnx mcp catalog render --spec examples/mcp/clients/claude-code.yml` writes
`examples/mcp/clients/claude-code/broker-agent.mcp.json` for the example profile
`profile:broker-agent` (granted `hnx-broker`, `hnx-catalog` and an instance of `notes`), and
`make mcp-check` fails when it drifts. Its `hnx-broker` entry:

<!-- hnx:mcp-render examples/mcp/clients/claude-code/broker-agent.mcp.json hnx-broker -->
```json
{
  "hnx-broker": {
    "args": [
      "broker",
      "mcp",
      "--socket",
      "/run/hnx-broker/broker.sock"
    ],
    "command": "hnx",
    "type": "stdio"
  }
}
```

A compiled agent profile grants it as `hnx-broker` in `grants.mcp`; its catalog record
(`examples/mcp/hnx-broker.yml`) classes each tool, `exec` being the worst a broker action can be,
so a reader profile cannot hold it. What the agent may actually do is still the
broker manifest's grant for its profile. See also [MCP server](mcp.md) ([[mcp]]).

### The CLI against a running broker

Every request command takes `--socket PATH` (or `$HNX_BROKER_SOCKET`) and then asks the running
broker instead of opening the state: `actions`, `call`, `submit`, `status`, `run`, `cancel` and
`pending --mine` act as this process's mapped profile (`--as` is a usage error), `approve`/`deny`
`--as ISSUER:SUBJECT` need this process to be a relay, and `pending` and `audit` list for a relay.
`status` is the owner's full view: the request, its state and verdict, its result, and every
approval filed for it, each with `approver_kind` (`human`, `agent`, or null when the approver is no
longer in the manifest), judged against the manifest when asked. That, not an event's `tier_used`,
is what StackStorm's approved-run rule (A03) trusts ([stackstorm.md](stackstorm.md)).

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
| original date | `created`, `date` (a bare date is midnight UTC): kept as provenance `created:<timestamp>`; the filed note's `created` is the broker's clock | the filename's leading date, else the file's mtime |
| `affects`, `related` | the same keys, when valid | dropped and reported |
| `provenance` | `inputs`: `imported-from:<file>`, `requested-by:<original agent>`; `source`: the importing caller | - |
| slug | the original agent's name, then the filename after its date (and that name) | the agent's name, then the title |

`requesting_agent` is never carried over: the broker binds it to the caller doing the import (with
`--socket`, the importer's mapped profile; without it, `--as`, only under `dev_identity`), so an
import cannot file a note as another agent; the original requester survives as provenance.
`status` is dropped (the broker keeps state). A `completion-request` or any other non-proposal
`type` is skipped and reported (close those with the records lifecycle). Every other key is listed
as unmapped. Filenames come from the day of the import and the slug, so a second `--apply` the
same day reports `lane-exists` and adds nothing (a re-run on a later day files the queue again:
run `--apply` once, after a clean dry run); the slug keeps the original agent's name, so two
agents' proposals with the same title get two files, and two source files that would still share
one name are a `conflict` (the second is not filed). Exit status 1 when any file could not be mapped or
filed, or conflicts. A
suggested order: run the broker in `shadow` beside the guard hook, import the queue, point the
agents at the MCP tools, then remove the agents' write access to the old directory.

## Testing

| Layer | What runs | Where |
|---|---|---|
| unit | the engine, lanes, exec handlers, the socket server (peer map, refusals, modes), the CLI, the outbox (emit order across processes and a clock stepped back; `test_broker_outbox.py`), the outbox relay (ordering, a lost PubAck, a crash before the mark, the bus down, poison and malformed files, `--skip`, the first start, pruning; `test_broker_relay.py`), the MCP tools in memory and over stdio, the hub's Approvals page against a real `hnx broker serve` | `tests/broker/`, `tests/status/test_approvals.py` (`pytest`, every pull request) |
| scenario, local processes | `compose/lab-in-a-box/broker_e2e.py`'s scenario against a broker socket, a hub subprocess, the agent's `hnx broker mcp` behind a real MCP stdio client and `hnx broker` CLI calls, all as the test's uid (the broker maps each process to a distinct uid by the role it was started with) | `tests/compose/test_lab_broker_e2e.py` (every pull request, with the `mcp` extra) |
| end to end, real uids | the same scenario in the lab-in-a-box: the broker (`hnx-broker`, no network, `manifest.production.yml`), the hub (`hnx-hub`, the relay) and the edge in three containers sharing the socket volume; the edge also runs the broker's outbox relay as its own user, `hnx-broker-relay`, with only the broker's `outbox/` (read-only) and its own `relay/` mounted, against the lab's NATS JetStream (`events`) | the nightly smoke's `broker` check; locally `make lab-broker` (or `make lab-smoke` for the whole lab) |

The scenario's steps, each a line of the report (`broker_e2e.py run --json`, and the smoke's
`broker` check detail):

1. `mcp-tools`: the agent's MCP server lists its tools; `broker_actions` names the profile the
   peer's uid maps to;
2. `memory-write`: `memory_write` lands in `<data-root>/memory/<profile>/`, mode `600`, owned by
   the broker, not the agent;
3. `proposal-file`: `proposal_file` files `records/inbox/<date>-<agent>-<slug>-<tag>.md`, named after the
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
10. `bus-relay` (with a bus: the lab, and the local test over the JetStream wire fake):
    `hnx broker relay --once` as the relay's uid (`hnx-broker-relay`) publishes the request's `decision.requested` and
    `decision.returned`, in that order, with source `svc:broker` and the event id as
    `Nats-Msg-Id`, and a second pass publishes nothing;
11. `bus-acl` (with a bus): a client without a user is refused; the StackStorm bridge's NATS user
    (`hnx-st2-bridge`) tries to publish a forged `decision.returned` for the request with source
    `svc:broker`, `verdict: accept`, `tier_used: human` and is refused by the server (a permission
    violation), as is its `STREAM.PURGE`; the stream's last `decision.returned` is still the
    broker's;
12. `audit`: the relay's `hnx broker audit` holds a record of every step, each with the peer's
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
