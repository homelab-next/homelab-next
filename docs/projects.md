# Projects: project management as a capability

`projects` is the sixteenth capability (ADR-0020): projects, their ordered steps and one-off
tasks, under a few board rules, linked by uid to the strategy records they serve
([strategy.md](strategy.md)). The contract is `conformance/protocols/projects.py`; the reference
implementation keeps one Markdown file per item (`homelabnext/projects/`, `hnx projects`, the
hub's Projects page); OpenProject is the first product adapter
(`homelabnext/projects/openproject/`).

## The model

Everything is a **work item** of one of three kinds:

| Kind | What it is | Statuses |
|---|---|---|
| `project` | multi-step work; its steps are the `step` items that name it, in `order` | `open`, `closed` |
| `step` | one step of a project: the work queue | `blocked`, `todo`, `in_progress`, `done`, `cancelled` |
| `task` | a one-off piece of work; may name a project, need not | the same five |

Every item has:

* a **`uid`**: a UUIDv7 (RFC 9562), its identity. Nothing stores a number. The CLI prints the
  whole uid and the hub page a short form (its last 8 hex digits); wherever the CLI takes an
  item (a REF) it accepts the uid or a unique prefix or suffix of it, at least 6 hex digits
  (dashes ignored).
* a **`version`** that grows by one on every change. `update` must quote the version it read; a
  stale one is a `Conflict` and nothing is written (optimistic concurrency).
* optional `assignee` (`profile:<id>`, `human:<id>` or `agent:<id>`), `due` (a date),
  `description`, `parent` (a step or task of the same project: sub-items) and `external_key` (the
  caller's idempotency key: a second create with it returns the first item).
* when finished (`done`, `cancelled`, a `closed` project): a one-line `result` and the date
  (`closed_on`).
* **links**, always to a uid: `supports`, `serves`, `measures` or `answers` an external record
  (a strategy objective, requirement, measure or RFI), or `blocks` / `precedes` another step or
  task.

### The board rules (each one a MUST of the conformance suite)

1. **Unique identities.** Every item gets its own UUIDv7; an `external_key` names at most one
   item.
2. **A step belongs to an open project.** A step names an existing project; it (or a task that
   names a project) cannot be created in, or reopened in, a closed project. A project with an
   unfinished step or task cannot be closed.
3. **A finished project closes.** When the last unfinished step or task of a project with steps
   reaches `done` or `cancelled`, the project closes in the same write (result: `all N steps
   finished (...)`); a task in the project holds it open like a step does. A finished project
   is not reopened; start a new one.
4. **A finished item says how it finished:** `done`/`cancelled` (and a `closed` project) carry a
   one-line result and the date.
5. **Blocks hold.** An item does not finish while an unfinished item `blocks` it.
6. **Links resolve.** A record link names a uid the strategy seam knows; a dependency names an
   existing step or task; nothing links to itself; `blocks`, `precedes` and `parent` never form
   a cycle.

Plus the feed: `changes_since(cursor)` reports every item changed after the cursor, at least at
its latest version (`None` is a snapshot of every item); each change becomes a
`homelabnext.project.changed` event.

## The Markdown reference (`hnx projects`)

```
<dir>/<uid>.md                            front-matter (the item's fields) + the description
<dir>/.changes/<stamp>-<uid>-v<n>.json    the change journal, one file per change
```

Writes follow ADR-0014's rules for conflict-free files: a new item and every journal entry are
created exclusively (a hard link that fails when the name exists, never an overwrite); an item
file is replaced atomically and only while its stored version is still the one the writer read,
under an `flock` on the directory (no lock file appears in the tree). Journal names are unique
per `(uid, version)`, so two clones merge in git without a conflict; a cursor is the last journal
name read and is complete within one working copy (after a pull, read from a snapshot).

Over `examples/projects` (each line runs as written, in order, in the tests):

```bash
hnx projects list --status blocked
hnx projects show 53a6402b1c8d                    # the project, by a unique suffix of its uid
hnx projects new project "Move the edge proxy" --key edge-move   # the key exists: that project
hnx projects new step "Hand the old guest back" --project 01a15edd-032d --assignee profile:responder
hnx projects link 62fc01d0e24b "OO 1.1" supports  # a display number resolves to the uid
hnx projects close 62fc01d0e24b "edge suite green on the new guest"
hnx projects move 367830786dcb in_progress        # no longer blocked
hnx projects check                                # the board rules over files edited by hand
hnx projects feed                                 # homelabnext.project.changed, JSON lines
```

`feed --cursor C` continues from the cursor a previous `feed` printed on stderr. `check` ends
with `N problem(s) in M item(s) of DIR`; every command but `new` refuses a `--dir` that does
not exist (exit 2) rather than reading an empty board.

`--dir` defaults to `examples/projects` and `--strategy` (the records links may name) to
`examples/strategy`; a lab keeps both in its private repository (ADR-0011). Exit codes: 0 ok, 1 a
rule refused the change or `check` found problems, 2 usage or input error. `make check` runs
`hnx projects check` over the examples.

## The hub page

`hnx status serve --projects DIR [--strategy DIR]` adds **Projects** (`/projects`, menu panel
`projects`, `schemas/status/views.schema.json` 1.6): open projects with their step progress
(done of all, cancelled not counted) and every step's state, date and result; blocked steps and
tasks with what blocks them; and the work linked to each strategy record, by its display number.
Read-only, server-rendered, every value escaped.

## Events

`homelabnext.project.changed` (`schemas/events/project.changed.schema.json`): `uid`, `kind`,
`version`, `op` (`created`, `updated`, `closed`, `linked`, `unlinked`), `status`, `title`,
`project`, `origin` (`markdown` or `openproject`), `ref` (`wp:<id>`) and the `links` as of that
version. The id derives from `<uid>:v<version>` (Markdown) or `wp:<id>:v<lockVersion>`
(OpenProject), so the same version seen twice is one event.

## Strategy records: the seam and the identity

`homelabnext.projects.strategy.strategy_records(root)` is the only reader of the strategy tree:
it yields `{uid, type, title, parent_uid, links}` (plus the display label, status and prose a
mirror shows). It reads the strategy loader of ADR-0019: every record is `<uid>.md` with `uid`,
`type`, `parent` and `order`, linking by uid. `parent_uid` is the cascade (a measure's parent is
the objective it measures); `supports`, `serves` and `raised_by` are the links. Display numbers
(`OO 1.2`) are computed by `homelabnext.identity` from type, parent and order and are never
stored here either: projects link by uid, and `resolve_record` turns a typed display number, or
a legacy code from `aliases.yml` (with a deprecation warning), into the uid. Uids are minted by
`homelabnext.identity.UidGenerator`.

### MOP readings, never MOE

`homelabnext.projects.measures.completion_reading(items, measure)` turns the share of finished
work linked to an objective into a reading for a **MOP** of that objective. Completion is
activity, so a MOE follows the doctrine rule `activity_never_moe` (passed as `doctrine=`, the
shipped doctrine by default): `error` refuses it, `warn` reads it with a warning, `off` reads it.
Nothing here ever changes an objective's status: achievement is a reviewed transition in the
strategy repository.

## OpenProject

Pinned against OpenProject **17.9** (API v3, HAL+JSON). The adapter is a small stdlib client:
the API token is named, never stored (`token: secret:openproject/api-token`, delivered as
`HNX_SECRET_OPENPROJECT_API_TOKEN`), https with verification (plain http only to loopback or with
`allow_plaintext`), same-origin redirects, `offset`/`pageSize` paging, a `lockVersion` on every
`PATCH` (409 is a `Conflict`), retries with exponential backoff on timeouts, 429 and 5xx (a
`POST` or a `PATCH` only when nothing reached the server: a retried `PATCH` that had been
applied would quote a stale `lockVersion` and report the write as a conflict).

```yaml
# openproject.yml (every key but base_url optional)
base_url: https://openproject.example.internal
token: secret:openproject/api-token
strategy_project: strategy      # the read-only Strategy project
work_project: lab               # where projects, steps and tasks live
sync_user: hnx-sync
viewer_roles: [Reader]
```

### How the contract maps

| Contract | OpenProject |
|---|---|
| item | a work package of type `Project`, `Step` or `Task` in `work_project` |
| `uid` | custom field **External key** (Text, filterable) |
| `version` | `lockVersion + 1` |
| project, parent | the work package parent (a step's is its project's work package) |
| status | the status of that name (`To do`, `In progress`, `Blocked`, `Done`, `Cancelled`, `Open`, `Closed`) |
| title, description, due | `subject`, `description`, `dueDate` |
| external key, assignee, result, closed on, order | custom field **hnx state** (Long text, a JSON document; it also carries a digest of the links, so a link change moves `lockVersion` and `updatedAt`) |
| `blocks`, `precedes` | relations of those types |
| `supports`, `serves`, `measures`, `answers` | a `relates` relation to the record's work package in the Strategy project, the label in the relation's description (there are no custom relation types) |

The whole conformance suite passes against this mapping on the recorded fake: `hnx conform run
projects --target projects-openproject` (`conformance/targets/projects-openproject.yml`, the
adapter `homelabnext.conform.adapters.openproject:make`; copy the target with `config:
<openproject.yml>` to run it against a real instance). Each operation reads the work project's work
packages and relations once: right for a lab (tens to hundreds of items), not for a large
instance. A work package made by hand in the UI has no External key; `adopt()` gives it a fresh
uid so it becomes an item.

### Admin setup, once (no API exists for these)

OpenProject 17.9 offers `GET` only for types, statuses and custom fields, and no API at all for
webhooks: an administrator does this once in the UI. `hnx projects doctor --target openproject
--config openproject.yml` checks every item by name and prints the step for each one missing.

1. **Service user** `hnx-sync` and its API token (Admin > API and webhooks: enable API tokens);
   deliver the token as `HNX_SECRET_OPENPROJECT_API_TOKEN`.
2. **Types** (Admin > Work packages > Types): `SO`, `OO`, `TO`, `TT`, `CCIR`, `FFIR`, `PIR`,
   `RFI`, `MOP`, `MOE`, and the work types `Project`, `Step`, `Task`.
3. **Statuses** (Admin > Work packages > Status): `Active`, `Open`, `To do`, `In progress`,
   `Blocked` (open), and `Achieved`, `Retired`, `Answered`, `Expired`, `No-find`, `Done`,
   `Cancelled`, `Closed` with *closed* ticked. Workflows: only the sync role may change the status
   of a strategy type.
4. **Custom fields** (Admin > Custom fields): `External key` (Text, *used as a filter*, for all
   projects) and `hnx state` (Long text); enable both on every type above and in both projects.
5. **Strategy project** (identifier `strategy`): enable the ten strategy types; members other
   than `hnx-sync` get a view-only role (`Reader`); `hnx-sync` gets *edit work packages* and
   *manage work package relations*.
6. **Work project** (identifier `lab`, or a template to copy): enable `Project`, `Step`, `Task`;
   a Status board covers the kanban view (action boards are Community edition since 17.3).
7. Keep **"Allow cross-project work package relations"** on (the default): work relates to
   strategy records across projects.
8. **Webhook** (optional; Admin > API and webhooks > Webhooks): work package created/updated, all
   projects, with a secret delivered as `HNX_SECRET_OPENPROJECT_WEBHOOK_SECRET`. Its target is a private
   address, so set `OPENPROJECT_SSRF_PROTECTION_IP_ALLOWLIST` to the receiver's subnet
   (unverified on a live instance).

### Strategy sync (repository -> OpenProject, one way)

`hnx projects sync-strategy --target openproject --config openproject.yml --dry-run|--apply`
mirrors every strategy record into the Strategy project:

* **upsert by uid**: the work package whose External key is the record's uid is patched (with
  its `lockVersion`), a missing one created; type and status are the record's;
* **cascade and links**: `parent` becomes the work package parent (parents first: an objective's
  parent objective, a measure's objective); `supports`, `serves` and `raised_by` become `relates` relations with the edge name
  in the description; stale ones are removed only between two strategy work packages, never a
  relation to execution work;
* **content hash**: what the sync wrote is hashed into `hnx state`; an unchanged repository makes
  zero writes;
* **repo wins**: a mirrored record edited in OpenProject (it no longer hashes to what was written)
  is written back and reported as `reverted`;
* **never closes on its own**: statuses come from the records; a record gone from the repository
  is reported as an `orphan` and left alone; finished work never moves an objective.

### Change feed (OpenProject -> events)

Webhooks are a hint, not a guarantee: they are sent after the journal aggregation window (5
minutes by default), retried only on timeouts, carry no delete or relation events, and are signed
with an HMAC-SHA1 without a timestamp. So `ChangeFeed.poll(cursor)` reads every work item whose
`updatedAt` moved since the cursor (`<time>|<versions already seen at that second>`, because
OpenProject's times have second precision) and is the completeness guarantee; the webhook
receiver (`make_webhook_server`, loopback by default) refuses any request without a valid
`X-OP-Signature` (401) and hands the payload to the same feed. Both build the same event id from
`wp:<id>:v<lockVersion>`, and the feed emits each id once (claimed under a lock: the webhook
server's threads and the poll run at once). Every event is validated against its schema as it
is built: a work package no valid event describes (an External key typed by hand that is not a
uid, a status with no contract name) is not emitted but noted in `ChangeFeed.problems`. A
strategy work package changed by anyone but the sync user is noted for the next sync to revert.

### Community vs Enterprise

| Need | Edition |
|---|---|
| types, statuses, custom fields, relations, cross-project relations, boards (action boards since 17.3), webhooks, API tokens, LDAP | Community |
| read-only work package status (hard lock) | Enterprise Basic: on Community the permission-isolated Strategy project does the job |
| SSO with OIDC or SAML (an Authentik front door) | Enterprise Professional: on Community use Authentik's LDAP outpost or local accounts |
| the MCP server | Enterprise Professional: agents on Community use the REST API (this adapter) |
| hierarchy custom fields, programs and portfolios, custom project phases | Enterprise |

### Limits

* Setup is not code: the admin steps above, verified by `doctor`.
* The mirror shows strategy prose to everyone with view access to the Strategy project: keep
  OpenProject on the lab network and the project's membership small (ADR-0011).
* Relation-only changes do not move `updatedAt` in OpenProject; the adapter's own link changes do
  (through `hnx state`), one made by hand in the UI shows only at the work package's next change.
* Pin the image to 17.9 and re-run the suite before an upgrade (the API moves monthly).
