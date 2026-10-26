---
summary: 'The registers of lessons, runbooks and invariants: uids, one file per record, the record format, links, events, status changes and lessons as backlog.'
summary_of: outline:sha256:5c3a61233c7a5e2c
---
<!-- SPDX-License-Identifier: Apache-2.0 -->
# Registers: lessons, runbooks and invariants

The registers are the lab's written knowledge: what went wrong and why (lessons), the correct
ordered way to do a job (runbooks), and the properties that must stay true (invariants). Lessons
and runbooks are **one Markdown file per record**; invariants stay **one YAML file**.

```
examples/registers/
  lessons/<uid>.md ...         one lesson per file (pitfalls and practices): prose + stable fields
  lessons/<uid>.events/        its append-only events, one file each (reviews, recurrences, ...)
  runbooks/<uid>.md ...        one runbook per file (and <uid>.events/)
  aliases.yml                  legacy code -> uid (LL-001 -> ...), written by the uid migration
  invariants.yml               the machine checks `hnx invariants run` executes
examples/review-policy.yml     which reviews each artefact needs (shared with docs/systems/)
```

```
hnx registers build examples/registers build/registers   # validate (fatal) and render HTML + JSON
hnx registers links examples/registers/lessons [--check]  # regenerate / check the Links blocks
hnx registers review examples/registers [--today D] [--strict] [--json]   # what the review owes
hnx registers summaries examples/registers docs [--json]   # summary lint (ADR-0032)
hnx registers split lessons.yml lessons/ | join lessons/ lessons.yml     # convert either way
hnx reviews digest examples/registers/lessons/<uid>.md   # the digest a review must carry
hnx reviews digest lab/modules/<id>   # a fetched module's tree digest (docs/modules.md, "Supply chain")
hnx registers events add lessons/<uid>.md event.yml   # validate, then append one event
hnx registers events migrate examples/registers/lessons docs/systems   # inline state -> events
hnx registers decide examples/registers RECORDS_ROOT --as human:operator [--dry-run]
hnx ids check-lost | check-dupes | check-uids                          # make ids-check
hnx records uid | numbers examples/registers | assign-uids TREE...     # identity (ADR-0019)
```

The strategy-to-task records (objectives, measures, requirements, RFIs; [strategy](strategy.md),
[[strategy]]) use this same machinery: one Markdown file per record named for its uid, sidecar
events, `check-lost`, review tiers, and intents applied by a decider.

## Identity: uids, and numbers that are computed

Every record is identified by its `uid`, a UUIDv7 created with the record and never changed
([ADR-0019](adr/0019-record-uids-computed-numbers.md), [[adr/0019-record-uids-computed-numbers|ADR-0019]]).
Links, `related`, `superseded_by`, `incorporated_into`, a runbook's `lessons`, `from_lessons`, sidecar directories,
graph nodes (`lesson:<uid>`) and intents use it. **No number is stored**: the number a record is
shown with (`LL 3`, `RB 1`) is its position among its siblings -- all lessons, or all runbooks --
sorted by the optional `order` field (a number) and then by uid (creation order), computed by
`homelabnext.identity.numbers` wherever a record is shown (the register pages, `hnx registers
review`, `hnx records numbers`, the MCP server, the graph's node `label`). Adding or reordering a
record changes what is shown; it never touches another record, a link or a file name, and two
authors who each add a lesson never collide. `hnx records uid` prints a new uid.

Records written before uids carried a numbered `id` (`LL-001`) and were migrated with
`hnx records assign-uids examples/registers` (idempotent: a second run changes nothing). The
migration recorded every old code in `aliases.yml`; a legacy code met outside the repository (an
intent filed earlier, `hnx graph related lesson:LL-001`, an MCP call) resolves through it on read
with a `LegacyRecordCode` deprecation warning, while a code inside a record is a validation error.
A customization's `links` are stricter: the migration rewrites them, and a code `aliases.yml` does
not hold or has retired is an error there ([customizations](customization.md#links)).
A tombstone of the numbered era (a file holding only `id:` and `retired: {reason, replaced_by}`)
did not become a record: its code is in the `retired:` block of `aliases.yml` with the
successor's uid, so an old citation of it still lands on the successor.

## Why one file per record

A single-file register makes concurrent authors collide: both read "the next free id", both
append, and the merge either renumbers by hand or fuses two entries into one record that silently
deletes the other. With one file per record named for its uid two authors never touch the same
file and never claim the same key, and `check-lost` catches a deleted record file. What machines append to
a record (reviews, recurrences, verification runs, status changes) is not in the record file at
all but in one file per event beside it (see "Events and derived state"), so an agent adding a
review and a person editing the prose in Obsidian never touch the same file either.

Invariants stay one file on purpose: they are short machine checks (statement, observable,
expected, remediation) with no prose body, the runner reads them as one document, seventy of them
run in CI and their ids are cited from the checklist, docs and code. Splitting them would buy
nothing an editor needs and would move every citation. Their ids are the checklist's row ids
(chosen to match a row, never allocated), so they keep them.

## A record file

Front-matter holds the structured fields (Obsidian shows them as properties); the long prose
fields are named `## Heading` sections; the `## Links` block is generated. A complete example,
`examples/registers/lessons/<uid>.md` (shown as `LL 5`):

```markdown
---
uid: 01a15e4e-758c-7315-892d-68b45030268f
type: lesson
title: Measure certificate lifetime from the client side
summary: Judge a certificate by what a client is served (connect and read notAfter), not by the renewal job's exit code or log.
kind: practice
status: active
date: 2026-10-19
author: unknown
systems: [proxy, tls]
applies_to: [openssl, tls]
review_by: 2027-04-19
verification:
  observable: openssl s_client -connect proxy.lab.example:443 ... | openssl x509 -noout -checkend 1209600
  expected: exit 0 while the served certificate has 14 days or more left
related: [01a15e4e-758c-7311-82ff-6357fd41e8c8]
---

## Method

Check what a client is actually served (connect, read notAfter) instead of trusting the renewal
job's own exit code or log.

## Rationale

A renewal that fails quietly looks exactly like one that worked from the server side.

## Links

<!-- hnx:gen:links -->
- Applies to: `openssl`, `tls`
- Systems: [[systems/proxy|proxy]], [[systems/tls|tls]]
- Related: [[01a15e4e-758c-7311-82ff-6357fd41e8c8]]
<!-- /hnx:gen -->
```

Rules the parser enforces (fatally, all problems at once):

* the record has a canonical `uid` (lowercase UUIDv7) and `type: lesson` or `type: runbook`;
  the file is named for its uid (`<uid>.md`); a name that disagrees with the uid fails, and so do
  two files with one uid, a numbered `id:` (run `hnx records assign-uids`) and two records with
  one `order`;
* every line of the body is inside a `## ` section; a section heading must be one the kind knows,
  once; a prose field is never in the front-matter (fenced code may contain `##` lines);
* prose fields (sections) are compared without surrounding whitespace, the only normalization;
* a runbook's steps are the `## Steps` section, a numbered list in which each item carries its own
  `- verify:` line and optionally `- from_lessons: [[<uid>]]` (the lesson the step came from); a
  runbook may also name the lessons it was written from as a whole in its front-matter,
  `lessons: [<uid>, ...]` (lesson uids only: a legacy `LL-NNN` code is refused, and every uid must
  name a lesson of the register);
* the `## Links` block is a function of the record's own front-matter only (`systems`, `related`,
  a runbook's `lessons`, `applies_to`, and an `Archive:` line for an inactive record), links written `[[<uid>]]` with no
  number or title, so editing, retitling or renumbering one record never makes another stale. `make check` fails while one is stale; `hnx registers links DIR` rewrites it.

* `summary:` (optional, ADR-0032) is one line of at most 160 characters with no control or
  invisible format character (Unicode Cc, Cf, Zl, Zp, Cs; an ordinary no-break space is fine): the record's level 0, which the MCP server's `context_for` serves instead of the
  content ([MCP server](mcp.md), [[mcp]]). Write it for a reader deciding whether to open the
  record; it is content, so it is in the review digest and a review covers it. A malformed one
  fails the validation and `hnx registers summaries` (part of `make registers`); a record or
  docs page **without** one fails the lint too. A docs page carries one in its front-matter the
  same way.
* `summary_of:` (docs pages only, machine-owned) is the freshness stamp of an **authored** page
  summary: `outline:sha256:<first 16 hex of the SHA-256>` of the page's heading outline, one
  `<level> <cleaned title>` line per heading in order, front matter and body text excluded
  (`levels.outline_digest`). The lint fails a page whose digest differs from `summary_of`, or that
  has none, naming the page: reread the summary, then run
  `python3 -m homelabnext.registers summaries --restamp <path>`. Editing body text without
  touching a heading never triggers it. `--restamp PATH...` rewrites only that one line (every
  other byte is kept, the file is re-parsed to prove it) and refuses a page with no authored
  summary; `--restamp-all PATH...` exists only for a migration. A **generated** summary
  (`summary_generated: true`) is exempt, because its generator's `--check` keeps it current.
  **Register records are exempt too**: a record is structured fields, not a heading outline, its
  summary is part of its review digest, and any change to the record already invalidates its
  reviews, so a second stamp would add nothing.
  **Limits of the digest:** it sees headings only. A page with no headings always matches (its
  digest never changes), and headings past the parse bound (1 MiB or 100,000 lines of body, as
  `levels.parse` reads) are not seen, so a rename there does not make the summary stale. Headings
  inside code fences, HTML comments and raw `<pre>`/`<details>` blocks do not count. A quoted
  `"summary":` key is handled by `--restamp`; a symbolic link, a path with `..`, a register
  record or a front matter that does not parse (a duplicate key) is refused, and `--restamp`
  with several paths writes all of them or none. `summary_of` is a machine key of the system-page
  review digest (like `summary_generated`), so restamping never invalidates a human review.

Sections: a pitfall has Symptom, Contributing factor, Root cause, Preventive control, Open reason,
Notes; a practice has Method, Rationale, Retired reason, Notes; a runbook has Purpose and Steps.

`homelabnext.registers.load_register(path, kind=None, *, active_only=False) -> dict` reads either
a record directory or a legacy single YAML file and returns the register document the validators
take (`{"lessons": [...]}`); everything in the code base reads registers
through it. `active_only=True` drops retired, incorporated and superseded lessons and superseded
runbooks: what the graph and context packs read.

Opening `examples/registers/` as an Obsidian vault shows records linked to each other (`[[<uid>]]`
in `related`, a runbook's `lessons` and steps' `from_lessons`, resolving to `<uid>.md`) and to their systems
(`[[systems/proxy|proxy]]`).

## Events and derived state

Beside each record (and each `docs/systems/<service>.md` page) is a sidecar directory
`<RECORD>.events/` holding one small YAML file per event
(`schemas/registers/register_event.schema.json`, `homelabnext/registers/events.py`):

```
lessons/<uid>.events/
  20261019T000000Z-review-agent-example-checker.yml
  20261019T000001Z-review-agent-example-auditor.yml
  20261020T093000Z-verified-agent-example-checker.yml
  20261020T093000Z-verified-agent-example-checker-2.yml   # same second, same writer: -2
```

| event | fields | derives |
|---|---|---|
| `review` | the review entry (`by kind role date verdict digest note`) | `reviews` (inline first, then events in order) |
| `recurrence` | `by date note evidence` (pitfalls only) | `recurrences` = inline base (0 when absent) + one per event |
| `verified` | `by date outcome (pass/fail) result evidence` | `last_verified` = the latest passing run (never written by hand) |
| `transition` | `by date from to set intent requested_by reason` | the status (base status + every applied transition, in order) |
| `value` | `by date value-or-finding observed_at sample definition_digest definition_version evidence` | `values`, a strategy measure's readings ([strategy](strategy.md)); not content |

* A name is `<UTC YYYYMMDDTHHMMSSZ>-<event>-<actor slug>[-<n>].yml`; files are created
  exclusively (an existing name is an error, never an overwrite) and the next `-<n>` is taken
  when another writer got the same second. Events are never edited; a correction is a new event.
* The loader computes the derived fields, so `load_register` returns the same document as before
  and the graph, packs, context, MCP, review and render code read it unchanged. Event files are
  not graph nodes.
* A recurrence and a transition are content (they are in the review digest); a verification run
  and a review are not. A transition whose `from` is not the status at that point, a misnamed or
  invalid event, or a sidecar without its record fails the build.
* `hnx registers events migrate DIR...` moves inline `reviews:` / `recurrences:` into events,
  losslessly (the loaded document is deep-equal before and after, or nothing is written), and
  re-running it finishes an interrupted run without duplicates.

Who writes what: people and agents write record files (prose, stable fields) and event files
(`review`, `recurrence`, `verified`); **only the decider writes `transition` events**.

### Writing through the library

`homelabnext.registers.write`: `write_record(path, doc)`, `write_event(record, event)`,
`write_events(...)` (a batch) and `write_register(dir, files)` (a whole new directory, used by
`split`) validate with the build's fatal rules against the register as it will be (every record,
every event, the sibling register, the invariants and the review policy's identity rules), then
write atomically (`homelabnext.state.atomic_write_text`). Invalid content is refused and nothing
is written. The review-tier requirement is opt-in there (`require_reviews=True`): an edit or a
recurrence legitimately creates review debt that a later review event pays, and the build still
fails until it is paid. `hnx registers events add RECORD EVENT.yml` is the command form.

### Status changes: intents and the decider

Nobody edits `status` to move a record through its lifecycle. An agent files an intent through
the records library (`homelabnext.records`, inbox lane), a note of `type: register-transition`
with `record`, `from`, `to`, `reason` and the field the target needs (`retired_by`,
`incorporated_into` or `superseded_by`; optionally `retired_on`, default the day it was created --
not `on`, which YAML 1.1 reads as `true`: a note with a non-string key is invalid). `hnx registers decide` (library:
`homelabnext.registers.transitions.TransitionDecider`) takes each one under a lock:

* `from` is not the current status (another intent got there first): **denied** with that reason;
* the record would be invalid after the change: **denied**, naming the problems;
* the policy's tiers for the target are not met by current reviews of the *prospective* content:
  **waiting** (the note stays in the inbox; the output prints the digest reviewers must stamp),
  so a transition needing a human approve waits for a current human `approve` review event;
* the note does not validate: **invalid** (it stays in the inbox for its agent to fix or withdraw;
  a malformed note, of this type or any other, never stops the other intents);
* otherwise **applied**: a `transition` event, then the note moves to `decided/completed/` (via
  approved), each move with its audit sidecar.

Two conflicting intents (both retiring one lesson with different `retired_by`): the first decided
applies, the second is denied. A crash between the event and the moves (or between the two moves,
leaving the note in `decided/approved/`) is finished, not re-decided, on the next run. It is a command, not a service: run it by hand, from CI or from a timer.

## Lessons are backlog: kinds and lifecycle

A lesson is knowledge not yet built into the system. It is meant to graduate and stop being a
standalone lesson, and the regular review drains that backlog:

* **pitfalls graduate into mechanisms** (an invariant, a test, a gate: `retired_by`);
* **practices graduate into procedures** (a runbook step or a system page: `incorporated_into`).

| kind | statuses | required |
|---|---|---|
| `pitfall` (a problem) | open -> partial -> controlled -> **retired** | symptom, contributing factor, root cause (not a person), a control (or `open_reason` while open), a falsifiable `verification`, `recurrences`; `controlled` needs `review_by`; `retired` needs `retired_by` and `retired_on` |
| `practice` (a method that works) | active -> **incorporated** / superseded / retired | `applies_to` (technologies, products, versions or system tags), a Method; `active` needs `review_by`; `incorporated` needs `incorporated_into`; `superseded` needs `superseded_by` (another practice); `retired` needs a Retired reason and `retired_on` |

`retired_by` names an invariant id of `invariants.yml` (`M-17`), a repository path (a test or a
lint: `tests/registers/test_register_records.py`) or `make:<target>`, and every name must resolve.
A controlled pitfall may name a `retired_by` candidate early; the review suggests retiring it as
soon as that mechanism holds. `incorporated_into` names a runbook's uid, `<uid>#1` (step 1) or
`docs/systems/<service>.md[#use|verify|failure]`, which must exist, and the runbook step should
cite the practice back with `from_lessons` (a missing back-reference is a warning). Runbooks
carry `review_by` (methods and tools change) and may be replaced with `superseded_by`.

Graduated and replaced records stay as files, because their uids are cited and `check-lost` still
guards them; they render under **Archive** on the generated pages and in their own Links block.
In `examples/registers/`, `LL 2` ("Two authors took the same lesson number") is the worked example
of a retired pitfall (retired by M-17, M-16 and the record tests) and `LL 4` of an incorporated
practice (into step 1 of `RB 2`); `hnx records numbers examples/registers` lists their uids.

## Reviews

Every lesson and runbook (and every docs/systems page) has an `author:` (`unknown` only for the
backfilled examples) and reviews, each one a `review` event file in its sidecar (an inline
`reviews:` list still loads, as the base the events add to), shared model in
`homelabnext/reviews.py`:

```yaml
# lessons/<uid>.events/20261019T000000Z-review-agent-assessment-lead.yml
event: review
by: agent:assessment-lead        # issuer:subject
kind: agent                      # agent | human
role: check                      # check | audit | approve
date: 2026-10-19
verdict: pass                    # pass | changes | reject
digest: sha256:3f9a0c41e2b7      # `hnx reviews digest FILE` (a prefix of >= 12 hex digits)
note: optional one line or a link to the evidence
```

* identities are normalized and compared like the broker's approvals
  (`homelabnext.broker.qualified_identity`); the author never reviews their own record;
* roles: `check` (an agent confirms the record is correct and complete), `audit` (an independent
  agent audit that looks for what is wrong, missing or unproven), `approve` (a human signs off);
* an `audit` review comes from a different agent than every `check` review;
* `challenge`, the role's earlier name, is a deprecated alias: a file that still says it is read
  as `audit` with a warning (never a failure); write `audit`;
* a requirement's `min` counts distinct reviewers (normalized identities), not reviews;
* a `human` review must be by a `kind: human` reviewer in the policy's allowlist; an agent identity
  (an `agent:` issuer, or an allowlist entry of `kind: agent`) in a human slot fails;
* a review counts only while its `digest` matches the record's current content (every field but
  `uid`, `order`, `reviews` and `last_verified`, with the events applied; the Links block is not
  content, and moving a record with `order` is not an edit), and only with `verdict: pass`. A
  `rekey` event (written only by the uid migration, `by: hnx:migrate`) carries the reviews of the
  digest before the identity rewrite to the digest after it. Editing a record
  after review makes its reviews stale; there is no date to forget to bump. `last_reviewed` is
  derived (the latest current passing review) and shown on the pages.

`examples/review-policy.yml` says, per artefact kind and state, what a status needs. The defaults:
an open or partial pitfall needs nothing (recording a problem is never blocked); a controlled
pitfall, an active practice and an active runbook need an agent check and an agent audit
review; retiring a pitfall, and incorporating or superseding a practice, also need a human
approve. A record whose status lacks what the policy requires fails the build, naming the
missing tier. The policy is validated fatally: every artefact kind lists every state.

These checks prove the files are consistent, not who typed them; authenticated sign-off is the
broker's approval flow.

## The review: `hnx registers review`

```
$ hnx registers review examples/registers --today 2027-05-01
[registers] lesson review as of 2027-05-01: 5 item(s) due
[registers] incorporate:
[registers]   LL 5 Measure certificate lifetime from the client side: candidate runbook(s) RB 1; incorporated will need human approve
[registers] update:
...
[registers] keep:
[registers]   LL 3 Backup job silently skipped a new guest: review_by 2027-01-17; still unsolved: work it, or bump review_by
```

Actions, in this order: **review** (the status needs reviews it lacks, by tier), **retire** (a
controlled pitfall whose `retired_by` already holds: every invariant it names passes in
`invariants.results.json`), **incorporate** (a due practice, with the runbooks sharing its tags
as candidates), **supersede** (a due practice with a newer one for the same technology),
**update** (a due practice with nowhere to go, or a due runbook), **keep** (a due pitfall that
cannot graduate yet: work it or bump `review_by`). `make check` prints it as a warning and never
fails on it; `--strict` exits 1 while anything is due, and `--json` is for agents.

## Adding a lesson

1. Get a uid (`hnx records uid`) and create `examples/registers/lessons/<uid>.md` (copy an
   existing record of the same kind) with `uid: <uid>` and `type: lesson`. Never write a number:
   the one it is shown with is computed (`order:` places it among the others, if it matters).
2. Fill the front-matter and the sections the kind needs; run
   `hnx registers links examples/registers/lessons` to write its Links block.
3. `hnx registers build examples/registers build/registers` must pass. A new pitfall can be
   committed `open` with no reviews; a status that claims more needs the reviews the policy
   names, stamped with `hnx reviews digest <file>` and written as review events
   (`hnx registers events add`).
4. Commit and open a pull request. Nothing is allocated at merge time: the uid is the record's
   identity for good, so two pull requests adding a lesson each never collide.

A runbook is the same with `runbooks/<uid>.md` and `type: runbook`. Never delete a record: a
lesson that is solved is retired, not removed, and `check-lost` refuses a commit in which a
record of the parent commit has vanished.
