<!-- SPDX-License-Identifier: Apache-2.0 -->
# Registers: lessons, runbooks and invariants

The registers are the lab's written knowledge: what went wrong and why (lessons), the correct
ordered way to do a job (runbooks), and the properties that must stay true (invariants). Lessons
and runbooks are **one Markdown file per record**; invariants stay **one YAML file**.

```
examples/registers/
  lessons/LL-001.md ...        one lesson per file (pitfalls and practices)
  runbooks/RB-001.md ...       one runbook per file
  invariants.yml               the machine checks `hnx invariants run` executes
examples/review-policy.yml     which reviews each artefact needs (shared with docs/systems/)
```

```
hnx registers build examples/registers build/registers   # validate (fatal) and render HTML + JSON
hnx registers links examples/registers/lessons [--check]  # regenerate / check the Links blocks
hnx registers review examples/registers [--today D] [--strict] [--json]   # what the review owes
hnx registers split lessons.yml lessons/ | join lessons/ lessons.yml     # convert either way
hnx reviews digest examples/registers/lessons/LL-002.md   # the digest a review must carry
hnx ids resolve | check-lost | check-dupes | check-placeholders
```

## Why one file per record

A single-file register makes concurrent authors collide: both read "the next free id", both
append, and the merge either renumbers by hand or fuses two entries into one record that silently
deletes the other. With one file per record two authors never touch the same file, ids are
allocated at merge time, and `check-lost` catches a deleted record file.

Invariants stay one file on purpose: they are short machine checks (statement, observable,
expected, remediation) with no prose body, the runner reads them as one document, seventy of them
run in CI and their ids are cited from the checklist, docs and code. Splitting them would buy
nothing an editor needs and would move every citation.

## A record file

Front-matter holds the structured fields (Obsidian shows them as properties); the long prose
fields are named `## Heading` sections; the `## Links` block is generated. A complete example,
`examples/registers/lessons/LL-005.md`:

```markdown
---
id: LL-005
title: Measure certificate lifetime from the client side
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
related: [LL-001]
reviews:
- by: agent:example-checker
  kind: agent
  role: check
  date: 2026-10-19
  verdict: pass
  digest: sha256:...
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
- Related: [[LL-001]]
<!-- /hnx:gen -->
```

Rules the parser enforces (fatally, all problems at once):

* the file is named for its id (`LL-005.md`), or `LL-NEW.md` / `LL-NEW-<slug>.md` until a
  maintainer allocates the number; a name that disagrees with the id fails, and so do two files
  with one id;
* every line of the body is inside a `## ` section; a section heading must be one the kind knows,
  once; a prose field is never in the front-matter (fenced code may contain `##` lines);
* prose fields (sections) are compared without surrounding whitespace, the only normalization;
* a runbook's steps are the `## Steps` section, a numbered list in which each item carries its own
  `- verify:` line and optionally `- from_lessons: [[LL-004]]` (the lesson the step came from);
* the `## Links` block is a function of the record's own front-matter only (`systems`, `related`,
  `applies_to`, and an `Archive:` line for an inactive record), so editing one record never makes
  another stale. `make check` fails while one is stale; `hnx registers links DIR` rewrites it.

Sections: a pitfall has Symptom, Contributing factor, Root cause, Preventive control, Open reason,
Notes; a practice has Method, Rationale, Retired reason, Notes; a runbook has Purpose and Steps.

`homelabnext.registers.load_register(path, kind=None, *, active_only=False) -> dict` reads either
a record directory or a legacy single YAML file and returns the register document the validators
take (`{"lessons": [...], "retired": {...}}`); everything in the code base reads registers
through it. `active_only=True` drops retired, incorporated and superseded lessons and superseded
runbooks: what the graph and context packs read.

Opening `examples/registers/` as an Obsidian vault shows records linked to each other (`[[LL-001]]`,
`[[RB-002]]`, steps' `from_lessons`) and to their systems (`[[systems/proxy|proxy]]`).

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
soon as that mechanism holds. `incorporated_into` names `RB-002`, `RB-002#1` (step 1) or
`docs/systems/<service>.md[#use|verify|failure]`, which must exist, and the runbook step should
cite the practice back with `from_lessons` (a missing back-reference is a warning). Runbooks
carry `review_by` (methods and tools change) and may be replaced with `superseded_by`.

Graduated and replaced records stay as files, because their ids are cited and `check-lost` still
guards them; they render under **Archive** on the generated pages and in their own Links block.
`examples/registers/lessons/LL-002.md` is the worked example of a retired pitfall (two authors
taking one id, retired by M-17, M-16 and the record tests) and `LL-004.md` of an incorporated
practice (into `RB-002#1`).

## Reviews

Every lesson and runbook (and every docs/systems page) has an `author:` (`unknown` only for the
backfilled examples) and a `reviews:` list, shared model in `homelabnext/reviews.py`:

```yaml
reviews:
  - by: agent:j8-lead            # issuer:subject
    kind: agent                  # agent | human
    role: check                  # check | adversarial | approve
    date: 2026-10-19
    verdict: pass                # pass | changes | reject
    digest: sha256:3f9a0c41e2b7  # `hnx reviews digest FILE` (a prefix of >= 12 hex digits)
    note: optional one line or a link to the evidence
```

* identities are normalized and compared like the broker's approvals
  (`homelabnext.broker.qualified_identity`); the author never reviews their own record;
* an `adversarial` review comes from a different agent than every `check` review;
* a `human` review must be by a `kind: human` reviewer in the policy's allowlist; an agent identity
  (an `agent:` issuer, or an allowlist entry of `kind: agent`) in a human slot fails;
* a review counts only while its `digest` matches the record's current content (every field but
  `reviews`; the Links block is not content), and only with `verdict: pass`. Editing a record
  after review makes its reviews stale; there is no date to forget to bump. `last_reviewed` is
  derived (the latest current passing review) and shown on the pages.

`examples/review-policy.yml` says, per artefact kind and state, what a status needs. The defaults:
an open or partial pitfall needs nothing (recording a problem is never blocked); a controlled
pitfall, an active practice and an active runbook need an agent check and an adversarial agent
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
[registers]   LL-005 Measure certificate lifetime from the client side: candidate runbook(s) RB-001; incorporated will need human approve
[registers] update:
...
[registers] keep:
[registers]   LL-003 Backup job silently skipped a new guest: review_by 2027-01-17; still unsolved: work it, or bump review_by
```

Actions, in this order: **review** (the status needs reviews it lacks, by tier), **retire** (a
controlled pitfall whose `retired_by` already holds: every invariant it names passes in
`invariants.results.json`), **incorporate** (a due practice, with the runbooks sharing its tags
as candidates), **supersede** (a due practice with a newer one for the same technology),
**update** (a due practice with nowhere to go, or a due runbook), **keep** (a due pitfall that
cannot graduate yet: work it or bump `review_by`). `make check` prints it as a warning and never
fails on it; `--strict` exits 1 while anything is due, and `--json` is for agents.

## Adding a lesson

1. Create `examples/registers/lessons/LL-NEW-<slug>.md` (copy an existing record of the same
   kind). Write `id: LL-NEW`, never a number.
2. Fill the front-matter and the sections the kind needs; run
   `hnx registers links examples/registers/lessons` to write its Links block.
3. `hnx registers build examples/registers build/registers` must pass. A new pitfall can be
   committed `open` with no reviews; a status that claims more needs the reviews the policy
   names, stamped with `hnx reviews digest <file>`.
4. Commit and open a pull request. A maintainer runs `make ids-resolve` at merge time, which
   allocates the number under the per-repository lock, rewrites `LL-NEW` inside the file and
   renames it to `LL-NNN.md`.

A runbook is the same with `runbooks/RB-NEW-<slug>.md`. Never renumber or delete a record: an id
that was wrong becomes a tombstone (a record file whose front-matter is `id:` plus a
`retired: {reason:, replaced_by:}` mapping), and a lesson that is solved is retired, not removed.
