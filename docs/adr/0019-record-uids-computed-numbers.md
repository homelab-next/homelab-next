# ADR-0019: Records are identified by UUIDs; numbers are computed

- **Status:** proposed
- **Date:** 2026-10-21
- **Related:** ADR-0014 (conflict-free writes), ADR-0015 (strategy to task),
  `docs/registers.md`, `docs/strategy.md`, `homelabnext/identity/`

## Context

Every record (lessons, runbooks, and the strategy-to-task records SO/OO/TO/TT, MOP/MOE,
CCIR/FFIR/PIR, RFI) was keyed by a stored number: `LL-001` was its id, its file name, the
target of every link to it, its sidecar directory and its graph node. A stored number has to be
allocated, and allocation is the problem:

- **Merge races.** Two branches that each add a record both take the next free number. The
  project carried machinery only to avoid that: `XX-NEW` placeholders, a per-repository lock
  and high-water mark, a maintainer step at merge time (`make ids-resolve`), a CI gate that main
  carries no placeholder, and `check-lost` for the entries a bad merge fused.
- **Renumbering churn.** A number means a position, and positions move. In a hierarchy it is
  worse: "PIR 2.1" is the first child of PIR 2, and inserting a PIR before it, splitting it or
  moving it under another parent changes the number of the record and of everything below it.
  A stored number then has to be rewritten in the record, in every link to it and in every file
  name, or it lies. The maintainer's words: "As long as we use UUID/GUID instead of numbers we
  won't have to go back and renumber anything", and "Normally you might have PIR 1 and PIR 2 or
  PIR 2.1 and that changes too much to keep numbers or reference them."

## Decision

1. Every record carries a `uid`: a UUIDv7 (RFC 9562), created with the record and never
   changed. It is the record's only identity: links, references, sync keys, sidecar event
   directories and knowledge-graph nodes use it. Generation is standard library only and
   monotonic within a process (`homelabnext.identity.uid`); only the canonical lowercase form
   validates.
2. A record stores `uid`, `type`, `title`, `parent` (a uid, where the type has a hierarchy),
   optionally `order` (a number: its sort key among its siblings) and its links by uid. **No
   number is stored.**
3. The display number is computed at render time from type, parent and sibling position
   (`homelabnext.identity.numbers`): siblings are the records of one type with one parent,
   sorted by `order` and then by uid (creation time); a child's number is its parent's plus
   its position (`OO 1.2`, `MOE 1.2.1`, `PIR 2.1`; a register is flat: `LL 3`). Every surface
   that shows a record computes it the same way: the docs vault index, the status hub pages,
   the register pages, the MCP server, the CLI and the graph's node `label`. Inserting,
   reordering or re-parenting a record changes what is shown and never a record, a link or a
   file name.
4. Files are `<type-dir>/<uid>.md` (and `<uid>.events/`), so a rename or a move never changes a
   path. A record's generated `## Links` block holds `[[<uid>]]` only, so editing one record
   never makes another stale; generated pages show `[[<uid>|<number> <title>]]` (the Obsidian
   alias form) next to a relative Markdown link, and are regenerated (and checked) like every
   generated page.
5. The record hierarchy and the typed-link table are data: `hierarchy` and `links` in the
   strategy doctrine (`examples/strategy/doctrine.yml`). The validation is fatal, like the
   register gates: every record has a valid uid; uids are unique; every reference resolves to a
   uid; a parent exists, is of a type the doctrine allows and forms no cycle; sibling `order`
   values are unique.
6. Allocation is retired: `hnx ids alloc|resolve|check-placeholders`, the lock, the high-water
   mark, the `register-ids-resolve` hook, `make ids-resolve` and `make ids-placeholders` are
   gone. `check-lost` stays, keyed by uid (a uid that disappears between commits is a lost
   record), and `check-dupes` refuses a uid twice or a record not named for it; `check-uids`
   refuses a record without one. The invariants register keeps its keys: they are the
   checklist's row ids, chosen to match a row, never allocated.
7. Migration is one idempotent command, `hnx records assign-uids TREE... [--also PATH...]`: it
   gives each numbered record a uid (in code order, so an unchanged register shows the numbers it
   had), rewrites every reference, renames the files and sidecars, appends a `rekey` event where
   the identity rewrite moved a reviewed record's digest (by `hnx:migrate` only; reviews of the
   old digest recorded before it count for the new one), and writes `<tree>/aliases.yml`
   (legacy code -> uid). A legacy code met outside the repository -- an intent filed earlier, an
   id typed into `hnx graph related`, an MCP call -- resolves through that map on read, with a
   `LegacyRecordCode` deprecation warning; a code inside a record is a validation error.
8. Schemas: requiring `uid` is breaking, so the strategy record schemas, `lesson` and `runbook`
   are major-bumped to 2.0 (frozen baselines of 1.0 stay, and the migration reads 1.x records);
   the records note (1.4), the register event (1.3) and the doctrine (1.1) widen additively.

## Consequences

- Two pull requests that each add a record never collide, and there is no merge-time step.
- A number shown yesterday may name another record today. Prose, tickets and commit messages
  that need a stable reference use the uid (or a link); a number is a reading aid, not a key.
- External systems key on the uid. An OpenProject (or any tracker) work package created for a
  record stores the record's uid in a custom field and syncs by it; the computed number may be
  shown in its subject and is refreshed on each sync, never matched on. The same holds for a
  ticket, a dashboard panel or a backup manifest: match on uid, display the number.
- uids are long. Records show their number and title; the uid is printed beside it where a
  reader may need to act on it (the CLI, the hub's element titles, the register pages).
- Record files in Obsidian show `[[<uid>]]` links; the generated pages carry the readable alias.
- `aliases.yml` must be kept (never edited by hand): it is the only bridge from an old code.

## Alternatives

- **Keep numbers and the allocation machinery.** Works for flat registers at merge time, but
  cannot survive a re-parent or an insert in a hierarchy without rewriting records and links.
- **Hierarchical stored codes (`PIR-2.1`).** Encode the very position that changes.
- **Slugs from titles.** Stable until the title changes; collide across records; a rename is a
  move.
- **UUIDv4.** Unique, but random order: the default sibling order and a readable creation time
  come free with v7.
- **Content hashes.** Change with every edit; an identity must not.
