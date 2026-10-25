# ADR-0032: Agent context is authored Markdown served in levels; no context database

- **Status:** proposed
- **Date:** 2026-10-25
- **Related:** ADR-0019 (record uids), ADR-0024 (MCP catalog), ADR-0028 (Veritas),
  [MCP server](../mcp.md), [`context` capability](../capabilities/context.md),
  [registers](../registers.md), [agent profiles and context packs](../agent.md)

## Context

An agent's context in this platform is authored Markdown and YAML in git: pages under `docs/`,
lessons and runbooks as one record file each, capability contracts, the registry. Veritas
(ADR-0028) makes those files the source of truth, and the knowledge graph, the `context`
reference store and the read-only MCP server (`hnx mcp serve`) are built from them.

Two pressures pull against that:

- **Packs bloat.** `context_for` returned every hit's whole content, up to 32,768 characters
  each. An agent that asked for ten hits to decide which one mattered paid for all ten. Small
  local models feel this first: the content crowds out the task.
- **Context databases offer a fix.** Systems such as OpenViking keep agent context in a
  dedicated store, compile documents into tiers (an abstract, an overview, the full text, often
  written by a model) and retrieve by meaning over embeddings. The lab's existing estate runs
  one. A tiered read is the right idea; the open question was where it should live.

The other way to get tiers is to read them off the documents themselves: a short authored
summary, the heading outline with sizes, one section on request. A Markdown reader that serves a
file's tree, one section and its front-matter shows the shape is enough for navigation, but a
filesystem reader has none of this platform's scope rules, profile verification or digests.

## Decision

1. **homelab-next does not adopt OpenViking or another context database.** Agent context stays
   authored Markdown and YAML in git (ADR-0028), indexed in-process by the `context` reference
   store over the knowledge graph. No service stores, compiles or embeds it.
2. **Context is served in three levels** by `hnx mcp serve` (`homelabnext/context/levels.py`,
   `homelabnext/mcp/catalog.py`):
   - **L0, the summary:** a front-matter `summary:` the author wrote and a review covered
     (`summary_source: authored`), else the document's first prose paragraph reduced to visible
     text and cut to 160 characters (`first-paragraph`), or for a node built from attributes its
     first line (`synthesized`), else nothing (`none`). `context_for` returns this level by default
     (`detail: "summary"`: id, kind, title, path, score, digest, summary; no content);
     `detail: "full"` still returns the content.
   - **L1, the outline:** `outline(id_or_path, allowed)` gives the summary, the size, the digest
     and every ATX heading (level, title, slug, heading path, section size), parsed outside the
     front-matter, fenced code and raw HTML blocks, lines split on `\n` only. Setext headings
     are not headings. Slugs and paths are unique and valid only for the outline they came from.
   - **L2, one section:** `section(id_or_path, heading, allowed, outline_digest, offset, limit)`
     gives the section a slug or a full heading path names exactly, with its size and digest,
     paged, and refuses a name from an outline of an earlier content. There is no fuzzy match:
     an unknown or ambiguous name is an error listing the slugs.
3. **Every level is scoped like `context_for`.** `allowed` is mandatory and has no wildcard,
   `--scope-from-profile` narrows it to a verified profile's grants, and a document outside the
   scope is refused with exactly the message of a missing one.
4. **Every level is deterministic, bounded and carries digests.** The same checkout gives
   byte-identical results; `digest` is the sha256 of the whole document or section, so a pack
   that cites one can be checked against git. Parsing is linear and bounded (1 MiB, 100,000
   lines) and every title, slug, path and derived summary is cleaned of control and invisible
   format characters before a model sees it; content stays the raw document text its digest
   covers, and is untrusted data.
5. **A summary is authored, short and reviewed.** `summary:` is accepted on lessons (schema
   2.1), runbooks (2.2) and docs pages: one line, at most 160 characters, no control or invisible
   format character.
   It is content, so it is in the record's review digest. `hnx registers summaries` (in
   `make registers`) fails a malformed summary and counts a missing one as a warning; the
   example records carry one.

## Consequences

- **Easier:** a pack starts from summaries and opens only the sections a task needs. Nothing can
  drift, because there is no second copy: an edited page is the new context once the server
  restarts. A summary is reviewed with the record, so no model-written abstract stands in for
  what the author meant. There is no compile step that rewrites a whole corpus after a change,
  and no extra service to run, secure, back up or upgrade. Scoping and digests are the ones the
  platform already proves.
- **Harder:** someone has to write summaries. Until they do, the first-paragraph fallback serves
  the first prose it finds (it skips an ADR's status list and a generated page's quoted banner,
  and prefers an ADR's Context), which is a guess at what the author would have written. The
  lint counts the gap; it does not fail on it yet. A tighter gate needs a later change. The
  parser is a deliberate subset of Markdown (no setext headings, raw HTML only as whole blocks),
  documented with its limits.
- **What we lose:** semantic search over large unstructured corpora, which is what systems like
  OpenViking are for: finding a passage by meaning in material nobody structured (papers,
  vendor manuals, mail archives). Ranking here stays relation first, then keywords. If a
  corpus like that appears (a research collection, for example), it can sit behind the `context`
  contract as an adapter declaring the `semantic` feature (`conformance/protocols/context.py`
  describes one), scoped and verified like any other. It should be adopted only after evals show
  it beats the keyword store on that corpus.
- **Packs use the levels too:** an `include:` rule's `detail` (`full` by default, `summary` or
  `outline`) makes a context pack carry a node's level 0 or 1 instead of its body, and the pack
  record keeps the digest of the full content. Generated capability and system pages carry a
  `summary:` derived from the registry and the contract, so the lint's gap shrinks without
  anyone writing a line.
- **Obliges us to maintain:** the parsing rules in `homelabnext/context/levels.py` and their
  tests (fences, front-matter, slugs, paths), the summary rule shared by the lint, the record
  validation and the schemas, and the behaviour change in `context_for`'s default.

## Alternatives

- **Adopt OpenViking (or another context database) in homelab-next.** It brings tiers and
  semantic retrieval, but its tiers are compiled, often by a model, so they can drift from the
  source and cannot be reviewed like a record. A change re-runs the compile, the service is one
  more stateful product with its own scope model, and the platform's profile scoping would have
  to be re-proved on top of it. Rejected for the platform's own authored context. The lab's
  existing estate is not affected by this decision.
- **A filesystem Markdown reader as a separate MCP server** (tree, section and front-matter
  tools over a directory). It is the same idea, but it reads any file under its root, knows
  nothing of profile scope, inactive records or digests, and would be a second server to
  register and grant. Rejected in favour of the same tools inside `hnx-catalog`.
- **Keep `context_for` returning full content and trim it in the client.** The cost is paid
  before the client can trim, and every client would have to re-invent it. Rejected; `full`
  stays available on request.
- **Model-written summaries cached beside the files.** Cheap to produce, but they would be a
  generated copy that is neither authored nor reviewed, which is the drift Veritas forbids.
  Rejected.
