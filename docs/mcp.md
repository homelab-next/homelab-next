<!-- SPDX-License-Identifier: Apache-2.0 -->
# MCP server: the repository as structured answers

`hnx mcp serve` is a read-only [Model Context Protocol](https://modelcontextprotocol.io) server
over this checkout, so an agent asks for a capability's contract, a schema or the context for a
task and gets JSON built from the source of truth, instead of reading and re-parsing prose. It
speaks **stdio only**: there is no network listener. Code: `homelabnext/mcp/`
(`catalog.py` the tools, `scope.py` the profile scope, `server.py` the SDK binding).

```
pip install 'homelabnext[mcp]'          # the official mcp SDK (1.x or 2.x)
hnx mcp serve [--root CHECKOUT] [--registry FILE] [--scope-from-profile PROFILE.json --policy POLICY --lock LOCK]
hnx mcp tools                           # what each tool answers (no SDK needed)
hnx mcp call context_for --args '{"task_text": "...", "allowed": ["doc:docs/", "cap:"]}'
hnx mcp call outline --args '{"id_or_path": "docs/graph.md", "allowed": ["doc:docs/"]}'
hnx mcp call section --args '{"id_or_path": "docs/graph.md", "heading": "...", "allowed": ["doc:docs/"]}'
```

A client configuration starts it as a subprocess. Do not write that configuration by hand: the
server is the `hnx-catalog` record of the [MCP catalog](mcp-catalog.md) ([[mcp-catalog]]), and
`hnx mcp catalog render --profile build/profile.json --client claude-code --policy policy.yml`
writes the entry, with `--scope-from-profile` pointing at the profile and `--policy`/`--lock` at
the deployed ceiling policy and lock (render refuses a profile `hnx agent verify --policy` would
refuse, and the server verifies it again at start against the same policy and lock).
`hnx mcp call` runs the same handler in-process, without the SDK, for scripts and debugging.

## Tools

Every result is one JSON text block: compact, keys sorted, deterministic for a given checkout,
and at most 262,144 characters (`MAX_RESULT_CHARS`). A list that would not fit loses its trailing
items and the result says so (`"truncated": {"dropped": N, "reason": "result size cap"}`). A
refused call is an MCP tool error with the reason.

| Tool | Answers | Built from |
|---|---|---|
| `list_capabilities()` | every capability: purpose, operations, MUST/SHOULD counts, fake, adapters, services | `homelabnext.sop.capabilities.summary_data` |
| `get_contract(capability)` | operations (signature, params with types and defaults, returns, raises, docstring), data shapes (field tables), constants, errors, schemas, checks (id, level, assertion, requires), features, mutants, adapters with recorded product limits, providing and depending services | `contract_data`, the model the [capability pages](capabilities/README.md) ([[capabilities/README\|capabilities]]) are rendered from |
| `get_schema(id_or_path)` | one JSON Schema, by graph id (`schema:schemas/...`), path (with or without `schemas/`), `$id` URL or `family/name` (`agent/profile`) | `schemas/` |
| `find_services(capability=None, tag=None)` | registry services: name, capability, impl, owner, tags, depends_on, mcp; names only | `examples/services.yml` (or `--registry`) |
| `related(ids_or_paths, depth=2, budget=25, include_inactive=False)` | the ranked graph neighbourhood, seeds, ids that resolved to nothing; a record is named by its node id (`lesson:<uid>`) or its bare uid, and a legacy code (`lesson:LL-001`) resolves through the alias map with a deprecation warning (ADR-0019) | [knowledge graph](graph.md) ([[graph]]) |
| `context_for(task_text, allowed, paths=[], kinds=[], budget=10, detail="summary")` | ranked hits, relation before keywords, each with its summary (`summary_source`) and sha256 digest; `detail: "full"` adds the snippet and the content | the [`context`](capabilities/context.md) ([[capabilities/context\|context]]) reference store over the graph |
| `outline(id_or_path, allowed)` | one document's level 1: id, path, title, summary, `summary_source`, chars, digest and every heading (level, title, slug, heading path, chars) | the same store; `homelabnext/context/levels.py` |
| `section(id_or_path, heading, allowed, outline_digest=None, offset=0, limit=None)` | one document's level 2: the section a slug or full heading path names exactly, with its subsections, chars and digest, paged (`next_offset`) and refused when the document changed since the outline | the same store; `homelabnext/context/levels.py` |
| `lessons_due(today=None)` | the lesson review's due list by action: each row's record by uid (`id`) and computed number (`label`, `LL 3`), the uids its reason names (`refs`), and `labels` (uid -> number) | `hnx registers review` ([[registers]]) |
| `terms()` | the project's terms and scope: auditing, audit review, auditing tool, internal assessment, the authorized scope, how threat vocabulary is used | `homelabnext/agent/terms.md`, the [terms](terms.md) ([[terms]]) page's source and every session pack's `terms` section |
| `invariants_status()` | the invariants page's verdict, counts and `all_hold`, and per criterion: statement, status (the page's: `deferred`, `server` or `untested` without a committed result), checked_at, remediation when not passing | `examples/registers/invariants.results.json`, judged by `homelabnext.registers.render` |

`context_for` is the main tool. Its seeds are the graph nodes defined by `paths` (the files the
task edits) and the ids and names the text mentions (`seeds_for`); the store ranks documents
related to them above keyword matches and never returns a retired, superseded or incorporated
record. `kinds: []` means every kind.

## Documents in levels

Context is authored Markdown and YAML in git (ADR-0028), served in levels so a pack carries only
what the task opens, and nothing is stored, summarised or embedded anywhere else
([ADR-0032](adr/0032-agent-context-is-authored-markdown-in-levels.md)):

| Level | Tool | What comes back |
|---|---|---|
| L0 | `context_for` (default `detail: "summary"`) | per hit: id, kind, title, path, score, digest, `summary` and `summary_source`; no content |
| L1 | `outline` | the document's summary, size, digest and heading outline with each section's size |
| L2 | `section` | one section, its own heading through the next heading of the same or a higher level |

* **The summary** is the front-matter `summary:` an author wrote and a review covered
  (`summary_source: "authored"`; lessons and runbooks, lesson schema 2.1 and runbook 2.2, and
  any docs page with front-matter). The generated capability and system pages carry a summary
  their generator derived, marked `summary_generated: true`: it is served as `"generated"`
  (nobody wrote or reviewed it) and `hnx registers summaries` counts those apart. Without one, a Markdown document gets its first prose
  paragraph (`"first-paragraph"`): a block that starts as a quote, a list, a table, HTML or an
  image is skipped; prose before the first `##` heading wins, else the first under `## Context`
  (an ADR's), else the first anywhere; links become their text, wiki-links their label, and
  emphasis, code marks and tags are dropped; it is cut at the last sentence end within 160
  characters, else at a word with `…`. A node the indexer built from attributes (a capability, a
  service, a check) gets its first line, plus its plain attributes when that line is a bare name
  (`"synthesized"`). Anything else is `""` (`"none"`). A summary is one line of at most 160
  characters: `hnx registers summaries` fails a malformed one and counts a missing one as a
  warning (`--missing` lists them; [registers](registers.md), [[registers]]).
* **Headings** are ATX headings (`#` to `######`) outside the front-matter, fenced code (a
  ```` ``` ```` or `~~~` fence; an unclosed fence runs to the end), HTML comments and raw
  `<pre>`, `<script>`, `<style>` and `<details>` blocks (from the opening tag at a line start to
  the first line with the closing tag; nesting is not tracked, and other raw HTML is not
  interpreted). **Setext headings** (text underlined with `===` or `---`) are not headings here:
  their text stays paragraph text. A line ends at `\n` only: `\r`, `\v`, `\f`, `\x1c`-`\x1e`,
  `\x85`, U+2028 and U+2029 are text inside a line, so none can start a hidden heading. An empty
  heading (`#` alone) is not listed but ends the section before it; text before the first heading
  (the preamble) is not a section (`context_for` with `detail: "full"` returns it).
* **Titles, slugs and paths.** A title is the heading's visible text (inline markup reduced as
  for summaries). A slug is that text lower-cased with each run of characters other than
  letters, digits and `_` made one `-`. A repeated slug is qualified by its parent's slug
  (`unreleased/added`) and, if that is taken too, counted (`added~2`); a plain slug never holds
  `/` or `~`, so it cannot collide with a qualified or counted one. The heading path is the
  titles from the top down joined by `/` (`/`, `~` and `\` in a title escaped with `\`); a
  document's sole leading H1 is its title and not a segment (`Context`, not
  `ADR-0032: .../Context`); a repeated path gets `~2`, `~3` ... on its last segment.
  **A slug or path is valid only for the outline it came from, and `outline_digest` is how to
  pin it**: pass that outline's `digest` as `section`'s `outline_digest` and a document edited
  since is refused instead of served wrong.
* **A section is named exactly**, by its slug or its full heading path: no case folding, no
  prefix and no fuzzy match. An unknown name, or one that is one heading's slug and another's
  path, is a tool error listing the document's slugs (never repeating the name sent).
* **Sizes, digests and paging.** `chars` is the document's or the section's length in characters
  and `digest` the sha256 of all of it; a pack that cites a digest can be checked against the
  checkout. `context_for`'s full content is capped at 32,768 characters
  (`MAX_HIT_CONTENT_CHARS`; `content_truncated` and `content_chars` then say so). A section is
  read `offset` characters in, at most `limit` (default and ceiling 32,768) at a time; when more
  follows, `truncated: true` and `next_offset` say where to continue.
* **Bounds.** The parser reads at most 1 MiB and 100,000 lines of a document, a heading title
  from at most 2,048 characters of its line, and a front-matter block of at most 64 KiB; it is
  linear in what it reads, and parses are memoised per content digest (at most 128 documents
  and about 64 MiB; the memo keeps headings and the derived summary, never the text). Past the bound an
  outline lists the headings it read with `parse_truncated: true` and `parsed_chars`.
* **Clean text, raw content.** Every title, slug, path and derived summary has control and
  line-separator characters (Unicode Cc, Zl, Zp) turned into spaces and invisible format
  characters (Cf: bidi overrides, zero-width characters, the BOM; Cs) removed, so a document
  cannot hide escape codes or reordered text in the names and summaries a model reads. An
  authored summary holding one is refused by the lint and the record validation, and is not
  served as authored. **Content is not cleaned:** a section's `content` (and `context_for`'s
  full `content`) is the raw document text, byte for byte what `digest` covers, so an escape
  sequence, a bidi override or a zero-width character in the document is in it too. Treat
  content as untrusted data, as for every tool here.
* **Scope.** `outline` and `section` take the same mandatory `allowed` as `context_for`, narrowed
  the same way by `--scope-from-profile`. A document is named by its id (`doc:docs/graph.md`,
  `lesson:<uid>`, a bare uid or a legacy code, without the legacy code's deprecation warning,
  which would otherwise say the record exists) or its repo-relative path, and one outside the
  scope is refused with exactly the message of one that does not exist
  (`no such document in scope`). A path that defines several in-scope records (a register row
  file) is refused: name one by id.

**Behaviour change:** `context_for` used to return every hit's content. It now defaults to
`detail: "summary"` (an explicit `null` is the default too); pass `"detail": "full"` for the old
answer (plus the two summary fields).
No caller in this repository read the content: the context-pack assembler builds packs from
the graph, not from this tool.

Example (trimmed):

```
$ hnx mcp call context_for --args '{"task_text": "add an adapter for the context capability",
    "paths": ["conformance/protocols/context.py"], "allowed": ["cap:", "doc:docs/"], "budget": 3}'
{"detail":"summary","hits":[{"digest":"99ec33d3...","id":"cap:context","kind":"cap","path":"",
  "score":3.261642857,"summary":"scoped retrieval for agents: ...","summary_source":"synthesized",
  "title":"scoped retrieval ..."},
  {"id":"doc:docs/capabilities/context.md","kind":"doc","score":2.99,"summary_source":"first-paragraph",...},
  {"id":"doc:docs/conformance.md","kind":"doc","score":1.99,"summary":"A capability is *replaceable* ...",...}],
 "scope":["cap:","doc:docs/"],"scoped_by":null,"seeds":["cap:context"]}

$ hnx mcp call outline --args '{"id_or_path": "examples/registers/lessons/<uid>.md", "allowed": ["lesson:"]}'
{"chars":1376,"digest":"35f57f47...","headings":[{"chars":168,"level":2,"path":"Symptom","slug":"symptom",
  "title":"Symptom"},...,{"chars":107,"level":2,"path":"Links","slug":"links","title":"Links"}],
 "id":"lesson:<uid>","path":"examples/registers/lessons/<uid>.md",
 "summary":"A silent renewal failure let the proxy certificate expire; ...","summary_source":"authored",
 "title":"Certificate expired on the internal reverse proxy"}

$ hnx mcp call section --args '{"id_or_path": "lesson:<uid>", "heading": "root-cause", "allowed": ["lesson:"]}'
{"chars":154,"content":"## Root cause\n\nNothing measured certificate lifetime ...","digest":"...",
 "heading":"Root cause","id":"lesson:<uid>","offset":0,"slug":"root-cause"}
```

## Security model

* **Read-only by construction.** The tool list is exactly the eleven tools above (`TOOLS`; a test
  pins it against an allowlist, and every tool carries `readOnlyHint`, not destructive, not
  open-world). No tool writes, runs a command or opens a connection; there is no shell, no
  generic file read and no fetch. The server runs stdio only.
* **Nothing outside the checkout.** A caller-supplied path is repo-relative: an absolute path,
  `..`, `~`, a backslash or a control character is refused, and so is a path through a symbolic
  link. Only `get_schema` reads a file a caller names, and only a `.json` file under `schemas/`;
  `outline` and `section` resolve a path to a knowledge-graph node and serve its indexed content.
  Every other answer comes from the sources the documentation generators read.
* **Scope is mandatory for content.** `context_for`, `outline` and `section` refuse a call
  without `allowed` (a list of exact ids or namespaces ending in `:` or `/`, as in the `context`
  contract; no wildcard).
* **A profile bounds the server, and a call cannot widen it.** `--scope-from-profile` takes a
  compiled agent profile ([agent profiles](agent.md), [[agent]]) and needs `--policy` and `--lock`.
  The profile must verify against them (schema, the reader rule, grants within the policy's
  ceiling, digest and the lock's reviewed digest; `verify_profile`): checked only against the
  ceiling stored in the file, a profile that whoever can write the file widened, with its digest
  recomputed, would widen the server's scope. It must also be **granted
  this server** (`hnx-catalog` in `grants.mcp`), or the server does not start. Its scope is
  derived from its grants: the profile node; per granted capability `cap:<x>`, `check:<x>/` and
  `doc:docs/capabilities/<x>.md`; per granted MCP server `mcp:<m>`; and every registry service
  providing a granted capability or exposing a granted server, with its system page. A call's
  `allowed` is then **intersected** with that scope: an entry the grant does not cover is dropped,
  and a wider namespace is replaced by the granted entries inside it (`cap:` against a grant of
  `cap:lake-query` gives `cap:lake-query`); `outline` and `section` refuse a document outside the
  result exactly like a missing one. `related` is computed over the in-scope nodes only, so
  nothing outside is returned or related through, and an out-of-scope seed reads like an unknown
  one. The catalog tools are bounded the same way: `list_capabilities`, `get_contract`,
  `find_services` and `lessons_due` return only in-scope capabilities, services (also in
  `depends_on`, providers and consumers) and lesson or runbook records, and an out-of-scope
  capability reads like an unknown one. `get_schema`, `invariants_status` and `terms` describe the
  repository's public contracts and are not scoped. Without `--scope-from-profile` every tool
  sees everything, as before.
* **Registered like any other MCP server.** `hnx-catalog` is a record of the
  [MCP catalog](mcp-catalog.md) (`examples/mcp/hnx-catalog.yml`): first-party origin, stdio,
  every tool classed `read`, `implements: [cap:context]`. Its classes are derived from that
  record, so a profile may grant it, a reader profile included, and the compiler,
  `hnx agent verify` and `hnx agent lint` judge it like every other grant. A test holds the
  record's tool list equal to `TOOLS`. It is not a row in `examples/services.yml`: the registry
  describes network services with an address and a port, and a stdio server has neither.
* **Untrusted text.** Tool outputs return repository content: what git holds is trusted-repo
  content, but it is still data, and a client should fence it like any other context. `task_text`
  is only split into words for matching; it is never interpreted, executed or used as a path, and
  it is not echoed back (refusal messages never repeat it).

The server loads the checkout's sources on first use and keeps them for its lifetime: restart it
to see later edits.

## The broker's tool server (`hnx-broker`)

`hnx mcp serve` only reads. The other MCP server in the package is the broker's,
`hnx broker mcp --socket PATH` ([broker](broker.md), [[broker]]): stdio as well, built on the same
SDK plumbing (`homelabnext/mcp/server.py`: `new_server`, `hints`, `register`, `tool_error`), but
its tools *act*, through a running broker that authenticates the MCP process by its uid:
`broker_actions`, `broker_call`, `broker_submit`, `broker_status`, `broker_run`, `broker_cancel`,
`broker_pending`, `memory_write`, `finding_write`, `proposal_file`. No tool takes an identity. It
is the catalog record `examples/mcp/hnx-broker.yml` (each tool classed: `read`, `record-write`
or `exec`; `broker_submit` and `broker_run` need approval) with `acts_via: broker`: its acting
tools are broker calls, so it is the one acting server any profile may hold without an exception
(the catalog check ties the record's tools to the ones `mcp_tools.py` registers, and no other
record may claim `acts_via: broker`)
(agents act only through the broker, [ADR-0030](adr/0030-agents-act-only-through-the-broker.md),
[[agent]] G-13). A profile grants it in `grants.mcp`, with `cap:broker` for an `execute` or
`privileged` tier, and the reader rule refuses it to any profile that reads untrusted content. Split such an agent into a reader (with `hnx-catalog`) and an
actor (with `hnx-broker`).
