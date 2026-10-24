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
| `context_for(task_text, allowed, paths=[], kinds=[], budget=10)` | ranked hits with content and sha256 digest, relation before keywords | the [`context`](capabilities/context.md) ([[capabilities/context\|context]]) reference store over the graph |
| `lessons_due(today=None)` | the lesson review's due list by action: each row's record by uid (`id`) and computed number (`label`, `LL 3`), the uids its reason names (`refs`), and `labels` (uid -> number) | `hnx registers review` ([[registers]]) |
| `terms()` | the project's terms and scope: auditing, audit review, auditing tool, internal assessment, the authorized scope, how threat vocabulary is used | `homelabnext/agent/terms.md`, the [terms](terms.md) ([[terms]]) page's source and every session pack's `terms` section |
| `invariants_status()` | the invariants page's verdict, counts and `all_hold`, and per criterion: statement, status (the page's: `deferred`, `server` or `untested` without a committed result), checked_at, remediation when not passing | `examples/registers/invariants.results.json`, judged by `homelabnext.registers.render` |

`context_for` is the main tool. Its seeds are the graph nodes defined by `paths` (the files the
task edits) and the ids and names the text mentions (`seeds_for`); the store ranks documents
related to them above keyword matches, never returns a retired, superseded or incorporated record,
and caps each hit's content at 32,768 characters (`content_truncated` and `content_chars` then
say so; `digest` is always the full content's). `kinds: []` means every kind.

Example (trimmed):

```
$ hnx mcp call context_for --args '{"task_text": "add an adapter for the context capability",
    "paths": ["conformance/protocols/context.py"], "allowed": ["cap:", "doc:docs/"], "budget": 3}'
{"hits":[{"content":"scoped retrieval for agents: relation before keywords, ...","digest":"99ec33d3...",
  "id":"cap:context","kind":"cap","path":"","score":3.261642857,"snippet":"...","title":"scoped retrieval ..."},
  {"id":"doc:docs/capabilities/context.md","kind":"doc","path":"docs/capabilities/context.md","score":2.99,...},
  {"id":"doc:docs/conformance.md","kind":"doc","path":"docs/conformance.md","score":1.99,...}],
 "scope":["cap:","doc:docs/"],"scoped_by":null,"seeds":["cap:context"]}
```

## Security model

* **Read-only by construction.** The tool list is exactly the eight tools above (`TOOLS`; a test
  pins it against an allowlist, and every tool carries `readOnlyHint`, not destructive, not
  open-world). No tool writes, runs a command or opens a connection; there is no shell, no
  generic file read and no fetch. The server runs stdio only.
* **Nothing outside the checkout.** A caller-supplied path is repo-relative: an absolute path,
  `..`, `~`, a backslash or a control character is refused, and so is a path through a symbolic
  link. Only `get_schema` reads a file a caller names, and only a `.json` file under `schemas/`.
  Every other answer comes from the sources the documentation generators read.
* **Scope is mandatory for content.** `context_for` refuses a call without `allowed` (a list of
  exact ids or namespaces ending in `:` or `/`, as in the `context` contract; no wildcard).
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
  `cap:lake-query` gives `cap:lake-query`). `related` is computed over the in-scope nodes only, so
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
