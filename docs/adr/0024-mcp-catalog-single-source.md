---
summary: One record per MCP server is the single source for the class table, graph, system pages and hub views.
summary_of: outline:sha256:d394840b82bb7d3b
---
# ADR-0024: Keep every MCP server in one catalog and generate everything else from it

- **Status:** proposed
- **Date:** 2026-10-22
- **Related:** ADR-0017, ADR-0021, `schemas/platform/mcp_server.schema.json`,
  [MCP catalog](../mcp-catalog.md), [agent profiles](../agent.md), [graph](../graph.md),
  [broker](../broker.md), [private overlay](../private-overlay.md)

## Context

What a lab knows about its MCP servers ends up in many places: a capability-class table that
names servers by slug, registry rows with an `mcp` block, profile grants by name, graph nodes,
documentation pages that say "MCP: none", hand-written `mcpServers` snippets, and one client
configuration per agent runtime. Nothing ties them together, so they drift. The shapes seen in
a lab that grew this way: a registry naming a server by one spelling and the profiles granting it
by another (so an access block said "no registry service" for a server that had one), client
configs copied by hand into several runtime homes until a fallback home held a small fraction of
the primary's entries and silently stripped tools from part of the runs, a remote server's
credential pasted as a literal header, third-party servers started with `npx -y package` at
whatever version the registry served that day, and one server binary registered once per agent
because each instance needs its own scope.

## Decision

1. **One record per server** in a catalog directory, `<catalog>/<id>.yml`, schema
   `platform/mcp_server` 1.0. The example lab's catalog is `examples/mcp/` (fictional); a real
   lab's is its private overlay's `lab/mcp/`, found through the existing data-dir lookups
   (`HNX_EXAMPLES_DIR`, `HNX_DATA_DIR`) or `--catalog`.
2. A record states: id, owner, description; **origin** (a first-party code path, or a package
   with an exact version and sha256 or lock and its reviewed `bins`, an image digest, or a git
   commit: never a floating version; or a third party's `hosted` server); **transport** (a stdio
   server's entrypoint, `bin`, and its own arguments, never the launcher; a lab server's
   streamable-http/sse by **registry service name**, never a URL; or a hosted server's `remote`
   https URL); runtime (agent-local, a registry host and user, or hosted);
   credentials as **`secret:` names only** (env, headers, arguments); non-secret settings;
   **typed per-instance parameters** and an instance-name template; egress (registry services and
   hosts, `internet`, or `none`); the data tier it returns; the capabilities it fronts and the
   capability contracts it **implements**; every tool with its capability classes and whether it
   needs approval; reviews; and a lifecycle (draft, active, deprecated, retired, with a reason).
3. **Everything else is derived.** The `mcp` section of the capability-class table is the union of
   each server's tool classes (`ToolClasses.load`); the graph's `mcp:` nodes and their edges, the
   system pages' MCP lines, the status hub's MCP servers page and every client configuration
   (`hnx mcp catalog render`: Claude Code, Claude Desktop, Hermes, llm-orchestrator, generic) are
   generated from the records. A hand-written client configuration is drift (`--check`).
4. **Validation is fatal** (`hnx mcp catalog check`, `make mcp-check`, CI): schema, the id is the
   file name, pinned third-party origins whose launch is generated (below; the sha256 is a
   declarative record of the reviewed artifact; no launcher verifies it), no literal credential
   or `$` expansion in arguments and settings, every tool classed, egress agreeing with the tool
   classes, parameters (hard-denied environment keys, collisions, defaults that fit their type),
   templates naming declared parameters, endpoints, hosts and egress resolving in the registry,
   every registry `mcp` entry resolving to a catalog server, `replaced_by` naming an active
   server, `implements` naming a homelab-next contract, and the review policy's
   `mcp-server.active` tier (agent check, agent audit, human approve).
5. **Grants name catalog ids.** The compiler, `verify` and `hnx agent lint` refuse a profile or
   manifest naming a server the catalog does not hold, one that is not active or deprecated (an
   allowlist; deprecated with a note), and a local-only server for a profile whose data may go to
   the cloud, and judge nothing against a catalog that fails its own schema or id rules; the
   reader rule (no exec, file-write,
   egress or credential grant for a profile that reads untrusted content) judges the derived
   classes.
6. **Instances, not copies.** A server is declared once; the renderer instantiates it per granted
   profile and lane with that grant's parameter values, and writes every runtime home a render
   spec names from that one source, so no home can hold fewer servers than another. It renders
   only profiles `hnx agent verify` accepts against the ceiling policy (a compiled profile without
   one is refused: its stored ceiling and digest are whatever last edited the file; the policy
   also attests each profile's `data_tier` and `model_role`, so no profile declares itself
   local-only to receive local-only servers, and grants a local-only profile a server that
   reaches the internet only by a named `internet_mcp` exception), and only records that pass check's whole record
   check and the reviews of the `review-policy.yml` beside the catalog (refused without one
   unless `--no-review-policy`, for local experiments). A render spec is trusted input.
7. **The launch is generated, never written.** A stdio record names its origin, the server's
   `bin` (for a package one of the bin names it declares, `origin.bins`, which the review reads
   from the released artifact, because npx and uvx run any command on `PATH` under that name;
   for a first-party server `hnx` with an `entry` from a fixed allowlist of the subcommands that
   serve MCP, and only that entry's flags, or a path under its code path) and the server's own
   arguments. The renderer writes the launcher from the origin kind with fixed flags: npm `npx
   -y --prefix=<npm_prefix> --package=<pkg>@<ver> -- <bin>`, pypi `uvx --no-config --from
   <pkg>[<extras>]==<ver> <bin>`, git the same at its commit (pypi: and subdirectory), image
   `docker run -i --rm [-e NAME ...] <image>@<digest>`, a first-party path absolute under the
   render's `checkout_root`. `npm_prefix` is an absolute, empty directory the render names
   (refused, where it exists on the render host, when it is the root, a symlink or not empty), so
   npx reads no `node_modules` or `.npmrc` from the client's working directory; `--no-config`
   keeps a `uv.toml` from redirecting uvx's index. A record has no field for a launcher, a
   launcher flag, a mount, a network or another entrypoint, so the pin controls what runs by
   construction. (Three review rounds of reading arbitrary launcher command lines each found a
   new way to run something the pin did not name; the parser now only serves the importer.) No
   setting, env or parameter key may configure the process or its launcher (`PATH`, `LD_*`,
   `NODE_*`, `NPM_CONFIG_*`, `UV_*`, `PIP_*`, the docker CLI's `DOCKER_HOST`, `DOCKER_CONFIG`
   ..., and what loads code or redirects trust inside a launcher: `OPENSSL_*`, `SSL_CERT_*`,
   `SSLKEYLOGFILE`, `*_PROXY`, glibc's `GCONV_PATH`, `GLIBC_TUNABLES`, `MALLOC_*` ..., any case).
8. **Import, then pin.** `hnx mcp catalog import` turns an existing lab's client configs into
   draft records in a directory it is given (`--out`, required): credentials become `secret:`
   names, failing closed (every environment value is one unless its key is allowlisted as
   non-secret; reported by name, never by value), URLs become registry-name guesses, a launch is
   mapped to origin, bin and arguments (its launcher flags dropped and named; one it cannot map
   is not copied at all), origins stay unpinned, so check fails until the
   maintainer pins, classifies and reviews each one.

## Consequences

- Adding an MCP server is one reviewed record; granting it is one profile line; every client
  file and page follows by regeneration.
- The registry's `mcp` names are now catalog ids (the example's `lake_query` and
  `agent_runtime` became `lake` and `agent-runtime`), so the reader profile's `lake` grant
  finally resolves to the lake query service in the access block and the keyring.
- The example catalog carries a record for every server name the class table used to list, so
  levels and reader verdicts for those names are unchanged.
- Literal-credential detection in arguments and settings is defense in depth, not the control:
  credentials belong in `env` as `secret:` names, and `leak_scan` and gitleaks guard the
  repository. A heuristic can be tuned (both directions are tested), but it cannot be complete.
- The generated launch adds `--` after npx's options (so a server argument is never npx's), and
  a record migrated from the command-line shape keeps only its `bin` and the server's arguments.
- `bins` is attested by review, not proven: check runs without network and cannot fetch the
  package. The `sha256` is declarative the same way. Every render names an absolute
  `npm_prefix` (and a `checkout_root` when a path bin is written); npm's user config and the
  client's own `npm_config_*`/`UV_*` environment still apply, as the client user's settings.
- No message of check, render or import carries a value from a record, spec, profile or
  parameter (a value may be a credential pasted by mistake, and messages reach logs): fields and
  rules are named, URLs shown as scheme and host, a record's free-text `reason` pointed at, never
  repeated, and a grant name the catalog does not hold given by its position.
  The schema (`platform/mcp_server` 1.0) was not released before this change, so it changed in
  place.
- Rendered files that land in another program's format (Hermes `mcp_servers`, llm-orchestrator's
  `configs/mcp_catalog.yaml` and `grants:` blocks) are byte-stable; that program's own loader stays
  the last word, and its rules are encoded as a test (`clients.orch_accepts`).
- Secret placeholders (`${HNX_SECRET_<NAME>}`) are expanded by Claude Code itself; Hermes and
  llm-orchestrator need their deploy to substitute them from the secret store when it installs the
  file. Claude Desktop expands nothing in its config, so render refuses a server that needs a
  secret for it, and its output is a fragment to merge, never the whole config file.

## Alternatives

- **Keep the class table as the list and add fields to it.** One YAML file grows into the catalog
  without per-server review, history or ownership; and it is packaged code, which an overlay
  cannot replace without shadowing the whole table.
- **Make the registry the catalog.** The registry describes network services with an address and
  a port; most MCP servers are stdio subprocesses of a client and have neither.
- **Generate from the client configs** (the import, run continuously). It would bless whatever the
  configs hold, unpinned versions and literal secrets included, and keep them as the source.
