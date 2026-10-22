<!-- SPDX-License-Identifier: Apache-2.0 -->
# The MCP catalog: one list of MCP servers

Every MCP server an agent may use is one record in one catalog. Everything else that knows about
MCP servers is generated from it: the capability classes the agent compiler and the reader rule
judge, the knowledge graph's `mcp:` nodes, the MCP line of the system pages, the status hub's
**MCP servers** page, and every client configuration an agent runtime reads. The decision is
[ADR-0024](adr/0024-mcp-catalog-single-source.md); the schema is
`schemas/platform/mcp_server.schema.json` (1.0); the code is `homelabnext/mcp/servers.py` (records
and checks), `clients.py` (rendering), `importer.py` (import) and `catalog_cli.py`.

## What lives where now

| What | Where | Source or derived |
|---|---|---|
| One record per server (`<id>.yml`) | `examples/mcp/` (fictional); a real lab's in its private overlay, `lab/mcp/` ([private overlay](private-overlay.md)) | **source** |
| Who may use a server | a profile's `grants.mcp` (compiled) or `mcp` (lean), by catalog id | source (the grant); checked against the catalog |
| Per-instance parameter values, lanes, runtime homes | a render spec, `examples/mcp/clients/*.yml` | source (the deployment) |
| Capability classes of each server | `homelabnext/agent/tool_classes.yml` has no `mcp` section any more | derived: union of the record's tool classes |
| A registry service's `mcp` block | `services.yml` | must name the catalog id whose endpoint it is (checked) |
| Graph `mcp:<id>` nodes, `served_by`, `reaches`, `fronts`, `implements`, `replaced_by` edges | `hnx graph` ([graph](graph.md)) | derived |
| System page MCP line | `docs/systems/<service>.md` (`hnx docs systems generate`) | derived |
| Status hub MCP servers page | `/mcp-servers` (directory menu group) | derived |
| Client configs (`.mcp.json`, Claude Desktop, Hermes `mcp_servers`, llm-orchestrator catalog and `grants:` blocks) | wherever each runtime reads them | derived: `hnx mcp catalog render` |
| The access block and keyring levels | `hnx agent pack`, `hnx agent keyring` | derived (through the classes) |

## A record

```yaml
id: notes                        # what a profile grants; the file is notes.yml
description: A notes store, one instance per agent.
owner: platform-team
status: active                   # draft | active | deprecated | retired (+ reason, replaced_by)
origin:                          # first-party path | package | image | git | unknown
  {kind: package, ecosystem: pypi, package: example-notes-mcp, version: 1.2.0, sha256: <64 hex>}
transport: {type: stdio, command: uvx, args: [--from, example-notes-mcp==1.2.0, notes-mcp]}
# or {type: streamable-http, endpoint: svc:lake-query, path: /mcp}  -- a registry name, never a URL
runtime: agent-local             # or {host: <registry host>, user: <system user>}
env: {NOTES_TOKEN: secret:mcp/notes-token}      # credentials: secret names only
settings: {NOTES_ROOT: /srv/notes}              # non-secret, the same for every instance
timeout: 120
parameters:                      # typed, per instance; delivered in env
  writable: {env: NOTES_WRITABLE_PREFIX, pattern: '[a-z0-9/_-]+/', default: 'agents/{profile}/'}
  mode: {env: NOTES_MODE, enum: [read, write], default: write}
instance: notes-{profile}-{lane} # the name a client sees
egress: none                     # or [svc:<name>, host:<name>, internet]
data_tier: local-only            # what it returns may reach local-only profiles only
capabilities: [cap:records-propose]   # the platform capabilities it gives access to
implements: [cap:context]        # homelab-next contracts it implements (its conformance suite)
tools:
- {name: read_note, classes: [read], approval: false}
- {name: write_note, classes: [record-write], approval: false}
author: agent:example-builder
reviews: [...]                   # check, audit, approve (homelabnext.reviews)
```

The classes are `tool_classes.yml`'s: `read`, `record-write`, `exec`, `file-write`, `egress`,
`credential`. A server's classes are the union of its tools'.

## The rules (`hnx mcp catalog check`, fatal)

`make mcp-check` (part of `make check` and CI) runs the check and every render spec's `--check`.
Every problem is printed with its file and the exit code is 1; while the catalog itself has
problems the grants are not judged (a note says so), since they would be judged against it.

- the record fits the schema (a mismatch is reported against the origin kind or transport type
  the record names), its id is its file name (so ids are unique), and every record file is
  `<id>.yml` (a `.yaml` or `.json` file is refused, never skipped);
- a third-party origin is **pinned**: an exact version (never a range, `latest` or a wildcard;
  npm a full `x.y.z`) with a sha256 or a lock file (relative to the catalog, existing, naming the
  package), an image digest, or a 40-hex commit; `kind: unknown` fails; a first-party path exists
  in the checkout;
- the pin is what runs: `npx`/`bunx` arguments name `package@version`, `uvx`/`pipx`/`uv`
  `package==version`, `docker`/`podman` `image@digest`. The `sha256` itself is **declarative**:
  it records the reviewed artifact, but no launcher verifies it when it fetches the package;
- every tool is classed with a declared class, and the server lists at least one;
- egress agrees with the classes: a tool classed `egress` needs an egress other than `none`, and
  `internet` needs an egress tool;
- credentials are `secret:` names (env, headers, arguments), two of them never map to the same
  `HNX_SECRET_*` variable, and a setting whose key names a credential is refused; no argument or
  setting holds a literal credential: a credential flag's value (`--token X`, `--api-key=X`, a
  header after `--header`) is a `secret:` reference, nothing looks like a token, `secret:` appears
  only as a whole argument, `--flag=secret:<name>` or `Header: [Scheme ]secret:<name>`, and `$`
  (`${VAR}`, `$(cmd)`, which a client would expand) appears in neither;
- parameters: every parameter has an `enum` or a `pattern`; its env key is never one
  llm-orchestrator hard-denies (`PATH`, `LD_*`, `DYLD_*`, `PYTHONPATH`, `PYTHONHOME`,
  `PYTHONSTARTUP`, `PYTHONINSPECT`, `HOME`, `SHELL`, `BASH_ENV`, `ENV`, `NODE_OPTIONS`,
  `HERMES_HOME`), never names a credential, never also a fixed setting or secret, never shared by
  two parameters; a default fits its enum and pattern and holds no `$` or `secret:`; templates name only `{id}`,
  `{profile}`, `{lane}`, the parameters, and in arguments `{profile_file}`;
- with the registry: an HTTP endpoint is a registry http(s) service, and a registry service's
  `mcp` block names this catalog id with the same transport and path; every registry `mcp` entry
  resolves to a catalog server; runtime hosts and egress services and hosts exist; every
  `capabilities` entry is a registry service's capability, a class-table capability or a
  conformance contract (a record that fails the schema gets no follow-on registry errors);
- `reason` and `replaced_by` appear only on a deprecated or retired record, and `replaced_by`
  names an active server; `implements` names a homelab-next capability contract
  (a conformance capability), so the graph ties the server to that contract's suite;
- with the review policy: an `active` record carries current agent check, agent audit and human
  approve reviews (`mcp-server.active` in `examples/review-policy.yml`; `hnx reviews digest
  examples/mcp/<id>.yml` gives the digest to stamp);
- every agent profile and context manifest in the checkout (or `--grants PATH...`) grants only
  catalog ids whose status is `active` or `deprecated` (an allowlist: `draft`, `retired` and
  anything else are refused), of a server with a known `data_tier`, never a `local-only` server to
  a profile whose `data_tier` is not `local-only`, and a reader holds no exec, file-write, egress
  or credential server. A `deprecated` grant passes with a note naming the reason and its
  `replaced_by`. The compiler, `hnx agent verify`, `hnx agent lint` and `render` apply the same
  rules, and they judge grants only against a sound catalog: a record that fails the schema, an
  id that is not its file name or two records with one id refuse every judgement (so a stray
  record cannot reclassify a server).

## Adding a server

1. Write `<catalog>/<id>.yml` with `status: draft`, pin its origin, list every tool with its
   classes. Put credentials in the secret store under the `secret:` names you write.
2. `hnx mcp catalog check` until it is clean.
3. Get it reviewed (agent check, agent audit, human approve), then set `status: active`.
4. Grant it: add the id to a profile spec's `mcp` (and its ceiling), recompile.
5. `make mcp-render`, commit the rendered client configs.

## Instances: one declaration, every profile, every home

A record with `parameters` is instantiated per granted profile and lane. A render spec says which
profiles, lanes and homes:

```yaml
client: hermes
catalog: ..                     # relative to the spec
registry: ../../services.yml
lanes: [real, shadow]
profiles:
  - file: profile.broker-agent.json
    profile_file: /etc/hnx/profiles/broker-agent.json   # {profile_file} in arguments
    params:
      notes@shadow: {mode: read}           # SERVER@LANE overrides one lane
  - file: profile.collector.json
    params:
      notes: {writable: agents/collector/inbox/}
outputs:
  - {home: primary, path: hermes/primary.yaml}
  - {home: fallback, path: hermes/fallback.yaml}
```

Each parameter's value is the grant's (`params`), else its default; a list value expands into one
instance per element. A value is a string (quote YAML's `true` or `0755`), passed through
verbatim: it may not contain `$`, `secret:` or a control character, so a grant can never route a
secret or an environment variable to a server (secrets come only from the record's own `env`,
`headers` and arguments). Values are checked against the parameter's enum and pattern; an unknown
parameter, a missing required value, a parameter for a server the profile is not granted, or two
different definitions under one instance name are refused. Every home gets every instance, so a
fallback home can never hold fewer servers than the primary.

## Rendering client configs

```
hnx mcp catalog render --spec examples/mcp/clients/hermes.yml [--check]
hnx mcp catalog render --profile build/profile.json --client claude-code \
    [--param notes.mode=read] [--lanes real] [--out .mcp.json] [--check]
```

| `--client` | Writes |
|---|---|
| `claude-code` | `.mcp.json`: `{"mcpServers": {name: {"type": "stdio", "command", "args", "env"}}}`, remote servers as `{"type": "http"/"sse", "url", "headers"}` |
| `claude-desktop` | `claude_desktop_config.json`'s `mcpServers` (stdio only; a remote server is reported and left out) |
| `generic` | `mcpServers` with an explicit `transport` and `timeout` |
| `hermes` | Hermes Agent's `mcp_servers:` YAML block (`command`, `args`, `env`, `timeout`; remote: `url`, `headers`) |
| `llm-orchestrator` | its `configs/mcp_catalog.yaml` (`kinds:` with `command`, `args`, `timeout`, fixed `env`, `allowed_env` = the parameters' env keys) and each profile's `grants:` block (`real`/`shadow` lists of `name`, `kind`, `env`), spliced into the profile file |

Render trusts no profile the compiler would not have produced: a compiled profile must pass
everything `hnx agent verify` checks (schema, a digest that is present and matches, the stored
ceiling and budgets, the reader rule and the catalog grant rules judged against the catalog being
rendered), a lean one (`platform/agent_profile`) its schema, the same grant rules and `mcp` within
`mcp_ceiling`; anything else is refused. A spec's output and `grants_file` paths are relative to
the spec's directory (or `--root DIR`) and must stay under it: an absolute path, a `..` that
escapes it or a symlink is refused, and each file is written to a temporary file and renamed into
place.

Only the profile's granted servers are rendered. A credential is never a value: it is
`${HNX_SECRET_<NAME>}` (the registry's `secret_env_name`), which Claude Code expands from its
environment and every other client's deploy substitutes when it installs the file. An HTTP
server's URL is built from the registry (scheme, capability alias, port, path). Every rendered
file carries a generated note (a JSON `_generated` key or a YAML comment) naming the catalog
digest. `--check` compares every output of the spec and fails on any drift: a hand edit, a stale
render, or a home that lost an entry.

The generated example that [broker](broker.md) shows is
`examples/mcp/clients/claude-code/broker-agent.mcp.json`.

### llm-orchestrator

`--client llm-orchestrator` emits exactly the format llm-orchestrator's per-job grants read
(`internal/grants`, ADR-022 there): one kind per grantable stdio server (a remote server, or one
whose arguments or settings vary per instance, is reported and left out unless a rendered profile
is granted it, when it is refused), and per profile a `grants:` block whose instances set only
their parameters' env keys. `clients.orch_accepts` encodes that loader's rules (known fields only,
names, a command, no hard-denied allowed key, no duplicate, a known kind, only allowed env keys)
and the render refuses anything it would refuse. To switch an orchestrator checkout from a
hand-written catalog to the rendered one:

1. import its servers (below), pin, classify and review them, and add `parameters` with `env`
   for every key its grants set per agent, and an `instance` template that reproduces the names
   its prompts use;
2. write a render spec with `client: llm-orchestrator`, `lanes: [real, shadow]`, one `profiles`
   entry per orchestrator profile (`grants_file:` that profile's YAML, `params:` its values) and
   one output for `configs/mcp_catalog.yaml`;
3. render, diff against the hand-written files (the server definitions must come out identical;
   the orchestrator's equivalence test is the judge), commit, and run `--check` in its CI.

## Importing an existing lab

```
hnx mcp catalog import ~/.claude.json .mcp.json claude_desktop_config.json hermes-config.yaml \
    --out lab/mcp
hnx mcp catalog check --catalog lab/mcp --registry lab/services.yml
```

It reads `mcpServers` (Claude Code, Claude Desktop, also under `projects` in `~/.claude.json`),
`servers` (VS Code) and `mcp_servers` (Hermes) and writes one **draft** record per server into
`--out` (required, so a draft never lands in a catalog or a public checkout by default):

- secrets are stripped, **failing closed**: every environment value becomes a `secret:` reference
  named `mcp/<name>-<key>` unless its key names a path, mode, level and the like and nothing in
  the value looks like a credential (those are kept as `settings`, and the report asks you to
  confirm each); a `${VAR}` becomes a `secret:` name (a rendered `${HNX_SECRET_MCP_NOTES_TOKEN}`
  becomes `secret:mcp/notes-token` again). In the arguments, the value after a credential flag
  (`--token`, `--github-token`, `--client-secret`, ...) or in `--flag=VALUE`, a header after
  `--header` (its name kept), a container runner's `-e KEY=VALUE` (moved to `env`), anything that
  looks like a token and any argument carrying a credential marker (`Authorization:`, a
  `KEY=VALUE` in a shell line) become references; URL userinfo and query strings are removed. A
  launcher's package spec (`name==1.2.0`, `@scope/name@1.2.0`) is never mistaken for one. The
  report lists each reference by server and key with the name to store it under and never prints
  a value; a config that does not parse is reported by file, line and column only. The entry's
  own description is not copied;
- the origin is guessed from the launcher (`npx`, `uvx`, `pipx`, `docker run`; `git+https://` as
  a git origin) and never pinned: no hash is invented, so check fails until you add the version
  and sha256, the image digest or the commit; anything else is `kind: unknown`;
- a remote server's URL is not copied: its endpoint becomes `svc:<first label of the host>` for
  you to correct to the registry name, and its path is kept only when it is a plain MCP path
  (`/mcp`, `/sse`, ...);
- tools are not in a client config, so none are listed; egress is written as `none`; a `timeout`
  is kept;
- importing is lossy: every rendered instance (`notes-collector-real`, `notes-collector-shadow`)
  comes back as its own record. Fold them into one record with `parameters` by hand.

Then, per record: pin the origin, list and class the tools, correct endpoint, egress and data
tier, set the owner, store each reported secret in the secret store, get it reviewed and set it
`active`. Finally write the render specs for your runtimes and replace each hand-written client
config by its render.

## Reviews and lifecycle

A record's review digest is the record without its `reviews` (`hnx reviews digest FILE`), so any
change to what the server is drops it back to needing review. `draft` and `retired` servers cannot
be granted; a `deprecated` one can while profiles move to its `replaced_by`, and `hnx agent lint`,
`hnx mcp catalog check` and `render` print a note for every such grant. The MCP servers page
shows each server's current reviews and state.
