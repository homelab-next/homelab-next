---
summary: 'The MCP catalog, one record per MCP server: the record, fatal rules, adding a server, instances, rendering client configs, importing a lab and reviews.'
summary_of: outline:sha256:647464bd0bd26d9b
---
<!-- SPDX-License-Identifier: Apache-2.0 -->
# The MCP catalog: one list of MCP servers

Every MCP server an agent may use is one record in one catalog. Everything else that knows about
MCP servers is generated from it: the capability classes the agent compiler and the reader rule
judge, the knowledge graph's `mcp:` nodes, the MCP line of the system pages, the status hub's
**MCP servers** page, and every client configuration an agent runtime reads. The decision is
[ADR-0024](adr/0024-mcp-catalog-single-source.md); the schema is
`schemas/platform/mcp_server.schema.json` (1.1); the code is `homelabnext/mcp/servers.py` (records
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
origin:                          # first-party path | package | image | git | hosted | unknown
  {kind: package, ecosystem: pypi, package: example-notes-mcp, version: 1.2.0, sha256: <64 hex>,
   bins: [notes-mcp]}            # the bin names the package declares, as the review read them
transport: {type: stdio, bin: notes-mcp, args: []}   # one of bins, and the server's own args:
# the launch (uvx --no-config --from example-notes-mcp==1.2.0 notes-mcp) is generated from the origin
# or {type: streamable-http, endpoint: svc:lake-query, path: /mcp}  -- a lab server: a registry name
# or {type: remote, url: https://mcp.vendor.example.com/mcp}  -- a third party's hosted server
runtime: agent-local             # or {host: <registry host>, user: <system user>}, or hosted
env: {NOTES_TOKEN: secret:mcp/notes-token}      # credentials: secret names only
settings: {NOTES_ROOT: /srv/notes}              # non-secret, the same for every instance
timeout: 120
parameters:                      # typed, per instance; delivered in env
  writable: {env: NOTES_WRITABLE_PREFIX, pattern: '[a-z0-9/_-]+/', default: 'agents/{profile}/'}
  mode: {env: NOTES_MODE, enum: [read, write], default: write}
instance: notes-{profile}-{lane} # the name a client sees
egress: none                     # or [svc:<name>, host:<name>, internet]
data_tier: local-only            # what it returns may reach local-only profiles only
tlp: red                         # 1.3: the TLP label of what it returns; agrees with data_tier
capabilities: [cap:records-propose]   # the platform capabilities it gives access to
implements: [cap:context]        # homelab-next contracts it implements (its conformance suite)
tools:
- {name: read_note, classes: [read], approval: false}
- {name: write_note, classes: [record-write], approval: false}
# acts_via: broker | direct      # 1.1: required with an exec, file-write, send or credential tool
# direct_reason: ...             # with acts_via: direct, and only then
author: agent:example-builder
reviews: [...]                   # check, audit, approve (homelabnext.reviews)
```

The classes are `tool_classes.yml`'s: `read`, `record-write`, `exec`, `file-write`, `egress`,
`send`, `credential`. A server's classes are the union of its tools'.

`tlp` (1.3, [ADR-0033](adr/0033-data-carries-tlp-every-reader-has-a-ceiling.md) decisions 11 and
12) is the TLP label of what the server returns, from the terms of the data behind it: what its
tool output carries into a model request. It agrees with `data_tier`: `local-only` is a label above
`clear`, `cloud-allowed` is `clear`, and the check refuses a record where they disagree (or whose
`tlp` is not a canonical label). A record without `tlp` is read from its `data_tier`
(`servers.record_label`: `clear` for `cloud-allowed`, `red` for `local-only`, the most restrictive
reading), and `hnx mcp catalog check` names every such record in one note. A profile is granted
the server only when its `tlp` is at or below the profile's `tlp_ceiling`
([agent profiles](agent.md#profile-compiler)).

A server with an **acting** tool (a class in the table's `broker_only`: `exec`, `file-write`,
`send`, `credential`) says how it acts (1.1, [ADR-0030](adr/0030-agents-act-only-through-the-broker.md)):
`acts_via: broker` only on the broker's own front (`hnx-broker`, checked structurally against
`homelabnext/broker/mcp_tools.py`), else `acts_via: direct` with a `direct_reason`. Agents act only through the broker, so a profile holds a direct server
only as an exception: a current human approve review of the record plus the ceiling policy's
`direct_mcp` entry for that profile ([agent profiles](agent.md), G-13). `approval: true` means the
broker grants an approval; a client's confirmation prompt is not one, so only a broker server
marks an acting tool `approval: true`.

## The rules (`hnx mcp catalog check`, fatal)

`make mcp-check` (part of `make check` and CI) runs the check and every render spec's `--check`.
Every problem is printed with its file and the exit code is 1; while the catalog itself has
problems the grants are not judged (a note and the summary line say so), since they would be
judged against it. Without a registry (none beside the catalog and no `--registry`) a note says
the registry cross-references were not checked.

No problem, note or refusal of check, render or import carries a value from a record, a render
spec, a profile or a parameter: those lines reach logs, and a value may be a credential pasted by
mistake. A message names the field and the rule it broke (`env/CASES_TOKEN: does not match ...`,
`parameter mode: the value is not one of the parameter's enum`); a name or id that matches its own
pattern may appear; a URL appears as its scheme and host, its userinfo as `***`; a file that does
not parse is reported by its problem, line and column (`homelabnext/mcp/credentials.py`, safe
messages; `tests/mcp/test_mcp_no_value_in_messages.py` seeds one fake secret everywhere). A
deprecated or retired record's `reason` is free text, so a note or refusal says the record's
reason says why (render names the record file) and never repeats it; a profile's grant names
appear only when the catalog or class table holds them, any other as `an unknown MCP server (mcp
entry N)`.

- the record fits the schema (a mismatch is reported against the origin kind or transport type
  the record names), its id is its file name (so ids are unique), and every record file is
  `<id>.yml` (a `.yaml` or `.json` file is refused, never skipped);
- a third-party origin is **pinned**: an exact version (never a range, `latest` or a wildcard;
  npm a full `x.y.z`) with a sha256 or a lock file (relative to the catalog, existing, naming the
  package), an image digest, or a 40-hex commit; `kind: unknown` fails; a first-party path exists
  in the checkout;
- the pin is what runs, because the record does not write the launch: it names its origin, the
  server's entrypoint (`transport.bin`) and the server's own `args`, and render **generates** the
  launch from the origin with fixed flags (`servers.launch`):
  - npm: `npx -y --prefix=<npm_prefix> --package=<package>@<version> -- <bin>`;
  - pypi: `uvx --no-config --from <package>[<extras>]==<version> <bin>` (`extras`: pypi only,
    each a valid extra name);
  - git: the same from `git+<repo>#<commit>` (npm) or `git+<repo>@<commit>[#subdirectory=<dir>]`
    (pypi; `subdirectory` is relative, never `..`, and refused for npm, which installs no git
    subdirectory); the origin names its `ecosystem`, its repo is an https URL without credentials;
  - image: `docker run -i --rm [-e NAME ...] <repository>@<digest>` (one `-e` per env, setting and
    parameter env key; no bin: the image runs its own entrypoint; a registry with a port,
    `registry.example:5000/team/srv`, is fine);
  - first-party: `hnx <entry>` or a path bin, below.

  The launchers are bare names resolved on `PATH`. A record cannot carry a launcher flag
  (`--python <path>`, `--with`, an index, `--registry`, `--privileged`, `-v /:/host`, `--network
  host`, `--entrypoint`): there is no field for one, and its `args` follow the bin (after npx's
  `--`, after uvx's command), so they reach the server, never the launcher. Refused: a `cargo` or
  `go` package (no generated launch pins one: run it from an image). A leading `v` in a version is
  not a difference; an npm version is a full `x.y.z`. Docker is the one container runner the
  launch names (podman users install its `docker` alias), and no record declares a mount, a
  published port or a network: there is no field for one (an image that needs the Docker socket,
  like the retired `docker` example, cannot be catalogued);
- **the bin is one of the package's reviewed `bins`.** npx and uvx run *any* command on `PATH`
  under the bin's name (`npx --package=PIN -- id` runs `id`), so an npm, pypi or git origin lists
  `bins:`, the bin names its released artifact declares (`package.json` `bin`, a wheel's
  `console_scripts`), and `transport.bin` must be one of them; without a bin, the launch runs the
  single declared bin, or the package's base name when `bins` lists it, else the record names
  one. `bins` is in the review digest: **the review attests it**. Check cannot fetch the package
  (it runs without network), so it cannot prove the list; it only refuses a bin outside it, and
  (defense in depth) an interpreter, shell, wrapper or launcher in it (`node`, `python3.12`,
  `sh`, `env`, `curl` ...);
- **the launch is anchored, never the client's working directory.** npx resolves
  `node_modules/<package>` and reads a project `.npmrc` (a registry, say) in its working directory
  before the pinned package, so every npm launch carries `--prefix=<npm_prefix>`: an absolute, empty
  directory on the client's host that the agent cannot write (the render spec's `npm_prefix:`, or
  `--npm-prefix`; render refuses a missing or relative one for any npm server it writes, and npx
  itself fails when it does not exist). Where the directory exists on the host render runs on,
  render also refuses it when it is the filesystem root, a symlink, or not empty; where it does not,
  render notes that it must be created empty (the render host may not be the client's, so this is a
  check where it can be one, not a guarantee). npm then reads its project config and `node_modules`
  from there. uvx launches carry `--no-config`: no `uv.toml` (the user-level one is writable by the
  agent's own user) or `[tool.uv]` can redirect the index (uv already ignores a project's config for
  `uv tool run`). Both were verified against npx 10 and uv 0.11 with local fake packages and
  registries. What remains: npm's user config (`~/.npmrc`) and any `npm_config_*`/`UV_*` in the
  client's own environment apply, as the client user's settings (a record cannot set one, below);
  and the server runs with the client's working directory as its own, which is the server's business
  (a filesystem server's roots, say);
- a **first-party** server runs this checkout's code: `bin: hnx` with an `entry` from a fixed
  allowlist in code (`servers.HNX_ENTRIES`: `mcp-serve` is `hnx mcp serve`, `broker-mcp` is `hnx
  broker mcp`, the subcommands that serve MCP on stdio), whose `args` may hold only that entry's
  flags, each once and with a value (`--root`, `--registry`, `--scope-from-profile`, `--policy`,
  `--lock`; `--socket`; `--scope-from-profile` only with `--policy` and `--lock`; the path flags
  `--root`, `--registry`, `--policy`, `--lock` and `--socket` absolute, since a relative one resolves in the
  client's working directory), so no record reaches `invariants run --plugins-dir`, `--notify-cmd`,
  `broker run`, `workflows run`, `conform run` or `--out`; or a path bin under `origin.path`, which
  render writes absolute under the spec's `checkout_root:` (or `--checkout-root`; required,
  absolute, not a symlink) after checking it is a file there and not a symlink, and which check
  holds to the repository when it runs from a checkout;
- the `sha256` itself is **declarative**: it records the reviewed artifact, but no launcher
  verifies it when it fetches the package;
- a **third party's hosted** server (`transport: {type: remote, url, protocol}`, `origin: {kind:
  hosted, provider}`, `runtime: hosted`, each only with the others): the URL is https with a DNS
  host and no userinfo, query or fragment, a path that cannot carry a credential (an MCP path
  such as `/mcp`, `/sse`, `/v1/mcp`, or lower-case words and versions; a key that a vendor puts
  in the path goes in a header as a `secret:` name instead, and the same rule holds for a lab
  server's `transport.path`), no host label that looks like a credential (any label, a single-label
  host included: `<key>.mcp.vendor.example`, `<key>.example`; an IDN `xn--` label is judged decoded, and as written when it does not decode), never an IPv4 address in any notation (a host whose
  last label is a decimal, octal or `0x` number is one to a URL parser and to `getaddrinfo`:
  `0x7f.0x1`), never a private, test or lab host (`.local`, `.internal`, `.home.arpa`, the
  registry's domain or hosts: a lab server is reached by registry name), its egress names
  `internet`, its `data_tier` is `cloud-allowed` (what it returns is already at the vendor), and
  its credentials are only `headers` as `secret:` names. A name that resolves to a lab address
  (DNS rebinding, `*.nip.io`) is not caught: check does not resolve names;
- every tool is classed with a declared class, and the server lists at least one;
- egress agrees with the classes: a tool classed `egress` needs an egress other than `none`, and
  `internet` needs an egress tool;
- credentials are `secret:` names (env, headers, arguments), two of them never map to the same
  `HNX_SECRET_*` variable, and no argument or setting holds a literal credential, by the rules
  `homelabnext/mcp/credentials.py` holds for check and import alike. A name is read by its last
  word: a credential word (`--token`, `--githubToken`, `--pw`, `PGPASSWORD`, `--api-key`,
  `AUTHORIZATION`, `--auth-header`, `--token-value`) always takes a credential, path or not
  (only a `*_FILE`/`*_PATH`/`*_DIR` name takes a path: `TOKEN_FILE=/run/secrets/x`); a weak word
  (`key`, `auth`, `session`, `credentials`) takes one unless the value is a plain name, a path or
  an auth method (`--key id`, `--sort-key created_at`, `--session default`, `--auth oauth`,
  `GOOGLE_APPLICATION_CREDENTIALS=/etc/gcp/sa.json`). So a credential flag's value (`--token X`,
  `--token ./x`, `--token=-x`, `-p X` or `-pX` unless a port, `-u user:pw` and its long forms (`--user user:pw`, `--user=user:pw`, `--username`, `--proxy-user`, an attached `-uuser:pw`, and httpie's `-a user:pw`, `-auser:pw` and `-a=user:pw`; a numeric `uid:gid` is not one, nor an IP, `localhost` (any case, a trailing dot allowed) or empty host with a port after `-a`, nor a path after `-a` whose host is dotted, an IP, `localhost` or a drive letter (`backup.example.com:/data`, `C:/x`; `alice:/pw` is a credential); short flags are case-sensitive, so curl's `-A` user agent is not one), a header after
  `--header` or in `--header=`) is a `secret:` reference, nothing looks like a token (a token
  prefix such as `ghp_`, or a long, mixed, high-entropy value, `/`-separated base64 and
  dash-grouped random parts included), no URL carries one (userinfo, a credential-named query
  parameter, a token-like path segment such as a webhook's), no JSON (a string or a number under
  a credential key), `KEY=VALUE`, DSN (`password=x`, `Password=x;`), `user:pw@host` or inline
  PEM key carries one, `secret:` appears only as a whole argument, `--flag=secret:<name>` or
  `[--header=]Header: [Scheme ]secret:<name>`, and nothing a client would expand appears
  (`$NAME`, `${VAR}`, `$(cmd)`; a regex's trailing `$` is fine). Not credentials: a switch
  (`--no-auth`), a name whose last word is about one (`--token-file`, `--secret-name`,
  `--session-timeout`, `--max-tokens`, `TOKENIZER`, `AUTH_ENABLED`, `SESSION_BACKEND`), and
  identifiers made of plain words and numbers (`claude-3-5-sonnet-20241022`), a ULID or UUID, an
  image digest, a 40- or 64-hex commit or digest, an email, a Windows or module path. This is
  **defense in depth**, not the control: the control is that credentials live in `env` as
  `secret:` names, and `leak_scan` and gitleaks guard the repository; a heuristic can be tuned
  (both directions are tested) but never made complete;
- no setting, `env` secret or parameter env key configures the process or its launcher (any
  case): a record's environment is the launcher's too (`npx`, `uvx`, `docker` read it), so
  `NPM_CONFIG_REGISTRY` or `UV_INDEX_URL` would fetch another package for the pin. Refused:
  `PATH`, `HOME`, `SHELL`, `BASH_ENV`, `ENV`, `HERMES_HOME`, `LD_*`, `DYLD_*`, `PYTHON*`,
  `NODE_*`, `NPM_CONFIG_*`, `UV_*`, `PIP_*`, `PIPX_*`, `BUN_*`, `COREPACK_*`, `YARN_*`, `PNPM_*`,
  `GIT_*`, `XDG_*`, podman's `CONTAINER*`, and the docker CLI's own configuration: `DOCKER_HOST`,
  `DOCKER_CONFIG`, `DOCKER_CERT_PATH`, `DOCKER_TLS*`, `DOCKER_CONTEXT`, `DOCKER_API_VERSION`,
  `DOCKER_DEFAULT_PLATFORM`, `DOCKER_CONTENT_TRUST*`, `DOCKER_CLI_*`, `DOCKER_BUILDKIT`,
  `DOCKER_CUSTOM_HEADERS`, `BUILDKIT*`, `COMPOSE_*` (an image record's env reaches the docker CLI as
  well as the container). Another `DOCKER_` name, such as `DOCKER_CONTAINER` that an image reads
  inside the container, is the server's own setting. Also refused, because they load code or
  redirect trust inside the launcher (an `OPENSSL_CONF` engine makes `npx` load a shared object):
  `OPENSSL_*`, `SSL_CERT_*`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, `SSLKEYLOGFILE` (the TLS
  stack writes every session's keys to it), every `*_PROXY`
  (`HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `NO_PROXY`), `GCONV_PATH`, `LOCPATH`, `NLSPATH`,
  `HOSTALIASES`, `RES_OPTIONS`, `LOCALDOMAIN`, `GLIBC_TUNABLES`, `MALLOC_*`, `TZDIR`,
  `JAVA_TOOL_OPTIONS`, `_JAVA_OPTIONS`, `JDK_JAVA_OPTIONS`, `PERL5OPT`, `PERL5LIB`, `PERLLIB`,
  `RUBYOPT`, `RUBYLIB`, `BASH_FUNC_*`, `SHELLOPTS`, `BASHOPTS` and `PS4` (`TZ` stays a setting).
  A superset of llm-orchestrator's hard-denied list;
- parameters: every parameter has an `enum` or a `pattern`; its env key never names a credential, never also a fixed setting or secret, never shared by
  two parameters; a default fits its enum and pattern and holds no `$` or `secret:`; templates
  name only `{id}`, `{profile}`, `{lane}`, `{home}`, the parameters, and in arguments
  `{profile_file}`;
- with the registry: an HTTP endpoint is a registry http(s) service, and a registry service's
  `mcp` block names this catalog id with the same transport and path; every registry `mcp` entry
  resolves to a catalog server; runtime hosts and egress services and hosts exist (a record that
  fails the schema gets no follow-on registry errors);
- every `capabilities` entry is a registry service's capability, a class-table capability or a
  conformance contract, checked with or without a registry (without one, a service's capability
  cannot be resolved and is reported, with a hint to pass `--registry`);
- `reason` and `replaced_by` appear only on a deprecated or retired record, and `replaced_by`
  names an active server; `implements` names a homelab-next capability contract
  (a conformance capability), so the graph ties the server to that contract's suite;
- an `active` or `deprecated` record with an acting tool (`broker_only` class) declares
  `acts_via` (`direct` with a `direct_reason`), only the broker's own front (fixed in code: id,
  origin, launch and its exact tools) may say `acts_via: broker`, and only it marks an acting tool
  `approval: true` (ADR-0030);
- classes are floored in code, not only declared: a record of known acting software (by a word
  of what it launches, its package, image, bins, git repo or hosted provider, not its id: ssh,
  shells, kubernetes, ansible, docker, filesystem, git, a secret store, chat or mail senders) has
  a tool in that class; a tool whose first verb acts (run, exec, apply, deploy, delete, send,
  publish, trigger, click, type...; `createIssue` is split at its camelCase) carries an acting
  class; a tool whose first verb writes (create, update, write...) is `file-write`, or
  `record-write` only on a record that fronts a capability the class table classes
  `record-write` (`capabilities` or `implements`: an API that validates what it writes; a label
  such as `cap:metrics` is not one); a tool whose first verb reads (`get_commit`,
  `list_open_alerts`) is a read by its name. A module's contributed records are floored the same;
- with the review policy: an `active` record carries current agent check, agent audit and human
  approve reviews (`mcp-server.active` in `examples/review-policy.yml`; `hnx reviews digest
  examples/mcp/<id>.yml` gives the digest to stamp);
- every agent profile and context manifest in the checkout (or `--grants PATH...`) grants only
  catalog ids whose status is `active` or `deprecated` (an allowlist: `draft`, `retired` and
  anything else are refused), of a server with a known `data_tier`, never a `local-only` server to a
  profile whose `data_tier` is not `local-only`, never a server whose `tlp` is above the profile's
  TLP ceiling, a reader holds no exec, file-write, egress or
  credential server, and no profile holds an acting server that does not act through the broker
  unless it is a reviewed direct exception its ceiling policy lists (G-13). A `deprecated` grant passes with a note pointing at the record's reason and
  naming its `replaced_by`. The compiler, `hnx agent verify`, `hnx agent lint` and `render` apply
  the same rules, and they judge grants only against a sound catalog: a record that fails the
  schema, an id that is not its file name or two records with one id refuse every judgement (so a
  stray record cannot reclassify a server).

## Adding a server

1. Write `<catalog>/<id>.yml` with `status: draft`, pin its origin, list the bin names the
   package declares (`bins`, read from the released artifact), list every tool with its
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
policy: policy/ceilings.yml     # the ceiling policy (and optionally lock:) profiles are judged by
registry: ../../services.yml
lanes: [real, shadow]
npm_prefix: /var/lib/hnx/npm-prefix   # an absolute, empty directory npx reads its config from
checkout_root: /opt/hnx               # where a first-party path bin is resolved (when one is)
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

A spec may also name `owns:`, globs (relative to the spec) of the files it is the only writer
of: `--check` reports any file there that no output renders (a stale home, a hand-written
config).

Homes may differ where the deployment needs them to: an output's `params` (`SERVER` or
`SERVER@LANE` to values) override the profiles' values in that home for every profile granted the
server, and `{home}` (the output's `home`, empty outside a spec) is a template like `{profile}`:

```yaml
outputs:
  - {home: local, path: hermes/local.yaml}
  - {home: cloud, path: hermes/cloud.yaml, params: {vault: {producer_tier: cloud}}}
```

Each parameter's value is the grant's (`params`, then the home's), else its default; a list value expands into one
instance per element. A value is a string (quote YAML's `true` or `0755`), passed through
verbatim: it may not contain `$`, `secret:` or a control character, so a grant can never route a
secret or an environment variable to a server (secrets come only from the record's own `env`,
`headers` and arguments). Lanes and homes are templated too (`{lane}`, `{home}`), so each is a
plain name (`^[a-z][a-z0-9-]{0,31}$`), in a spec and in `--lanes` alike. Values are checked
against the parameter's enum and pattern; an unknown parameter, a missing required value, a
parameter for a server the profile is not granted (or, in an output's `params`, that no profile of
the spec is granted), a `SERVER@LANE` whose lane is not rendered, or two different definitions
under one instance name are refused: a typo is never silently ignored. Every home gets every instance, so a
fallback home can never hold fewer servers than the primary.

## Rendering client configs

```
hnx mcp catalog render --spec examples/mcp/clients/hermes.yml [--check]
hnx mcp catalog render --profile build/profile.json --client claude-code \
    --policy policy.yml [--lock lock.yml] [--param notes.mode=read] [--lanes real] \
    [--npm-prefix /var/lib/hnx/npm-prefix] [--checkout-root /opt/hnx] [--out .mcp.json] [--check]
```

| `--client` | Writes |
|---|---|
| `claude-code` | `.mcp.json`: `{"mcpServers": {name: {"type": "stdio", "command", "args", "env"}}}`, remote servers (a lab's by registry name, a hosted one by its URL) as `{"type": "http"/"sse", "url", "headers"}` |
| `claude-desktop` | a **fragment**: the `mcpServers` to merge into `claude_desktop_config.json` (stdio only; a remote server is reported and left out). Claude Desktop does not expand `${VAR}` in that file, so a server that needs a secret is refused (start it through a wrapper that reads the secret store). Never point an output at the live file: it holds other settings the render would replace |
| `generic` | `mcpServers` with an explicit `transport` and `timeout` |
| `hermes` | Hermes Agent's `mcp_servers:` YAML block (`command`, `args`, `env`, `timeout`; remote: `url`, `headers`). An entry has no transport field, so a legacy `sse` server is refused rather than reached as streamable HTTP |
| `llm-orchestrator` | its `configs/mcp_catalog.yaml` (`kinds:` with `command`, `args`, `timeout`, fixed `env`, `allowed_env` = the parameters' env keys) and each profile's `grants:` block (`real`/`shadow` lists of `name`, `kind`, `env`), spliced into the profile file |

Render trusts no profile the compiler would not have produced: a compiled profile must pass
everything `hnx agent verify --policy [--lock]` checks (schema, a digest that is present and
matches, the policy's ceiling (the stored one may not be wider) and budgets, the reader rule and
the catalog grant rules judged against the catalog being rendered, and with a lock the reviewed
digest), and it is refused without a ceiling policy (a spec's `policy:` and optional `lock:`,
relative to the spec, or `--policy`/`--lock` with `--profile`): the ceiling and digest stored in
the file are whatever last edited it, so a hand edit with a recomputed digest would otherwise
render. A lean one (`platform/agent_profile`) must pass its schema, the same grant rules, `mcp`
within `mcp_ceiling`, `mcp` and `capabilities` within the policy's ceiling, and the reader rule
whenever the policy marks the profile a reader (`reads_untrusted: true` in its entry; the file's
own `reads_untrusted: false` does not turn it off, as for a compiled profile); it is refused
without a policy too (its own `mcp_ceiling` proves only that it agrees with itself); anything
else is refused. The policy also **attests** each profile's `data_tier` and `model_role`
(optional keys of its entry): the profile must say the same, and only a profile whose entry says
`data_tier: local-only` is granted a local-only server, so a profile cannot declare itself
local-only to receive local-only data ([agent profiles](agent.md)). A local-only profile is
granted no server that reaches the internet (a hosted one, or `egress: internet`), where its
context would go, unless its entry names that server in `internet_mcp`, an exception the policy
owner makes per profile and server. The example
specs share `examples/mcp/clients/policy/ceilings.yml`. Nor does render write a record check
would refuse: every record it writes (the granted ones; for llm-orchestrator every grantable one,
since its catalog holds them all) must pass check's **whole** record check (schema and id, pin and
launch, tools and egress, a hosted server's URL, credentials, parameters and templates,
capabilities, lifecycle, and the registry's cross-references: the spec's registry, else
`services.yml` beside the catalog) and carry the reviews its status needs under
`review-policy.yml` beside the catalog directory. A catalog with no review policy there is
refused unless `--no-review-policy` says this is a local experiment (the records then go
unreviewed). A render spec is **trusted input**: it names the catalog, the policy, the lock, the
anchors and where files are written, so review it like the code that runs it. A spec's output and `grants_file` paths are relative to
the spec's directory (or `--root DIR`) and must stay under it: an absolute path, a `..` that
escapes it or a symlink is refused, and each file is written to a temporary file and renamed into
place.

Only the profile's granted servers are rendered. A credential is never a value: it is
`${HNX_SECRET_<NAME>}` (the registry's `secret_env_name`), which Claude Code expands from its
environment and the Hermes and llm-orchestrator deploys substitute when they install the file
(Claude Desktop expands nothing: see above). An HTTP server's URL is built from the registry
(scheme, capability alias, port, path). Every rendered file carries a generated note (a JSON
`_generated` key or a YAML comment) naming the digest of the records **it** holds, so editing a
record another file holds never makes this one drift. `--check` compares every output of the spec
(line endings and trailing newlines aside) and fails on any drift: a hand edit, a stale render,
or a home that lost an entry.

The generated example that [broker](broker.md) shows is
`examples/mcp/clients/claude-code/broker-agent.mcp.json`.

### llm-orchestrator

`--client llm-orchestrator` emits exactly the format llm-orchestrator's per-job grants read
(`internal/grants`, ADR-022 there): one kind per grantable stdio server (a remote server, or one
whose arguments or settings vary per instance, is reported and left out unless a rendered profile
is granted it, when it is refused: the job would otherwise run silently without it; a server
that acts other than through the broker is left out unless a rendered profile is granted it,
which only a policy's `direct_mcp` exception allows, so the controller refuses any other profile's
grant of it), and per profile a `grants:` block whose instances set only their parameters' env
keys.
`clients.orch_accepts` encodes that loader's rules (YAML without a duplicate key, as yaml.v3
reads it; known fields only, names, a command, no hard-denied allowed key, no duplicate server, a
known kind, only allowed env keys) and its scheduler's (a profile that grants one lane must grant
the other, or every job of the empty lane fails), and the render refuses anything it would refuse,
in `--profile` mode too. So render both lanes (`lanes: [real, shadow]`).

The block is spliced into the orchestrator's own profile file, which must exist: everything from
the marker line `# Per-job MCP grants (ADR-022).` to the end of the file is the render's. A
`grants:` key outside the block (the result would have two) or any key after the marker (the
splice would delete it) is refused. The rendered catalog replaces the orchestrator's whole
`configs/mcp_catalog.yaml`, so the spec's `check_profiles:` glob names every profile file the
orchestrator loads: each one with a `grants:` block, rendered by this spec or not, must accept the
new catalog, or the render is refused (the controller would refuse to start).

To switch an orchestrator checkout from a hand-written catalog to the rendered one:

1. import its servers (below), pin, classify and review them, and add `parameters` with `env`
   for every key its grants set per agent, and an `instance` template that reproduces the names
   its prompts use;
2. write a render spec with `client: llm-orchestrator`, `lanes: [real, shadow]`, one `profiles`
   entry per orchestrator profile (`grants_file:` that profile's YAML, `params:` its values),
   one output for `configs/mcp_catalog.yaml` and `check_profiles: configs/profiles/*.yaml`;
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
  becomes `secret:mcp/notes-token` again; `${VAR:-default}` names `VAR`). In the
  server's own arguments, everything check would refuse as a literal credential (the same rules,
  above) becomes a reference, and more, failing closed: any argument carrying a credential
  marker (`Authorization:`, `password`) becomes a reference (an argument that already is one,
  `Authorization: Bearer secret:<name>` included, is kept), and a URL (or each URL of a
  comma-separated list; a URL inside other text, such as a user agent, is left alone unless it
  carries a credential) keeps only its scheme, host, port and a plain MCP path (userinfo, query and any other path are removed, in arguments
  and in `*_URL` settings alike). A path is kept as a setting whatever its key (it says where a
  credential is, never what it is). The report lists each reference by server and key with the
  name to store it under and never prints a value; a config that does not parse is reported by
  file, line and column only. The entry's own description is not copied;
- the launch is **mapped, never copied**: the command line is read the way its launcher reads
  it (`npx`/`bunx`, `uvx`, `uv tool run`, `pipx run`, `docker run`/`podman run`, `hnx`;
  `homelabnext/mcp/launch.py`) and becomes the origin its launch position names (a package, a
  `git+https://` repo without its userinfo, an image; never pinned: no hash is invented, so check
  fails until you add the version and sha256, the image digest or the commit), the bin (the
  command after `--from`/`--spec`/`--package`) and the server's own arguments. Every launcher
  flag (`--python`, `--with`, an index, `-v`, `--privileged` ...) is dropped and named in the
  report; a container runner's `-e KEY=VALUE` becomes a setting when it is an allowlisted one,
  else an `env` secret, and `-e KEY` an `env` secret. `origin.bins` is filled with the bin the
  config ran (or the default npx/uvx picked) and the report says so: it is what the config ran,
  not what the package declares, so the review reads the real list from the artifact. pypi
  extras (`pkg[extra]==ver`), a git `#subdirectory=` and a registry port are kept. An `hnx`
  command line maps to its entry (`hnx mcp serve ...`, `hnx broker mcp ...`) with only that
  entry's flags, or not at all. What it cannot map (a shell, `env`, an
  interpreter, a path, `npm exec`, an unknown flag before the launch position, `--entrypoint`, a
  bin that is not the package's own such as `npx -p PKG node -e ...`) becomes `kind: unknown`
  with none of its arguments copied;
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
