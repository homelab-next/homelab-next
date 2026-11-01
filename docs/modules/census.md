---
summary: 'Module manifest reference: what the census gathers from hosts (agents, MCP servers, lake tables, service rows) and why other kinds are not gathered.'
summary_of: outline:sha256:38552004d519beca
---
<!-- SPDX-License-Identifier: Apache-2.0 -->
# Modules: what the census gathers

> Part of [the module manifest](../modules.md) ([[modules]]), the draft for operator review
> ([ADR-0027](../adr/0027-feature-and-provider-modules.md), proposed); the census itself and the
> deploy-time loader are on [the loader at deploy time](loader-deploy.md).

## What the census gathers

**Agents, from the running broker.** On a host whose inventory sets `module_census_broker_socket`
(the broker's socket, under `/run/`), the census also asks the broker, as root, which agents it
serves: `hnx broker agents --socket PATH`, the broker's one **operator** operation
([broker](../broker.md)). The broker host's manifest must list the census identity, root
(`{uid: 0}`), in `operators` (broker manifest 1.8); no peer is an operator otherwise, root
included. The answer is the agent keys whose profile the manifest both maps a transport peer to
and grants something, names only, and it is audited. An agent, a relay, the Code Mode runner and
a sandbox are refused it (`not-the-operator`), and an unlisted root `unknown-caller`; `hnx`
then names the `operators` key. Only that one task becomes root (`module_census_hnx_cli`, an
absolute path, default `/opt/hnx/bin/hnx`, pinned on the deploy's command line like
`module_census_systemctl_cli`); the systemctl queries stay unprivileged. A broker that
refuses fails the census, never passes it. Each answered line must be one agent key, or the census is unreadable; `agents` is
the union over every broker asked, and stays in `not_gathered` when no host's census asked one (a
lab whose inventory sets no socket has not shown which agents run, which is never read as
"none"). What the broker answers is believed, like a unit line: an overlay that sets no socket
leaves `agents` not compared, and the gather says so.

**MCP servers, from the installed clients.** A host's inventory may list the MCP client
configurations installed on it (`module_census_mcp_configs`, in `host_vars`: each `{path,
client}`, the file `hnx mcp catalog render` wrote and the deploy put in place, client one of
`claude-code`, `generic` or `hermes`: a fleet host's clients; `claude-desktop`, a person's own
machine, is never a fleet host's, and the `llm-orchestrator` client's catalog lists kinds, not
servers). The list is trusted overlay input: it names files the census reads on the host, so each
must be named as its client's configuration (`claude-code` `.mcp.json` or `<name>.mcp.json`,
`generic` those or `mcp.json`, `hermes` `config.yaml`) and any other name is refused before it is
opened. The census reads each in one step (`library/mcp_client_configs.py`): every directory on
its way opened without following a link, root's or the connection user's, and refused when its
group or others may write it (a root-owned sticky directory, `/tmp`, passes: no one can replace
an entry in it they do not own, though what is reached through it must still be root's or the
user's); the file a regular file with a single link, root's or the user's, no one but its owner
may write, at most 1 MiB, read without blocking.

A configuration can hold secrets (an `env` value, a header), so **its text never leaves the
host**: the module parses it there, for its client (the `mcpServers` object of a JSON client file,
duplicate keys, `NaN` and `Infinity` refused; the `mcp_servers` mapping of a Hermes file, read
with PyYAML's safe loader with aliases and duplicate keys refused; where PyYAML is not installed
on the host, a Hermes file fails the census rather than its text being sent), and returns only
whether the file is present and the server names it registers. The task runs with `no_log`, and
so does the one that writes the answer. `gather` checks each name again; every one is a name that
client registers when it starts; an absent file registers nothing, and the gather says so. A name
that is not an inventory name, or a file that does not parse, fails the census, for the whole
fleet: one host's stray name stops it. `mcp_servers` is gathered when at least one host lists a
configuration and stays in `not_gathered` otherwise. The names themselves are only checked for
shape, so a secret pasted where a server name belongs (lower case, digits and hyphens pass) could
come back like any name. Three bounds limit that. A name over 64 characters (the longest an `instance` can expand to) is refused on the host
and again by `gather`, so it is never returned, written to the census answer or persisted in the
inventory. Every problem and refusal that names a server prints it clipped: the owning module's
id whole (it says which module the name was bound to) and, when the rest is over 16 characters,
only the first 8 of it and the name's length. What is persisted is the census answer per host and
the gathered inventory's `mcp_servers`: names of at most 64 characters, in the MCP name shape (`[a-z0-9][a-z0-9_-]*`: an underscore is allowed, as in the `instance` pattern), which a
short pasted secret could still be; both files are the runner's, mode 0600.

The loader matches each registered name back to its catalog record by the record's instance
template (`instance:`, default `{id}`: `{id}` is the record's id and every other placeholder one
or more name segments), so a parameterized server's `notes-<profile>-<lane>` counts for the
record that declares it. A template that begins with a placeholder other than `{id}`
(`{profile}-x`, which would claim any name ending in its tail) is refused, in a module's record
and in the core's catalog. A name its prefix binds to a module is matched against that module's
records only, so another module's template never claims it; a name bound to no module against
every selected record. Of several records that match one name, an exact id wins, then the template
that fixes the longest prefix; a name still matched by several is reported as ambiguous. A name no
record matches is judged as any other kind's, by its module prefix, and one bound to no module
must be one of the core's MCP records (its id or an instance of it) when the core's catalog was
read. The file is what the client reads at start, so a home that lost an entry, or one a hand
added, shows; whether a server then launched does not, nor anything a client reads from files the
host does not list (a user-level or a project's own configuration, a managed policy file).

**Lake tables, from the catalog.** On the host that runs the lake catalog (the lake-catalog
slot's contract is the Iceberg REST catalog), the inventory may set `module_census_catalog_url`
(in `host_vars`: `http://<loopback IP literal>:<port>`, the catalog as its own host reaches it)
and `module_census_catalog_warehouse`, with `module_census_catalog_api_root` (default `/catalog`)
and, when the catalog wants a bearer token, `module_census_catalog_token_file`, a plain file name
in `/etc/homelabnext` on that host (set only with the URL). The census then runs `hnx modules
catalog-tables` there (`homelabnext.modules.census.catalog_tables`): it lists the warehouse's
top-level namespaces and each one's tables with **GET requests only**, so it can change nothing
whatever rights the token carries; over plain `http` to a loopback IP literal only (`https` is
refused: the request never leaves the host, so TLS would add a certificate to manage and protect
nothing; a name such as `localhost` is refused: it resolves to what the resolver says); with no
redirect followed and no proxy, so the token goes to that address alone. The token file must be a
plain name directly in `/etc/homelabnext` (the role's assert and the command both refuse any other
path, so the task that becomes root can be pointed at no other file) and is read in one step:
never through a link, a regular file with a single link, owned by the reading user and readable or
writable by no one else, one line of token characters. The token is never printed, and an error
names the request and its HTTP status only, **never what the catalog answered** (a refusal can echo
the request, its credential included); the role reports that line with control characters removed
and cut to 200 characters. Only that task becomes root, and only when a token file is named (to
read it); without one it runs as the connection user. **The token never leaves the catalog host**:
the runner holds no catalog credential, and the answer carries names only. Each page of a listing
is read to at most 1 MiB, more than 4,096 namespaces or tables fails the census rather than being
cut short, and the whole listing gives up after two minutes (the task's own timeout, three, backs
that).

The host prints `{"tables": ["<namespace>.<name>", ...], "left_out": n}`: a namespace or table
whose name is not of the inventory's shape (`[a-z][a-z0-9_]*` each, at most 129 characters as
`table:<namespace>.<name>`) is left out and counted, and the gather notes the count. Each namespace
directly under a listed one (`GET /namespaces?parent=<ns>`, paged like the rest) is counted there
too, and neither its tables nor its own children are listed; a namespace the catalog drops between
listing it and listing its tables (a 404) is counted and skipped. No module's table can have such
a name (its manifest's schema refuses it), so leaving one out hides no module's table. `gather` reads each name again strictly, and `tables` is
the union over every catalog listed (at most 4,096); it stays in `not_gathered` when no host's
census listed a catalog. A catalog that cannot be listed (unreachable, a refused token, a reply
that is not the contract's) fails the census.

`hnx modules check --running` judges each listed table like any running name: `table:<id_>.<name>`
is bound to the module whose id, with `-` read as `_`, is `<id_>`, which must declare it and be
selected; every selected module's declared table must exist. A table in the core's namespace
(`ocsf`) is the core's and must be one of its OCSF tables (`tables table:ocsf.<name> is in the
core's namespace but is no core table`), when the core's tables were read; without them the check
says so. A catalog usually holds more than the fleet's tables (an archive, a scratch namespace),
so the selection names the lab's own namespaces in `lab_table_namespaces` (each `{namespace, why}`,
`why` required; see [Site selection](selection.md#site-selection-platformmodule_selection-10-a-draft-schema)).
With the list, a table in any other namespace that no module id binds is a problem (`tables
table:stray.x runs in namespace stray, which is no module's, the core's or the lab's`): a table a
retired module left behind, in a namespace no current module id names, is caught too, and `[]`
says the lab keeps no namespace of its own. Without the list such a table is not judged, and the
check says so (`the lab's own table namespaces are not declared`). Without the core's tables, a
table in `ocsf` is not judged either way.
What the catalog lists is believed, as a host's `systemctl` output is: it says which tables the
catalog holds, not whether anything writes to them.

**Service rows, by what listens.** Each host's answer also carries the sockets it listens on: the
role's `listening_sockets` module reads the kernel's own socket tables (`/proc/net/tcp`, `tcp6`,
`udp`, `udp6`, never a command's output, each read to a fixed size) and reports each listening TCP
port and each bound, unconnected UDP port as `tcp/<port>` or `udp/<port>`, with `@lo` for a socket
bound only to a loopback address (`tcp/631@lo`). A line whose address or port is not the kernel's
hex is skipped; a host with more than 16,384 distinct sockets fails the census rather than being
cut short. `hnx modules gather` parses them strictly (proto, a port 1 to 65535 and the optional
`@lo`, at most 16,384 per host) and writes them to the inventory's `listening`, per host. Service
rows stay in `not_gathered`: a socket names no row.

With `listening`, `hnx modules check --running` judges each selected module's row by whether the
host the site places it on listens on its port, on an address other hosts can reach (TCP, UDP for
a `udp` row, either for `dns`; a socket bound only to loopback answers no other host):
`rows <name> (<module>) is declared on <host> but <census host> listens on no tcp/<port>`, with
`(only on loopback: tcp/<port>)` when that is all there is. A provider's row is judged under each
instance the site names, on the host that entry's own placement gives it. A row's site host is the
census host of that name, or the one whose first DNS label it is (`data` for
`data.example.internal`), either compared case-insensitively; a row placed on no census host, or
on a name two census hosts share as a first label, is noted ("no census host has that name") and
not judged.

This is **derived**, from what the host reports and what the row and the placement declare, and it
is one way. Its limits:

- a port another program holds reads as the row answering;
- any bound, unconnected UDP socket counts, a client's on an ephemeral port included, so a row's
  UDP port can be another program's;
- a row reached only through NAT into another network namespace, with no socket on the host (a
  container port published by packet rewriting alone, with no proxy process holding it), reads as
  not answering;
- a row nobody declared is never seen, and the core's own rows are not judged.

**Why the other kinds are not gathered.** The census lists only what a host, or a query the runner
can make without new credentials, reports truthfully and in full; a kind it cannot measure stays in
`not_gathered`, so the loader says it was not compared instead of judging the declarations against
themselves. Beside the fleet units, the recovery pairs, the agents, the MCP servers and the lake
tables have such a source, and service rows are judged by what listens (above); for the rest:

| Kind | What exists today | What a census of it would need |
|---|---|---|
| `rows` by name (service rows that answer) | the listening sockets judge each declared row (above), but name none; the status hub's `status.json` reads only the rows that offer a status source, so a row without one would read as not running | a liveness probe every service row carries (or the hub reporting every row, sourced or not), read on loopback where the hub runs |

Reading these back from the manifests or the role table would only restate what is declared, so
none is.
